import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { once } from 'node:events';
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { setImmediate as flush } from 'node:timers/promises';
import { ProxyPool, loadProxyConfig, renderProxyUrl, redactSecrets } from './proxy-pool.mjs';

// Every credential below is invented test data. No test reads proxy.local.json,
// uses process.env credential values, changes system proxy settings, or accesses WAN.
function config(overrides = {}) {
  return {
    enabled: true, protocol: 'http', host: '127.0.0.1', port: 8080,
    username_template: 'dummy-{country}-{session}',
    password_template: 'FAKE@password/{country}/{session}',
    default_country: 'US', countries: ['US', 'GB'], pool_size: 1,
    lease_ttl_seconds: 30, max_leases: 4, ...overrides,
  };
}

function tempConfig(t, value) {
  const dir = mkdtempSync(join(tmpdir(), 'cyberstrike-proxy-test-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'fixture.json');
  writeFileSync(path, typeof value === 'string' ? value : JSON.stringify(value));
  return path;
}

async function listen(t, server) {
  const sockets = new Set();
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.on('error', () => {});
    socket.once('close', () => sockets.delete(socket));
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
  });
  return server.address().port;
}

async function fixture(t) {
  let slowResponse;
  let slowStarted;
  const slowReady = new Promise((resolve) => { slowStarted = resolve; });
  const origin = http.createServer(async (req, res) => {
    if (req.url === '/slow') {
      slowResponse = res;
      slowStarted();
      return;
    }
    let body = '';
    for await (const chunk of req) body += chunk;
    res.end(JSON.stringify({ method: req.method, body, path: req.url }));
  });
  const originPort = await listen(t, origin);
  const echoPort = await listen(t, net.createServer((socket) => socket.pipe(socket)));
  const records = [];
  const upstream = http.createServer((req, res) => {
    const auth = Buffer.from((req.headers['proxy-authorization'] ?? '').replace(/^Basic /, ''), 'base64').toString();
    records.push({ method: req.method, auth, url: req.url });
    if (req.url.endsWith('/reject')) {
      res.writeHead(407, { 'content-type': 'text/plain' });
      res.end(`UNSAFE upstream diagnostic: ${auth}`);
      return;
    }
    const target = new URL(req.url);
    assert.equal(target.hostname, '127.0.0.1');
    assert.equal(Number(target.port), originPort);
    const headers = { ...req.headers };
    delete headers['proxy-authorization'];
    const outgoing = http.request(target, { method: req.method, headers, agent: false }, (response) => {
      res.writeHead(response.statusCode, response.headers);
      response.pipe(res);
    });
    outgoing.on('error', () => res.destroy());
    res.on('close', () => outgoing.destroy());
    req.pipe(outgoing);
  });
  upstream.on('connect', (req, client, head) => {
    const auth = Buffer.from((req.headers['proxy-authorization'] ?? '').replace(/^Basic /, ''), 'base64').toString();
    records.push({ method: 'CONNECT', auth, url: req.url });
    if (req.url === 'reject.example:443') {
      client.end(`HTTP/1.1 407 Denied\r\n\r\nUNSAFE ${auth}`);
      return;
    }
    assert.equal(req.url, `127.0.0.1:${echoPort}`);
    const target = net.connect(echoPort, '127.0.0.1', () => {
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head.length) target.write(head);
      client.pipe(target);
      target.pipe(client);
    });
    target.on('error', () => client.destroy());
    client.on('error', () => target.destroy());
    client.on('close', () => target.destroy());
    target.on('close', () => client.destroy());
  });
  const port = await listen(t, upstream);
  const pool = new ProxyPool(config({ port }));
  t.after(() => pool.close());
  return {
    pool, records, port, echoPort,
    originUrl: `http://127.0.0.1:${originPort}`,
    slowReady,
    finishSlow: () => slowResponse.end('slow complete'),
  };
}

function request(proxyUrl, target, { method = 'GET', body = '', agent = false } = {}) {
  const proxy = new URL(proxyUrl);
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: proxy.hostname, port: proxy.port, path: target,
      method, agent, headers: { host: new URL(target).host, 'content-length': Buffer.byteLength(body) },
    }, (response) => {
      let data = '';
      response.on('data', (chunk) => { data += chunk; });
      response.on('error', reject);
      response.on('end', () => resolve({ status: response.statusCode, body: data }));
    });
    req.on('error', reject);
    req.end(body);
  });
}

function connect(proxyUrl, target) {
  const proxy = new URL(proxyUrl);
  return new Promise((resolve, reject) => {
    const req = http.request({ host: proxy.hostname, port: proxy.port, method: 'CONNECT', path: target, agent: false });
    req.on('error', reject);
    req.on('connect', (response, socket, head) => {
      socket.on('error', () => {});
      resolve({ status: response.statusCode, socket, head });
    });
    req.end();
  });
}

async function echo(socket, text) {
  const received = once(socket, 'data');
  socket.write(text);
  const [data] = await received;
  assert.equal(data.toString(), text);
}

function expectedAuth(pool, lease) {
  const url = new URL(renderProxyUrl(pool.config, { country: lease.country, session: lease.session_id }));
  return `${decodeURIComponent(url.username)}:${decodeURIComponent(url.password)}`;
}

function fakeClock(t) {
  let now = Date.now();
  t.mock.method(Date, 'now', () => now);
  t.mock.timers.enable({ apis: ['setInterval'] });
  return async (milliseconds) => {
    now += milliseconds;
    t.mock.timers.tick(milliseconds);
    for (let iteration = 0; iteration < 6; iteration++) await flush();
  };
}

test('missing explicit config is disabled and does not consume environment credentials', async (t) => {
  const path = tempConfig(t, {});
  const cfg = loadProxyConfig({
    CYBERSTRIKE_PROXY_CONFIG: `${path}.missing`, CYBERSTRIKE_PROXY_PASSWORD: 'IGNORED_DUMMY',
  });
  assert.equal(cfg.enabled, false);
  assert.equal(cfg.password_template, '');
  const pool = new ProxyPool(cfg);
  t.after(() => pool.close());
  assert.equal(pool.status().available, false);
  assert.equal(pool.status().lease_count, 0);
  await assert.rejects(pool.acquire(), /disabled/);
  assert.equal(await pool.release('unknown'), false);
});

test('config loading is synchronous, supports cwd-relative paths and environment overrides', (t) => {
  const path = tempConfig(t, config({ protocol: 'SOCKS5H', countries: ['us', 'gb', 'US'], default_country: 'jp' }));
  const env = {
    CYBERSTRIKE_PROXY_CONFIG: relative(process.cwd(), path),
    CYBERSTRIKE_PROXY_PASSWORD: 'ENV_FAKE-{country}-{session}',
    CYBERSTRIKE_PROXY_USERNAME_TEMPLATE: 'ENV_USER-{session}',
  };
  const cfg = loadProxyConfig(env);
  assert.equal(cfg.protocol, 'socks5h');
  assert.deepEqual(cfg.countries, ['US', 'GB']);
  assert.equal(cfg.default_country, 'JP');
  assert.equal(cfg.password_template, env.CYBERSTRIKE_PROXY_PASSWORD);
  assert.equal(cfg.username_template, env.CYBERSTRIKE_PROXY_USERNAME_TEMPLATE);
  assert.ok(Object.isFrozen(cfg));
  assert.ok(Object.isFrozen(cfg.countries));
  const empty = loadProxyConfig({ CYBERSTRIKE_PROXY_CONFIG: path, CYBERSTRIKE_PROXY_PASSWORD: '' });
  assert.equal(empty.password_template, '');
});

test('configuration validates every boundary without echoing input', (t) => {
  for (const patch of [
    { enabled: 'yes' }, { protocol: 'ftp' }, { host: 'http://DUMMY_USER:DUMMY_PASS@example.com' },
    { port: 0 }, { port: 65536 }, { pool_size: 0 }, { pool_size: 9 }, { pool_size: 1.5 },
    { max_leases: 0 }, { max_leases: 65 }, { lease_ttl_seconds: 29 }, { lease_ttl_seconds: 86401 },
    { revived_lease_ttl_seconds: 29 }, { revived_lease_ttl_seconds: 3601 },
    { countries: ['USA'] }, { countries: 'US' }, { default_country: '1A' },
    { username_template: 123 }, { password_template: 'DUMMY\nSECRET' },
  ]) {
    assert.throws(() => new ProxyPool(config(patch)), (error) => {
      assert.match(error.message, /^Invalid proxy configuration:/);
      assert.doesNotMatch(error.message, /DUMMY|SECRET/);
      return true;
    });
  }
  for (const patch of [
    { pool_size: 1, max_leases: 1, lease_ttl_seconds: 30, port: 1 },
    { pool_size: 8, max_leases: 64, lease_ttl_seconds: 86400, port: 65535 },
    { pool_size: 1, max_leases: 1, lease_ttl_seconds: 1800, revived_lease_ttl_seconds: 120 },
  ]) {
    const pool = new ProxyPool(config(patch));
    t.after(() => pool.close());
    assert.equal(pool.config.max_leases, patch.max_leases);
  }
  const malformed = tempConfig(t, '{"password_template":"DUMMY_SECRET",');
  assert.throws(() => loadProxyConfig({ CYBERSTRIKE_PROXY_CONFIG: malformed }), /^Error: Invalid proxy configuration: JSON$/);
});

test('URL encoding substitutes country/session in BOTH credential fields for all protocols', () => {
  for (const protocol of ['http', 'https', 'socks5', 'socks5h']) {
    const cfg = config({ protocol, host: 'example.com', username_template: 'FAKE @/{country}/{session}', password_template: 'FAKE:@?#/{session}/{country}' });
    const rendered = renderProxyUrl(cfg, { country: 'jp', session: 'sid @/?#' });
    const parsed = new URL(rendered);
    assert.equal(parsed.protocol, `${protocol}:`);
    assert.equal(decodeURIComponent(parsed.username), 'FAKE @/JP/sid @/?#');
    assert.equal(decodeURIComponent(parsed.password), 'FAKE:@?#/sid @/?#/JP');
    assert.equal(parsed.host, 'example.com:8080');
    assert.match(rendered, /%40/);
    assert.match(rendered, /%2F/);
    assert.equal(parsed.search, '');
    assert.equal(parsed.hash, '');
  }
  assert.equal(new URL(renderProxyUrl(config({ host: '::1' }), { country: 'US', session: 'abc' })).hostname, '[::1]');
});

test('redaction removes URL, Basic, JSON, raw and URI-escaped rendered credentials', () => {
  const cfg = config({ username_template: 'DUMMY-{country}-{session}', password_template: 'FAKE_PASS-{session}' });
  const url = renderProxyUrl(cfg, { country: 'JP', session: 'xyz123' });
  const auth = 'DUMMY-JP-xyz123:FAKE_PASS-xyz123';
  const result = redactSecrets(`${url} raw ${auth} Basic ${Buffer.from(auth).toString('base64')}`, cfg);
  assert.doesNotMatch(result, /DUMMY|FAKE_PASS|xyz123/);
  assert.match(result, /REDACTED/);
  assert.doesNotMatch(redactSecrets({ password_template: 'FAKE_VALUE', username: 'FAKE_USER' }, cfg), /FAKE_VALUE|FAKE_USER/);
  assert.doesNotMatch(redactSecrets({ password: 'prefix"FAKE_QUOTED_SECRET' }, {}), /FAKE_QUOTED_SECRET/);
  const escapedCfg = config({ password_template: 'DUMMY @/{session}' });
  assert.doesNotMatch(redactSecrets('DUMMY%20%40%2Fabc123', escapedCfg), /DUMMY|abc123/);
  assert.equal(typeof redactSecrets(new Error(url), cfg), 'string');
  const circular = {}; circular.self = circular;
  assert.equal(redactSecrets(circular, cfg), '[Unserializable value]');
});

test('HTTP POST is forwarded exactly once, with credentials only at the upstream', async (t) => {
  const { pool, records, originUrl } = await fixture(t);
  const lease = await pool.acquire({ country: 'JP' }); // Preference list is not an allowlist.
  assert.equal(lease.country, 'JP');
  const publicUrl = new URL(lease.proxy_url);
  assert.equal(publicUrl.hostname, '127.0.0.1');
  assert.equal(publicUrl.username, '');
  assert.equal(publicUrl.password, '');
  assert.equal(publicUrl.protocol, 'http:');
  for (const field of ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY']) assert.equal(lease.env[field], lease.proxy_url);
  assert.equal(lease.env.NO_PROXY, 'localhost,127.0.0.1,::1');
  const result = await request(lease.proxy_url, `${originUrl}/post`, { method: 'POST', body: 'one write' });
  assert.equal(result.status, 200);
  assert.deepEqual(JSON.parse(result.body), { method: 'POST', body: 'one write', path: '/post' });
  assert.equal(records.length, 1);
  assert.equal(records[0].auth, expectedAuth(pool, lease));
  assert.doesNotMatch(JSON.stringify({ lease, status: pool.status() }), /DUMMY|FAKE@|username|password|upstream/);
});

test('reuse renews TTL; country changes and explicit rotations change only that session', async (t) => {
  const { pool } = await fixture(t);
  const first = await pool.acquire({ country: 'GB' });
  let now = Date.now();
  t.mock.method(Date, 'now', () => now);
  now += 5000;
  const reused = await pool.acquire({ leaseId: first.lease_id });
  assert.equal(reused.country, 'GB');
  assert.equal(reused.session_id, first.session_id);
  assert.equal(reused.proxy_url, first.proxy_url);
  assert.ok(Date.parse(reused.expires_at) > Date.parse(first.expires_at));
  const changed = await pool.acquire({ leaseId: first.lease_id, country: 'JP' });
  assert.notEqual(changed.session_id, first.session_id);
  const rotated = await pool.rotate(first.lease_id);
  assert.equal(rotated.country, 'JP');
  assert.notEqual(rotated.session_id, changed.session_id);
  await assert.rejects(pool.rotate(), /required/);
  await assert.rejects(pool.acquire({ leaseId: 'unknown' }), /not found/);
});

test('concurrent independent leases and CONNECT tunnels remain isolated across rotation', async (t) => {
  const { pool, records, echoPort, originUrl } = await fixture(t);
  const [a, b] = await Promise.all([pool.acquire({ country: 'US' }), pool.acquire({ country: 'GB' })]);
  assert.notEqual(a.lease_id, b.lease_id);
  assert.notEqual(a.session_id, b.session_id);
  assert.notEqual(a.proxy_url, b.proxy_url);
  const target = `127.0.0.1:${echoPort}`;
  const [tunnelA, tunnelB] = await Promise.all([connect(a.proxy_url, target), connect(b.proxy_url, target)]);
  t.after(() => { tunnelA.socket.destroy(); tunnelB.socket.destroy(); });
  assert.equal(tunnelA.status, 200);
  assert.equal(tunnelB.status, 200);
  await Promise.all([echo(tunnelA.socket, 'a first'), echo(tunnelB.socket, 'b first')]);
  const closedA = once(tunnelA.socket, 'close');
  const next = await pool.rotate(a.lease_id);
  await closedA;
  assert.equal(tunnelB.socket.destroyed, false);
  await echo(tunnelB.socket, 'b survives');
  const fresh = await connect(next.proxy_url, target);
  t.after(() => fresh.socket.destroy());
  await echo(fresh.socket, 'a second');
  assert.equal(records.filter((r) => r.method === 'CONNECT').at(-1).auth, expectedAuth(pool, next));
  await Promise.all([request(next.proxy_url, `${originUrl}/a`), request(b.proxy_url, `${originUrl}/b`)]);
  assert.equal(records.find((r) => r.url.endsWith('/b')).auth, expectedAuth(pool, b));
  assert.equal(await pool.release(a.lease_id), true);
  await echo(tunnelB.socket, 'b after release');
});

test('capacity never evicts active leases and pool_size does not limit lease count', async (t) => {
  const { pool, originUrl } = await fixture(t);
  const results = await Promise.allSettled(Array.from({ length: 6 }, () => pool.acquire()));
  const leases = results.filter((r) => r.status === 'fulfilled').map((r) => r.value);
  assert.equal(leases.length, 4);
  assert.equal(results.filter((r) => r.status === 'rejected').length, 2);
  assert.equal(pool.status().lease_count, 4);
  assert.equal(pool.config.pool_size, 1);
  for (const lease of leases) assert.equal((await request(lease.proxy_url, `${originUrl}/alive`)).status, 200);
  assert.equal(await pool.release(leases[0].lease_id), true);
  assert.equal(await pool.release(leases[0].lease_id), false);
  await pool.acquire();
  assert.equal(pool.status().lease_count, 4);
});

test('TTL timer automatically closes idle gateways and requests renew idle TTL', async (t) => {
  const advance = fakeClock(t);
  const { pool, originUrl } = await fixture(t);
  const idle = await pool.acquire();
  const live = await pool.acquire();
  await advance(20000);
  await request(live.proxy_url, `${originUrl}/renew`);
  await advance(11000);
  assert.equal(pool.status().lease_count, 1);
  assert.equal(pool.status().leases[0].lease_id, live.lease_id);
  await assert.rejects(request(idle.proxy_url, `${originUrl}/closed`));
  // The idle lease is reaped and remembered, so a late caller can be renewed.
  assert.equal(pool.status().renewable_lease_count, 1);
  // The surviving lease is the one that served traffic. Its observed tunnel
  // bytes keep renewing it, so it is deliberately NOT asserted to expire on a
  // fixed schedule; an idle lease that never drove traffic is the reaping case
  // covered above and by the explicit expiry tests.
  assert.equal(pool.status().leases[0].lease_id, live.lease_id);
});

test('an expired lease is renewed onto the same exit instead of failing', async (t) => {
  const advance = fakeClock(t);
  const { pool, originUrl } = await fixture(t);
  const idle = await pool.acquire();
  await advance(31000);
  assert.equal(pool.status().lease_count, 0);

  const renewed = await pool.acquire({ leaseId: idle.lease_id });
  assert.equal(renewed.lease_id, idle.lease_id);
  assert.equal(renewed.country, idle.country);
  // Same exit identity, new local socket: the caller must adopt the new address.
  assert.equal(renewed.session_id, idle.session_id);
  assert.equal(renewed.proxy_url_changed, true);
  assert.equal(renewed.renewal_reason, 'expired_lease_renewed');
  assert.notEqual(renewed.proxy_url, idle.proxy_url);
  assert.equal(pool.status().lease_count, 1);
  assert.equal((await request(renewed.proxy_url, `${originUrl}/alive`)).status, 200);
  // Renewal is not a free renewal loop: the tombstone is consumed.
  assert.equal(pool.status().renewable_lease_count, 0);
});

test('rotation during renewal changes the session and reports it', async (t) => {
  const advance = fakeClock(t);
  const { pool, originUrl } = await fixture(t);
  const idle = await pool.acquire();
  await advance(31000);
  const rotated = await pool.acquire({ leaseId: idle.lease_id, rotate: true });
  assert.equal(rotated.lease_id, idle.lease_id);
  assert.equal(rotated.session_id !== idle.session_id, true);
  assert.equal(rotated.renewal_reason, 'expired_lease_rotated');
  assert.equal((await request(rotated.proxy_url, `${originUrl}/alive`)).status, 200);
});

test('a lease expired beyond the revival window is reported as gone', async (t) => {
  const advance = fakeClock(t);
  const { pool } = await fixture(t);
  const idle = await pool.acquire();
  await advance(31000);
  // The default revival window is 120s; past the lease TTL plus that window the
  // tombstone is reaped and the honest error returns.
  await advance(150000);
  await assert.rejects(pool.acquire({ leaseId: idle.lease_id }), /expired/);
});

test('long HTTP requests and CONNECT byte traffic protect valid use from TTL reclamation', async (t) => {
  const advance = fakeClock(t);
  const { pool, slowReady, finishSlow, echoPort, originUrl } = await fixture(t);
  const slowLease = await pool.acquire();
  const slow = request(slowLease.proxy_url, `${originUrl}/slow`);
  await slowReady;
  const lease = await pool.acquire();
  const tunnel = await connect(lease.proxy_url, `127.0.0.1:${echoPort}`);
  t.after(() => tunnel.socket.destroy());
  await echo(tunnel.socket, 'first');
  await advance(25000);
  await echo(tunnel.socket, 'ongoing');
  await advance(25000);
  assert.equal(pool.status().lease_count, 2);
  assert.equal(tunnel.socket.destroyed, false);
  finishSlow();
  assert.equal((await slow).body, 'slow complete');
  const closed = once(tunnel.socket, 'close');
  await advance(31000);
  await closed;
  assert.equal(pool.status().lease_count, 0);
});

test('gateway failures have safe messages and never trigger automatic rotation or replay', async (t) => {
  const { pool, records, originUrl } = await fixture(t);
  const lease = await pool.acquire();
  const result = await request(lease.proxy_url, `${originUrl}/reject`, { method: 'POST', body: 'no retry' });
  assert.ok(result.status >= 400);
  assert.equal(result.body, 'Proxy gateway request failed');
  assert.equal(records.length, 1);
  assert.doesNotMatch(result.body, /FAKE|dummy|UNSAFE/);
  const tunnel = await connect(lease.proxy_url, 'reject.example:443');
  assert.ok(tunnel.status >= 400);
  const chunks = [tunnel.head];
  for await (const data of tunnel.socket) chunks.push(data);
  assert.doesNotMatch(Buffer.concat(chunks).toString(), /FAKE|dummy|UNSAFE/);
  const same = await pool.acquire({ leaseId: lease.lease_id });
  assert.equal(same.session_id, lease.session_id);
  assert.ok(pool.status().leases[0].failures >= 1);
});

test('SOCKS5 and SOCKS5H gateways authenticate without exposing SOCKS diagnostics', async (t) => {
  for (const protocol of ['socks5', 'socks5h']) {
    const records = [];
    const port = await listen(t, net.createServer((socket) => {
      let buffer = Buffer.alloc(0);
      let authenticated = false;
      socket.on('data', (chunk) => {
        buffer = Buffer.concat([buffer, chunk]);
        if (!authenticated) {
          if (buffer.length < 2 || buffer.length < 2 + buffer[1]) return;
          buffer = buffer.subarray(2 + buffer[1]);
          authenticated = true;
          socket.write(Buffer.from([5, 2]));
        }
        if (buffer.length < 2) return;
        const usernameLength = buffer[1];
        if (buffer.length < 3 + usernameLength) return;
        const passwordLength = buffer[2 + usernameLength];
        if (buffer.length < 3 + usernameLength + passwordLength) return;
        records.push({
          username: buffer.subarray(2, 2 + usernameLength).toString(),
          password: buffer.subarray(3 + usernameLength, 3 + usernameLength + passwordLength).toString(),
        });
        socket.end(Buffer.from([1, 1])); // Deliberately reject the fictional account.
      });
    }));
    const pool = new ProxyPool(config({ protocol, port }));
    t.after(() => pool.close());
    const lease = await pool.acquire({ country: 'JP' });
    assert.match(lease.proxy_url, /^http:\/\/127\.0\.0\.1:/);
    const tunnel = await connect(lease.proxy_url, 'unresolved.example:443');
    assert.ok(tunnel.status >= 400);
    const chunks = [tunnel.head];
    for await (const chunk of tunnel.socket) chunks.push(chunk);
    assert.equal(Buffer.concat(chunks).toString(), 'Proxy gateway request failed');
    const upstream = new URL(renderProxyUrl(pool.config, { country: lease.country, session: lease.session_id }));
    assert.deepEqual(records, [{ username: decodeURIComponent(upstream.username), password: decodeURIComponent(upstream.password) }]);
    assert.equal((await pool.acquire({ leaseId: lease.lease_id })).session_id, lease.session_id);
  }
});

test('release and close are idempotent and terminate localhost gateways', async (t) => {
  const { pool, originUrl, echoPort } = await fixture(t);
  const a = await pool.acquire();
  const b = await pool.acquire();
  const tunnel = await connect(a.proxy_url, `127.0.0.1:${echoPort}`);
  const closed = once(tunnel.socket, 'close');
  await pool.close();
  await closed;
  await pool.close();
  assert.equal(await pool.release(a.lease_id), false);
  assert.equal(pool.status().available, false);
  assert.equal(pool.status().lease_count, 0);
  await assert.rejects(pool.acquire(), /closed/);
  await assert.rejects(request(b.proxy_url, `${originUrl}/gone`));
});

test('example is disabled and contains only an example endpoint and credential placeholders', () => {
  const example = JSON.parse(readFileSync(new URL('./proxy.example.json', import.meta.url), 'utf8'));
  assert.equal(example.enabled, false);
  assert.equal(example.host, 'example.com');
  assert.match(example.username_template, /PLACEHOLDER/);
  assert.match(example.password_template, /PLACEHOLDER/);
});
