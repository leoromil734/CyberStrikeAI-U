import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createHash } from 'node:crypto';
import { HttpInspector, MAX_BODY_BYTES, productionTransport, ScopePolicy } from '../lib/http.mjs';
import { runLab } from '../lib/runtime.mjs';
import { capture, delay, input, modelServer, streamText, streamTool, temporaryDirectory } from '../test-support/fixtures.mjs';

// The production Undici transport is exercised over real loopback sockets.
// Only this programmatic test injection maps the public scope to the local
// fixture; stdin has no transport override and the production policy is intact.
async function wireFixture(t, respond) {
  const requests = [];
  const server = http.createServer((req, res) => {
    requests.push({ method: req.method, url: req.url });
    respond(req, res);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  });
  const url = new URL(`http://127.0.0.1:${server.address().port}/`);
  const transport = (_scopedUrl, options) => productionTransport(url, options);
  return { requests, url, transport };
}

function inspector(transport, options = {}) {
  return new HttpInspector({ policy: new ScopePolicy(['https://example.com']), limits: input().limits, transport, ...options });
}

for (const method of ['GET', 'HEAD']) {
  test(`REAL HTTP: ${method} completes and cleanup never emits an unhandled stream error`, async t => {
    const wire = await wireFixture(t, (_req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain', 'content-length': '13' });
      res.end('local fixture');
    });
    const client = inspector(wire.transport);
    const result = await client.inspect('https://example.com/', method);
    // Undici may emit the destroy error on setImmediate, after close() resolves.
    await delay(10);
    assert.equal(result.status, 200);
    assert.equal(result.bytes_read, method === 'HEAD' ? 0 : 13);
    assert.equal(result.body_sha256, method === 'HEAD' ? null : createHash('sha256').update('local fixture').digest('hex'));
    assert.equal(client.slots.active, 0);
    assert.deepEqual(wire.requests, [{ method, url: '/' }]);
  });
}

for (const location of ['/not-authorized', 'https://different.invalid/']) {
  test(`REAL HTTP: redirect ${location} stops without draining, following or crashing`, async t => {
    const wire = await wireFixture(t, (_req, res) => {
      res.writeHead(302, { location, 'content-type': 'text/plain' });
      res.end('unconsumed redirect response');
    });
    const client = inspector(wire.transport);
    const result = await client.inspect('https://example.com/', 'GET');
    await delay(10);
    assert.equal(result.status, 302);
    assert.equal(result.redirect.followed, false);
    assert.equal(result.bytes_read, 0);
    assert.equal(result.body_sha256, null);
    assert.equal(wire.requests.length, 1);
    assert.equal(client.slots.active, 0);
  });
}

test('REAL HTTP: simultaneous cleanup calls are idempotent for an unconsumed body', async t => {
  const wire = await wireFixture(t, (_req, res) => res.writeHead(200).end('unread fixture'));
  const response = await productionTransport(wire.url, { method: 'GET' });
  const first = response.close();
  const second = response.close();
  assert.equal(first, second, 'cleanup must share the same completion promise');
  await Promise.all([first, second]);
  await delay(10);
  assert.equal(response.body.destroyed, true);
});

test('REAL HTTP: body read timeout remains a tool failure and releases the slot', async t => {
  const wire = await wireFixture(t, (_req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.flushHeaders();
    // Intentionally leave the body open until the client's read timeout.
  });
  const client = inspector(wire.transport, { timeoutMs: 50 });
  await assert.rejects(client.inspect('https://example.com/', 'GET'), error => error.code === 'http_timeout');
  await delay(10);
  assert.equal(client.slots.active, 0);
});

test('REAL HTTP: response size limit is not swallowed by safe cleanup', async t => {
  const wire = await wireFixture(t, (_req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end(Buffer.alloc(MAX_BODY_BYTES * 2, 65));
  });
  const client = inspector(wire.transport);
  try {
    const result = await client.inspect('https://example.com/', 'GET');
    assert.equal(result.truncated, true);
    assert.equal(result.hash_covers, 'prefix_only');
    assert(result.bytes_read <= MAX_BODY_BYTES);
  } catch (error) {
    assert.equal(error.code, 'http_failed');
  }
  await delay(10);
  assert.equal(client.slots.active, 0);
});

for (const scenario of ['HEAD', 'redirect']) {
  test(`REAL SDK + REAL HTTP: ${scenario} emits tool_end, report and final completion`, async t => {
    const cwd = await temporaryDirectory(t);
    const wire = await wireFixture(t, (_req, res) => {
      if (scenario === 'redirect') res.writeHead(302, { location: 'https://different.invalid/' }).end('redirect fixture');
      else res.writeHead(200, { 'content-type': 'text/plain' }).end('head fixture');
    });
    const model = await modelServer(t, (body, res) => {
      const prior = body.messages.filter(message => message.role === 'tool');
      if (!prior.length) streamTool(res, 'inspect_http', { url: 'https://example.com/', method: scenario === 'HEAD' ? 'HEAD' : 'GET' });
      else streamText(res, '本机夹具的 HTTP 观察已完成；没有访问真实目标，也没有确认漏洞。');
    });
    const output = capture();
    const config = input({ model: { ...input().model, base_url: model.base_url } });
    const result = await runLab(config, { cwd, write: output.write, transport: wire.transport });
    await delay(10);
    assert.equal(result.status, 'completed', output.lines.join(''));
    assert.equal(result.exitCode, 0);
    assert.equal(model.requests.length, 2);
    assert.equal(wire.requests.length, 1);
    const events = output.events();
    assert(events.some(event => event.type === 'tool_end' && event.data.name === 'inspect_http' && !event.data.is_error));
    assert(events.some(event => event.type === 'report'));
    assert.equal(events.at(-1).type, 'complete');
    assert.equal(events.at(-1).data.status, 'completed');
    assert(!events.some(event => event.type === 'error'));
  });
}
