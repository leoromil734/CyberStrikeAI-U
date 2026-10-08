import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { assertPublicAddress, createSafeLookup, HttpInspector, MAX_BODY_BYTES, ScopePolicy } from '../lib/http.mjs';
import { delay, input, response } from '../test-support/fixtures.mjs';

function inspector(options = {}) {
  return new HttpInspector({ policy: new ScopePolicy(['https://example.com']), limits: input().limits, ...options });
}

test('scope matches exact origin and explicit original URLs, not invented paths', () => {
  const policy = new ScopePolicy(['https://example.com'], '也观察 https://example.com/about。');
  assert.equal(policy.assert('https://example.com/').origin, 'https://example.com');
  assert.equal(policy.assert('https://example.com/about').pathname, '/about');
  for (const url of [
    'https://sub.example.com/', 'http://example.com/', 'https://example.com:444/',
    'https://example.com.evil.invalid/', 'https://example.com/admin', 'file:///tmp/no',
    'https://@example.com/', 'https://user:pass@example.com/', 'https://example.com\\@127.0.0.1/',
    'https://example.com/\n', 'ftp://example.com/',
  ]) assert.throws(() => policy.assert(url), undefined, url);
});

test('block loopback, metadata, private and encoded/mapped addresses at policy boundary', () => {
  for (const host of [
    '127.0.0.1', '127.1', '2130706433', '0x7f000001', '[::1]', '[::]',
    '[::ffff:127.0.0.1]', '[::ffff:7f00:1]', '[64:ff9b::a9fe:a9fe]',
    '169.254.169.254', '100.100.100.200', '168.63.129.16', '[fe80::1]', '[fd00::1]',
    '10.0.0.1', '192.168.1.1', '172.16.0.1', '0.0.0.0', 'localhost',
    'a.localhost', 'metadata.google.internal', 'metadata.goog', 'instance-data.ec2.internal',
  ]) assert.throws(() => new ScopePolicy([`http://${host}/`]), undefined, host);
  assert.doesNotThrow(() => assertPublicAddress('93.184.216.34'));
  assert.doesNotThrow(() => assertPublicAddress('2606:4700:4700::1111'));
});

test('DNS resolution rejects mixed private results and rechecks each connection', async () => {
  let resolutions = 0;
  const lookup = createSafeLookup((_host, options, callback) => {
    assert.equal(options.all, true);
    resolutions++;
    callback(null, resolutions === 1 ? [{ address: '93.184.216.34', family: 4 }] : [{ address: '93.184.216.34', family: 4 }, { address: '127.0.0.1', family: 4 }]);
  });
  const resolve = () => new Promise((yes, no) => lookup('example.com', { all: true }, (error, result) => error ? no(error) : yes(result)));
  assert.deepEqual(await resolve(), [{ address: '93.184.216.34', family: 4 }]);
  await assert.rejects(resolve(), /阻断/);
  assert.equal(resolutions, 2);
});

test('redirects are never followed even if in scope', async () => {
  for (const location of ['https://evil.invalid/', 'http://169.254.169.254/', '/second']) {
    let calls = 0;
    let closed = false;
    const http = inspector({ transport: async () => { calls++; return response({ status: 302, headers: { location }, close: async () => { closed = true; } }); } });
    const observed = await http.inspect('https://example.com/', 'GET');
    assert.equal(calls, 1);
    assert.equal(observed.redirect.followed, false);
    assert.equal(observed.bytes_read, 0);
    assert.equal(closed, true);
    assert(!JSON.stringify(observed).includes('169.254'));
  }
});

test('request cap is shared and atomic under concurrency; max_parallel held through body read', async () => {
  let active = 0;
  let maximum = 0;
  let calls = 0;
  const issues = [];
  const http = inspector({ limits: { ...input().limits, max_requests: 3, max_parallel: 2 }, onIssue: (code) => issues.push(code), transport: async () => {
    calls++; active++; maximum = Math.max(maximum, active);
    await delay(10);
    return response({ close: async () => { active--; } });
  } });
  const results = await Promise.allSettled(Array.from({ length: 6 }, () => http.inspect('https://example.com/')));
  assert.equal(results.filter((entry) => entry.status === 'fulfilled').length, 3);
  assert.equal(calls, 3);
  assert.equal(maximum, 2);
  assert.equal(active, 0);
  assert(issues.includes('request_budget'));
});

test('invalid scope/method consumes no network budget', async () => {
  let calls = 0;
  const http = inspector({ transport: async () => { calls++; return response(); } });
  await assert.rejects(http.inspect('https://evil.invalid/'));
  await assert.rejects(http.inspect('https://example.com/', 'POST'));
  assert.equal(http.requests, 0);
  assert.equal(calls, 0);
});

test('body has hard cap, hash identifies only captured prefix; no cookies/raw body exposed', async () => {
  const content = Buffer.alloc(MAX_BODY_BYTES * 3, 65);
  let closed = false;
  const issues = [];
  const http = inspector({ onIssue: (code) => issues.push(code), transport: async () => response({ chunks: [content], headers: { 'set-cookie': 'secretcookie', 'content-type': 'text/plain' }, close: async () => { closed = true; } }) });
  const value = await http.inspect('https://example.com/');
  assert.equal(value.bytes_read, MAX_BODY_BYTES);
  assert.equal(value.truncated, true);
  assert.equal(value.hash_covers, 'prefix_only');
  assert.equal(value.body_sha256, createHash('sha256').update(content.subarray(0, MAX_BODY_BYTES)).digest('hex'));
  assert.equal(value.headers['set-cookie'], undefined);
  assert(!JSON.stringify(value).includes('AAAA'));
  assert.equal(closed, true);
  assert(issues.includes('body_budget'));
});

test('cancellation interrupts active HTTP and prevents queued requests', async () => {
  const cancel = new AbortController();
  let calls = 0;
  let aborted = false;
  const http = inspector({ limits: { ...input().limits, max_parallel: 1 }, signal: cancel.signal, transport: async (_url, { signal }) => {
    calls++;
    return new Promise((_, reject) => signal.addEventListener('abort', () => { aborted = true; reject(new Error('aborted')); }, { once: true }));
  } });
  const pending = Promise.allSettled([http.inspect('https://example.com/'), http.inspect('https://example.com/')]);
  await delay(5);
  cancel.abort();
  const results = await pending;
  assert(results.every((entry) => entry.status === 'rejected'));
  assert.equal(calls, 1);
  assert.equal(aborted, true);
  assert.equal(http.slots.active, 0);
});

test('HTTP timeout applies to pending body reads, not just response headers', async () => {
  let closed = false;
  const http = inspector({ timeoutMs: 10, transport: async () => ({ status: 200, headers: {}, body: { [Symbol.asyncIterator]: () => ({ next: () => new Promise(() => {}) }) }, close: async () => { closed = true; } }) });
  await assert.rejects(http.inspect('https://example.com/'), /超时/);
  assert.equal(closed, true);
  assert.equal(http.slots.active, 0);
});
