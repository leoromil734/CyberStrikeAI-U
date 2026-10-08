import test from 'node:test';
import assert from 'node:assert/strict';
import { PlatformBridge, MAX_BRIDGE_RESPONSE_BYTES } from '../lib/platform.mjs';
import { configSecrets, createRedactor } from '../lib/protocol.mjs';
import { delay } from '../test-support/fixtures.mjs';
import { bridgeServer, bridgeResponse, bridgeToken, platformInput } from '../test-support/platform.mjs';

function client(t, server, options = {}) {
  const config = platformInput();
  config.platform.bridge = { url: server.url, token: server.token };
  const bridge = new PlatformBridge({ bridge: config.platform.bridge, limits: config.limits, redact: createRedactor(configSecrets(config)), ...options });
  t.after(() => bridge.close());
  return bridge;
}

test('bridge uses its own authenticated POST transport, independent of model fetch origin confinement', async (t) => {
  const server = await bridgeServer(t, (_body, res) => bridgeResponse(res, 'real local fixture output', { execution_id: 'execution-fixture-1' }));
  const bridge = client(t, server);
  const previous = globalThis.fetch;
  globalThis.fetch = () => { throw new Error('model-only fetch must not be used'); };
  try {
    const result = await bridge.call('exec', { command: 'offline fixture only' }, 'worker-2');
    assert.equal(result.isError, false);
    assert.equal(result.content[0].text, 'real local fixture output');
    assert.equal(result.details.execution_id, 'execution-fixture-1');
    assert.doesNotMatch(result.details.summary, /real local fixture output/);
    assert.deepEqual(server.requests[0].body, { name: 'exec', arguments: { command: 'offline fixture only' }, agent_id: 'worker-2' });
    assert.equal(server.requests[0].method, 'POST');
    assert.equal(server.requests[0].path, '/tools/call');
    assert.equal(server.requests[0].headers.authorization, `Bearer ${bridgeToken}`);
    assert.equal(server.requests[0].headers.cookie, undefined);
  } finally { globalThis.fetch = previous; }
});

test('bridge reports HTTP authentication errors without retrying or reflecting its token', async (t) => {
  const server = await bridgeServer(t);
  const bridge = client(t, server);
  bridge.token = 'incorrect-fixture-token';
  const result = await bridge.call('exec', {}, 'coordinator');
  assert.equal(result.isError, true);
  assert.match(result.content[0].text, /HTTP 401/);
  assert(!JSON.stringify(result).includes(bridgeToken));
  assert.equal(server.requests.length, 1);
});

for (const status of [301, 302, 307, 308]) {
  test(`bridge refuses ${status} redirects without forwarding credentials or reading the redirect body`, async (t) => {
    const target = await bridgeServer(t);
    const server = await bridgeServer(t, (_body, res) => {
      res.writeHead(status, { location: target.url, 'content-type': 'text/plain' });
      res.write('unconsumed redirect body'); // Never end: cleanup must destroy it.
    });
    const bridge = client(t, server);
    await assert.rejects(bridge.call('exec', {}, 'coordinator'), /跳转/);
    assert.equal(server.requests.length, 1);
    assert.equal(target.requests.length, 0);
    await bridge.close();
    await bridge.close();
  });
}

test('bridge abort cancels in-flight response reads and queued requests without starting them', { timeout: 10000 }, async (t) => {
  const started = Promise.withResolvers();
  const closed = Promise.withResolvers();
  const server = await bridgeServer(t, (_body, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.flushHeaders();
    res.on('close', closed.resolve);
    started.resolve();
  });
  const cancel = new AbortController();
  const bridge = client(t, server, { signal: cancel.signal, limits: { max_parallel: 1, timeout_seconds: 60 } });
  const pending = Promise.allSettled([bridge.call('exec', {}, 'worker-1'), bridge.call('exec', {}, 'worker-2'), bridge.call('exec', {}, 'worker-3')]);
  await started.promise;
  cancel.abort();
  const results = await pending;
  assert(results.every((result) => result.status === 'rejected'));
  await closed.promise;
  assert.equal(server.requests.length, 1);
  assert.equal(bridge.slots.active, 0);
  assert.equal(bridge.slots.queue.length, 0);
});

test('bridge maps application is_error and strips known credentials before returning any model content', async (t) => {
  const key = platformInput().model.api_key;
  const server = await bridgeServer(t, (_body, res) => bridgeResponse(res, `${key} ${bridgeToken} ${encodeURIComponent(bridgeToken)} ${Buffer.from(bridgeToken).toString('base64')}`, { is_error: true, execution_id: 'failed-execution-1' }));
  const result = await client(t, server).call('record_vulnerability', { evidence_id: 'missing' }, 'coordinator');
  assert.equal(result.isError, true);
  assert.equal(result.details.execution_id, 'failed-execution-1');
  for (const secret of [key, bridgeToken, Buffer.from(bridgeToken).toString('base64')]) assert(!JSON.stringify(result).includes(secret));
});

test('bridge rejects malformed results and bounds real response transport size', async (t) => {
  for (const payload of ['not JSON', JSON.stringify({ content: [{ type: 'image', text: 'no' }], is_error: false }), JSON.stringify({ content: [], is_error: 'false' })]) {
    const server = await bridgeServer(t, (_body, res) => res.writeHead(200).end(payload));
    await assert.rejects(client(t, server).call('exec', {}, 'coordinator'), /JSON|约定/);
  }
  const large = await bridgeServer(t, (_body, res) => bridgeResponse(res, 'x'.repeat(MAX_BRIDGE_RESPONSE_BYTES + 1)));
  await assert.rejects(client(t, large).call('exec', {}, 'coordinator'), /上限|读取失败/);
  await delay(5); // Surface late body cleanup errors before the test exits.
});
