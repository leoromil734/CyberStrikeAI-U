import test from 'node:test';
import assert from 'node:assert/strict';
import { readdir } from 'node:fs/promises';
import { runLab } from '../lib/runtime.mjs';
import { createPiSession } from '../lib/sdk.mjs';
import { RunControl } from '../lib/control.mjs';
import { validateInput } from '../lib/protocol.mjs';
import { capture, delay, modelServer, streamText, streamTool, temporaryDirectory } from '../test-support/fixtures.mjs';
import { bridgeServer, bridgeResponse, platformInput } from '../test-support/platform.mjs';

async function fixture(t, { maxTurns = 40, summaryHandler } = {}) {
  const cwd = await temporaryDirectory(t);
  const config = platformInput({ limits: { max_turns: maxTurns } });
  config.model.context_window = 8192;
  const bridge = await bridgeServer(t, (_body, res) => bridgeResponse(res, 'ACTUAL_OFFLINE_EVIDENCE '.repeat(750) + config.platform.bridge.token + config.model.api_key));
  let normalCalls = 0;
  let summaries = 0;
  let resumed = false;
  const errors = [];
  const model = await modelServer(t, async (body, res, turn) => {
    try {
      const raw = JSON.stringify(body);
      for (const secret of [config.model.api_key, bridge.token, bridge.url]) assert(!raw.includes(secret));
      if (!body.tools?.length) {
        summaries++;
        assert.match(raw, /context summarization assistant/);
        assert((body.max_tokens ?? body.max_completion_tokens) <= config.model.max_tokens);
        if (summaryHandler) await summaryHandler(body, res, turn);
        else streamText(res, 'COMPACTED_EVIDENCE_MARKER: offline evidence only; preserve scope and unresolved checks.');
      } else {
        normalCalls++;
        if (raw.includes('COMPACTED_EVIDENCE_MARKER')) resumed = true;
        if (normalCalls <= 5) streamTool(res, 'exec', { command: 'offline fixture only' });
        else streamText(res, '已根据真实工具结果与压缩摘要完成离线测试。');
      }
    } catch (error) { errors.push(error); throw error; }
  });
  config.model.base_url = model.base_url;
  config.platform.bridge = { url: bridge.url, token: bridge.token };
  return { cwd, config, bridge, model, errors, counts: () => ({ normalCalls, summaries, resumed }) };
}

test('PLATFORM REAL SDK: automatic compaction summarizes and continues tools with isolated credentials and no disk writes', { timeout: 20000 }, async (t) => {
  const f = await fixture(t);
  const output = capture();
  const result = await runLab(f.config, { cwd: f.cwd, write: output.write });
  assert.deepEqual(f.errors, []);
  assert.equal(result.status, 'completed', output.lines.join(''));
  assert(f.counts().summaries > 0, JSON.stringify(f.counts()));
  assert(f.counts().resumed, 'summary must reach a subsequent operational model request');
  assert.equal(f.counts().normalCalls, 6);
  assert.equal(f.bridge.requests.length, 5);
  assert(f.model.requests.every((request) => request.headers.authorization === `Bearer ${f.config.model.api_key}`));
  assert.deepEqual(await readdir(f.cwd), []);
});

test('PLATFORM REAL SDK: automatic summary requests consume the same strict model turn budget', { timeout: 20000 }, async (t) => {
  const f = await fixture(t, { maxTurns: 3 });
  const output = capture();
  const result = await runLab(f.config, { cwd: f.cwd, write: output.write });
  assert.deepEqual(f.errors, []);
  assert.equal(result.status, 'partial');
  assert(f.counts().summaries > 0, JSON.stringify(f.counts()));
  assert.equal(f.model.requests.length, 3);
  assert.match(output.lines.join(''), /轮次预算/);
});

test('PLATFORM REAL SDK: summary failures are reported as partial without raw provider errors or retries', { timeout: 20000 }, async (t) => {
  const f = await fixture(t, { summaryHandler: (_body, res) => res.writeHead(401).end('PRIVATE_COMPACTION_PROVIDER_ERROR') });
  const output = capture();
  const result = await runLab(f.config, { cwd: f.cwd, write: output.write });
  assert.deepEqual(f.errors, []);
  assert.equal(result.status, 'partial');
  assert(f.counts().summaries > 0);
  assert.match(output.lines.join(''), /自动上下文压缩失败/);
  assert(!output.lines.join('').includes('PRIVATE_COMPACTION_PROVIDER_ERROR'));
  // A new threshold check can try again at a later turn; no provider retry loop.
  assert(f.counts().summaries <= f.counts().normalCalls + 1);
});

test('PLATFORM REAL SDK: cancelling an active automatic summary aborts the model connection and emits no late events', { timeout: 15000 }, async (t) => {
  const started = Promise.withResolvers();
  const closed = Promise.withResolvers();
  const f = await fixture(t, { summaryHandler: (_body, res) => {
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.flushHeaders();
    res.once('close', closed.resolve);
    started.resolve();
  } });
  const controller = new AbortController();
  const output = capture();
  const running = runLab(f.config, { cwd: f.cwd, write: output.write, signal: controller.signal });
  await started.promise;
  controller.abort();
  assert.equal((await running).status, 'partial');
  await closed.promise;
  const count = output.events().length;
  await delay(20);
  assert.equal(output.events().length, count);
  assert.equal(output.events().at(-1).type, 'complete');
});

test('SDK settings: platform enables supported compaction while probe keeps it disabled', async (t) => {
  const cwd = await temporaryDirectory(t);
  for (const mode of ['platform', 'probe']) {
    const config = validateInput(platformInput());
    const control = new RunControl(config.limits);
    const session = await createPiSession({ config: config.model, mode, cwd, systemPrompt: 'offline', tools: [], control });
    try {
      assert.equal(session.settingsManager.getCompactionSettings().enabled, mode === 'platform');
      if (mode === 'platform') assert.deepEqual(session.settingsManager.getCompactionSettings(), { enabled: true, reserveTokens: 8000, keepRecentTokens: 8000 });
      assert.equal(control.turns, 0, 'enabling compaction must not make initialization requests');
    } finally { await session.dispose(); await control.close(); }
  }
  assert.deepEqual(await readdir(cwd), []);
});
