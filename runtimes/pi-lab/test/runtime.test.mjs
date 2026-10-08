import test from 'node:test';
import assert from 'node:assert/strict';
import { runLab } from '../lib/runtime.mjs';
import { capture, delay, fakeFactory, input, response } from '../test-support/fixtures.mjs';

async function run(script, overrides = {}, options = {}) {
  const output = capture();
  const state = {};
  const result = await runLab(input(overrides), { write: output.write, sessionFactory: fakeFactory(script, state), ...options });
  return { result, events: output.events(), raw: output.lines.join(''), state };
}

test('single real-style session can finish without fabricated children/findings', async () => {
  const value = await run(async ({ assistant }) => assistant('未发送 HTTP 请求；仅完成用户说明的离线分析。'));
  assert.equal(value.result.status, 'completed');
  assert.equal(value.events[0].agent_id, 'coordinator');
  assert.equal(value.events.filter((event) => event.type === 'agent_start').length, 1);
  assert.equal(value.events.filter((event) => event.type === 'finding').length, 0);
  assert.equal(value.events.at(-1).type, 'complete');
});

test('coordinator delegates actual sessions concurrently with no recursive tool', async () => {
  let active = 0;
  let maximum = 0;
  const value = await run(async ({ id, tools, assistant, call }) => {
    if (id === 'coordinator') {
      const result = await call('delegate_agents', { tasks: Array.from({ length: 5 }, (_, index) => ({ name: `task-${index}`, task: '离线分析' })) });
      assert.equal(result.agents.length, 5);
      assert(result.agents.every((entry) => entry.summary.startsWith('worker-')));
      assistant('根据五个实际子会话的摘要汇总。');
    } else {
      assert(!tools.some((tool) => tool.name === 'delegate_agents'));
      assert.deepEqual(tools.map((tool) => tool.name).sort(), ['inspect_http', 'record_finding', 'record_surface']);
      active++; maximum = Math.max(maximum, active);
      await delay(15);
      active--;
      assistant(`${id} 实际结果`);
    }
  });
  assert.equal(maximum, 2);
  assert.equal(value.result.status, 'completed');
  assert.equal(value.events.filter((event) => event.type === 'agent_start').length, 6);
  assert.equal(value.state.disposes, 6);
});

test('child total persists across batches and returns partial instead of invented work', async () => {
  const value = await run(async ({ id, call, assistant }) => {
    if (id === 'coordinator') {
      await call('delegate_agents', { tasks: [{ name: 'one', task: '分析' }] });
      const batch = await call('delegate_agents', { tasks: [{ name: 'two', task: '分析' }, { name: 'three', task: '分析' }] });
      assert.equal(batch.skipped, 1);
      assistant('最后一个任务未执行，只有部分结果。');
    } else assistant('实际子会话结果');
  }, { limits: { ...input().limits, max_agents: 2 } });
  assert.equal(value.events.filter((event) => event.type === 'agent_start').length, 3);
  assert.equal(value.result.status, 'partial');
  assert.equal(value.result.exitCode, 1);
  assert.match(value.events.find((event) => event.type === 'report').data.text, /子会话预算/);
});

test('provider error that resolves prompt, empty answer, length stop all fail honestly', async () => {
  for (const stop of ['error', 'aborted', 'length', 'toolUse']) {
    const value = await run(async ({ assistant }) => assistant('not a valid completed report', stop));
    assert.equal(value.result.status, 'partial', stop);
    assert.notEqual(value.result.exitCode, 0);
  }
  const empty = await run(async ({ assistant }) => assistant(''));
  assert.equal(empty.result.status, 'partial');
  assert(empty.events.some((event) => event.type === 'error'));
});

test('finding cannot become confirmed or observed without actual evidence', async () => {
  for (const status of ['confirmed', 'observed']) {
    const value = await run(async ({ call, assistant }) => {
      await assert.rejects(call('record_finding', { title: '未验证', url: 'https://example.com/', severity: 'low', status, evidence: '模型猜测', remediation: '人工复核' }));
      assistant('没有真实 HTTP 证据。');
    });
    assert.equal(value.events.filter((event) => event.type === 'finding').length, 0);
    assert.equal(value.result.status, 'partial');
  }
});

test('HTTP evidence, surface, finding and graph edges have real references', async () => {
  const value = await run(async ({ call, assistant }) => {
    await call('inspect_http', { url: 'https://example.com/', method: 'GET' });
    await call('record_surface', { label: '页面', url: 'https://example.com/', detail: '已观察' });
    await call('record_finding', { title: 'HTTP 状态观察', url: 'https://example.com/', severity: 'info', status: 'observed', evidence: '观察到 200，但这不是漏洞确认。', remediation: '必要时人工验证' });
    assistant('已观察 HTTP 状态，未确认任何漏洞。');
  }, {}, { transport: async () => response() });
  assert.equal(value.result.status, 'completed');
  const finding = value.events.find((event) => event.type === 'finding');
  assert.equal(finding.data.status, 'observed');
  assert.match(finding.data.evidence, /body_sha256/);
  const ids = new Set(value.events.filter((event) => event.type === 'node').map((event) => event.data.id));
  for (const edge of value.events.filter((event) => event.type === 'edge')) {
    assert(ids.has(edge.data.source)); assert(ids.has(edge.data.target));
  }
});

test('model response, task names and errors never expose configured secrets', async () => {
  const key = input().model.api_key;
  const value = await run(async ({ assistant }) => assistant(`text ${key} ${encodeURIComponent(key)} ${Buffer.from(key).toString('base64')} ${input().model.base_url}`));
  assert(!value.raw.includes(key));
  assert(!value.raw.includes(input().model.base_url));
  const failure = await run(async () => { throw new Error(`private failure ${key}`); });
  assert(!failure.raw.includes(key));
  assert(!failure.raw.includes('private failure'));
  assert.equal(failure.result.status, 'partial');
});

test('run cancellation aborts coordinator, workers, in-flight HTTP and queued work', async () => {
  const cancel = new AbortController();
  let activeHttp = 0;
  const state = {};
  const output = capture();
  const pending = runLab(input(), {
    signal: cancel.signal, write: output.write,
    sessionFactory: fakeFactory(async ({ id, call, assistant }) => {
      if (id === 'coordinator') {
        await call('delegate_agents', { tasks: Array.from({ length: 4 }, () => ({ name: 'child', task: '观察' })) });
        assistant('should not complete');
      } else await call('inspect_http', { url: 'https://example.com/', method: 'GET' });
    }, state),
    transport: async (_url, { signal }) => {
      activeHttp++;
      return new Promise((_, reject) => signal.addEventListener('abort', () => { activeHttp--; reject(new Error('cancelled')); }, { once: true }));
    },
  });
  while (activeHttp < 2) await delay(1);
  cancel.abort();
  const result = await pending;
  assert.equal(result.status, 'partial');
  assert.equal(activeHttp, 0);
  assert.equal(state.sessions.length, 3);
  assert(state.aborts >= 3);
  for (const session of state.sessions) {
    const id = session.options.id;
    const events = output.events().filter((event) => event.agent_id === id);
    assert.equal(events.filter((event) => event.type === 'tool_start').length, events.filter((event) => event.type === 'tool_end').length);
  }
  const completeIndex = output.events().findIndex((event) => event.type === 'complete');
  await delay(5);
  assert.equal(output.events().length - 1, completeIndex);
});

test('shared max_turns is checked across child sessions', async () => {
  const value = await run(async ({ id, control, call, assistant }) => {
    if (id === 'coordinator') {
      await call('delegate_agents', { tasks: [{ name: 'a', task: '离线分析' }, { name: 'b', task: '离线分析' }] });
      assert.throws(() => control.takeTurn(), /轮次预算/);
      assistant('轮次用尽，仅部分结果。');
    } else assistant('已用一次轮次。');
  }, {}, { controlOptions: { maxTurns: 3 } });
  assert.equal(value.result.status, 'partial');
});

test('total timeout aborts a pending model session', async () => {
  const value = await run(async ({ signal }) => delay(5000, null, { signal }), { limits: { ...input().limits, timeout_seconds: 1 } });
  assert.equal(value.result.status, 'partial');
  assert.match(value.raw, /时间预算/);
  assert(value.state.aborts > 0);
});
