import test from 'node:test';
import assert from 'node:assert/strict';
import { validateInput, validateBridgeUrl, createRedactor, configSecrets, createEmitter, clip, MAX_TEXT } from '../lib/protocol.mjs';
import { compilePlatformTools, platformSystemPrompt } from '../lib/platform.mjs';
import { runLab } from '../lib/runtime.mjs';
import { input, capture, fakeFactory } from '../test-support/fixtures.mjs';
import { platformInput } from '../test-support/platform.mjs';

test('platform contract preserves internal hosts/CIDRs/paths/exclusions and keeps probe defaults', () => {
  const config = validateInput(platformInput({ limits: {} }));
  assert.deepEqual(config.scope, platformInput().scope);
  assert.equal(config.mode, 'platform');
  assert.deepEqual(config.limits, { max_parallel: 2, max_agents: 6, timeout_seconds: 900, max_turns: 120, max_tool_calls: 600 });
  assert.equal(validateInput(input()).mode, 'probe');
  assert.deepEqual(validateInput(input({ mode: 'probe' })), validateInput(input()));
  assert.equal(validateInput(input()).limits.max_turns, 20);
  assert.equal(validateInput(input()).limits.max_tool_calls, 256);
  assert.throws(() => validateInput(input({ mode: 'other' })), /mode/);
  const extremes = { max_parallel: 8, max_agents: 32, timeout_seconds: 21600, max_turns: 500, max_tool_calls: 2000 };
  assert.deepEqual(validateInput(platformInput({ limits: extremes })).limits, extremes);
  for (const [key, values] of Object.entries({ max_parallel: [0, 9], max_agents: [0, 33], timeout_seconds: [59, 21601], max_turns: [0, 501], max_tool_calls: [0, 2001] })) {
    for (const value of values) assert.throws(() => validateInput(platformInput({ limits: { [key]: value } })), new RegExp(key));
  }
});

test('bridge URL accepts only a literal IPv4 loopback HTTP endpoint with an explicit port', () => {
  assert.equal(validateBridgeUrl('http://127.0.0.1:49152/tools/call'), 'http://127.0.0.1:49152/tools/call');
  for (const url of [
    'http://localhost:49152/tools/call', 'http://127.0.0.2:49152/tools/call', 'http://127.1:49152/tools/call',
    'http://2130706433:49152/tools/call', 'http://0x7f000001:49152/tools/call', 'http://[::1]:49152/tools/call',
    'http://[::ffff:127.0.0.1]:49152/tools/call', 'http://example.com:49152/tools/call', 'https://127.0.0.1:49152/tools/call',
    'http://user@127.0.0.1:49152/tools/call', 'http://127.0.0.1/tools/call', 'http://127.0.0.1:0/tools/call',
    'http://127.0.0.1:65536/tools/call', 'http://127.0.0.1:49152/tools/call?', 'http://127.0.0.1:49152/tools/call#',
    'http://127.0.0.1:49152/tools/call?token=SECRET', 'http://127.0.0.1:49152/tools/call#SECRET',
    'http://127.0.0.1:49152/other', 'http://127.0.0.1:49152/x/../tools/call', 'http://127.0.0.1:49152/tools/%63all',
    'http://127.0.0.1:49152/tools/call/', 'http://127.0.0.1:49152\\tools\\call',
  ]) assert.throws(() => validateBridgeUrl(url), /platform.bridge.url/, url);
});

test('platform tool names cannot collide with local helpers/discovery and schemas preserve nested constraints', () => {
  for (const name of ['delegate_agents', 'record_surface', 'record_finding', 'inspect_http', 'codemode', 'tool_search', 'mcp__server_tool', 'with space', 'with.dot', 'bad/name', 'a'.repeat(65), '']) {
    const raw = platformInput();
    raw.platform.tools[0].name = name;
    assert.throws(() => validateInput(raw), /名称|name/);
  }
  const duplicate = platformInput();
  duplicate.platform.tools.push(duplicate.platform.tools[0]);
  assert.throws(() => validateInput(duplicate), /重复/);
  const raw = platformInput();
  raw.platform.tools[0].input_schema.type = 'string';
  assert.throws(() => validateInput(raw), /JSON Schema/);
  raw.platform.bridge.token = 'bad\r\nAuthorization: surprise';
  assert.throws(() => validateInput(raw), /token/);
  const config = validateInput(platformInput());
  const tools = compilePlatformTools(config.platform.tools, createRedactor(configSecrets(config)));
  const exec = tools.find((tool) => tool.name === 'exec');
  assert.deepEqual(exec.parameters, config.platform.tools.find((tool) => tool.name === 'exec').input_schema);
  assert(exec.validator.Check({ command: 'fixture', options: { count: 2, mode: 'offline', api_key: 'user-provided-fixture' } }));
  assert(!exec.validator.Check({ command: 'fixture', options: { count: 0 } }));
  assert(!exec.validator.Check({ command: 'fixture', options: { mode: 'unknown' } }));
  assert(!exec.validator.Check({ command: 'fixture', unexpected: true }));
  const refs = [{ name: 'referenced', description: '', input_schema: { type: 'object', properties: { target: { $ref: '#/$defs/target' } }, required: ['target'], $defs: { target: { type: 'string', minLength: 2 } } } }];
  const compiled = compilePlatformTools(refs, (value) => value)[0];
  assert(compiled.validator.Check({ target: 'ok' }));
  assert(!compiled.validator.Check({ target: 'x' }));
  refs[0].input_schema.properties.target.$ref = 'https://never-fetch.invalid/schema';
  assert.throws(() => compilePlatformTools(refs, (value) => value), /JSON Schema/);
});

test('platform coordinator and workers receive role, shared skill index, handoff contract and explicit budgets', async () => {
  const output = capture();
  const state = {};
  const config = platformInput();
  // Even accidental secret interpolation into trusted instructions is removed.
  config.platform.instructions += ` ${config.platform.bridge.token} ${config.platform.bridge.url} ${config.model.api_key}`;
  const result = await runLab(config, { write: output.write, sessionFactory: fakeFactory(async ({ id, tools, systemPrompt, prompt, call, assistant }) => {
    assert.match(systemPrompt, /渗透测试/);
    assert.match(systemPrompt, id === 'coordinator' ? /ROLE_CONTRACT_MARKER/ : /WORKER_CONTRACT_MARKER/);
    assert.doesNotMatch(systemPrompt, id === 'coordinator' ? /WORKER_CONTRACT_MARKER/ : /ROLE_CONTRACT_MARKER/);
    assert.match(systemPrompt, /SHARED_SKILL_INDEX_MARKER/);
    assert.match(systemPrompt, /load_skill for pentest-agent-os/);
    assert.match(systemPrompt, /120 model calls, 600 custom tool calls/);
    assert.match(systemPrompt, /write_file/);
    assert.match(systemPrompt, /排除：10.23.8.9/);
    assert.doesNotMatch(systemPrompt, /GET\/HEAD|Do not scan|Raw HTTP bodies|Allowed exact origins/);
    for (const secret of [config.model.api_key, config.platform.bridge.token, config.platform.bridge.url]) assert(!systemPrompt.includes(secret));
    assert(!tools.some((tool) => ['inspect_http', 'bash', 'read', 'edit'].includes(tool.name)));
    if (id === 'coordinator') {
      const delegated = await call('delegate_agents', { tasks: [{ name: '有界交接', task: '仅核对离线结果的证据引用。' }] });
      assert.match(delegated.agents[0].summary, /实际交接结论/);
      assistant('已汇总真实交接结论。');
    } else {
      assert.match(systemPrompt, /WORKER_CONTRACT_MARKER/);
      assert.match(prompt, /仅核对离线结果/);
      assert(!tools.some((tool) => tool.name === 'delegate_agents'));
      assistant('实际交接结论：还没有工具证据。');
    }
  }, state) });
  assert.equal(result.status, 'completed', output.lines.join(''));
  assert.equal(state.sessions.length, 2);
  assert.equal(state.disposes, 2);
  assert(!output.lines.join('').includes(config.platform.bridge.token));
});

test('platform worker instructions replace coordinator contract and empty legacy values fall back once', () => {
  const config = validateInput(platformInput());
  const worker = platformSystemPrompt(config, false);
  assert(!worker.includes(config.platform.instructions));
  assert.equal(worker.split(config.platform.worker_instructions).length, 2);
  config.platform.worker_instructions = '';
  assert.equal(platformSystemPrompt(config, false).split(config.platform.instructions).length, 2);
});

test('platform runtime argument validation is a warning, not a fatal run issue', async () => {
  const output = capture();
  const result = await runLab(platformInput(), { write: output.write, sessionFactory: fakeFactory(async ({ call, assistant }) => {
    await assert.rejects(call('exec', {}), /JSON Schema/);
    assistant('参数未通过校验；尚未执行，交付状态必须由服务端判断。');
  }) });
  assert.equal(result.status, 'completed');
  assert(output.events().some((event) => event.type === 'tool_end' && event.data.is_error));
  assert(output.events().some((event) => event.type === 'node' && event.data.kind === 'tool' && event.data.status === 'failed'));
  assert.match(output.events().find((event) => event.type === 'report').data.text, /工具警告.*Go 服务端/);
});

test('platform visualization notes accept internal paths but never emit formal finding events', async () => {
  const output = capture();
  const result = await runLab(platformInput(), { write: output.write, sessionFactory: fakeFactory(async ({ call, assistant }) => {
    const surface = await call('record_surface', { label: '内部应用', url: 'http://10.23.0.2/new/path', detail: '分析笔记，没有执行请求。' });
    assert.equal(surface.status, 'hypothesis');
    const finding = await call('record_finding', { title: '待验证事项', url: 'lab.internal', evidence: '只有假设，须走平台验证门禁。' });
    assert.equal(finding.status, 'hypothesis');
    assistant('已保存可视化分析笔记，未确认漏洞。');
  }) });
  assert.equal(result.status, 'completed');
  assert(!output.events().some((event) => event.type === 'finding'));
  assert(output.events().some((event) => event.type === 'node' && event.data.kind === 'note'));
});

test('report stays within 24000 characters and serialized NDJSON remains below 96 KiB', () => {
  const lines = [];
  const emit = createEmitter((line) => lines.push(line));
  for (const character of ['证', '\u0000', '\n', '😀']) {
    const text = clip(character.repeat(MAX_TEXT * 2));
    assert(text.length <= MAX_TEXT);
    emit('report', 'coordinator', { text });
  }
  for (const line of lines) {
    assert(Buffer.byteLength(line) < 96 * 1024);
    assert(JSON.parse(line).data.text.length <= MAX_TEXT);
    assert.equal(line.trim().split('\n').length, 1);
  }
});
