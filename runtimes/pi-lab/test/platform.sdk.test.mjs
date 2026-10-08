import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { runLab } from '../lib/runtime.mjs';
import { capture, delay, modelServer, root, streamText, streamTool, temporaryDirectory } from '../test-support/fixtures.mjs';
import { bridgeServer, bridgeResponse, bridgeToken, platformInput } from '../test-support/platform.mjs';

function wired(config, model, bridge) {
  config.model.base_url = model.base_url;
  config.platform.bridge = { url: bridge.url, token: bridge.token };
  return config;
}
function streamTools(res, calls) {
  res.writeHead(200, { 'content-type': 'text/event-stream' });
  res.write(`data: ${JSON.stringify({ id: 'offline', choices: [{ index: 0, delta: { role: 'assistant', tool_calls: calls.map((call, index) => ({ index, id: call.id, type: 'function', function: { name: call.name, arguments: JSON.stringify(call.args) } })) }, finish_reason: null }] })}\n\n`);
  res.end(`data: ${JSON.stringify({ id: 'offline', choices: [{ index: 0, delta: {}, finish_reason: 'tool_calls' }] })}\n\ndata: [DONE]\n\n`);
}

test('PLATFORM REAL SDK: role/skills, concurrent bridge tools and actual shared workspace handoffs reach the coordinator', { timeout: 20000 }, async (t) => {
  const cwd = await temporaryDirectory(t);
  const config = platformInput();
  // This fixture tests full raw-result handoffs; compaction has its own real-SDK suite.
  config.model.context_window = 256000;
  const artifacts = new Map();
  let active = 0;
  let peak = 0;
  const bridge = await bridgeServer(t, async (body, res) => {
    assert(['coordinator', 'worker-1', 'worker-2', 'worker-3'].includes(body.agent_id));
    if (body.name === 'load_skill') {
      assert.equal(body.arguments.name, 'pentest-agent-os');
      bridgeResponse(res, `PLATFORM_SKILL_CONTENT ${bridgeToken} ${config.model.api_key} ${config.platform.bridge.url}`);
    } else if (body.name === 'exec') {
      assert.deepEqual(body.arguments.options, { count: 2, mode: 'offline' }, 'PI must validate/coerce the original nested JSON Schema');
      active++; peak = Math.max(peak, active);
      await delay(50);
      active--;
      bridgeResponse(res, JSON.stringify({ evidence: `REAL_EVIDENCE_${body.agent_id}`, bulk: 'RAW_TOOL_RESULT_NOT_AN_EVENT_'.repeat(5000), secret: bridgeToken }), { execution_id: `exec-${body.agent_id}` });
    } else if (body.name === 'write_file') {
      artifacts.set(body.arguments.path, body.arguments.content);
      bridgeResponse(res, JSON.stringify({ saved: body.arguments.path }), { execution_id: `write-${body.agent_id}` });
    } else if (body.name === 'read_file') {
      assert(artifacts.has(body.arguments.path));
      bridgeResponse(res, artifacts.get(body.arguments.path), { execution_id: 'read-shared-evidence' });
    } else throw new Error('unexpected tool');
  });
  const model = await modelServer(t, (body, res) => {
    const names = body.tools.map((tool) => tool.function.name);
    const coordinator = names.includes('delegate_agents');
    const system = body.messages.filter((message) => message.role === 'system').map((message) => message.content).join('\n');
    assert.match(system, coordinator ? /ROLE_CONTRACT_MARKER/ : /WORKER_CONTRACT_MARKER/);
    assert.doesNotMatch(system, coordinator ? /WORKER_CONTRACT_MARKER/ : /ROLE_CONTRACT_MARKER/);
    assert.match(system, /SHARED_SKILL_INDEX_MARKER/);
    assert.match(system, /渗透测试/);
    if (!coordinator) assert.match(system, /WORKER_CONTRACT_MARKER/);
    assert(!names.some((name) => ['inspect_http', 'bash', 'read', 'edit', 'codemode', 'tool_search'].includes(name)));
    for (const secret of [bridgeToken, config.model.api_key, bridge.url]) assert(!JSON.stringify(body).includes(secret));
    const prior = body.messages.filter((message) => message.role === 'tool');
    if (!prior.length) { streamTool(res, 'load_skill', { name: 'pentest-agent-os' }); return; }
    assert.match(prior[0].content, /PLATFORM_SKILL_CONTENT/);
    if (coordinator) {
      if (prior.length === 1) streamTool(res, 'delegate_agents', { tasks: [{ name: '证据任务 A', task: '在已授权范围内执行离线夹具，保存实际证据至 /evidence/A。' }, { name: '证据任务 B', task: '独立执行离线夹具，保存实际证据至 /evidence/B。' }] });
      else if (prior.length === 2) {
        const delegated = JSON.parse(prior[1].content);
        assert.equal(delegated.agents.length, 2);
        assert(delegated.agents.every((agent) => agent.status === 'completed' && agent.summary.includes('REAL_EVIDENCE')));
        streamTool(res, 'delegate_agents', { tasks: [{ name: '交接复核', task: `FOLLOWUP_USE_SHARED_ARTIFACT：读取 /evidence/A；此前真实结果：${delegated.agents[0].summary}` }] });
      } else {
        const shared = JSON.parse(prior[2].content);
        assert.match(shared.agents[0].summary, /SHARED_REAL_EVIDENCE_worker-1/);
        streamText(res, '协调器已汇总三个真实 PI 工作会话与后端共享证据；所有记录仍须遵循平台验证门禁。');
      }
    } else {
      const assigned = JSON.stringify(body.messages.find((message) => message.role === 'user').content);
      if (assigned.includes('FOLLOWUP_USE_SHARED_ARTIFACT')) {
        assert.match(assigned, /REAL_EVIDENCE_worker-1/);
        if (prior.length === 1) streamTool(res, 'read_file', { path: '/evidence/A' });
        else { assert.match(prior[1].content, /REAL_EVIDENCE_worker-1/); streamText(res, 'SHARED_REAL_EVIDENCE_worker-1，经平台 read_file 复核先前交接证据。'); }
      } else if (prior.length === 1) streamTool(res, 'exec', { command: 'offline fixture only; not an actual shell execution', options: { count: '2', mode: 'offline' } });
      else if (prior.length === 2) {
        const evidence = JSON.parse(prior[1].content).evidence;
        streamTool(res, 'write_file', { path: assigned.includes('/evidence/A') ? '/evidence/A' : '/evidence/B', content: evidence });
      } else streamText(res, `${JSON.parse(prior[1].content).evidence}；证据已写入 ${JSON.parse(prior[2].content).saved}。`);
    }
  });
  const output = capture();
  const result = await runLab(wired(config, model, bridge), { cwd, write: output.write });
  assert.equal(result.status, 'completed', output.lines.join(''));
  assert.deepEqual(bridge.errors, []);
  assert.equal(peak, 2);
  assert.equal(artifacts.size, 2);
  assert.equal(output.events().filter((event) => event.type === 'agent_start').length, 4);
  assert.equal(bridge.requests.length, 9);
  const execution = output.events().find((event) => event.type === 'node' && event.data.kind === 'tool' && event.data.detail.includes('exec-worker-1'));
  assert(execution);
  assert.equal(JSON.parse(execution.data.detail).execution_id, 'exec-worker-1');
  assert(output.events().some((event) => event.type === 'edge' && event.data.target === execution.data.id));
  const raw = output.lines.join('');
  for (const secret of [bridgeToken, config.model.api_key, bridge.url, 'RAW_TOOL_RESULT_NOT_AN_EVENT_']) assert(!raw.includes(secret));
  assert(output.lines.every((line) => Buffer.byteLength(line) < 96 * 1024));
  assert.match(output.events().find((event) => event.type === 'report').data.text, /三个真实 PI/);
  assert.deepEqual(await readdir(cwd), [], 'platform workspace writes must never become Node filesystem writes');
});

test('PLATFORM REAL SDK: defaults allow more than 20 model turns and 256 actual tool calls', { timeout: 30000 }, async (t) => {
  const cwd = await temporaryDirectory(t);
  const bridge = await bridgeServer(t, (_body, res) => bridgeResponse(res));
  const model = await modelServer(t, (_body, res, turn) => {
    if (turn <= 21) streamTools(res, Array.from({ length: 13 }, (_, index) => ({ id: `loop-${turn}-${index}`, name: 'exec', args: { command: 'offline fixture' } })));
    else streamText(res, '完成 273 次本机工具夹具调用；没有真实目标操作。');
  });
  const output = capture();
  const result = await runLab(wired(platformInput(), model, bridge), { cwd, write: output.write });
  assert.equal(result.status, 'completed', output.lines.join(''));
  assert.equal(model.requests.length, 22);
  assert.equal(bridge.requests.length, 273);
});

test('PLATFORM REAL SDK: turn budget is shared by workers and exhausted runs never complete', async (t) => {
  const cwd = await temporaryDirectory(t);
  const bridge = await bridgeServer(t);
  const model = await modelServer(t, (body, res) => {
    if (body.tools.some((tool) => tool.function.name === 'delegate_agents')) streamTool(res, 'delegate_agents', { tasks: [{ name: 'A', task: '离线分析 A' }, { name: 'B', task: '离线分析 B' }] });
    else streamText(res, '实际子会话摘要。');
  });
  const output = capture();
  const config = platformInput({ limits: { max_turns: 3 } });
  const result = await runLab(wired(config, model, bridge), { cwd, write: output.write });
  assert.equal(result.status, 'partial');
  assert.equal(model.requests.length, 3);
  assert.match(output.lines.join(''), /轮次预算/);
  assert.equal(output.events().at(-1).data.status, 'partial');
});

test('PLATFORM REAL SDK: tool budget stops additional bridge execution and equality is already partial', async (t) => {
  const cwd = await temporaryDirectory(t);
  const bridge = await bridgeServer(t);
  for (const attempts of [2, 3]) {
    const model = await modelServer(t, (body, res) => {
      const prior = body.messages.filter((message) => message.role === 'tool');
      if (prior.length < attempts) streamTool(res, 'exec', { command: 'fixture' });
      else streamText(res, '已达到预算，应为部分结果。');
    });
    const output = capture();
    const before = bridge.requests.length;
    const result = await runLab(wired(platformInput({ limits: { max_tool_calls: 2 } }), model, bridge), { cwd, write: output.write });
    assert.equal(result.status, 'partial');
    assert.equal(bridge.requests.length - before, 2);
    assert.match(output.lines.join(''), /2 次自定义工具调用预算/);
    assert(output.events().filter((event) => event.type === 'agent_end').every((event) => event.data.status !== 'completed'));
  }
});

test('PLATFORM REAL SDK: record_finding stays a note and record_vulnerability uses backend validation errors', async (t) => {
  const cwd = await temporaryDirectory(t);
  const bridge = await bridgeServer(t, (body, res) => {
    assert.equal(body.name, 'record_vulnerability');
    bridgeResponse(res, 'validation_gate_denied: missing independent evidence', { is_error: true, execution_id: 'vuln-gate-denial-1' });
  });
  const model = await modelServer(t, (body, res) => {
    const prior = body.messages.filter((message) => message.role === 'tool');
    if (prior.length === 0) streamTool(res, 'record_finding', { title: '待验证', url: 'http://10.23.1.2/path', evidence: '离线假设' });
    else if (prior.length === 1) streamTool(res, 'record_vulnerability', { evidence_id: 'missing' });
    else { assert.match(prior.at(-1).content, /validation_gate_denied/); streamText(res, '验证门禁拒绝，未登记正式漏洞。'); }
  });
  const output = capture();
  const result = await runLab(wired(platformInput(), model, bridge), { cwd, write: output.write });
  // Runtime completion is NOT acceptance by the server vulnerability gate.
  assert.equal(result.status, 'completed');
  assert.match(output.events().find((event) => event.type === 'report').data.text, /工具警告.*Go 服务端/);
  assert.equal(bridge.requests.length, 1);
  assert(!output.events().some((event) => event.type === 'finding'));
  assert(output.events().some((event) => event.type === 'tool_end' && event.data.name === 'record_vulnerability' && event.data.is_error));
  assert(output.events().some((event) => event.type === 'node' && event.data.detail.includes('vuln-gate-denial-1') && event.data.status === 'failed'));
});

test('PLATFORM REAL SDK: corrected parameter/backend errors allow runtime completion with warnings; asynchronous waiting remains successful', async (t) => {
  const cwd = await temporaryDirectory(t);
  for (const scenario of ['invalid_arguments', 'backend_error', 'async_pending']) {
    let bridgeCalls = 0;
    const bridge = await bridgeServer(t, (_body, res) => {
      bridgeCalls++;
      if (scenario === 'backend_error' && bridgeCalls === 1) bridgeResponse(res, 'temporary wait; retry by an explicit model decision', { is_error: true });
      else if (scenario === 'async_pending' && bridgeCalls === 1) bridgeResponse(res, JSON.stringify({ status: 'running', execution_id: 'offline-pending' }));
      else bridgeResponse(res, 'recovered and completed');
    });
    const model = await modelServer(t, (body, res) => {
      const prior = body.messages.filter((message) => message.role === 'tool');
      if (!prior.length) streamTool(res, 'exec', scenario === 'invalid_arguments' ? {} : { command: 'offline' });
      else if (prior.length === 1) streamTool(res, 'exec', { command: 'offline corrected request or poll' });
      else streamText(res, '已纠正参数或等待后端任务并取得结果。');
    });
    const output = capture();
    const result = await runLab(wired(platformInput(), model, bridge), { cwd, write: output.write });
    assert.equal(result.status, 'completed', scenario);
    assert.equal(result.exitCode, 0);
    const failedNodes = output.events().filter((event) => event.type === 'node' && event.data.kind === 'tool' && event.data.status === 'failed');
    assert.equal(failedNodes.length, scenario === 'async_pending' ? 0 : 1);
    const report = output.events().find((event) => event.type === 'report').data.text;
    if (scenario === 'async_pending') assert.doesNotMatch(report, /工具警告/);
    else {
      assert.match(report, /1 次工具错误/);
      assert.match(report, /Go 服务端覆盖、执行及证据门禁确认/);
    }
    assert(output.events().filter((event) => event.type === 'agent_end').every((event) => event.data.status === 'completed'));
    assert.equal(bridgeCalls, scenario === 'invalid_arguments' ? 1 : 2);
    assert(output.events().some((event) => event.type === 'tool_end' && !event.data.is_error));
    assert.equal(output.events().some((event) => event.type === 'tool_end' && event.data.is_error), scenario !== 'async_pending');
  }
});

test('PLATFORM REAL SDK: bridge HTTP/authentication failures stay partial even after a successful later call', async (t) => {
  const cwd = await temporaryDirectory(t);
  for (const status of [400, 401, 403, 500]) {
    let calls = 0;
    const bridge = await bridgeServer(t, (_body, res) => {
      if (++calls === 1) res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify({ error: 'offline transport rejection' }));
      else bridgeResponse(res, 'later success');
    });
    const model = await modelServer(t, (body, res) => {
      const prior = body.messages.filter((message) => message.role === 'tool');
      if (prior.length < 2) streamTool(res, 'exec', { command: 'offline' });
      else streamText(res, '后续调用成功，但桥 HTTP 故障仍需报告。');
    });
    const output = capture();
    const result = await runLab(wired(platformInput(), model, bridge), { cwd, write: output.write });
    assert.equal(result.status, 'partial', String(status));
    assert.equal(calls, 2);
    assert.match(output.lines.join(''), /桥 HTTP 请求失败/);
    assert.equal(output.events().filter((event) => event.type === 'node' && event.data.kind === 'tool' && event.data.status === 'failed').length, 1);
  }
});

test('PLATFORM REAL SDK: broken bridge connections and protocols stay partial after subsequent recovery', async (t) => {
  const cwd = await temporaryDirectory(t);
  for (const failure of ['disconnect', 'json', 'schema', 'redirect']) {
    let calls = 0;
    const bridge = await bridgeServer(t, (_body, res) => {
      if (++calls > 1) { bridgeResponse(res, 'later success'); return; }
      if (failure === 'disconnect') res.destroy();
      else if (failure === 'json') res.writeHead(200).end('invalid JSON');
      else if (failure === 'schema') res.writeHead(200).end(JSON.stringify({ content: [], is_error: 'false' }));
      else res.writeHead(302, { location: 'http://127.0.0.1:1/never-follow' }).end();
    });
    const model = await modelServer(t, (body, res) => {
      const prior = body.messages.filter((message) => message.role === 'tool');
      if (prior.length < 2) streamTool(res, 'exec', { command: 'offline' });
      else streamText(res, '后续调用成功，保留先前桥连接或协议失败。');
    });
    const output = capture();
    const result = await runLab(wired(platformInput(), model, bridge), { cwd, write: output.write });
    assert.equal(result.status, 'partial', failure);
    assert.equal(calls, 2);
    assert.match(output.events().find((event) => event.type === 'report').data.text, /平台工具桥/);
  }
});

test('PLATFORM REAL SDK: recovered worker argument errors do not contaminate coordinator completion; failed worker sessions do', async (t) => {
  const cwd = await temporaryDirectory(t);
  for (const scenario of ['corrected', 'model_failed']) {
    const bridge = await bridgeServer(t);
    const model = await modelServer(t, (body, res) => {
      const coordinator = body.tools.some((tool) => tool.function.name === 'delegate_agents');
      const prior = body.messages.filter((message) => message.role === 'tool');
      if (coordinator) {
        if (!prior.length) streamTool(res, 'delegate_agents', { tasks: [{ name: '离线任务', task: '仅调用本机测试夹具并交接真实结果。' }] });
        else streamText(res, '已收到工作会话结果；最终交付由服务端门禁确认。');
      } else if (scenario === 'model_failed') res.writeHead(401).end('offline model failure');
      else if (!prior.length) streamTool(res, 'exec', {});
      else if (prior.length === 1) streamTool(res, 'exec', { command: 'corrected offline fixture' });
      else streamText(res, '参数已纠正，实际工具完成。');
    });
    const output = capture();
    const result = await runLab(wired(platformInput(), model, bridge), { cwd, write: output.write });
    assert.equal(result.status, scenario === 'corrected' ? 'completed' : 'partial');
    const worker = output.events().find((event) => event.type === 'agent_end' && event.agent_id === 'worker-1');
    assert.equal(worker.data.status, scenario === 'corrected' ? 'completed' : 'failed');
    if (scenario === 'corrected') assert.match(output.events().find((event) => event.type === 'report').data.text, /工具警告/);
  }
});

test('PLATFORM REAL SDK: cancellation aborts a bridge request, live PI sessions and queued workers', { timeout: 15000 }, async (t) => {
  const cwd = await temporaryDirectory(t);
  const started = Promise.withResolvers();
  const closed = Promise.withResolvers();
  const bridge = await bridgeServer(t, (_body, res) => {
    res.writeHead(200, { 'content-type': 'application/json' }); res.flushHeaders();
    res.on('close', closed.resolve);
    started.resolve();
  });
  const model = await modelServer(t, (body, res) => {
    if (body.tools.some((tool) => tool.function.name === 'delegate_agents')) streamTool(res, 'delegate_agents', { tasks: Array.from({ length: 4 }, (_, index) => ({ name: `工作 ${index}`, task: '调用本机离线夹具。' })) });
    else streamTool(res, 'exec', { command: 'fixture' });
  });
  const output = capture();
  const cancel = new AbortController();
  const running = runLab(wired(platformInput({ limits: { max_parallel: 1 } }), model, bridge), { cwd, write: output.write, signal: cancel.signal });
  await started.promise;
  cancel.abort();
  const result = await running;
  await closed.promise;
  assert.equal(result.status, 'partial');
  assert.equal(bridge.requests.length, 1);
  assert.equal(model.requests.length, 2);
  assert.deepEqual(output.events().filter((event) => event.type === 'agent_start').map((event) => event.agent_id), ['coordinator', 'worker-1']);
  for (const id of ['coordinator', 'worker-1']) {
    const events = output.events().filter((event) => event.agent_id === id);
    assert.equal(events.filter((event) => event.type === 'tool_start').length, events.filter((event) => event.type === 'tool_end').length);
  }
  const count = output.events().length;
  await delay(20);
  assert.equal(output.events().length, count);
  assert.equal(output.events().at(-1).type, 'complete');
});

async function snapshot(directory, prefix = '') {
  const files = {};
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) Object.assign(files, await snapshot(path, prefix + entry.name + '/'));
    else files[prefix + entry.name] = await readFile(path, 'utf8');
  }
  return files;
}

test('PLATFORM CLI + REAL SDK: platform context and credentials stay off disk; host resources stay disabled', { timeout: 15000 }, async (t) => {
  const dir = await temporaryDirectory(t);
  const cwd = join(dir, 'run');
  const host = join(dir, 'host');
  const agentDir = join(host, '.pi', 'agent');
  await mkdir(join(agentDir, 'extensions'), { recursive: true });
  await mkdir(join(cwd, '.pi', 'extensions'), { recursive: true });
  await writeFile(join(agentDir, 'auth.json'), JSON.stringify({ openai: { type: 'api_key', key: 'WRONG_HOST_KEY' } }));
  await writeFile(join(agentDir, 'models.json'), 'INVALID_HOST_MODELS_MUST_NOT_BE_READ');
  await writeFile(join(agentDir, 'settings.json'), JSON.stringify({ extensions: ['builtin:mcp'], packages: ['./forbidden'], cacheWarming: 'idle', defaultTools: ['bash', 'read', 'codemode', 'mcp__*'] }));
  await writeFile(join(agentDir, 'extensions', 'forbidden.mjs'), 'throw new Error("HOST_EXTENSION_LOADED");');
  await writeFile(join(cwd, '.pi', 'extensions', 'forbidden.mjs'), 'throw new Error("PROJECT_EXTENSION_LOADED");');
  await writeFile(join(cwd, '.pi', 'mcp.json'), 'INVALID_PROJECT_MCP_MUST_NOT_BE_READ');
  await writeFile(join(cwd, 'AGENTS.md'), 'HOST_CONTEXT_MUST_NOT_REACH_MODEL');
  const config = platformInput();
  config.model.api_key = '!literal-platform-fixture-key';
  const bridge = await bridgeServer(t, (_body, res) => bridgeResponse(res, `${bridgeToken} ${config.model.api_key} ${config.platform.bridge.url}`, { execution_id: 'offline-secret-redaction' }));
  const model = await modelServer(t, (body, res) => {
    assert(!JSON.stringify(body).includes('HOST_CONTEXT_MUST_NOT_REACH_MODEL'));
    for (const secret of [bridgeToken, config.model.api_key, bridge.url]) assert(!JSON.stringify(body).includes(secret));
    const prior = body.messages.filter((message) => message.role === 'tool');
    if (!prior.length) streamTool(res, 'load_skill', { name: 'pentest-agent-os' });
    else streamText(res, `仅本机模拟结果。${bridgeToken} ${config.model.api_key} ${bridge.url}`);
  });
  wired(config, model, bridge);
  const before = await snapshot(dir);
  const child = spawn(process.execPath, [join(root, 'runner.mjs')], {
    cwd, env: { ...process.env, HOME: host, USERPROFILE: host, PI_CODING_AGENT_DIR: agentDir, OPENAI_API_KEY: 'WRONG_ENV_KEY', OPENAI_LOG: 'debug' },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  t.after(() => { if (child.exitCode === null) child.kill(); });
  let stdout = ''; let stderr = '';
  child.stdout.on('data', (chunk) => { stdout += chunk; });
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  child.stdin.end(JSON.stringify(config) + '\n');
  const code = await new Promise((resolve, reject) => { child.once('error', reject); child.once('close', resolve); });
  assert.equal(code, 0, stdout + stderr);
  assert.equal(stderr, '');
  assert.deepEqual(await snapshot(dir), before);
  for (const secret of [bridgeToken, config.model.api_key, bridge.url]) assert(!stdout.includes(secret));
  assert.equal(model.requests[0].headers.authorization, `Bearer ${config.model.api_key}`);
  assert.equal(bridge.requests[0].headers.authorization, `Bearer ${bridgeToken}`);
  assert.equal(JSON.parse(stdout.trim().split('\n').at(-1)).data.status, 'completed');
});
