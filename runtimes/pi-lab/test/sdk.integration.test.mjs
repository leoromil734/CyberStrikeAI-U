import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { runLab } from '../lib/runtime.mjs';
import { capture, delay, input, modelServer, response, root, streamText, streamTool, temporaryDirectory } from '../test-support/fixtures.mjs';

async function snapshot(directory, prefix = '') {
  const result = {};
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    const name = prefix + entry.name;
    if (entry.isDirectory()) Object.assign(result, await snapshot(path, name + '/'));
    else result[name] = await readFile(path, 'utf8');
  }
  return result;
}

test('REAL SDK: coordinator invokes delegate_agents, two workers inspect/record and final report follows summaries', async (t) => {
  const cwd = await temporaryDirectory(t);
  const model = await modelServer(t, async (body, res) => {
    const tools = body.tools.map((tool) => tool.function.name);
    const prior = body.messages.filter((message) => message.role === 'tool');
    if (tools.includes('delegate_agents')) {
      if (prior.length === 0) streamTool(res, 'delegate_agents', { tasks: [{ name: 'HTTP observation A', task: '观察已授权 URL' }, { name: 'HTTP observation B', task: '独立观察已授权 URL' }] });
      else {
        const result = JSON.parse(prior.at(-1).content);
        assert.equal(result.agents.length, 2);
        assert(result.agents.every((agent) => agent.status === 'completed'));
        streamText(res, '协调器根据两个真实 PI 子会话的观察汇总：HTTP 200 仅为事实，没有确认漏洞。');
      }
    } else {
      await delay(5);
      if (prior.length === 0) streamTool(res, 'inspect_http', { url: 'https://example.com/', method: 'GET' });
      else if (prior.length === 1) streamTool(res, 'record_finding', { title: 'HTTP 状态事实', url: 'https://example.com/', severity: 'info', status: 'observed', evidence: 'HTTP 200 不等于漏洞。', remediation: '需要时人工复核。' });
      else streamText(res, '实际子会话观察为 HTTP 200；已记录观察证据，未确认漏洞。');
    }
  });
  const config = input({ model: { ...input().model, base_url: model.base_url } });
  const output = capture();
  let inspections = 0;
  const result = await runLab(config, { cwd, write: output.write, transport: async () => { inspections++; return response(); } });
  assert.equal(result.status, 'completed', output.lines.join(''));
  assert.equal(inspections, 2);
  assert.equal(model.requests.length, 8);
  assert.equal(output.events().filter((event) => event.type === 'agent_start').length, 3);
  assert.equal(output.events().filter((event) => event.type === 'finding').length, 2);
  assert.match(output.events().find((event) => event.type === 'report').data.text, /真实 PI 子会话/);
  for (const request of model.requests) {
    assert.equal(request.path, '/v1/chat/completions');
    assert.equal(request.headers.authorization, `Bearer ${config.model.api_key}`);
    assert.equal(request.body.model, config.model.id);
    assert(request.body.max_tokens === config.model.max_tokens || request.body.max_completion_tokens === config.model.max_tokens);
    assert(request.body.tools.every((tool) => ['inspect_http', 'record_surface', 'record_finding', 'delegate_agents'].includes(tool.function.name)));
  }
  assert.deepEqual(await readdir(cwd), []);
  assert(!output.lines.join('').includes(config.model.api_key));
});

test('REAL SDK: provider errors are not success even when prompt resolves; no SDK error details leak', async (t) => {
  const cwd = await temporaryDirectory(t);
  const config = input();
  const server = await modelServer(t, (_body, res) => res.writeHead(401, { 'content-type': 'application/json' }).end(JSON.stringify({ error: { message: `private error ${config.model.api_key}`, type: 'invalid_request_error' } })));
  config.model.base_url = server.base_url;
  const output = capture();
  const result = await runLab(config, { cwd, write: output.write });
  assert.equal(result.status, 'partial');
  assert.equal(server.requests.length, 1, 'provider retries must be disabled');
  assert(!output.lines.join('').includes(config.model.api_key));
  assert(!output.lines.join('').includes('private error'));
  assert(output.events().some((event) => event.type === 'error'));
});

test('REAL SDK: shared 20-turn cap stops model/tool loops without a 21st network call', async (t) => {
  const cwd = await temporaryDirectory(t);
  const server = await modelServer(t, (_body, res) => streamTool(res, 'inspect_http', { url: 'https://example.com/', method: 'HEAD' }));
  const output = capture();
  const result = await runLab(input({ model: { ...input().model, base_url: server.base_url } }), { cwd, write: output.write, transport: async () => response() });
  assert.equal(result.status, 'partial');
  assert.equal(server.requests.length, 20);
  assert.match(output.lines.join(''), /轮次预算/);
});

test('REAL SDK: model redirects are rejected without contacting a second origin', async (t) => {
  const cwd = await temporaryDirectory(t);
  const server = await modelServer(t, (_body, res) => res.writeHead(302, { location: 'http://different.invalid/credential-capture' }).end());
  const output = capture();
  const result = await runLab(input({ model: { ...input().model, base_url: server.base_url } }), { cwd, write: output.write });
  assert.equal(result.status, 'partial');
  assert.equal(server.requests.length, 1);
});

test('REAL SDK: claude maps to anthropic-messages, uses stdin key and correct endpoint', async (t) => {
  const cwd = await temporaryDirectory(t);
  const server = await modelServer(t, (_body, res) => {
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    const send = (type, payload) => res.write(`event: ${type}\ndata: ${JSON.stringify({ type, ...payload })}\n\n`);
    send('message_start', { message: { id: 'msg_offline', type: 'message', role: 'assistant', model: 'offline-model', content: [], stop_reason: null, usage: { input_tokens: 10, output_tokens: 0 } } });
    send('content_block_start', { index: 0, content_block: { type: 'text', text: '' } });
    send('content_block_delta', { index: 0, delta: { type: 'text_delta', text: 'Claude 离线模拟报告；没有发送目标 HTTP 请求。' } });
    send('content_block_stop', { index: 0 });
    send('message_delta', { delta: { stop_reason: 'end_turn', stop_sequence: null }, usage: { output_tokens: 12 } });
    send('message_stop', {});
    res.end();
  });
  const config = input({ model: { ...input().model, provider: 'claude', base_url: server.base_url.replace(/\/v1$/, '') } });
  const output = capture();
  const result = await runLab(config, { cwd, write: output.write });
  assert.equal(result.status, 'completed', output.lines.join(''));
  assert.equal(server.requests[0].path, '/v1/messages?beta=true');
  assert.equal(server.requests[0].headers['x-api-key'], config.model.api_key);
});

test('CLI + REAL SDK: credentials never land on disk, host/project configuration and extensions are ignored', async (t) => {
  const dir = await temporaryDirectory(t);
  const cwd = join(dir, 'run');
  const host = join(dir, 'host');
  const agentDir = join(host, '.pi', 'agent');
  await mkdir(cwd, { recursive: true });
  await mkdir(join(agentDir, 'extensions'), { recursive: true });
  await mkdir(join(cwd, '.pi', 'extensions'), { recursive: true });
  await writeFile(join(agentDir, 'auth.json'), JSON.stringify({ openai: { type: 'api_key', key: 'WRONG_HOST_KEY' } }));
  await writeFile(join(agentDir, 'settings.json'), JSON.stringify({ defaultModel: 'WRONG_HOST_MODEL', cacheWarming: 'idle', defaultTools: ['bash', 'codemode', 'tool_search', 'mcp__*'], extensions: ['builtin:mcp'], packages: ['./forbidden-package'] }));
  await writeFile(join(agentDir, 'models.json'), 'INVALID_HOST_MODELS_MUST_NOT_BE_READ');
  await writeFile(join(agentDir, 'mcp.json'), 'INVALID_HOST_MCP_MUST_NOT_BE_READ');
  await writeFile(join(cwd, '.pi', 'mcp.json'), 'INVALID_PROJECT_MCP_MUST_NOT_BE_READ');
  await writeFile(join(cwd, '.pi', 'settings.json'), JSON.stringify({ extensions: ['builtin:mcp'], cacheWarming: 'idle', defaultTools: ['bash', 'mcp__*'] }));
  await writeFile(join(agentDir, 'extensions', 'do-not-load.mjs'), 'throw new Error("HOST_EXTENSION_WAS_LOADED");');
  await writeFile(join(cwd, '.pi', 'extensions', 'do-not-load.mjs'), 'throw new Error("PROJECT_EXTENSION_WAS_LOADED");');
  await writeFile(join(cwd, 'AGENTS.md'), 'FORBIDDEN_PROJECT_CONTEXT_MARKER');
  const config = input({ model: { ...input().model, api_key: '!literal-key-not-a-shell-command' } });
  const server = await modelServer(t, (body, res) => {
    assert(!JSON.stringify(body).includes('FORBIDDEN_PROJECT_CONTEXT_MARKER'));
    streamText(res, `正常离线报告 ${config.model.api_key}`);
  });
  config.model.base_url = server.base_url;
  const before = await snapshot(dir);
  const child = spawn(process.execPath, [join(root, 'runner.mjs')], {
    cwd, env: { ...process.env, HOME: host, USERPROFILE: host, PI_CODING_AGENT_DIR: agentDir, OPENAI_API_KEY: 'WRONG_ENV_KEY', OPENAI_LOG: 'debug' },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  let stdout = ''; let stderr = '';
  child.stdout.on('data', (chunk) => { stdout += chunk; });
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  child.stdin.end(JSON.stringify(config) + '\n');
  const code = await new Promise((resolve, reject) => { child.once('error', reject); child.once('close', resolve); });
  assert.equal(code, 0, stdout + stderr);
  assert.equal(stderr, '');
  assert(!stdout.includes(config.model.api_key));
  assert(!stdout.includes('WRONG_HOST'));
  assert.equal(server.requests[0].headers.authorization, `Bearer ${config.model.api_key}`);
  assert.deepEqual(await snapshot(dir), before);
  const events = stdout.trim().split('\n').map((line) => JSON.parse(line));
  assert.equal(events.at(-1).type, 'complete');
  assert.equal(events.at(-1).data.status, 'completed');
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  test(`CLI + REAL SDK: ${signal} handler aborts streaming request and emits final partial`, async (t) => {
    const cwd = await temporaryDirectory(t);
    let child;
    let closed = false;
    const server = await modelServer(t, async (_body, res) => {
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.flushHeaders();
      res.on('close', () => { closed = true; });
      // Windows child.kill(SIGTERM) forcibly terminates without JS handlers.
      // IPC triggers Node's actual signal handler portably, after SDK I/O starts.
      child.send(signal);
    });
    const wrapper = `process.on('message', signal => process.emit(signal)); await import(${JSON.stringify(pathToFileURL(join(root, 'runner.mjs')).href)}); process.disconnect();`;
    child = spawn(process.execPath, ['--input-type=module', '-e', wrapper], { cwd, stdio: ['pipe', 'pipe', 'pipe', 'ipc'] });
    t.after(() => { if (child.exitCode === null) child.kill(); });
    let stdout = ''; let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.stdin.end(JSON.stringify(input({ model: { ...input().model, base_url: server.base_url } })) + '\n');
    const code = await new Promise((resolve, reject) => { child.once('error', reject); child.once('close', resolve); });
    assert.equal(code, 1, stdout + stderr);
    assert.equal(stderr, '');
    const events = stdout.trim().split('\n').map((line) => JSON.parse(line));
    assert.equal(events.at(-1).type, 'complete');
    assert.equal(events.at(-1).data.status, 'partial');
    assert.equal(server.requests.length, 1);
    assert.equal(closed, true);
  });
}
