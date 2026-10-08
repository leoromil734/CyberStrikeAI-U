import { setTimeout as delay } from 'node:timers/promises';
import { mkdtemp, mkdir, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { createServer } from 'node:http';

export const root = fileURLToPath(new URL('../', import.meta.url));
export function input(overrides = {}) {
  return {
    run_id: 'offline-test', prompt: '仅观察 https://example.com/ 并报告限制。', scope: ['https://example.com'],
    limits: { max_parallel: 2, max_agents: 6, timeout_seconds: 30, max_requests: 80 },
    model: { provider: 'openai', base_url: 'https://models.invalid/v1', api_key: 'secret-test-KEY-123456', id: 'offline-model', context_window: 32000, max_tokens: 1024 },
    ...overrides,
  };
}
export async function temporaryDirectory(t) {
  const parent = join(root, '.test-tmp');
  await mkdir(parent, { recursive: true });
  const dir = await mkdtemp(join(parent, 'run-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}
export function response({ status = 200, headers = {}, chunks = [Buffer.from('offline evidence')], close = async () => {} } = {}) {
  return { status, headers, body: (async function* () { for (const chunk of chunks) yield chunk; })(), close };
}
export function capture() {
  const lines = [];
  return { write: (line) => lines.push(line), lines, events: () => lines.map((line) => JSON.parse(line)) };
}
export function fakeFactory(script, state = {}) {
  return async (options) => {
    const listeners = new Set();
    const controller = new AbortController();
    const messages = [];
    const emit = (event) => { for (const listener of listeners) listener(event); };
    const assistant = (value, stopReason = 'stop') => {
      const message = { role: 'assistant', content: [{ type: 'text', text: value }], stopReason };
      messages.push(message);
      emit({ type: 'message_end', message });
    };
    const call = async (name, args) => {
      const tool = options.tools.find((entry) => entry.name === name);
      emit({ type: 'tool_execution_start', toolName: name });
      try {
        if (!tool) throw new Error('Unknown tool');
        const result = await tool.execute('offline-tool-id', args, controller.signal);
        emit({ type: 'tool_execution_end', toolName: name, result, isError: false });
        return JSON.parse(result.content[0].text);
      } catch (error) {
        emit({ type: 'tool_execution_end', toolName: name, isError: true });
        throw error;
      }
    };
    const session = {
      state: { messages },
      subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener); },
      async prompt(prompt) {
        options.control.takeTurn();
        await script({ ...options, prompt, signal: controller.signal, assistant, call, emit });
      },
      async abort() { state.aborts = (state.aborts ?? 0) + 1; controller.abort(); },
      dispose() { state.disposes = (state.disposes ?? 0) + 1; },
    };
    (state.sessions ??= []).push({ options, session });
    return session;
  };
}
export { delay };

export function streamText(res, content, finish = 'stop') {
  res.writeHead(200, { 'content-type': 'text/event-stream' });
  res.write(`data: ${JSON.stringify({ id: 'offline', object: 'chat.completion.chunk', model: 'offline-model', choices: [{ index: 0, delta: { role: 'assistant', content }, finish_reason: null }] })}\n\n`);
  res.end(`data: ${JSON.stringify({ id: 'offline', choices: [{ index: 0, delta: {}, finish_reason: finish }] })}\n\ndata: [DONE]\n\n`);
}
export function streamTool(res, name, args) {
  res.writeHead(200, { 'content-type': 'text/event-stream' });
  res.write(`data: ${JSON.stringify({ id: 'offline', choices: [{ index: 0, delta: { role: 'assistant', tool_calls: [{ index: 0, id: `call-${Math.random().toString(16).slice(2)}`, type: 'function', function: { name, arguments: JSON.stringify(args) } }] }, finish_reason: null }] })}\n\n`);
  res.end(`data: ${JSON.stringify({ id: 'offline', choices: [{ index: 0, delta: {}, finish_reason: 'tool_calls' }] })}\n\ndata: [DONE]\n\n`);
}
export async function modelServer(t, handler) {
  const requests = [];
  const server = createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = JSON.parse(Buffer.concat(chunks).toString());
    requests.push({ path: req.url, headers: req.headers, body });
    try { await handler(body, res, requests.length); }
    catch { if (!res.writableEnded) res.writeHead(500).end('offline fixture failed'); }
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  });
  return { server, requests, base_url: `http://127.0.0.1:${server.address().port}/v1` };
}
