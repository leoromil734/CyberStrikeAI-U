import { createServer } from 'node:http';
import { input } from './fixtures.mjs';

export const bridgeToken = 'offline-bridge-token-0123456789abcdef';
export const platformTools = [
  { name: 'load_skill', description: 'Load a platform skill progressively.', input_schema: { type: 'object', properties: { name: { type: 'string', minLength: 1 } }, required: ['name'], additionalProperties: false } },
  { name: 'exec', description: 'Execute through inherited platform permissions.', input_schema: { type: 'object', properties: { command: { type: 'string', minLength: 1 }, options: { type: 'object', properties: { count: { type: 'integer', minimum: 1 }, mode: { enum: ['offline', 'preview'] }, api_key: { type: 'string' } }, additionalProperties: false } }, required: ['command'], additionalProperties: false } },
  ...['read_file', 'write_file', 'read_skill_file'].map((name) => ({ name, description: 'Platform workspace fixture; no actual filesystem action.', input_schema: { type: 'object', properties: { path: { type: 'string' }, content: { type: 'string' } }, required: ['path'], additionalProperties: false } })),
  { name: 'record_vulnerability', description: 'Use the existing platform evidence validation gate.', input_schema: { type: 'object', properties: { evidence_id: { type: 'string' } }, required: ['evidence_id'], additionalProperties: false } },
];
export function platformInput(overrides = {}) {
  return input({
    mode: 'platform',
    prompt: '在明确授权的离线靶场内执行具体分工，保存证据并汇总验证状态。',
    scope: ['127.0.0.1', '10.23.0.0/16', 'lab.internal', 'http://lab.internal/app/', '排除：10.23.8.9 和破坏性动作'],
    limits: { max_parallel: 2, max_agents: 6, timeout_seconds: 60 },
    platform: {
      role_name: '渗透测试', instructions: 'ROLE_CONTRACT_MARKER：按照项目既有角色路由，逐步加载技能并记录证据。',
      worker_instructions: 'WORKER_CONTRACT_MARKER：只完成交接目标，返回证据引用与待验证事项。',
      project_id: 'offline-project', conversation_id: 'offline-conversation', workspace: '/backend/workspace/offline-project',
      skills: [{ name: 'pentest-agent-os', description: 'SHARED_SKILL_INDEX_MARKER：共享执行契约。' }, { name: 'attack-surface-recon', description: '按角色路由逐步加载资产面技能。' }],
      tools: structuredClone(platformTools),
      bridge: { url: 'http://127.0.0.1:49152/tools/call', token: bridgeToken },
    },
    ...overrides,
  });
}
export function bridgeResponse(res, text = '{}', extra = {}) {
  res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ content: [{ type: 'text', text }], is_error: false, ...extra }));
}
export async function bridgeServer(t, handler = (_body, res) => bridgeResponse(res)) {
  const requests = [];
  const errors = [];
  const server = createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    let body;
    try { body = JSON.parse(Buffer.concat(chunks).toString()); } catch { res.writeHead(400).end('{}'); return; }
    requests.push({ method: req.method, path: req.url, headers: req.headers, body });
    if (req.headers.authorization !== `Bearer ${bridgeToken}`) {
      res.writeHead(401, { 'content-type': 'application/json' }).end(JSON.stringify({ error: `认证失败 ${bridgeToken}` }));
      return;
    }
    try { await handler(body, res, req); }
    catch (error) { errors.push(error); if (!res.writableEnded) res.writeHead(500).end(JSON.stringify({ error: 'offline fixture failed' })); }
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); });
  return { server, requests, errors, url: `http://127.0.0.1:${server.address().port}/tools/call`, token: bridgeToken };
}
