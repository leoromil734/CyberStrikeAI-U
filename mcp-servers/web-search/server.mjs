#!/usr/bin/env node
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import https from 'node:https';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { pathToFileURL } from 'node:url';
import { loadProxyConfig, ProxyPool, redactSecrets } from '../shared/proxy-pool.mjs';
import { ENGINES, SCENARIOS, researchPlan, classifyFailure } from './policy.mjs';
import { SearchService } from './service.mjs';

const country = z.string().regex(/^[a-zA-Z]{2}$/).describe('ISO 两字母国家代码，例如 US、GB、JP；省略使用代理默认国家').optional();
const leaseId = z.string().min(1).max(100);
const publicUrl = z.string().url().refine(value => {
  const url = new URL(value);
  return ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password;
}, '只接受无凭据的 HTTP(S) URL；上游还会阻止私网地址和不安全重定向');
const network = z.enum(['auto', 'direct', 'proxy']).default('auto')
  .describe('auto 先直连，仅连接类故障使用代理；direct 强制直连；proxy 强制代理且失败时最多更换一次出口');

export async function checkProxy(pool, options = {}, signal) {
  const lease = await pool.acquire({ country: options.country, leaseId: options.lease_id });
  const agent = new HttpsProxyAgent(lease.proxy_url);
  try {
    const data = await new Promise((resolve, reject) => {
      const request = https.get('https://api.ipify.org?format=json', { agent, signal, timeout: 12000 }, response => {
        let body = '';
        response.on('data', chunk => { body += chunk; if (body.length > 4096) request.destroy(new Error('Health response too large')); });
        response.on('error', reject);
        response.on('end', () => {
          if (response.statusCode !== 200) return reject(new Error(`Proxy health HTTP ${response.statusCode}`));
          try { resolve(JSON.parse(body)); } catch { reject(new Error('Invalid IP health response')); }
        });
      });
      request.on('timeout', () => request.destroy(new Error('Proxy health timeout')));
      request.on('error', reject);
    });
    return { status: 'ok', ...lease, exit_ip: data.ip, checked_at: new Date().toISOString(),
      note: 'country 是向提供商请求的国家，未作地理数据库验证；更换 sid 不保证每次返回不同 IP。' };
  } catch (error) {
    return { status: 'unavailable', ...lease, category: classifyFailure(error).category,
      error: redactSecrets(String(error.message ?? error), pool.config).slice(0, 500) };
  } finally { agent.destroy(); }
}

export function createServer(options = {}) {
  const pool = options.pool ?? new ProxyPool(loadProxyConfig());
  const service = options.service ?? new SearchService(pool);
  const server = new McpServer({ name: 'cyberstrike-web-search', version: '1.0.0' }, {
    instructions: '公开资料检索服务：使用 research_plan 选择检索路线、web_search 多引擎查找、web_fetch 获取原始正文；CVE/PoC 线索未经目标侧验证不能确认漏洞。需要代理的其他工具先调用 proxy_get，将返回的本地代理地址/环境变量用于单个进程。代理只作用于显式使用它的请求，不修改系统代理。'
  });
  const read = { readOnlyHint: true, destructiveHint: false, openWorldHint: true };
  const local = { readOnlyHint: false, destructiveHint: false, openWorldHint: false };
  const guarded = fn => async (args, extra) => {
    try {
      const value = await fn(args, extra?.signal);
      return { content: [{ type: 'text', text: redactSecrets(JSON.stringify(value, null, 2), pool.config) }],
        isError: value?.status === 'unavailable' };
    } catch (error) {
      return { content: [{ type: 'text', text: JSON.stringify({ status: 'unavailable', category: classifyFailure(error).category,
        error: redactSecrets(String(error.message ?? error), pool.config).slice(0, 1000) }) }], isError: true };
    }
  };
  server.registerTool('web_search', {
    description: '多引擎公开网页搜索。适用于 CVE/Nday 细节、PoC 链接、框架历史漏洞、修复版本、文档和报错。返回来源/时间/逐次故障诊断；空结果不能证明无漏洞。403/429/验证码不自动换 IP。',
    inputSchema: { query: z.string().min(1).max(1000), limit: z.number().int().min(1).max(30).default(10),
      engines: z.array(z.enum(ENGINES)).min(1).max(3).default(['bing', 'duckduckgo']), network, country,
      fresh: z.boolean().default(false).describe('跳过五分钟成功结果缓存，适合最新公告/版本查询') }, annotations: read,
  }, guarded((args, signal) => service.search(args, signal)));
  server.registerTool('web_fetch', {
    description: '获取公开 HTTP(S) 网页、公告、补丁、Markdown 或原始 PoC 源码，仅阅读不执行；阻止私网/危险重定向。JS/登录/验证码问题需使用已有 browser 工具，不应无限切换代理。',
    inputSchema: { url: publicUrl, maxChars: z.number().int().min(1000).max(100000).default(30000),
      renderMode: z.enum(['request', 'auto', 'browser']).default('request'), network, country }, annotations: read,
  }, guarded((args, signal) => service.fetch(args, signal)));
  server.registerTool('github_readme', {
    description: '读取 GitHub 公共仓库 README，用于审阅 PoC 使用前提和来源；不会克隆或执行仓库代码。',
    inputSchema: { url: publicUrl.refine(value => /^https:\/\/github\.com\/[^/]+\/[^/]+/.test(value), '需要 HTTPS GitHub 仓库地址'), network, country,
      maxChars: z.number().int().min(1000).max(100000).default(30000) }, annotations: read,
  }, guarded((args, signal) => service.fetch({ ...args, github: true }, signal)));
  server.registerTool('research_plan', {
    description: '生成有界的安全情报检索计划，不联网。覆盖 Nday/PoC、框架历史漏洞、依赖适用性、补丁回补、安全配置、报错与通用文档；附官方来源和验证清单。',
    inputSchema: { scenario: z.enum(SCENARIOS).default('general'), subject: z.string().min(1).max(300),
      version: z.string().max(100).default(''), cve: z.string().max(30).default(''), ecosystem: z.string().max(100).default(''),
      aliases: z.array(z.string().min(1).max(100)).max(2).default([]) },
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
  }, guarded(args => researchPlan(args)));
  server.registerTool('proxy_status', {
    description: '查看项目共享住宅代理池可用状态、协议和脱敏租约信息；不联网、不显示上游账户密码。', inputSchema: {},
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, guarded(() => {
    const { leases, ...summary } = pool.status();
    // 租约 ID 可控制出口；状态查询不公开其他任务的租约标识。
    return { ...summary, leases: (leases ?? []).map(({ lease_id, session_id, ...state }) => state) };
  }));
  server.registerTool('proxy_get', {
    description: '为当前 Agent/任务创建独立粘性出口，返回本地 HTTP CONNECT 代理 URL 和单进程环境变量，供 curl、浏览器及其他 MCP 按需使用。凭据不进入模型。复用时传 lease_id：若该租约仍存活则直接续期；若已因空闲过期，会按原 lease_id 重新签发同一出口（同国家、同上游 session），返回 renewed=true 且 proxy_url 已变化，须重新读取。换出口只影响此租约。仅同机/同容器网络空间可访问。',
    inputSchema: { country, lease_id: leaseId.optional(), rotate: z.boolean().default(false) }, annotations: local,
  }, guarded(args => pool.acquire({ country: args.country, leaseId: args.lease_id, rotate: args.rotate })));
  server.registerTool('proxy_rotate', {
    description: '更换指定租约的 sid 或国家并断开此租约旧隧道；保持返回的新地址，重新建立客户端连接。不会轮换其他 Agent 的出口；不要用于绕过账户配额或持续验证码。',
    inputSchema: { lease_id: leaseId, country }, annotations: local,
  }, guarded(args => pool.rotate(args.lease_id, { country: args.country })));
  server.registerTool('proxy_release', {
    description: '释放指定任务的本地代理网关，其他租约不受影响。', inputSchema: { lease_id: leaseId }, annotations: local,
  }, guarded(async args => ({ released: await pool.release(args.lease_id) })));
  server.registerTool('proxy_healthcheck', {
    description: '用指定租约经住宅代理访问 api.ipify.org，检查出口 IP 和连接；可能消耗少量代理流量。407/597 是凭据问题而非 IP 信誉问题。',
    inputSchema: { country, lease_id: leaseId.optional() }, annotations: read,
  }, guarded((args, signal) => checkProxy(pool, args, signal)));
  return { server, pool, service, close: async () => { await service.close(); await pool.close(); await server.close(); } };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  let instance;
  let closing = false;
  const close = async () => {
    if (closing) return; closing = true;
    const kill = setTimeout(() => process.exit(0), 5000); kill.unref();
    await instance?.close().catch(() => {});
  };
  try {
    instance = createServer();
    process.on('SIGINT', close); process.on('SIGTERM', close); process.stdin.on('end', close);
    await instance.server.connect(new StdioServerTransport());
  } catch (error) {
    // 只输出静态提示：配置解析失败的原文可能带有秘密。
    process.stderr.write('web-search MCP 启动失败，请检查代理配置和 npm ci 安装情况。\n');
    await close(); process.exitCode = 1;
  }
}
