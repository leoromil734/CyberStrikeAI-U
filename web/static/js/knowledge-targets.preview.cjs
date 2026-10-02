// Isolated, read-only UI fixture. Run: node web/static/js/knowledge-targets.preview.cjs
// No backend is contacted, no credentials are needed, and mutation requests are rejected.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const template = fs.readFileSync(path.resolve(root, '../templates/index.html'), 'utf8');
const pages = {
    'experience-memory': template.match(/<div id="page-experience-memory"[\s\S]*?(?=<!-- 知识检索历史页面 -->)/)[0],
    targets: template.match(/<div id="page-targets"[\s\S]*?(?=<!-- C2 监听器管理页面 -->)/)[0],
};
const resources = Object.fromEntries(['zh-CN', 'en-US'].map(lang => [lang, JSON.parse(fs.readFileSync(path.join(root, `i18n/${lang}.json`), 'utf8'))]));
function setupFixture(resources, options) {
    const experiences = [
        ['verified', 'shared', 'tool_repair', '修复工具输出中的编码问题', '统一工具输出的编码与解析条件。仅在验证过的工具版本内复用，其他版本需要重新检查执行证据。'],
        ['candidate', 'private', 'workflow', '按资产类型分组检查的工作流', '先区分域名、IP 与服务入口，再整理可重复使用的检查步骤。自动学习只生成候选，审核后才可复用。'],
        ['needs_review', 'project', 'vulnerability_method', '登录接口的响应差异验证方法', '记录请求前提、对照结果与清理步骤，环境或版本变化后需要重新复核。'],
        ['deprecated', 'private', 'negative_result', '旧版本工具参数的失败反例', '保留失败原因与修复条件，避免把过去有效的参数直接用于新版本。'],
        ['verified', 'shared', 'workflow', '跨任务复用前的证据检查', '检查来源、适用条件和可访问的证据。共享前需要移除客户数据、敏感标识与凭据。'],
        ['candidate', 'private', 'negative_result', '<script>样例内容始终按文本显示</script>', '这是一条用于测试长文本的只读经验。' + '较长的标题与正文应换行，元数据与操作按钮仍需保持可读。'.repeat(4)],
    ].map(([status, scope, kind, title, summary], i) => ({ id: `fixture-memory-${i + 1}`, revision: i + 1, status, scope, origin_project_id: 'demo-project', content: { title, summary, kind, conditions: { product: 'Demo application', versions: ['1.0'], required: { protocol: 'https' } }, steps: ['检查条件', '核对实际执行证据'], verification: 'Compare the expected result', failure_notes: [], cleanup: 'Remove temporary test data' } }));
    const targets = [
        { target: 'example.com', runCount: 4, submittedCount: 6, firstRunAt: '2026-09-26T03:21:00Z', lastRunAt: '2026-10-02T03:21:00Z', lastSubmittedAt: '2026-10-01T03:21:00Z', lastTaskTitle: 'Demo task' },
        { target: 'registered.example.com', runCount: 0, submittedCount: 2, lastSubmittedAt: '2026-10-02T02:21:00Z' },
        { target: 'a-long-target-name-for-mobile-layout.preview.example.com/api/health?format=json', runCount: 1, submittedCount: 1, lastRunAt: '2026-09-30T12:00:00Z' },
    ];
    let language = options.lang;
    window.__fixtureCalls = [];
    window.__fixtureErrors = [];
    window.__fixtureOptions = options;
    window.t = (key, params = {}) => {
        const text = key.split('.').reduce((obj, part) => obj?.[part], resources[language]) || key;
        return text.replace(/\{\{(\w+)\}\}/g, (_, name) => String(params[name] ?? ''));
    };
    window.applyTranslations = (root = document) => {
        root.querySelectorAll('[data-i18n]').forEach(el => {
            const text = window.t(el.getAttribute('data-i18n'));
            if (!el.children.length && !['INPUT', 'TEXTAREA'].includes(el.tagName) && el.getAttribute('data-i18n-skip-text') !== 'true') el.textContent = text;
            (el.getAttribute('data-i18n-attr') || '').split(',').filter(Boolean).forEach(attr => el.setAttribute(attr.trim(), text));
        });
        document.documentElement.lang = language;
    };
    const permissions = options.readOnly ? ['experience:read', 'target:read'] : ['experience:read', 'experience:write', 'experience:review', 'experience:export', 'target:read', 'target:delete'];
    window.hasPermission = permission => permissions.includes(permission);
    window.requirePermission = window.hasPermission;
    window.applyRBACToUI = (root = document) => root.querySelectorAll('[data-require-permission]').forEach(el => {
        const allowed = window.hasPermission(el.getAttribute('data-require-permission'));
        el.hidden = !allowed; if ('disabled' in el) el.disabled = !allowed;
        el.classList.toggle('rbac-permission-denied', !allowed);
    });
    window.rbacAfterDynamicRender = window.applyRBACToUI;
    window.readApiError = async response => (await response.json()).error || 'Read-only fixture error';
    window.notifyApiError = message => window.__fixtureErrors.push(message);
    window.showNotification = message => window.__fixtureErrors.push(message);
    window.apiFetch = async (url, request = {}) => {
        window.__fixtureCalls.push({ url, method: request.method || 'GET' });
        if (request.method && request.method !== 'GET') throw new Error('Mutation blocked by the read-only UI fixture');
        await new Promise(resolve => setTimeout(resolve, options.slow ? 3000 : 100));
        if (options.fail) return { ok: false, status: 503, json: async () => ({ error: '模拟读取失败 / Simulated read failure' }) };
        const parsed = new URL(url, location.origin);
        let data;
        if (parsed.pathname === '/api/experiences') {
            const params = parsed.searchParams;
            const filtered = experiences.filter(entry => (!params.get('status') || entry.status === params.get('status')) && (!params.get('kind') || entry.content.kind === params.get('kind')) && (!params.get('project_id') || entry.origin_project_id === params.get('project_id')) && (!params.get('query') || (entry.content.title + entry.content.summary).includes(params.get('query'))));
            const offset = Number(params.get('offset')) || 0;
            data = { items: options.empty ? [] : filtered.slice(offset, offset + (Number(params.get('limit')) || 25)) };
        } else if (parsed.pathname.startsWith('/api/experiences/')) {
            const id = parsed.pathname.split('/')[3];
            const entry = experiences.find(item => item.id === id) || experiences[0];
            const evidence = [{ role: 'validation', execution_id: 'fixture-execution-1' }];
            data = parsed.pathname.includes('/evidence/') ? { execution: { id: 'fixture-execution-1', output: '<script>Evidence is displayed as plain text</script>' } } : { entry, evidence };
        } else if (parsed.pathname === '/api/targets') {
            const keyword = (parsed.searchParams.get('keyword') || '').toLowerCase();
            const filtered = options.empty ? [] : targets.filter(item => item.target.toLowerCase().includes(keyword));
            data = { targets: filtered, total: filtered.length, page: 1, page_size: 50, total_pages: 1 };
        } else if (parsed.pathname.startsWith('/api/targets/') && parsed.pathname.endsWith('/events')) {
            data = { events: [
                { conversationId: 'fixture-conversation-1', conversationTitle: '首次验证 / Initial verification', startedAt: '2026-09-26T03:21:00Z' },
                { conversationId: 'fixture-conversation-2', conversationTitle: '复核对话 / Follow-up verification with a longer title to test wrapping on mobile', startedAt: '2026-10-02T03:21:00Z' },
            ] };
        } else throw new Error('Unknown fixture endpoint');
        return { ok: true, json: async () => data };
    };
    window.fixtureLanguage = () => {
        language = language === 'zh-CN' ? 'en-US' : 'zh-CN'; window.applyTranslations();
        document.dispatchEvent(new CustomEvent('languagechange'));
    };
    window.fixtureTheme = () => document.documentElement.setAttribute('data-theme', document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
    window.navigateToConversation = id => { document.getElementById('preview-notice').textContent = `只读模拟对话：${id}`; };
    window.showBatchImportModal = async () => { throw new Error('Task creation is unavailable in this read-only fixture'); };
    window.addEventListener('error', event => window.__fixtureErrors.push(event.message));
    document.addEventListener('DOMContentLoaded', () => {
        window.applyTranslations(); window.applyRBACToUI();
        if (options.page === 'targets') window.initTargetsPage(); else window.ExperienceMemory.refresh();
    });
}
function previewHtml(url) {
    const options = {
        page: url.searchParams.get('page') === 'targets' ? 'targets' : 'experience-memory',
        theme: url.searchParams.get('theme') === 'dark' ? 'dark' : 'light',
        lang: url.searchParams.get('lang') === 'en-US' ? 'en-US' : 'zh-CN',
        readOnly: url.searchParams.get('read') === '1', fail: url.searchParams.get('fail') === '1', empty: url.searchParams.get('empty') === '1', slow: url.searchParams.get('slow') === '1',
    };
    const serialize = value => JSON.stringify(value).replace(/</g, '\\u003c');
    const setup = setupFixture.toString().replace(/<\/script/gi, '<\\/script');
    return `<!doctype html><html lang="${options.lang}" data-theme="${options.theme}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>经验与目标 · 只读 UI 预览</title><link rel="stylesheet" href="/static/css/style.css"><link rel="stylesheet" href="/static/css/experience.css"><link rel="stylesheet" href="/static/css/targets.css"><style>
    .preview-sidebar { width:224px; flex-shrink:0; padding:24px 16px; border-right:1px solid var(--border-color); background:var(--bg-primary); color:var(--text-primary); }
    .preview-sidebar p { margin:16px 0; color:var(--text-secondary); font-size:12px; }.preview-sidebar a { display:block; margin:12px 0; color:var(--accent-color); }
    #preview-controls { padding:8px 16px; display:flex; gap:8px; flex-wrap:wrap; border-bottom:1px solid var(--border-color); background:var(--bg-primary); }#preview-controls button { font-size:12px; }#preview-notice { font-size:12px; color:var(--text-secondary); }
    @media(max-width:700px) { .preview-sidebar { display:none; } }
    </style><script>(${setup})(${serialize(resources)},${serialize(options)});</script></head><body><div class="container"><div id="preview-controls"><button type="button" class="btn-secondary" onclick="fixtureTheme()">切换深浅色</button><button type="button" class="btn-secondary" onclick="fixtureLanguage()">切换中英文</button><span id="preview-notice">本地只读模拟数据 · 不连接后端</span></div><div class="main-layout"><aside class="preview-sidebar"><strong>CyberStrikeAI</strong><p>只读前端验证 / UI fixture</p><a href="/?page=experience-memory&theme=${options.theme}&lang=${options.lang}&read=${options.readOnly ? 1 : 0}">经验记忆</a><a href="/?page=targets&theme=${options.theme}&lang=${options.lang}&read=${options.readOnly ? 1 : 0}">目标历史</a></aside><main class="content-area">${pages[options.page].replace('class="page"', 'class="page active"')}</main></div></div><script src="/static/js/experience.js"></script><script src="/static/js/targets.js"></script></body></html>`;
}
function startPreview(port = 18483) {
    const assets = new Set(['/static/css/style.css', '/static/css/experience.css', '/static/css/targets.css', '/static/js/experience.js', '/static/js/targets.js']);
    const server = http.createServer((request, response) => {
        const url = new URL(request.url, 'http://127.0.0.1');
        if (request.method !== 'GET') { response.writeHead(405); response.end('Read-only fixture'); return; }
        if (url.pathname === '/_close') { response.writeHead(204); response.end(); server.close(); server.closeAllConnections(); return; }
        if (url.pathname === '/') { response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }); response.end(previewHtml(url)); return; }
        if (assets.has(url.pathname)) {
            response.writeHead(200, { 'Content-Type': url.pathname.endsWith('.css') ? 'text/css; charset=utf-8' : 'text/javascript; charset=utf-8', 'Cache-Control': 'no-store' });
            response.end(fs.readFileSync(path.join(root, url.pathname.replace('/static/', '')))); return;
        }
        response.writeHead(404); response.end('Unknown fixture resource');
    });
    server.listen(port, '127.0.0.1', () => console.log(`Read-only UI preview: http://127.0.0.1:${server.address().port}`));
    return server;
}
if (require.main === module) startPreview();
module.exports = { startPreview, previewHtml };
