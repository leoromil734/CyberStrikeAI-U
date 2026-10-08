'use strict';
// Offline only: a deliberately non-HTML-parsing DOM and an in-memory API. No service is started.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const lab = require('./pi-lab.js');
const source = fs.readFileSync(path.join(__dirname, 'pi-lab.js'), 'utf8');
const indexHTML = fs.readFileSync(path.join(__dirname, '../../templates/index.html'), 'utf8');
const routerSource = fs.readFileSync(path.join(__dirname, 'router.js'), 'utf8');
const stylesheet = fs.readFileSync(path.join(__dirname, '../css/pi-lab.css'), 'utf8');

class Element {
    constructor(tag = 'div', namespace = '') {
        this.tagName = tag.toUpperCase(); this.namespaceURI = namespace; this.children = []; this.attributes = new Map();
        this.listeners = {}; this.style = {}; this._text = ''; this.className = ''; this.value = ''; this.checked = false;
        this.disabled = false; this.hidden = false; this.parentNode = null;
        this.classList = {
            contains: name => this.className.split(/\s+/).includes(name),
            add: (...names) => { names.forEach(name => this.classList.toggle(name, true)); },
            remove: (...names) => { names.forEach(name => this.classList.toggle(name, false)); },
            toggle: (name, force) => {
                const names = new Set(this.className.split(/\s+/).filter(Boolean));
                const enabled = force === undefined ? !names.has(name) : force;
                if (enabled) names.add(name); else names.delete(name);
                this.className = [...names].join(' '); return enabled;
            },
        };
    }
    set textContent(value) { this._text = String(value); this.children = []; }
    get textContent() { return this._text + this.children.map(child => child.textContent).join(''); }
    set innerHTML(_) { throw new Error('HTML injection sink must never be used'); }
    get innerHTML() { throw new Error('HTML serialization must never be used'); }
    insertAdjacentHTML() { throw new Error('HTML injection sink must never be used'); }
    appendChild(child) { child.parentNode = this; this.children.push(child); return child; }
    replaceChildren(...children) { this._text = ''; this.children = []; children.forEach(child => this.appendChild(child)); }
    setAttribute(name, value) { this.attributes.set(name, String(value)); if (name === 'class') this.className = String(value); }
    getAttribute(name) { return name === 'class' ? this.className : this.attributes.get(name) ?? null; }
    addEventListener(name, callback) { (this.listeners[name] ||= []).push(callback); }
    dispatch(name, props = {}) { return Promise.all((this.listeners[name] || []).map(callback => callback({ target: this, preventDefault() {}, ...props }))); }
    querySelectorAll() { return []; }
    focus() { this.focused = true; }
    scrollIntoView() { this.scrolled = true; }
    reportValidity() { return true; }
    reset() {}
    click() { this.clicked = true; }
    remove() { if (this.parentNode) this.parentNode.children = this.parentNode.children.filter(child => child !== this); }
}
const response = (data, status = 200) => ({ status, ok: status >= 200 && status < 300, json: async () => data });
const deferred = () => { let resolve; let reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const tick = () => new Promise(resolve => setImmediate(resolve));
const ready = { enabled: true, ready: true, reason: '', runtime: 'pi-native', isolation: 'application-only', tools: ['http_get', 'http_head'], limits: { max_parallel: 4, max_agents: 12, timeout_seconds: 1800, max_requests: 32 } };
const run = (id = 'r1', status = 'running', extra = {}) => ({ id, status, title: '试验 ' + id, prompt: '观察安全响应头', scope: ['https://example.test'], ai_channel: '', model: 'offline-fixture', created_at: '2026-10-08T00:00:00Z', updated_at: '2026-10-08T00:00:01Z', limits: ready.limits, agents: [], nodes: [], edges: [], findings: [], report: '', error: '', event_count: 0, ...extra });
const event = seq => ({ seq, time: '2026-10-08T00:00:01Z', type: 'agent.completed', agent_id: 'a1', data: { text: '最终文本 ' + seq } });
const profile = { available: true, reason: '', role: { name: '渗透测试', description: '平台已有测试角色' }, skills: [{ name: 'recon', description: '授权信息收集' }], tools: [{ name: 'platform_tool', description: '平台工具索引' }], limits: { max_parallel: 8, max_agents: 32, timeout_seconds: 21600, max_turns: 500, max_tool_calls: 2000 } };
const projects = [{ id: 'project-one', name: '已授权项目' }];
const input = (extra = {}) => ({ mode: 'probe', title: '新试验', prompt: '仅观察响应头', scope: 'https://example.test\nhttps://other.test:8443/', ai_channel: '', max_parallel: 2, max_agents: 4, timeout_seconds: 300, authorized: true, ...extra });
const platformInput = (extra = {}) => input({ mode: 'platform', project_id: 'project-one', title: '平台任务', prompt: '执行明确授权范围内的测试并记录证据', scope: 'http://127.0.0.1:8080/api/\n10.20.0.0/24 排除网关\n内部应用测试环境，禁止破坏性操作', max_parallel: 3, max_agents: 12, timeout_seconds: 3600, max_turns: 120, max_tool_calls: 600, ...extra });

function fixture(options = {}) {
    const elements = new Map(); const created = []; const calls = []; const timers = new Map(); const blobs = []; const revoked = [];
    let nextTimer = 0; let owner = 'owner-one'; let permitted = options.permitted !== false; let implementation = options.fetch;
    for (const match of indexHTML.matchAll(/<([a-z0-9]+)\b[^>]*\bid="(pi-lab-[^"]+|page-pi-lab)"[^>]*>/g)) {
        const node = new Element(match[1]); node.id = match[2]; elements.set(node.id, node);
    }
    elements.get('page-pi-lab').className = 'page active';
    const body = new Element('body');
    const document = {
        body, getElementById: id => elements.get(id) || null,
        createElement: tag => { const node = new Element(tag); created.push(node); return node; },
        createElementNS: (ns, tag) => { const node = new Element(tag, ns); created.push(node); return node; },
    };
    elements.get('pi-lab-form').reset = () => {
        ['title', 'scope', 'prompt', 'channel', 'project'].forEach(id => { elements.get('pi-lab-' + id).value = ''; });
        elements.get('pi-lab-mode').value = 'platform';
        elements.get('pi-lab-authorized').checked = false;
        elements.get('pi-lab-parallel').value = '3'; elements.get('pi-lab-max-agents').value = '12'; elements.get('pi-lab-timeout').value = '3600';
        elements.get('pi-lab-max-turns').value = '120'; elements.get('pi-lab-max-tool-calls').value = '600';
    };
    const fallback = url => {
        if (url === '/api/pi-lab/status') return response(options.status || ready);
        if (url === '/api/pi-lab/profile') return response(options.profile || profile);
        if (url === '/api/projects?status=active&limit=500') return response({ projects: options.projects || projects });
        if (url === '/api/config/ai-channels') return response({ default_channel: 'one', channels: { one: { name: '主模型', model: 'offline-fixture' } } });
        if (url === '/api/pi-lab/runs') return response({ runs: options.runs || [] });
        if (url.includes('/events?')) return response({ events: [], cursor: Number(url.split('after=')[1]), has_more: false });
        if (url.startsWith('/api/pi-lab/runs/')) return response((options.runs || []).find(item => item.id === decodeURIComponent(url.split('/').pop())) || run(decodeURIComponent(url.split('/').pop())));
        throw new Error('Unexpected endpoint: ' + url);
    };
    const env = {
        document, hasPermission: () => permitted, getOwner: () => owner, ensureAuthenticated: options.ensureAuthenticated || (async () => true),
        apiFetch: async (url, opts) => {
            assert.match(url, /^\/api\/(pi-lab\/(?:status|profile|runs(?:\/[^/]+(?:\/cancel|\/events\?after=\d+)?)?)|config\/ai-channels|projects\?status=active&limit=500)$/);
            calls.push([url, opts]); return implementation ? implementation(url, opts, fallback) : fallback(url);
        },
        AbortController, Blob,
        URL: { createObjectURL(blob) { blobs.push(blob); return 'blob:offline-download'; }, revokeObjectURL(url) { revoked.push(url); } },
        setTimeout(callback, delay) { const id = ++nextTimer; timers.set(id, { callback, delay }); return id; },
        clearTimeout(id) { timers.delete(id); },
    };
    const controller = lab.createController(env);
    return { controller, env, document, elements, created, calls, timers, blobs, revoked,
        el: id => elements.get('pi-lab-' + id),
        state: () => controller.getSnapshot(),
        setFetch: fn => { implementation = fn; }, setOwner: value => { owner = value; }, setPermission: value => { permitted = value; },
        async fireTimer() { const [id, timer] = timers.entries().next().value; timers.delete(id); timer.callback(); await tick(); },
    };
}

test('page, navigation, permission extension, CSS and lifecycle are registered without touching auth.js', () => {
    assert.match(indexHTML, /id="page-pi-lab" class="page" data-require-permission="agent:execute"/);
    assert.match(indexHTML, /data-page="pi-lab" data-require-permission="agent:execute"/);
    assert.match(indexHTML, /\/static\/js\/pi-lab\.js\?v=/);
    assert.match(indexHTML, /\/static\/css\/pi-lab\.css\?v=/);
    assert.equal((routerSource.match(/'agents-management', 'pi-lab', 'settings'/g) || []).length, 2);
    assert.match(routerSource, /currentPage === 'pi-lab'[\s\S]*?window\.PiLab\.stop\(\)/);
    assert.match(routerSource, /case 'pi-lab':[\s\S]*?currentPage === pageId[\s\S]*?window\.PiLab\.init\(\)/);
    assert.match(stylesheet, /html\[data-theme="dark"\] #page-pi-lab/);
    assert.match(stylesheet, /@media \(max-width: 600px\)/);
    const ids = [...indexHTML.matchAll(/id="(pi-lab-[^"]+|page-pi-lab)"/g)].map(match => match[1]);
    assert.equal(ids.length, new Set(ids).size);
    const f = fixture(); const context = { document: f.document, setTimeout, clearTimeout, AbortController, URL, Blob, addEventListener() {} };
    context.window = context; vm.createContext(context);
    vm.runInContext('const PAGE_PERMISSION_MAP = {};', context);
    vm.runInContext(source, context);
    assert.equal(vm.runInContext('PAGE_PERMISSION_MAP["pi-lab"]', context), 'agent:execute');
    assert.ok(context.PiLab);
    assert.doesNotMatch(source, /innerHTML|insertAdjacentHTML|document\.write|\beval\s*\(/);
    assert.doesNotMatch(source, /\/api\/(tasks|batch|config['"]|mcp|conversations)/);
});

test('router stops PI immediately and ignores PI init delayed by i18n after navigation away', async () => {
    const wait = deferred(); const pi = new Element(); const dashboard = new Element();
    let initialized = 0; let stopped = 0;
    const context = {
        document: { getElementById: id => ({ 'page-pi-lab': pi, 'page-dashboard': dashboard })[id], querySelectorAll: selector => selector === '.page' ? [pi, dashboard] : [], querySelector: () => null, addEventListener() {} },
        location: { hash: '' }, history: { replaceState() {} }, addEventListener() {}, i18nReady: wait.promise,
        PiLab: { init() { initialized++; }, stop() { stopped++; } },
    };
    context.window = context; vm.createContext(context); vm.runInContext(routerSource, context);
    context.switchPage('pi-lab'); context.switchPage('dashboard');
    assert.equal(stopped, 1); assert.equal(initialized, 0);
    wait.resolve(); await tick(); assert.equal(initialized, 0);
    context.switchPage('pi-lab'); await tick(); assert.equal(initialized, 1);
    context.switchPage('pi-lab'); await tick(); assert.equal(initialized, 1);
});

test('scope accepts exact HTTP(S) origins, normalizes only authority and deduplicates', () => {
    assert.deepEqual(lab.parseScope(' https://EXAMPLE.test:443/ \nhttps://example.test\nhttp://[::1]:8080'), ['https://example.test', 'http://[::1]:8080']);
    for (const value of ['', 'example.test', '//example.test', 'file:///tmp', 'javascript:alert(1)', 'https://*.test', 'https://user:pass@example.test', 'https://example.test/path', 'https://example.test/a/..', 'https://example.test?', 'https://example.test#', 'https://example.test/\n/path', 'https://example.test\\@bad.test', 'https://exa\tmple.test', 'https://example.test\u0000']) {
        assert.throws(() => lab.parseScope(value), undefined, value);
    }
});

test('links reject active schemes, relative addresses, controls and credentials', () => {
    for (const value of ['javascript:alert(1)', 'data:text/html,hi', 'vbscript:alert(1)', '/local', '//evil.test', ' https://example.test', 'https://user:pass@example.test', 'https://example.test\\evil', 'https://example.test\n/a', null, {}]) assert.equal(lab.safeURL(value), '');
    assert.equal(lab.safeURL('https://example.test/a?x=%22'), 'https://example.test/a?x=%22');
    assert.equal(lab.safeURL('http://example.test:8080'), 'http://example.test:8080/');
});

test('creation enforces backend text and scope budgets', () => {
    assert.throws(() => lab.buildPayload(input({ title: '题'.repeat(121) }), ready), /120/);
    assert.throws(() => lab.buildPayload(input({ prompt: '中'.repeat(6000) }), ready), /16 KiB/);
    assert.throws(() => lab.buildPayload(input({ scope: Array.from({ length: 21 }, (_, i) => `https://s${i}.example.test`).join('\n') }), ready), /20/);
});

test('routine event polling does not repeatedly spawn runtime readiness checks', async () => {
    const f = fixture({ runs: [run()] });
    await f.controller.init();
    await f.controller.refresh(false);
    await f.controller.refresh(false);
    assert.equal(f.calls.filter(([url]) => url === '/api/pi-lab/status').length, 1);
    await f.controller.refresh(true);
    assert.equal(f.calls.filter(([url]) => url === '/api/pi-lab/status').length, 2);
    f.controller.stop();
});

test('creation validates authorization, numeric bounds, server limits and readiness', () => {
    assert.deepEqual(lab.buildPayload(input(), ready), { mode: 'probe', title: '新试验', prompt: '仅观察响应头', scope: ['https://example.test', 'https://other.test:8443'], ai_channel: '', authorized: true, max_parallel: 2, max_agents: 4, timeout_seconds: 300 });
    for (const extra of [{ authorized: false }, { authorized: 'true' }, { title: ' ' }, { prompt: '' }, { max_parallel: 0 }, { max_parallel: 5 }, { max_agents: 13 }, { max_agents: 1 }, { timeout_seconds: 59 }, { timeout_seconds: 1801 }, { max_parallel: 1.5 }, { max_agents: NaN }]) assert.throws(() => lab.buildPayload(input(extra), ready));
    assert.throws(() => lab.buildPayload(input(), { ...ready, enabled: false }));
    assert.throws(() => lab.buildPayload(input(), { ...ready, ready: false }));
    assert.throws(() => lab.buildPayload(input(), { ...ready, limits: { ...ready.limits, max_parallel: 1 } }));
    assert.equal(lab.buildPayload(input({ max_parallel: 1 }), { ...ready, limits: { ...ready.limits, max_parallel: 1 } }).max_parallel, 1);
});

test('event merge is monotonic, ordered and deduplicated; stalled pagination fails safely', () => {
    const result = lab.mergeEventPage([event(1), event(3)], 3, { events: [event(4), event(3), event(2)], cursor: 2, has_more: true });
    assert.deepEqual(result.events.map(item => item.seq), [1, 2, 3, 4]); assert.equal(result.cursor, 4); assert.equal(result.hasMore, true);
    assert.throws(() => lab.mergeEventPage([], 8, { events: [], cursor: 8, has_more: true }), /没有前进/);
    assert.throws(() => lab.mergeEventPage([], 0, { events: [{ seq: '1' }], cursor: 1, has_more: false }), /序号/);
    assert.throws(() => lab.mergeEventPage([], 0, { events: [], cursor: '1', has_more: false }), /格式/);
});

test('disabled or unconfigured runtime shows the reason, forbids creation and keeps historical detail readable', async () => {
    for (const status of [{ ...ready, enabled: false, ready: false, reason: '默认关闭：尚未启用实验' }, { ...ready, ready: false, reason: '原生 PI 运行时路径未配置' }]) {
        const f = fixture({ status, runs: [run('history', 'completed', { report: '保留的纯文本报告' })] });
        await f.controller.init();
        f.el('authorized').checked = true; await f.el('authorized').dispatch('change');
        assert.equal(f.el('submit').disabled, true); assert.ok(f.el('runtime-status').textContent.includes(status.reason));
        assert.equal(f.state().run.id, 'history'); assert.equal(f.el('report').textContent, '保留的纯文本报告');
        await f.controller.createRun(input()); assert.equal(f.calls.filter(([, opts]) => opts.method === 'POST').length, 0);
        assert.equal(f.el('export').disabled, false); f.controller.stop(); assert.equal(f.timers.size, 0);
    }
});

test('status failure and channel-list failure remain read-only recoverable with a default channel', async () => {
    let fail = true;
    const f = fixture({ runs: [run('history', 'completed')], fetch: (url, opts, fallback) => fail && (url.endsWith('/status') || url.endsWith('/ai-channels')) ? response({ error: '未配置 / 权限不足' }, 503) : fallback(url) });
    await f.controller.init();
    assert.equal(f.el('submit').disabled, true); assert.match(f.el('runtime-status').textContent, /无法读取 PI 状态/);
    assert.equal(f.el('channel').children.length, 1); assert.equal(f.el('channel').children[0].value, ''); assert.match(f.el('channel-hint').textContent, /默认模型/);
    assert.equal(f.state().run.id, 'history');
    fail = false; await f.controller.refresh(true);
    f.controller.setProject('project-one');
    f.el('authorized').checked = true; await f.el('authorized').dispatch('change');
    assert.equal(f.el('submit').disabled, false); assert.equal(f.el('channel').children.length, 2);
});

test('no-permission direct entry, actions and export cannot call any API', async () => {
    const f = fixture({ permitted: false }); await f.controller.init();
    await f.controller.createRun(input()); await f.controller.cancelRun(); f.controller.exportRun();
    assert.equal(f.calls.length, 0); assert.equal(f.timers.size, 0); assert.match(f.el('runtime-status').textContent, /agent:execute/);
});

test('initialization is idempotent, events paginate incrementally, and complete Run snapshots refresh even with no new event', async () => {
    let version = 1;
    const f = fixture({ runs: [run()], fetch: (url, opts, fallback) => {
        if (url === '/api/pi-lab/runs/r1') return response(run('r1', version === 1 ? 'running' : 'partial', { report: '报告版本 ' + version, findings: version === 1 ? [] : [{ id: 'f1', title: '观察', status: 'observed' }] }));
        if (url.endsWith('after=0')) return response({ events: [event(1), event(2)], cursor: 2, has_more: true });
        if (url.endsWith('after=2')) return response({ events: [event(2), event(3)], cursor: 3, has_more: false });
        return fallback(url);
    } });
    const first = f.controller.init(); const second = f.controller.init(); await Promise.all([first, second]);
    assert.equal(f.calls.filter(([url]) => url === '/api/pi-lab/status').length, 1);
    assert.deepEqual(f.state().events.map(item => item.seq), [1, 2, 3]); assert.equal(f.state().cursor, 3);
    assert.equal(f.el('form').listeners.submit.length, 1); assert.equal(f.timers.size, 1);
    assert.equal([...f.timers.values()][0].delay, 2000);
    version = 2; await f.controller.refresh();
    assert.equal(f.state().run.status, 'partial'); assert.equal(f.el('report').textContent, '报告版本 2'); assert.equal(f.el('observed-count').textContent, '1');
    assert.equal(f.calls.at(-1)[0], '/api/pi-lab/runs/r1/events?after=3'); assert.equal(f.timers.size, 1);
    assert.equal(f.calls.filter(([url]) => url.endsWith('/ai-channels')).length, 1);
});

test('slow polling is single-flight and leaving aborts requests, clears timers and suppresses stale responses', async () => {
    const wait = deferred(); let hold = false;
    const f = fixture({ runs: [run()], fetch: (url, opts, fallback) => hold && url === '/api/pi-lab/runs' ? wait.promise : fallback(url) });
    await f.controller.init(); hold = true;
    const first = f.controller.refresh(); const count = f.calls.length; const second = f.controller.refresh();
    assert.equal(f.calls.length, count); assert.equal(first, second); assert.equal(f.timers.size, 0);
    const pending = f.calls.at(-1)[1].signal;
    f.controller.stop(); assert.equal(pending.aborted, true); assert.equal(f.timers.size, 0);
    const before = f.state(); wait.resolve(response({ runs: [run('stale', 'completed', { title: '过期数据' })] })); await first;
    assert.deepEqual(f.state(), before); assert.equal(f.timers.size, 0); assert.doesNotMatch(f.el('runtime-status').textContent, /过期数据/);
    hold = false; await f.controller.init(); assert.equal(f.timers.size, 1); assert.equal(f.el('form').listeners.submit.length, 1);
});

test('page exit while waiting for authentication makes late initialization inert', async () => {
    const wait = deferred(); const f = fixture({ ensureAuthenticated: () => wait.promise });
    const init = f.controller.init(); f.controller.stop(); wait.resolve(true); await init;
    assert.equal(f.calls.length, 0); assert.equal(f.timers.size, 0);
});

test('selecting a run resets event cursor and ignores a previous run response even if the transport ignores abort', async () => {
    const wait = deferred(); let hold = false;
    const f = fixture({ runs: [run('r1'), run('r2')], fetch: (url, opts, fallback) => {
        if (hold && url === '/api/pi-lab/runs/r1') return wait.promise;
        if (url.includes('/events?')) return response({ events: [event(url.includes('/r1/') ? 5 : 1)], cursor: url.includes('/r1/') ? 5 : 1, has_more: false });
        return fallback(url);
    } });
    await f.controller.init(); assert.equal(f.state().cursor, 5);
    hold = true; const old = f.controller.refresh(); await tick();
    await f.controller.selectRun('r2');
    assert.equal(f.state().cursor, 1); assert.equal(f.state().run.id, 'r2'); assert.deepEqual(f.state().events.map(item => item.seq), [1]);
    assert.ok(f.calls.some(([url]) => url === '/api/pi-lab/runs/r2/events?after=0'));
    wait.resolve(response(run('r1', 'failed', { report: '过期报告' }))); await old;
    assert.equal(f.state().run.id, 'r2'); assert.doesNotMatch(f.el('report').textContent, /过期报告/); assert.equal(f.timers.size, 1);
    await f.controller.selectRun('r2'); assert.equal(f.calls.at(-1)[0], '/api/pi-lab/runs/r2/events?after=0');
});

test('returning to the page resumes the selected run with the retained cursor', async () => {
    const f = fixture({ runs: [run()], fetch: (url, opts, fallback) => url.endsWith('after=0') ? response({ events: [event(1)], cursor: 1, has_more: false }) : fallback(url) });
    await f.controller.init(); f.controller.stop(); await f.controller.init();
    assert.equal(f.calls.at(-1)[0], '/api/pi-lab/runs/r1/events?after=1'); assert.equal(f.state().events.length, 1); assert.equal(f.timers.size, 1);
});

test('event failures do not block full state refresh and a stalled cursor does not cause a tight loop', async () => {
    let error = true;
    const f = fixture({ runs: [run()], fetch: (url, opts, fallback) => {
        if (url.includes('/events?')) return error ? response({ error: '事件暂不可用' }, 503) : response({ events: [], cursor: 0, has_more: true });
        if (url === '/api/pi-lab/runs/r1') return response(run('r1', 'running', { report: error ? '版本一' : '版本二' }));
        return fallback(url);
    } });
    await f.controller.init(); assert.match(f.el('event-error').textContent, /事件暂不可用/); assert.equal(f.el('report').textContent, '版本一');
    error = false; await f.controller.refresh(); assert.match(f.el('event-error').textContent, /没有前进/);
    assert.equal(f.el('report').textContent, '版本二'); assert.equal([...f.timers.values()][0].delay, 2000);
});

test('large event histories are drained in bounded bursts without losing sequence numbers', async () => {
    const f = fixture({ runs: [run()], fetch: (url, opts, fallback) => {
        if (!url.includes('/events?')) return fallback(url);
        const next = Number(url.split('after=')[1]) + 1;
        return response({ events: [event(next)], cursor: next, has_more: next < 10 });
    } });
    await f.controller.init(); assert.equal(f.state().events.length, 8); assert.equal([...f.timers.values()][0].delay, 100);
    await f.fireTimer(); assert.equal(f.state().events.length, 10); assert.equal(f.state().cursor, 10); assert.equal(f.state().hasMore, false);
});

test('missing or forbidden detail clears stale report and events while showing an explicit error', async () => {
    let forbidden = false;
    const f = fixture({ runs: [run()], fetch: (url, opts, fallback) => forbidden && url === '/api/pi-lab/runs/r1' ? response({ error: '仅属主可见' }, 403) : fallback(url) });
    await f.controller.init(); forbidden = true; await f.controller.refresh();
    assert.equal(f.state().run, null); assert.equal(f.state().events.length, 0); assert.equal(f.el('export').disabled, true);
    assert.match(f.el('run-error').textContent, /仅属主可见/); assert.match(f.el('graph').textContent, /选择一个任务/);
});

test('all server text is rendered as text nodes, SVG has no untrusted markup, and URL links use noopener', async () => {
    const attack = '<img src=x onerror="globalThis.pwned=1"><script>bad()</script>';
    const unsafe = run('r1', attack, {
        title: attack, prompt: attack, model: attack, report: attack, error: attack,
        agents: [{ id: attack, role: attack, parent_id: '', task: attack, summary: attack, status: attack }],
        nodes: [{ id: 'n1', label: attack, detail: attack, kind: attack, status: attack, url: 'javascript:bad()' }, { id: 'n2', label: attack, url: 'https://example.test/safe', parent_id: 'n1' }],
        edges: [{ id: attack, source: 'n1', target: 'n2', label: attack }],
        findings: [{ id: attack, title: attack, status: 'hypothesis', severity: attack, evidence: attack, remediation: attack, url: 'data:text/html,<script>bad()</script>' }, { id: 'f2', title: attack, status: 'observed', url: 'https://example.test/safe' }],
    });
    const f = fixture({ runs: [unsafe], status: { ...ready, reason: attack, runtime: attack, isolation: attack, tools: [attack] }, fetch: (url, opts, fallback) => url.includes('/events?') ? response({ events: [{ ...event(1), type: attack, agent_id: attack, data: { text: attack } }], cursor: 1, has_more: false }) : fallback(url) });
    await f.controller.init();
    assert.equal(f.el('report').textContent, attack); assert.ok(f.el('runs').textContent.includes(attack)); assert.ok(f.el('agents').textContent.includes(attack));
    assert.ok(f.el('graph').textContent.includes(attack)); assert.ok(f.el('findings').textContent.includes(attack)); assert.ok(f.el('events').textContent.includes(attack));
    const groups = f.created.filter(node => node.tagName === 'G'); await groups[0].dispatch('click');
    assert.ok(f.el('node-detail').textContent.includes(attack)); assert.match(f.el('node-detail').textContent, /不可打开的地址/);
    assert.ok(!f.created.some(node => ['IMG', 'SCRIPT', 'IFRAME', 'FOREIGNOBJECT'].includes(node.tagName)));
    for (const node of f.created) {
        for (const key of node.attributes.keys()) assert.ok(!/^on/i.test(key), key);
        if (node.namespaceURI) assert.equal(node.getAttribute('href'), null);
        if (node.tagName === 'A') { assert.match(node.href, /^https?:\/\//); assert.equal(node.target, '_blank'); assert.equal(node.rel, 'noopener noreferrer'); }
    }
    assert.match(f.el('findings').textContent, /候选（hypothesis）/); assert.match(f.el('findings').textContent, /观察（observed）/); assert.match(f.el('findings').textContent, /不是已确认漏洞/);
});

test('agent and route cycles, orphan relationships and unknown finding states remain visible', async () => {
    const value = run('r1', 'interrupted', {
        nodes: [{ id: 'a', parent_id: 'b', label: 'A' }, { id: 'b', parent_id: 'a', label: 'B' }, { id: 'c', parent_id: 'missing', label: 'C' }],
        edges: [{ source: 'a', target: 'b', label: '关联' }, { source: 'b', target: 'a' }, { source: 'missing', target: 'a' }],
        agents: [{ id: 'a', parent_id: 'b', role: 'A' }, { id: 'b', parent_id: 'a', role: 'B' }, { id: 'c', parent_id: 'missing', role: 'C' }],
        findings: [{ id: 'unknown', status: 'confirmed', title: '不可信状态' }],
    });
    const f = fixture({ runs: [value] }); await f.controller.init();
    assert.equal(lab.graphLayout(value.nodes, value.edges).points.size, 3); assert.equal(f.el('agents').children.length, 3);
    assert.match(f.el('findings').textContent, /未分类结果/); assert.match(f.el('findings').textContent, /不能作为已确认漏洞/);
    assert.equal(f.el('observed-count').textContent, '0');
});

test('creation sends only the agreed payload, prevents duplicate POSTs and polls the accepted Run', async () => {
    const wait = deferred(); let accepted = false;
    const f = fixture({ fetch: (url, opts, fallback) => {
        if (url === '/api/pi-lab/runs' && opts.method === 'POST') return wait.promise;
        if (url === '/api/pi-lab/runs') return response({ runs: accepted ? [run('created', 'queued')] : [] });
        return fallback(url);
    } });
    await f.controller.init();
    const first = f.controller.createRun(input()); await f.controller.createRun(input());
    assert.equal(f.calls.filter(([, opts]) => opts.method === 'POST').length, 1); assert.equal(f.el('submit').disabled, true);
    const post = f.calls.find(([, opts]) => opts.method === 'POST');
    assert.deepEqual(JSON.parse(post[1].body), lab.buildPayload(input(), ready)); assert.equal(post[1].headers['Content-Type'], 'application/json');
    accepted = true; wait.resolve(response(run('created', 'queued'), 202)); await first; await tick();
    assert.equal(f.state().selectedId, 'created'); assert.equal(f.state().run.id, 'created'); assert.equal(f.el('authorized').checked, false);
    assert.ok(f.calls.some(([url]) => url === '/api/pi-lab/runs/created/events?after=0')); assert.equal(f.timers.size, 1);
});

test('failed POST preserves input and surfaces uncertainty instead of automatically retrying', async () => {
    const f = fixture({ fetch: (url, opts, fallback) => opts.method === 'POST' ? Promise.reject(new Error('离线网络错误')) : fallback(url) });
    await f.controller.init(); f.el('title').value = '保持草稿'; await f.controller.createRun(input()); await tick();
    assert.equal(f.el('title').value, '保持草稿'); assert.match(f.el('form-error').textContent, /先刷新历史确认/);
    assert.equal(f.calls.filter(([, opts]) => opts.method === 'POST').length, 1);
});

test('cancel uses an encoded ID, invalidates older reads and renders the returned terminal state', async () => {
    const id = 'run/with?special'; let cancelled = false;
    const f = fixture({ runs: [run(id)], fetch: (url, opts, fallback) => {
        if (url.endsWith('/cancel')) { cancelled = true; return response(run(id, 'cancelled')); }
        if (url === '/api/pi-lab/runs/' + encodeURIComponent(id)) return response(run(id, cancelled ? 'cancelled' : 'running'));
        return fallback(url);
    } });
    await f.controller.init(); await f.controller.cancelRun(); await tick();
    const post = f.calls.find(([, opts]) => opts.method === 'POST'); assert.equal(post[0], '/api/pi-lab/runs/' + encodeURIComponent(id) + '/cancel');
    assert.equal(f.state().run.status, 'cancelled'); assert.equal(f.el('cancel').disabled, true);
    await f.controller.cancelRun(); assert.equal(f.calls.filter(([, opts]) => opts.method === 'POST').length, 1);
});

test('channels project only ID/name/model and JSON export uses local state without any endpoint', async () => {
    const channel = { name: '安全模型', model: 'model-only' };
    Object.defineProperty(channel, 'api_key', { enumerable: true, get() { throw new Error('must never access credentials'); } });
    const value = run('r1', 'completed', { unrelated_configuration: 'do-not-export' });
    const f = fixture({ runs: [value], fetch: (url, opts, fallback) => url.endsWith('/ai-channels') ? response({ default_channel: 'one', channels: { one: channel } }) : fallback(url) });
    await f.controller.init();
    assert.deepEqual(f.state().channels, [{ id: 'one', name: '安全模型', model: 'model-only' }]);
    const calls = f.calls.length; f.controller.exportRun(); assert.equal(f.calls.length, calls); assert.equal(f.blobs.length, 1);
    const exported = JSON.parse(await f.blobs[0].text()); assert.equal(exported.run.id, 'r1'); assert.equal(exported.run.unrelated_configuration, undefined);
    assert.equal(exported.schema_version, 1); assert.equal(exported.cursor, 0); assert.match(exported.note, /不保证/);
    f.controller.stop(); assert.equal(f.timers.size, 1); await f.fireTimer(); assert.deepEqual(f.revoked, ['blob:offline-download']);
});

test('late event pages cannot leak into a newly selected run', async () => {
    const wait = deferred(); let hold = false;
    const f = fixture({ runs: [run('r1'), run('r2')], fetch: (url, opts, fallback) => hold && url.includes('/r1/events?') ? wait.promise : fallback(url) });
    await f.controller.init(); hold = true; const old = f.controller.refresh(); await tick();
    assert.ok(f.calls.at(-1)[0].includes('/r1/events?'));
    await f.controller.selectRun('r2');
    wait.resolve(response({ events: [{ ...event(99), data: { text: '旧试验的私有事件' } }], cursor: 99, has_more: false })); await old;
    assert.equal(f.state().run.id, 'r2'); assert.equal(f.state().cursor, 0); assert.equal(f.state().events.length, 0);
    assert.doesNotMatch(f.el('events').textContent, /旧试验/); assert.equal(f.timers.size, 1);
});

test('late cancellation response cannot replace another run selected during the mutation', async () => {
    const wait = deferred();
    const f = fixture({ runs: [run('r1'), run('r2')], fetch: (url, opts, fallback) => url.endsWith('/cancel') ? wait.promise : fallback(url) });
    await f.controller.init(); const cancel = f.controller.cancelRun();
    await f.controller.selectRun('r2'); assert.equal(f.state().selectedId, 'r2');
    wait.resolve(response(run('r1', 'cancelled', { report: '旧取消响应' }))); await cancel; await tick();
    assert.equal(f.state().run.id, 'r2'); assert.equal(f.state().run.status, 'running');
    assert.doesNotMatch(f.el('report').textContent, /旧取消响应/); assert.equal(f.timers.size, 1);
});

test('leaving during creation cannot reactivate polling when a late POST resolves', async () => {
    const wait = deferred();
    const f = fixture({ fetch: (url, opts, fallback) => opts.method === 'POST' ? wait.promise : fallback(url) });
    await f.controller.init(); const create = f.controller.createRun(input());
    const post = f.calls.at(-1); f.controller.stop(); assert.equal(post[1].signal.aborted, true);
    const count = f.calls.length; wait.resolve(response(run('late-created', 'queued'), 202)); await create; await tick();
    assert.equal(f.calls.length, count); assert.equal(f.state().run, null); assert.equal(f.timers.size, 0);
});

test('failed lists have a distinct retryable error and do not masquerade as empty history', async () => {
    let broken = true;
    const f = fixture({ fetch: (url, opts, fallback) => broken && url === '/api/pi-lab/runs' ? response({ error: '历史存储暂不可用' }, 503) : fallback(url) });
    await f.controller.init(); assert.match(f.el('list-error').textContent, /历史存储暂不可用/);
    assert.match(f.el('runs').textContent, /无可用历史列表/); assert.equal(f.state().run, null);
    broken = false; await f.controller.refresh(); assert.equal(f.el('list-error').hidden, true); assert.match(f.el('runs').textContent, /暂无 PI 任务/);
});

test('changing owner before re-entry clears cached history before awaiting authentication', async () => {
    const f = fixture({ runs: [run('private-run')] }); await f.controller.init(); f.controller.stop();
    const wait = deferred(); f.env.ensureAuthenticated = () => wait.promise; f.setOwner('different-owner');
    f.setFetch((url, opts, fallback) => url === '/api/pi-lab/runs' ? response({ runs: [] }) : fallback(url));
    const init = f.controller.init();
    assert.equal(f.state().run, null); assert.equal(f.state().runs.length, 0); assert.doesNotMatch(f.el('runs').textContent, /private-run/);
    wait.resolve(); await init; assert.equal(f.state().run, null);
});

test('authentication failure on re-entry cannot leave a previously enabled submit button active', async () => {
    const f = fixture(); await f.controller.init(); f.controller.setProject('project-one'); f.el('authorized').checked = true; await f.el('authorized').dispatch('change');
    assert.equal(f.el('submit').disabled, false); f.controller.stop();
    f.env.ensureAuthenticated = async () => { throw new Error('登录校验失败'); }; await f.controller.init();
    assert.equal(f.state().status, null); assert.equal(f.el('submit').disabled, true); assert.match(f.el('runtime-status').textContent, /登录校验失败/);
});

test('platform creation requires profile and project, preserves descriptive private scopes and allowlists its payload', () => {
    const source = platformInput({ role: 'ignored-client-role', skills: ['ignored'], execution_ids: ['ignored'] });
    assert.deepEqual(lab.buildPayload(source, ready, profile, projects), {
        mode: 'platform', project_id: 'project-one', role: '渗透测试', title: source.title, prompt: source.prompt,
        scope: ['http://127.0.0.1:8080/api/', '10.20.0.0/24 排除网关', '内部应用测试环境，禁止破坏性操作'],
        ai_channel: '', max_parallel: 3, max_agents: 12, timeout_seconds: 3600, max_turns: 120, max_tool_calls: 600, authorized: true,
    });
    assert.equal(lab.buildPayload(platformInput({ mode: undefined }), ready, profile, projects).mode, 'platform');
    assert.equal(lab.buildPayload(source, { ...ready, platform_available: false }, profile, projects).mode, 'platform');
    assert.throws(() => lab.buildPayload(source, { ...ready, platform_available: true }, null, projects), /能力配置/);
    assert.throws(() => lab.buildPayload(source, ready, { ...profile, available: false, reason: '角色不可用' }, projects), /角色不可用/);
    assert.throws(() => lab.buildPayload(source, ready, { ...profile, role: { name: '其他角色' } }, projects), /渗透测试/);
    for (const project_id of ['', undefined, {}, ' ', '/unsafe', 'unknown']) assert.throws(() => lab.buildPayload(platformInput({ project_id }), ready, profile, projects), /项目/);
    for (const mode of ['unknown', '__proto__']) assert.throws(() => lab.buildPayload(platformInput({ mode }), ready, profile, projects), /模式/);
});

test('platform budgets enforce five integer limits, UTF-8 input sizes and twenty descriptive scope lines', () => {
    for (const extra of [{ max_parallel: 9 }, { max_agents: 33 }, { timeout_seconds: 21601 }, { max_turns: 501 }, { max_tool_calls: 2001 }, { max_turns: 0 }, { max_tool_calls: -1 }, { max_tool_calls: 2.5 }, { max_agents: 2 }, { timeout_seconds: 59 }, { max_turns: NaN }, { authorized: false }, { title: '题'.repeat(121) }, { prompt: '文'.repeat(5462) }, { scope: ' \n ' }, { scope: Array(21).fill('内网测试环境').join('\n') }]) {
        assert.throws(() => lab.buildPayload(platformInput(extra), ready, profile, projects), undefined, JSON.stringify(extra));
    }
    const maximum = lab.buildPayload(platformInput({ ...profile.limits, title: '题'.repeat(120), prompt: 'x'.repeat(16384), scope: Array(20).fill('10.0.0.0/8 明确授权且排除生产').join('\n') }), ready, profile, projects);
    assert.equal(maximum.scope.length, 20); assert.equal(maximum.max_turns, 500); assert.equal(maximum.max_tool_calls, 2000);
    assert.throws(() => lab.buildPayload(platformInput(), ready, { ...profile, limits: { ...profile.limits, max_turns: 100 } }, projects), /模型轮次/);
    assert.deepEqual(lab.parsePlatformScope('  http://[::1]:8080/path?q=1 \r\n \n10.1.0.0/16\n仅指定内部应用'), ['http://[::1]:8080/path?q=1', '10.1.0.0/16', '仅指定内部应用']);
    assert.throws(() => lab.buildPayload(input({ scope: 'http://127.0.0.1/api/' }), ready), /origin/);
});

test('profile HTTP 403 reason is visible in capability and submit errors without enabling platform creation', async () => {
    const reason = '缺少 project:read、tool:execute 权限';
    const f = fixture({ fetch: (url, opts, fallback) => url.endsWith('/profile') ? response({ available: false, reason }, 403) : fallback(url) });
    await f.controller.init(); f.controller.setProject('project-one');
    f.el('authorized').checked = true; await f.el('authorized').dispatch('change');
    assert.equal(f.state().profile, null); assert.equal(f.el('submit').disabled, true);
    assert.equal(f.state().errors.profile, 'HTTP 403：' + reason);
    assert.ok(f.el('profile-status').textContent.includes(reason));
    await f.controller.createRun(platformInput());
    assert.ok(f.el('form-error').textContent.includes(reason));
    assert.equal(f.calls.filter(([, opts]) => opts.method === 'POST').length, 0);
    f.controller.stop();
});

test('profile errors fail closed without implicit fallback, while explicit probe mode remains usable', async () => {
    const failures = [response({ error: '无 profile 权限' }, 403), response({ error: '尚未部署 profile' }, 404), response({ available: false, reason: '平台工具未配置' }), response({ available: 'true' })];
    for (const failure of failures) {
        const f = fixture({ status: { ...ready, platform_available: true }, runs: [run('old', 'failed')], fetch: (url, opts, fallback) => {
            if (url.endsWith('/profile')) return failure;
            if (opts.method === 'POST') return response(run('probe-created', 'queued', { mode: 'probe' }), 202);
            return fallback(url);
        } });
        await f.controller.init(); f.controller.setProject('project-one');
        f.el('authorized').checked = true; await f.el('authorized').dispatch('change');
        assert.equal(f.state().mode, 'platform'); assert.equal(f.el('submit').disabled, true); assert.match(f.el('profile-status').textContent, /不可提交/);
        await f.controller.createRun(platformInput());
        assert.equal(f.calls.filter(([, opts]) => opts.method === 'POST').length, 0);
        assert.equal(f.state().run.id, 'old'); assert.equal(f.el('export').disabled, false);
        f.controller.setMode('probe'); assert.equal(f.el('profile-panel').hidden, true);
        f.el('authorized').checked = true; await f.el('authorized').dispatch('change'); assert.equal(f.el('submit').disabled, false);
        await f.controller.createRun(input()); await tick();
        const posts = f.calls.filter(([, opts]) => opts.method === 'POST'); assert.equal(posts.length, 1); assert.equal(JSON.parse(posts[0][1].body).mode, 'probe');
        f.controller.stop();
    }
});

test('project is required and permission failures show the reason instead of inventing a project', async () => {
    const f = fixture(); await f.controller.init();
    f.el('authorized').checked = true; await f.el('authorized').dispatch('change');
    assert.equal(f.el('submit').disabled, true); assert.equal(f.el('project').value, '');
    await f.controller.createRun(platformInput({ project_id: '' })); assert.match(f.el('form-error').textContent, /必须选择/);
    assert.equal(f.calls.filter(([, opts]) => opts.method === 'POST').length, 0);
    f.el('project').value = 'project-one'; await f.el('project').dispatch('change');
    assert.equal(f.state().projectId, 'project-one'); assert.equal(f.el('authorized').checked, false);
    f.el('authorized').checked = true; await f.el('authorized').dispatch('change'); assert.equal(f.el('submit').disabled, false);
    f.setFetch((url, opts, fallback) => url.startsWith('/api/projects?') ? response({ error: '缺少 project:read 权限' }, 403) : fallback(url));
    await f.controller.refresh(true);
    assert.match(f.el('project-hint').textContent, /HTTP 403.*project:read/); assert.equal(f.el('submit').disabled, true); assert.deepEqual(f.state().projects, []);
    await f.controller.createRun(platformInput()); assert.match(f.el('form-error').textContent, /project:read/);
    assert.equal(f.calls.filter(([, opts]) => opts.method === 'POST').length, 0);
    f.setFetch((url, opts, fallback) => url.startsWith('/api/projects?') ? response({ projects: [] }) : fallback(url));
    await f.controller.refresh(true); assert.match(f.el('project-hint').textContent, /原项目当前不可读/);
    f.controller.setProject(''); assert.match(f.el('project-hint').textContent, /暂无可读/); f.controller.stop();
});

test('mode switching updates default budgets, scope hints, required fields and explicit authorization', async () => {
    const f = fixture(); await f.controller.init();
    assert.equal(f.state().mode, 'platform'); assert.equal(f.el('mode').value, 'platform');
    assert.deepEqual(['parallel', 'max-agents', 'timeout', 'max-turns', 'max-tool-calls'].map(id => f.el(id).value), ['3', '12', '3600', '120', '600']);
    assert.deepEqual(['parallel', 'max-agents', 'timeout', 'max-turns', 'max-tool-calls'].map(id => f.el(id).max), ['8', '32', '21600', '500', '2000']);
    assert.match(f.el('mode-hint').textContent, /不再限于 GET\/HEAD/); assert.match(f.el('scope-hint').textContent, /CIDR.*任务约束/);
    f.el('scope').value = '10.0.0.0/8'; f.el('authorized').checked = true;
    f.el('mode').value = 'probe'; await f.el('mode').dispatch('change');
    assert.equal(f.el('authorized').checked, false); assert.equal(f.el('project').required, false); assert.equal(f.el('project').disabled, true);
    assert.equal(f.el('max-turns').disabled, true); assert.equal(f.el('max-turns').required, false);
    assert.equal(f.el('platform-budgets').hidden, true); assert.equal(f.el('profile-panel').hidden, true);
    assert.deepEqual(['parallel', 'max-agents', 'timeout'].map(id => f.el(id).value), ['2', '4', '300']);
    assert.deepEqual(['parallel', 'max-agents', 'timeout'].map(id => f.el(id).max), ['4', '12', '1800']);
    assert.match(f.el('scope-label').textContent, /origin/); assert.match(f.el('mode-hint').textContent, /仅 GET\/HEAD/);
    assert.equal(f.el('scope').value, '10.0.0.0/8');
    f.controller.setMode('platform'); assert.equal(f.el('project').required, true); assert.equal(f.el('max-turns').disabled, false);
    assert.equal(f.el('max-turns').value, '120'); assert.equal(f.el('max-tool-calls').value, '600'); assert.equal(f.el('authorized').checked, false);
    assert.equal(f.calls.filter(([, opts]) => opts.method === 'POST').length, 0); f.controller.stop();
});

test('form submission uses the platform contract and cancel keeps platform metadata and final events', async () => {
    let created = false; let cancelled = false;
    const platformRun = () => run('platform-run', cancelled ? 'cancelled' : 'running', { mode: 'platform', project_id: 'project-one', conversation_id: 'conversation-one', role: '渗透测试', skills: ['recon'], execution_ids: cancelled ? ['execution-final'] : [], limits: { max_parallel: 3, max_agents: 12, timeout_seconds: 3600, max_turns: 120, max_tool_calls: 600 }, report: cancelled ? '取消后最终报告' : '' });
    const f = fixture({ fetch: (url, opts, fallback) => {
        if (url === '/api/pi-lab/runs' && opts.method === 'POST') { created = true; return response(platformRun(), 202); }
        if (url === '/api/pi-lab/runs') return response({ runs: created ? [platformRun()] : [] });
        if (url.endsWith('/cancel')) { cancelled = true; return response(platformRun()); }
        if (url === '/api/pi-lab/runs/platform-run') return response(platformRun());
        if (url.includes('/events?') && cancelled) {
            const next = Number(url.split('after=')[1]) + 1;
            return response({ events: [event(next)], cursor: next, has_more: next < 10 });
        }
        return fallback(url);
    } });
    await f.controller.init(); f.controller.setProject('project-one');
    const draft = platformInput(); ['title', 'prompt', 'scope'].forEach(key => { f.el(key).value = draft[key]; });
    f.el('authorized').checked = true; await f.el('form').dispatch('submit'); await tick();
    const creation = f.calls.find(([, opts]) => opts.method === 'POST');
    assert.deepEqual(JSON.parse(creation[1].body), lab.buildPayload(draft, ready, profile, projects));
    assert.equal(f.state().run.mode, 'platform'); assert.equal(f.state().run.conversation_id, 'conversation-one');
    assert.equal(f.el('authorized').checked, false);
    await f.controller.cancelRun(); await tick();
    assert.equal(f.state().run.status, 'cancelled'); assert.equal(f.el('cancel').disabled, true);
    assert.equal(f.el('report').textContent, '取消后最终报告'); assert.equal(f.el('run-executions').textContent, 'execution-final');
    assert.equal(f.state().events.length, 8); assert.equal([...f.timers.values()][0].delay, 100);
    await f.fireTimer(); assert.equal(f.state().events.length, 10); assert.equal(f.state().hasMore, false); assert.equal([...f.timers.values()][0].delay, 10000);
    assert.equal(f.calls.filter(([url]) => url.endsWith('/status')).length, 1); assert.equal(f.calls.filter(([url]) => url.endsWith('/profile')).length, 1);
    f.controller.stop();
});

test('old runs remain probe records and copying failed records never posts or grants authorization', async () => {
    const old = run('old-failed', 'failed', { prompt: '原需求', error: '旧失败原因' });
    const platform = run('platform-failed', 'failed', { mode: 'platform', project_id: 'project-one', role: '渗透测试', scope: ['10.2.0.0/16'], limits: { max_parallel: 3, max_agents: 12, timeout_seconds: 3600, max_turns: 120, max_tool_calls: 600 }, ai_channel: 'removed-channel' });
    const f = fixture({ runs: [old, platform] }); await f.controller.init();
    assert.equal(f.state().run.mode, 'probe'); assert.equal(f.state().mode, 'platform'); assert.match(f.el('run-role').textContent, /旧版诊断/);
    const count = f.calls.length; f.el('authorized').checked = true; await f.el('copy').dispatch('click');
    assert.equal(f.calls.length, count); assert.equal(f.state().selectedId, 'old-failed'); assert.equal(f.state().mode, 'probe');
    assert.equal(f.el('title').value, old.title); assert.equal(f.el('prompt').value, old.prompt); assert.equal(f.el('scope').value, old.scope.join('\n'));
    assert.equal(f.el('authorized').checked, false); assert.equal(f.el('submit').disabled, true); assert.match(f.el('form-notice').textContent, /尚未提交/);
    await f.controller.selectRun('platform-failed'); f.el('authorized').checked = true;
    const beforeCopy = f.calls.length; f.controller.copyRun();
    assert.equal(f.calls.length, beforeCopy); assert.equal(f.state().mode, 'platform'); assert.equal(f.el('project').value, 'project-one');
    assert.equal(f.el('channel').value, 'removed-channel'); assert.equal(f.el('max-turns').value, '120'); assert.equal(f.el('authorized').checked, false);
    f.controller.newRun(); assert.equal(f.state().mode, 'platform'); assert.equal(f.el('title').value, ''); assert.equal(f.el('project').value, ''); assert.equal(f.el('channel').value, '');
    assert.equal(f.el('authorized').checked, false); assert.equal(f.calls.filter(([, opts]) => opts.method === 'POST').length, 0); f.controller.stop();
});

test('copying a platform run whose project is unavailable requires a new explicit project choice', async () => {
    const f = fixture({ runs: [run('failed', 'failed', { mode: 'platform', project_id: 'archived-project', scope: ['10.0.0.0/8'] })] });
    await f.controller.init(); f.controller.copyRun();
    assert.equal(f.el('project').value, 'archived-project'); assert.match(f.el('project-hint').textContent, /原项目当前不可读/);
    f.el('authorized').checked = true; await f.el('authorized').dispatch('change'); assert.equal(f.el('submit').disabled, true);
    assert.equal(f.calls.filter(([, opts]) => opts.method === 'POST').length, 0); f.controller.stop();
});

test('profile and project catalog project only legal metadata and render untrusted text without HTML', async () => {
    const attack = '<img src=x onerror="bad()"><script>bad()</script>';
    const project = { id: 'project-one', name: attack };
    Object.defineProperty(project, 'scope_json', { enumerable: true, get() { throw new Error('project configuration must not be read'); } });
    const skill = { name: attack, description: attack };
    Object.defineProperty(skill, 'body', { enumerable: true, get() { throw new Error('skill body must not be read'); } });
    const p = { ...profile, role: { name: '渗透测试', description: attack }, skills: [skill], tools: [skill] };
    Object.defineProperty(p, 'credentials', { enumerable: true, get() { throw new Error('credentials must not be read'); } });
    const f = fixture({ profile: p, projects: [project, { id: 'invalid/id', name: 'invalid' }, { id: {}, name: 'invalid' }, { id: 'no-name', name: {} }, { id: 'blank-name', name: ' ' }, { id: 'project-one', name: 'duplicate' }] });
    await f.controller.init(); assert.deepEqual(f.state().projects, [{ id: 'project-one', name: attack }]);
    assert.equal(f.state().profile.skills[0].body, undefined); assert.equal(f.state().profile.credentials, undefined);
    for (const id of ['project', 'profile-role', 'catalog-skills', 'catalog-tools']) assert.ok(f.el(id).textContent.includes(attack), id);
    assert.ok(!f.created.some(node => ['IMG', 'SCRIPT', 'IFRAME'].includes(node.tagName)));
    assert.deepEqual(lab.normalizeProjects({ projects: [null, project] }), [{ id: 'project-one', name: attack }]);
    assert.throws(() => lab.normalizeProjects({ projects: {} }), /格式/); f.controller.stop();
});

test('platform detail links encode metadata and local export preserves the agreed run metadata only', async () => {
    const id = 'c/one?x=<script>#part'; const attack = '<svg onload="bad()">';
    const value = run('platform-meta', 'completed', { mode: 'platform', project_id: 'project-one', conversation_id: id, role: attack, skills: ['recon', attack, {}], execution_ids: ['exec-one', attack, 3], limits: { ...profile.limits, unrelated: 'secret' }, api_key: 'secret', scope: ['10.0.0.0/8'] });
    const f = fixture({ runs: [value] }); let openedProject = ''; f.env.openProject = id => { openedProject = id; };
    await f.controller.init();
    assert.ok(f.el('run-role').textContent.includes(attack)); assert.ok(f.el('run-skills').textContent.includes(attack)); assert.ok(f.el('run-executions').textContent.includes(attack));
    assert.match(f.el('run-limits').textContent, /模型轮次 500.*工具调用 2000/); assert.match(f.el('run-integration').textContent, /项目、漏洞和工具监控/);
    const links = f.el('run-links').children.filter(node => node.tagName === 'A');
    assert.ok(links.some(node => node.href === '#chat?conversation=' + encodeURIComponent(id)));
    assert.ok(links.some(node => node.href === '#vulnerabilities?project_id=project-one')); assert.ok(links.some(node => node.href === '#mcp-monitor'));
    await links.find(node => node.href === '#projects?id=project-one').dispatch('click'); assert.equal(openedProject, 'project-one');
    const count = f.calls.length; f.controller.exportRun(); assert.equal(f.calls.length, count);
    const exported = JSON.parse(await f.blobs[0].text());
    assert.deepEqual({ mode: exported.run.mode, project_id: exported.run.project_id, conversation_id: exported.run.conversation_id, role: exported.run.role, skills: exported.run.skills, execution_ids: exported.run.execution_ids }, { mode: 'platform', project_id: 'project-one', conversation_id: id, role: attack, skills: ['recon', attack], execution_ids: ['exec-one', attack] });
    assert.equal(exported.run.limits.max_turns, 500); assert.equal(exported.run.limits.max_tool_calls, 2000);
    assert.equal(exported.run.limits.unrelated, undefined); assert.equal(exported.run.api_key, undefined); assert.equal(exported.profile, undefined);
    f.controller.stop();
});

test('failed global dependency checks and catalogs retry only on entry or manual refresh, never on event polls', async () => {
    let failing = true;
    const setup = ['/api/pi-lab/status', '/api/pi-lab/profile', '/api/projects?status=active&limit=500', '/api/config/ai-channels'];
    const f = fixture({ runs: [run()], fetch: (url, opts, fallback) => failing && setup.includes(url) ? response({ error: '离线依赖错误' }, 503) : fallback(url) });
    await f.controller.init(); await f.controller.refresh(); await f.fireTimer();
    for (const url of setup) assert.equal(f.calls.filter(([path]) => path === url).length, 1, url);
    assert.match(f.el('channel-hint').textContent, /HTTP 503.*离线依赖错误/); assert.match(f.el('profile-status').textContent, /HTTP 503.*离线依赖错误/);
    failing = false; await f.controller.refresh(true);
    for (const url of setup) assert.equal(f.calls.filter(([path]) => path === url).length, 2, url);
    assert.equal(f.state().profile.available, true); f.controller.stop();
});

test('refreshing setup blocks creation with stale availability until profile failure is known', async () => {
    const wait = deferred(); const f = fixture(); await f.controller.init(); f.controller.setProject('project-one');
    f.el('authorized').checked = true; await f.el('authorized').dispatch('change'); assert.equal(f.el('submit').disabled, false);
    f.setFetch((url, opts, fallback) => url.endsWith('/profile') ? wait.promise : fallback(url));
    const refresh = f.controller.refresh(true); assert.equal(f.el('submit').disabled, true);
    await f.controller.createRun(platformInput()); assert.equal(f.calls.filter(([, opts]) => opts.method === 'POST').length, 0);
    wait.resolve(response({ error: '角色读取失败' }, 503)); await refresh;
    assert.equal(f.state().profile, null); assert.equal(f.el('submit').disabled, true); assert.match(f.el('profile-status').textContent, /角色读取失败/); f.controller.stop();
});

test('identity change during profile loading clears catalogs, projects, authorization and cached task metadata', async () => {
    const wait = deferred(); const f = fixture({ runs: [run('private', 'completed', { mode: 'platform', conversation_id: 'private-conversation' })] });
    await f.controller.init(); f.controller.setProject('project-one'); f.el('authorized').checked = true;
    f.setFetch((url, opts, fallback) => url.endsWith('/profile') ? wait.promise : fallback(url));
    const refresh = f.controller.refresh(true); await tick(); f.setOwner('new-owner');
    wait.resolve(response({ ...profile, skills: [{ name: 'private-skill', description: '' }] })); await refresh;
    assert.equal(f.state().profile, null); assert.deepEqual(f.state().projects, []); assert.equal(f.state().projectId, '');
    assert.equal(f.el('authorized').checked, false); assert.equal(f.el('channel').value, ''); assert.equal(f.el('submit').disabled, true);
    assert.doesNotMatch(f.el('catalog-skills').textContent, /private-skill/); assert.doesNotMatch(f.el('run-links').textContent, /private-conversation/);
    assert.equal(f.timers.size, 0);
});

test('selecting history during a pending setup check cannot re-enable stale platform availability', async () => {
    const wait = deferred(); const f = fixture({ runs: [run('one'), run('two')] });
    await f.controller.init(); f.controller.setProject('project-one'); f.el('authorized').checked = true;
    f.setFetch((url, opts, fallback) => url.endsWith('/profile') ? wait.promise : fallback(url));
    const refresh = f.controller.refresh(true); await tick(); await f.controller.selectRun('two');
    assert.equal(f.state().run.id, 'two'); assert.equal(f.state().profile, null); assert.equal(f.el('submit').disabled, true);
    assert.match(f.el('runtime-status').textContent, /检查未完成/);
    await f.controller.createRun(platformInput()); assert.equal(f.calls.filter(([, opts]) => opts.method === 'POST').length, 0);
    wait.resolve(response(profile)); await refresh;
    assert.equal(f.state().profile, null); assert.equal(f.el('submit').disabled, true);
    f.setFetch((url, opts, fallback) => fallback(url)); await f.controller.refresh(true);
    assert.equal(f.state().profile.available, true); f.controller.stop();
});

test('invalid project metadata remains plain text and cannot call the shared project selector', async () => {
    const f = fixture({ runs: [run('invalid-project', 'completed', { mode: 'platform', project_id: '../config?x=<script>' })] });
    let opened = false; f.env.openProject = () => { opened = true; }; await f.controller.init();
    assert.match(f.el('run-links').textContent, /项目 ID 无效/);
    assert.ok(!f.el('run-links').children.some(node => node.tagName === 'A' && node.href.startsWith('#projects')));
    assert.equal(opened, false); f.controller.stop();
});

test('identity changes invalidate in-flight responses and erase the previous owner state', async () => {
    const wait = deferred(); let hold = false;
    const f = fixture({ runs: [run('private-run')], fetch: (url, opts, fallback) => hold && url.endsWith('/status') ? wait.promise : fallback(url) });
    await f.controller.init(); hold = true; const refresh = f.controller.refresh();
    f.setOwner('different-owner'); wait.resolve(response(ready)); await refresh;
    assert.equal(f.state().run, null); assert.equal(f.state().runs.length, 0); assert.equal(f.state().events.length, 0);
    assert.match(f.el('runtime-status').textContent, /身份或权限已变化/); assert.equal(f.timers.size, 0);
});
