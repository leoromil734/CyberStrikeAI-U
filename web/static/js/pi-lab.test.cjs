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
const input = (extra = {}) => ({ title: '新试验', prompt: '仅观察响应头', scope: 'https://example.test\nhttps://other.test:8443/', ai_channel: '', max_parallel: 2, max_agents: 4, timeout_seconds: 300, authorized: true, ...extra });

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
        ['title', 'scope', 'prompt', 'channel'].forEach(id => { elements.get('pi-lab-' + id).value = ''; });
        elements.get('pi-lab-authorized').checked = false;
        elements.get('pi-lab-parallel').value = '2'; elements.get('pi-lab-max-agents').value = '4'; elements.get('pi-lab-timeout').value = '300';
    };
    const fallback = url => {
        if (url === '/api/pi-lab/status') return response(options.status || ready);
        if (url === '/api/config/ai-channels') return response({ default_channel: 'one', channels: { one: { name: '主模型', model: 'offline-fixture' } } });
        if (url === '/api/pi-lab/runs') return response({ runs: options.runs || [] });
        if (url.includes('/events?')) return response({ events: [], cursor: Number(url.split('after=')[1]), has_more: false });
        if (url.startsWith('/api/pi-lab/runs/')) return response((options.runs || []).find(item => item.id === decodeURIComponent(url.split('/').pop())) || run(decodeURIComponent(url.split('/').pop())));
        throw new Error('Unexpected endpoint: ' + url);
    };
    const env = {
        document, hasPermission: () => permitted, getOwner: () => owner, ensureAuthenticated: options.ensureAuthenticated || (async () => true),
        apiFetch: async (url, opts) => {
            assert.match(url, /^\/api\/(pi-lab\/(?:status|runs(?:\/[^/]+(?:\/cancel|\/events\?after=\d+)?)?)|config\/ai-channels)$/);
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
    assert.deepEqual(lab.buildPayload(input(), ready), { title: '新试验', prompt: '仅观察响应头', scope: ['https://example.test', 'https://other.test:8443'], ai_channel: '', authorized: true, max_parallel: 2, max_agents: 4, timeout_seconds: 300 });
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
    assert.equal(f.el('submit').disabled, true); assert.match(f.el('runtime-status').textContent, /无法读取实验状态/);
    assert.equal(f.el('channel').children.length, 1); assert.equal(f.el('channel').children[0].value, ''); assert.match(f.el('channel-hint').textContent, /默认模型/);
    assert.equal(f.state().run.id, 'history');
    fail = false; await f.controller.refresh(true);
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
    assert.match(f.el('run-error').textContent, /仅属主可见/); assert.match(f.el('graph').textContent, /选择一个试验/);
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
    broken = false; await f.controller.refresh(); assert.equal(f.el('list-error').hidden, true); assert.match(f.el('runs').textContent, /暂无独立试验/);
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
    const f = fixture(); await f.controller.init(); f.el('authorized').checked = true; await f.el('authorized').dispatch('change');
    assert.equal(f.el('submit').disabled, false); f.controller.stop();
    f.env.ensureAuthenticated = async () => { throw new Error('登录校验失败'); }; await f.controller.init();
    assert.equal(f.state().status, null); assert.equal(f.el('submit').disabled, true); assert.match(f.el('runtime-status').textContent, /登录校验失败/);
});

test('identity changes invalidate in-flight responses and erase the previous owner state', async () => {
    const wait = deferred(); let hold = false;
    const f = fixture({ runs: [run('private-run')], fetch: (url, opts, fallback) => hold && url.endsWith('/status') ? wait.promise : fallback(url) });
    await f.controller.init(); hold = true; const refresh = f.controller.refresh();
    f.setOwner('different-owner'); wait.resolve(response(ready)); await refresh;
    assert.equal(f.state().run, null); assert.equal(f.state().runs.length, 0); assert.equal(f.state().events.length, 0);
    assert.match(f.el('runtime-status').textContent, /身份或权限已变化/); assert.equal(f.timers.size, 0);
});
