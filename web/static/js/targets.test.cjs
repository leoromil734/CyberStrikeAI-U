const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

class Element {
    constructor(attributes = {}) { this.attributes = new Map(Object.entries(attributes)); this.listeners = {}; this.value = ''; this.hidden = false; this.disabled = false; this.innerHTML = ''; this.textContent = ''; this.events = []; }
    setAttribute(name, value) { this.attributes.set(name, String(value)); }
    getAttribute(name) { return this.attributes.get(name) || null; }
    addEventListener(name, handler) { (this.listeners[name] ||= []).push(handler); }
    dispatchEvent(event) { this.events.push(event); }
    contains() { return false; }
    querySelectorAll() { return []; }
    closest() { return this; }
}
const languages = Object.fromEntries(['zh-CN', 'en-US'].map(lang => [lang, JSON.parse(fs.readFileSync(path.join(__dirname, `../i18n/${lang}.json`), 'utf8'))]));
function fixture(fetch = async () => response({ targets: [] }), options = {}) {
    const elements = new Map(); const calls = []; const timers = new Map(); const listeners = {}; const rbacRoots = []; const confirms = []; const notices = [];
    let timerId = 0; let language = 'zh-CN';
    const document = { activeElement: null,
        getElementById(id) { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); },
        addEventListener(name, handler) { listeners[name] = handler; },
    };
    const context = { document, URLSearchParams, URL, Event, Date, Set,
        console: { warn() {} },
        setTimeout: (callback, delay) => { const id = ++timerId; timers.set(id, { callback, delay }); return id; },
        clearTimeout: id => timers.delete(id),
        t: (key, opts = {}) => {
            const text = key.split('.').reduce((obj, part) => obj?.[part], languages[language]) || key;
            return text.replace(/\{\{(\w+)\}\}/g, (_, name) => String(opts[name] ?? ''));
        },
        apiFetch: async (url, requestOptions) => { calls.push([url, requestOptions]); return fetch(url, requestOptions); },
        rbacAfterDynamicRender: root => rbacRoots.push(root),
        applyTranslations: () => {},
        requirePermission: permission => (options.permissions || []).includes(permission),
        confirm: message => { confirms.push(message); return options.confirm !== false; },
        showNotification: (message, type) => notices.push({ message, type }),
        alert: message => notices.push({ message }),
    };
    context.window = context;
    vm.createContext(context);
    vm.runInContext(fs.readFileSync(path.join(__dirname, 'targets.js'), 'utf8'), context);
    return { context, document, elements, calls, timers, rbacRoots, confirms, notices,
        state: vm.runInContext('targetsPageState', context),
        changeLanguage: lang => { language = lang; listeners.languagechange(); },
        flushSearch: async () => { const queued = [...timers.values()]; timers.clear(); queued.forEach(timer => timer.callback()); await tick(); },
    };
}
const response = data => ({ ok: true, json: async () => data });
const tick = () => new Promise(resolve => setImmediate(resolve));
const target = { target: 'example.com', runCount: 3, submittedCount: 4, firstRunAt: '2026-10-01T03:00:00Z', lastRunAt: '2026-10-02T03:00:00Z', lastSubmittedAt: '2026-10-02T02:00:00Z', lastTaskTitle: 'Original task' };
const pageResponse = (targets = [target], extra = {}) => response({ targets, page: 1, page_size: 50, total: targets.length, total_pages: 1, ...extra });
const click = (context, attributes) => context.onTargetsTableClick({ target: new Element(attributes) });

test('target list query and page-size contract stay unchanged; overview distinguishes matching total from current page', async () => {
    const f = fixture(async () => pageResponse([target, { ...target, target: 'pending.example', runCount: 0 }], { page: 2, total: 65, total_pages: 2 }));
    f.state.keyword = 'example & one';
    await f.context.loadTargetsPage(2);
    assert.equal(f.calls[0][0], '/api/targets?page=2&page_size=50&keyword=example+%26+one');
    assert.equal(f.elements.get('targets-stat-total').textContent, '65');
    assert.equal(f.elements.get('targets-stat-executed').textContent, '1');
    assert.equal(f.elements.get('targets-stat-registered').textContent, '1');
    assert.equal(f.elements.get('targets-total').textContent, '共 65 个目标');
    assert.ok(f.elements.get('targets-table-body').innerHTML.includes('已登记，尚未运行'));
    assert.ok(f.elements.get('targets-table-body').innerHTML.includes('已登记 4 个任务'));
    assert.ok(f.elements.get('targets-pagination').innerHTML.includes('data-targets-page="1"'));
    assert.ok(f.elements.get('targets-pagination').innerHTML.includes('data-targets-page="2" disabled'));
    assert.equal(f.rbacRoots.at(-1), f.elements.get('targets-table-body'));
});

test('loading and failures never display stale totals or stale pagination and list retries are read-only', async () => {
    let resolve; let failing = false;
    const f = fixture(() => failing ? new Promise(done => { resolve = done; }) : pageResponse());
    await f.context.loadTargetsPage(1);
    failing = true;
    const loading = f.context.loadTargetsPage(2);
    assert.equal(f.elements.get('targets-table-body').getAttribute('aria-busy'), 'true');
    assert.ok(f.elements.get('targets-table-body').innerHTML.includes('targets-loader'));
    assert.equal(f.elements.get('targets-stat-total').textContent, '—');
    assert.equal(f.elements.get('targets-pagination').innerHTML, '');
    resolve({ ok: false, status: 503 }); await loading;
    assert.equal(f.elements.get('targets-table-body').getAttribute('aria-busy'), 'false');
    assert.ok(f.elements.get('targets-table-body').innerHTML.includes('data-action="retry-list"'));
    assert.equal(f.elements.get('targets-total').textContent, '—');
    failing = false;
    click(f.context, { 'data-action': 'retry-list' }); await tick();
    assert.equal(f.calls.at(-1)[0], '/api/targets?page=2&page_size=50');
    assert.ok(f.calls.every(([, opts]) => !opts || !opts.method || opts.method === 'GET'));
});

test('empty history differs from no search matches and exposes a clear-search recovery', async () => {
    const f = fixture(async () => pageResponse([]));
    await f.context.loadTargetsPage(1);
    assert.ok(f.elements.get('targets-table-body').innerHTML.includes('暂无目标历史'));
    assert.equal(f.elements.get('targets-stat-total').textContent, '0');
    f.state.keyword = 'not-found'; f.document.getElementById('targets-search').value = 'not-found';
    await f.context.loadTargetsPage(1);
    assert.ok(f.elements.get('targets-table-body').innerHTML.includes('没有匹配的目标'));
    assert.ok(f.elements.get('targets-table-body').innerHTML.includes('data-action="clear-search"'));
    assert.equal(f.elements.get('targets-search-clear').hidden, false);
    click(f.context, { 'data-action': 'clear-search' }); await tick();
    assert.equal(f.calls.at(-1)[0], '/api/targets?page=1&page_size=50');
    assert.equal(f.elements.get('targets-search').value, '');
    assert.equal(f.elements.get('targets-search-clear').hidden, true);
});

test('search keeps 300ms debounce, reset cancels pending search and event binding occurs once', async () => {
    const f = fixture(async () => pageResponse());
    await f.context.initTargetsPage(); await f.context.initTargetsPage();
    const input = f.elements.get('targets-search');
    assert.equal(input.listeners.input.length, 1);
    assert.equal(f.elements.get('targets-table-body').listeners.click.length, 1);
    assert.equal(f.elements.get('targets-pagination').listeners.click.length, 1);
    input.value = 'first'; input.listeners.input[0]({ target: input });
    input.value = 'second'; input.listeners.input[0]({ target: input });
    assert.equal(f.timers.size, 1);
    assert.equal([...f.timers.values()][0].delay, 300);
    await f.flushSearch();
    assert.ok(f.calls.at(-1)[0].endsWith('keyword=second'));
    input.value = 'stale'; input.listeners.input[0]({ target: input });
    await f.context.clearTargetsSearch();
    assert.equal(f.timers.size, 0);
    assert.equal(f.state.keyword, '');
    assert.equal(f.calls.at(-1)[0], '/api/targets?page=1&page_size=50');
});

test('out-of-order list responses and failures cannot overwrite the newest filter', async () => {
    const pending = [];
    const f = fixture(() => new Promise(resolve => pending.push(resolve)));
    const first = f.context.loadTargetsPage(1);
    f.state.keyword = 'newest';
    const second = f.context.loadTargetsPage(1);
    pending[1](pageResponse([{ ...target, target: 'newest.example' }])); await second;
    pending[0]({ ok: false, status: 500 }); await first;
    assert.equal(f.state.listStatus, 'ready');
    assert.equal(f.state.targets[0].target, 'newest.example');
    assert.equal(f.elements.get('targets-stat-total').textContent, '1');
    assert.ok(f.elements.get('targets-table-body').innerHTML.includes('newest.example'));
});

test('target and task text, dialogue IDs, titles and action labels are escaped in every HTML context', async () => {
    const malicious = { ...target, target: '"><img src=x onerror=unsafe()>', lastTaskTitle: '<script>unsafe()</script>' };
    const event = { conversationId: '"><img onerror=unsafe()>', conversationTitle: '<script>unsafe()</script>', startedAt: 'invalid' };
    const f = fixture(async url => url.includes('/events?') ? response({ events: [event] }) : pageResponse([malicious]));
    await f.context.loadTargetsPage(1); await f.context.toggleTargetRuns(malicious.target);
    const html = f.elements.get('targets-table-body').innerHTML;
    assert.ok(!html.includes('<img'));
    assert.ok(!html.includes('<script>'));
    assert.ok(html.includes('&lt;img'));
    assert.ok(html.includes('&lt;script&gt;unsafe()&lt;/script&gt;'));
    assert.ok(html.includes('aria-expanded="true"'));
    assert.ok(html.includes('data-require-permission="target:delete"'));
    assert.ok(html.includes('data-label="跑过次数"'));
    assert.equal(f.calls[1][0], '/api/targets/' + encodeURIComponent(malicious.target) + '/events?page=1&page_size=50');
});

test('expansion/collapse retains encoded event endpoint, cached records and conversation action', async () => {
    const name = 'example.com/path?x=1';
    const f = fixture(async url => url.includes('/events?') ? response({ events: [{ conversationId: 'conversation-one', conversationTitle: 'Run one', startedAt: target.lastRunAt }] }) : pageResponse([{ ...target, target: name }]));
    await f.context.loadTargetsPage(1); await f.context.toggleTargetRuns(name);
    const html = f.elements.get('targets-table-body').innerHTML;
    assert.ok(html.includes('aria-controls="target-runs-' + encodeURIComponent(name) + '"'));
    assert.ok(html.includes('data-conversation="conversation-one"'));
    assert.ok(html.includes('首次'));
    await f.context.toggleTargetRuns(name); await f.context.toggleTargetRuns(name);
    assert.equal(f.calls.filter(([url]) => url.includes('/events?')).length, 1);
    const opened = [];
    f.context.navigateToConversation = id => opened.push(id);
    click(f.context, { 'data-action': 'open-conversation', 'data-conversation': 'conversation-one' });
    assert.deepEqual(opened, ['conversation-one']);
});

test('inline event failure can be retried without changing expansion or submitting any task', async () => {
    let fail = true;
    const f = fixture(async url => url.includes('/events?') ? fail ? { ok: false, status: 403 } : response({ events: [] }) : pageResponse());
    await f.context.loadTargetsPage(1); await f.context.toggleTargetRuns(target.target);
    assert.ok(f.elements.get('targets-table-body').innerHTML.includes('data-action="retry-runs"'));
    fail = false;
    click(f.context, { 'data-action': 'retry-runs', 'data-target': target.target }); await tick();
    assert.equal(f.state.expanded.has(target.target), true);
    assert.ok(f.elements.get('targets-table-body').innerHTML.includes('没有明细记录'));
    assert.ok(f.calls.every(([, opts]) => !opts?.method || opts.method === 'GET'));
});

test('pending events from a prior list request cannot repopulate a refreshed page', async () => {
    let resolve;
    const f = fixture(url => url.includes('/events?') ? new Promise(done => { resolve = done; }) : pageResponse());
    await f.context.loadTargetsPage(1);
    const events = f.context.toggleTargetRuns(target.target);
    await f.context.loadTargetsPage(1);
    resolve(response({ events: [{ conversationId: 'obsolete' }] })); await events;
    assert.equal(f.state.expanded.size, 0);
    assert.equal(f.state.eventsCache[target.target], undefined);
    assert.ok(!f.elements.get('targets-table-body').innerHTML.includes('obsolete'));
});

test('language changes redraw registered/runs/detail labels without network calls or losing expansion', async () => {
    const f = fixture(async url => url.includes('/events?') ? response({ events: [] }) : pageResponse([{ ...target, runCount: 0 }]));
    await f.context.loadTargetsPage(1); await f.context.toggleTargetRuns(target.target);
    const before = f.calls.length;
    f.changeLanguage('en-US');
    const html = f.elements.get('targets-table-body').innerHTML;
    assert.ok(html.includes('Registered, not run yet'));
    assert.ok(html.includes('4 submitted tasks'));
    assert.ok(html.includes('Task: Original task'));
    assert.ok(html.includes('No run records'));
    assert.ok(!html.includes('已登记'));
    assert.equal(f.state.expanded.has(target.target), true);
    assert.equal(f.calls.length, before);
});

test('deletion still requires target:delete and user confirmation before sending the encoded DELETE', async () => {
    const denied = fixture();
    denied.context.deleteTargetRun(target.target);
    assert.equal(denied.confirms.length, 0); assert.equal(denied.calls.length, 0);
    const cancelled = fixture(undefined, { permissions: ['target:delete'], confirm: false });
    cancelled.context.deleteTargetRun(target.target);
    assert.equal(cancelled.confirms.length, 1); assert.equal(cancelled.calls.length, 0);
    const allowed = fixture(async () => pageResponse(), { permissions: ['target:delete'] });
    allowed.context.deleteTargetRun('example.com/x?y=1'); await tick();
    assert.equal(allowed.calls[0][0], '/api/targets/' + encodeURIComponent('example.com/x?y=1'));
    assert.deepEqual(JSON.parse(JSON.stringify(allowed.calls[0][1])), { method: 'DELETE' });
    assert.equal(allowed.calls[1][0], '/api/targets?page=1&page_size=50');
    assert.equal(allowed.notices[0].type, 'success');
});

test('restart only opens and prefills the existing task form; it never creates a task itself', async () => {
    const f = fixture(); let opens = 0;
    f.context.showBatchImportModal = async () => { opens++; };
    f.context.restartTargetTask(target.target); await tick();
    const input = f.elements.get('batch-tasks-input');
    assert.equal(opens, 1);
    assert.equal(input.value, '对 example.com 做全面 完整 深度的渗透测试 漏洞挖掘，包括品牌资产 子资产 子域名 IP等');
    assert.equal(input.events[0].type, 'input');
    assert.equal(f.calls.length, 0);
});

test('existing conversation fallback and invalid-time behavior stay available', () => {
    const f = fixture(); const actions = [];
    f.context.switchPage = page => actions.push(['page', page]);
    f.context.loadConversation = id => actions.push(['conversation', id]);
    f.context.openTargetConversation('original');
    assert.deepEqual(actions, [['page', 'chat'], ['conversation', 'original']]);
    assert.equal(f.context.formatTargetTime('invalid'), '');
    assert.equal(f.context.formatTargetTime(null), '');
    assert.match(f.context.formatTargetTime(target.lastRunAt), /^\d{2}-\d{2} \d{2}:\d{2}$/);
});

test('pagination still delegates page buttons, ignores disabled/current pages and preserves server page size', async () => {
    const f = fixture(async () => pageResponse([target], { page_size: 20, total: 45, total_pages: 3 }));
    await f.context.loadTargetsPage(1);
    const pager = f.elements.get('targets-pagination').innerHTML;
    assert.ok(pager.includes('data-targets-page="1" disabled'));
    assert.ok(pager.includes('data-targets-page="3"'));
    const disabled = new Element({ 'data-targets-page': '2' }); disabled.disabled = true;
    f.context.onTargetsPaginationClick({ target: disabled });
    f.context.onTargetsPaginationClick({ target: new Element({ 'data-targets-page': '1' }) });
    assert.equal(f.calls.length, 1);
    f.context.onTargetsPaginationClick({ target: new Element({ 'data-targets-page': '2' }) }); await tick();
    assert.equal(f.calls[1][0], '/api/targets?page=2&page_size=20');
});

test('Chinese and English targets translation keys stay aligned, including dynamic labels', () => {
    const zh = languages['zh-CN'].targets; const en = languages['en-US'].targets;
    assert.deepEqual(Object.keys(zh).sort(), Object.keys(en).sort());
    for (const filename of ['targets.js', '../../templates/index.html']) {
        const source = fs.readFileSync(path.join(__dirname, filename), 'utf8');
        for (const match of source.matchAll(/targets\.([a-zA-Z]+)['"]/g)) {
            assert.ok(zh[match[1]], `missing Chinese key ${match[1]}`);
            assert.ok(en[match[1]], `missing English key ${match[1]}`);
        }
    }
});
