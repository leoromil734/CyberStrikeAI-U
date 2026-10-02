const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

class Element {
    constructor(tag = 'div') { this.tag = tag; this.children = []; this.value = ''; this.hidden = false; this.disabled = false; this.listeners = {}; this.attributes = new Map(); this._text = ''; }
    set textContent(value) { this._text = String(value); this.children = []; }
    get textContent() { return this._text + this.children.map(child => child.textContent).join(''); }
    set innerHTML(_) { throw new Error('Remembered content must never be rendered as HTML'); }
    setAttribute(name, value) { this.attributes.set(name, String(value)); }
    getAttribute(name) { return this.attributes.get(name) || null; }
    append(...children) { this.children.push(...children); }
    replaceChildren(...children) { this.children = children; this._text = ''; }
    addEventListener(name, handler) { this.listeners[name] = handler; }
    querySelectorAll(tag) { return this.children.flatMap(child => [...(child.tag === tag ? [child] : []), ...child.querySelectorAll(tag)]); }
    querySelector(tag) { return this.querySelectorAll(tag)[0] || null; }
    scrollIntoView() {}
    click() {}
    remove() {}
}
const languages = Object.fromEntries(['zh-CN', 'en-US'].map(lang => [lang, JSON.parse(fs.readFileSync(path.join(__dirname, `../i18n/${lang}.json`), 'utf8'))]));
function fixture(fetch, permissions = ['experience:read']) {
    const elements = new Map();
    const calls = [];
    const notifications = [];
    const rbacRoots = [];
    const listeners = {};
    let language = 'zh-CN';
    const document = {
        getElementById(id) { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); },
        createElement(tag) { return new Element(tag); }, createElementNS(_, tag) { return new Element(tag); }, body: new Element('body'),
        addEventListener(name, handler) { listeners[name] = handler; },
    };
    document.getElementById('experience-detail').hidden = true;
    const context = { document, URLSearchParams, URL, JSON, console, setTimeout: () => 1,
        window: {
            t: (key, opts = {}) => {
                const text = key.split('.').reduce((obj, part) => obj?.[part], languages[language]) || key;
                return text.replace(/\{\{(\w+)\}\}/g, (_, name) => String(opts[name] ?? ''));
            },
            hasPermission: permission => permissions.includes(permission), notifyApiError: message => notifications.push(message),
            applyRBACToUI: root => rbacRoots.push(root),
        },
        apiFetch: async (url, options) => { calls.push([url, options]); return fetch(url, options); },
        readApiError: async response => (await response.json()).error || 'request failed',
    };
    vm.createContext(context);
    vm.runInContext(fs.readFileSync(path.join(__dirname, 'experience.js'), 'utf8'), context);
    return { manager: context.window.ExperienceMemory, elements, calls, document, notifications, rbacRoots, changeLanguage: lang => { language = lang; listeners.languagechange(); } };
}
const response = data => ({ ok: true, json: async () => data });
const entry = { id: 'memory-id', revision: 1, status: 'verified', scope: 'shared', content: { kind: 'workflow', title: '<script>unsafe()</script>', summary: '<img src=x onerror=unsafe()>', conditions: {}, steps: ['reference data'], verification: 'expected output' } };
const tick = () => new Promise(resolve => setImmediate(resolve));
const all = element => [element, ...element.children.flatMap(all)];
const byClass = (root, name) => all(root).find(node => (node.className || '').split(' ').includes(name));

test('remembered content is displayed only as text, including metadata and accessible labels', async () => {
    const malicious = { ...entry, scope: '<img onerror=unsafe()>', content: { ...entry.content, kind: '<svg onload=unsafe()>' } };
    const f = fixture(async () => response({ items: [malicious] }));
    await f.manager.refresh();
    const section = f.elements.get('experience-list').children[0];
    assert.equal(section.querySelector('h3').textContent, entry.content.title);
    assert.equal(byClass(section, 'experience-item-summary').textContent, entry.content.summary);
    assert.ok(section.textContent.includes(malicious.scope));
    assert.ok(section.textContent.includes(malicious.content.kind));
    assert.equal(section.querySelector('button').getAttribute('aria-label'), `查看与审核：${entry.content.title}`);
});

test('raw evidence uses a scoped experience endpoint and encoded IDs and project scope', async () => {
    const f = fixture(async url => url.includes('/evidence/') ? response({ execution: { result: '<script>unsafe()</script>' } }) : response({ entry, evidence: [{ execution_id: '../private?key=x', role: 'validation' }] }));
    f.document.getElementById('experience-project').value = 'project & one';
    await f.manager.open(entry.id);
    const button = f.elements.get('experience-evidence').querySelector('button');
    await button.listeners.click();
    assert.equal(f.calls[1][0], '/api/experiences/memory-id/evidence/' + encodeURIComponent('../private?key=x') + '?project_id=' + encodeURIComponent('project & one'));
    assert.ok(!f.calls[1][0].startsWith('/api/monitor/'));
    assert.ok(f.elements.get('experience-detail-json').textContent.includes('<script>unsafe()</script>'));
    assert.equal(f.rbacRoots.at(-1), f.elements.get('experience-detail'));
});

test('mutation actions respect front-end permissions', async () => {
    const f = fixture(async () => response({ entry, evidence: [] }));
    await f.manager.open(entry.id);
    const before = f.calls.length;
    f.manager.save(); f.manager.review(); f.manager.exportSkill(); f.manager.confirmOutcome(); f.manager.newProposal();
    assert.equal(f.calls.length, before);
    assert.equal(f.elements.get('experience-export').disabled, true);
});

test('stale list responses cannot overwrite newer filters or counts', async () => {
    const pending = [];
    const f = fixture(() => new Promise(resolve => pending.push(resolve)));
    const first = f.manager.refresh();
    const second = f.manager.refresh();
    pending[1](response({ items: [{ ...entry, content: { ...entry.content, title: 'newest' } }] }));
    await second;
    pending[0](response({ items: [entry, entry] }));
    await first;
    assert.equal(f.elements.get('experience-list').querySelector('h3').textContent, 'newest');
    assert.equal(f.elements.get('experience-stat-count').textContent, '1');
});

test('overview counts describe the accessible page and labels are localized', async () => {
    const f = fixture(async () => response({ items: [entry, { ...entry, status: 'candidate', scope: 'private' }, { ...entry, status: 'needs_review', scope: 'project' }, { ...entry, status: 'deprecated', scope: 'private' }] }));
    await f.manager.refresh();
    for (const [id, count] of Object.entries({ count: '4', verified: '1', review: '2', shared: '1' })) assert.equal(f.elements.get(`experience-stat-${id}`).textContent, count);
    const list = f.elements.get('experience-list');
    assert.ok(list.textContent.includes('条件内已验证'));
    assert.ok(list.textContent.includes('跨项目共享'));
    assert.ok(list.textContent.includes('工作流'));
    assert.ok(list.textContent.includes('版本 r1'));
});

test('loading clears stale pagination and unavailable counts; failure is text-only and retryable', async () => {
    let resolve;
    let fail = false;
    const f = fixture(() => fail ? new Promise(done => { resolve = done; }) : response({ items: [entry] }));
    await f.manager.refresh();
    fail = true;
    const loading = f.manager.refresh();
    assert.equal(f.elements.get('experience-list').getAttribute('aria-busy'), 'true');
    assert.equal(f.elements.get('experience-stat-count').textContent, '—');
    assert.equal(f.elements.get('experience-pagination').hidden, true);
    resolve({ ok: false, json: async () => ({ error: '<script>error()</script>' }) });
    await loading;
    assert.equal(f.elements.get('experience-list').getAttribute('aria-busy'), 'false');
    assert.ok(f.elements.get('experience-list').textContent.includes('<script>error()</script>'));
    assert.equal(f.elements.get('experience-list').querySelector('button').textContent, '重新加载');
    fail = false;
    await f.elements.get('experience-list').querySelector('button').listeners.click();
    await tick();
    assert.equal(f.elements.get('experience-stat-count').textContent, '1');
});

test('empty filters can be reset without granting write access or sending mutations', async () => {
    const f = fixture(async () => response({ items: [] }));
    ['experience-status', 'experience-kind', 'experience-project', 'experience-query'].forEach(id => { f.document.getElementById(id).value = 'filter'; });
    await f.manager.refresh();
    assert.equal(f.elements.get('experience-stat-count').textContent, '0');
    assert.ok(f.elements.get('experience-list').textContent.includes('当前筛选下没有可访问的经验'));
    await f.elements.get('experience-list').querySelector('button').listeners.click();
    assert.ok(f.calls.every(([, opts]) => opts.method === 'GET'));
    const params = new URL(f.calls.at(-1)[0], 'http://fixture.invalid').searchParams;
    for (const key of ['status', 'kind', 'query', 'project_id']) assert.equal(params.get(key), '');
    assert.equal(params.get('offset'), '0');
});

test('filter query names and 25-entry offset pagination stay unchanged', async () => {
    const items = Array.from({ length: 25 }, (_, i) => ({ ...entry, id: String(i) }));
    const f = fixture(async () => response({ items }));
    const filters = { 'experience-status': 'verified', 'experience-kind': 'tool_repair', 'experience-project': 'one & two', 'experience-query': 'title <query>' };
    Object.entries(filters).forEach(([id, text]) => { f.document.getElementById(id).value = text; });
    await f.manager.refresh();
    const params = new URL(f.calls[0][0], 'http://fixture.invalid').searchParams;
    assert.deepEqual(Object.fromEntries(params), { limit: '25', offset: '0', status: 'verified', kind: 'tool_repair', query: 'title <query>', project_id: 'one & two' });
    const next = f.elements.get('experience-pagination').querySelectorAll('button')[1];
    assert.equal(next.disabled, false);
    next.listeners.click(); await tick();
    assert.equal(new URL(f.calls[1][0], 'http://fixture.invalid').searchParams.get('offset'), '25');
    assert.equal(f.elements.get('experience-list-meta').textContent, '本页第 26–50 条');
    const previous = f.elements.get('experience-pagination').querySelectorAll('button')[0];
    previous.listeners.click(); await tick();
    assert.equal(new URL(f.calls[2][0], 'http://fixture.invalid').searchParams.get('offset'), '0');
});

test('language changes redraw labels without refetching or discarding unsaved JSON', async () => {
    const f = fixture(async url => response(url.includes('?limit=') ? { items: [entry] } : { entry, evidence: [] }));
    await f.manager.refresh(); await f.manager.open(entry.id);
    const editor = f.elements.get('experience-editor'); editor.value = 'unsaved JSON';
    const before = f.calls.length;
    f.changeLanguage('en-US');
    assert.ok(f.elements.get('experience-list').textContent.includes('Verified within conditions'));
    assert.ok(f.elements.get('experience-list').textContent.includes('Across projects'));
    assert.ok(f.elements.get('experience-list-meta').textContent.includes('Records 1–1'));
    assert.equal(editor.value, 'unsaved JSON');
    assert.equal(f.calls.length, before);
    assert.equal(f.elements.get('experience-evidence-count').textContent, '0 evidence records');
});

test('new candidates retain their JSON template while existing-only controls are unavailable', () => {
    const f = fixture(async () => response({}), ['experience:read', 'experience:write', 'experience:review', 'experience:export']);
    f.document.getElementById('experience-project').value = 'project-one';
    f.manager.newProposal();
    const body = JSON.parse(f.elements.get('experience-editor').value);
    assert.equal(body.origin_project_id, 'project-one');
    assert.equal(body.content.kind, 'workflow');
    assert.deepEqual(body.evidence, []);
    assert.equal(f.elements.get('experience-history').disabled, true);
    assert.equal(f.elements.get('experience-export').disabled, true);
    assert.equal(f.elements.get('experience-review-fields').hidden, true);
    assert.equal(f.elements.get('experience-review-draft-hint').hidden, false);
    assert.equal(f.calls.length, 0);
    f.manager.close(); assert.equal(f.elements.get('experience-detail').hidden, true);
});

test('saving and reviewing retain the original endpoints, revision and payload fields', async () => {
    const f = fixture(async url => response(url.includes('?limit=') ? { items: [entry] } : { ...entry, entry, evidence: [] }), ['experience:read', 'experience:write', 'experience:review']);
    await f.manager.open(entry.id);
    f.elements.get('experience-editor').value = JSON.stringify({ content: entry.content, evidence: [], origin_project_id: 'origin-one' });
    f.manager.save(); await tick();
    const save = f.calls.find(([, opts]) => opts.method === 'PUT');
    assert.equal(save[0], '/api/experiences/memory-id');
    assert.equal(JSON.parse(save[1].body).revision, 1);
    assert.equal(JSON.parse(save[1].body).origin_project_id, 'origin-one');
    f.document.getElementById('experience-review-status').value = 'needs_review';
    f.document.getElementById('experience-review-scope').value = 'project';
    f.document.getElementById('experience-review-note').value = 'checked evidence';
    f.manager.review(); await tick();
    const review = f.calls.find(([url]) => url.endsWith('/review'));
    assert.equal(review[1].method, 'POST');
    assert.deepEqual(JSON.parse(review[1].body), { revision: 1, status: 'needs_review', scope: 'project', note: 'checked evidence' });
});

test('revision history, ZIP export and confirmed outcomes retain their original contracts', async () => {
    const f = fixture(async url => url.includes('/skill') ? { ok: true, blob: async () => new Blob(['fixture ZIP bytes']) } : response(url.includes('?limit=') ? { items: [entry] } : { entry, evidence: [] }), ['experience:read', 'experience:review', 'experience:export']);
    f.document.getElementById('experience-project').value = 'project & one';
    await f.manager.open(entry.id);
    f.manager.history(); await tick();
    assert.ok(f.calls.some(([url, opts]) => url === '/api/experiences/memory-id/revisions?project_id=project%20%26%20one' && opts.method === 'GET'));
    f.manager.exportSkill(); await tick();
    assert.ok(f.calls.some(([url, opts]) => url === '/api/experiences/memory-id/skill?project_id=project%20%26%20one' && opts.method === 'GET'));
    const link = f.document.body.querySelector('a');
    assert.equal(link.download, 'experience-memory-id-r1.zip');
    assert.ok(link.href.startsWith('blob:'));
    const outcome = { revision: 1, execution_id: 'execution-one', result: 'inconclusive', note: 'checked conditions', environment: { project_id: 'project & one' } };
    f.elements.get('experience-outcome').value = JSON.stringify(outcome);
    f.manager.confirmOutcome(); await tick();
    const confirmed = f.calls.find(([url]) => url.endsWith('/confirmed-outcomes'));
    assert.equal(confirmed[1].method, 'POST');
    assert.deepEqual(JSON.parse(confirmed[1].body), outcome);
});

test('Chinese and English experience translation keys stay aligned', () => {
    const zh = languages['zh-CN'].experience;
    const en = languages['en-US'].experience;
    assert.deepEqual(Object.keys(zh).sort(), Object.keys(en).sort());
    const html = fs.readFileSync(path.join(__dirname, '../../templates/index.html'), 'utf8');
    for (const match of html.matchAll(/data-i18n="experience\.([^"]+)"/g)) {
        assert.ok(zh[match[1]], `missing Chinese key ${match[1]}`);
        assert.ok(en[match[1]], `missing English key ${match[1]}`);
    }
});
