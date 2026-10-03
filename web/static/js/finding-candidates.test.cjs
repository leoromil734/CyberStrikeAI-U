'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, 'projects.js'), 'utf8');
const template = fs.readFileSync(path.join(__dirname, '../../templates/index.html'), 'utf8');
const languages = Object.fromEntries(['zh-CN', 'en-US'].map(lang => [lang, JSON.parse(fs.readFileSync(path.join(__dirname, '../i18n', lang + '.json'), 'utf8'))]));
const response = data => ({ ok: true, json: async () => data });
const escape = value => String(value ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
const tick = () => new Promise(resolve => setImmediate(resolve));
function deferred() { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; }

function fixture(fetcher = async () => response({ candidates: [], limit: 100, offset: 0 })) {
    let lang = 'zh-CN';
    const elements = new Map(), calls = [], storageWrites = [], headerUpdates = [];
    function element(id, extra = {}) {
        const attributes = new Map();
        const node = { innerHTML: '', textContent: '', value: '', checked: false, open: false, style: {}, dataset: {},
            setAttribute: (name, value) => attributes.set(name, String(value)),
            getAttribute: name => attributes.get(name), ...extra };
        elements.set(id, node);
        return node;
    }
    const context = { console, AbortController, URLSearchParams, setTimeout, clearTimeout,
        localStorage: { getItem: () => null, setItem: (...args) => storageWrites.push(args) },
        document: { readyState: 'loading', addEventListener() {}, getElementById: id => elements.get(id) || null },
        escapeHtml: escape,
        t: (key, options = {}) => {
            const text = key.split('.').reduce((part, name) => part?.[name], languages[lang]) || key;
            return String(text).replace(/{{(\w+)}}/g, (_, name) => String(options[name] ?? ''));
        },
        apiFetch: async (url, options) => {
            calls.push({ url, options });
            return url.includes('/finding-candidates?') ? fetcher(url, options) : response({ id: 'project', name: 'Project' });
        }
    };
    context.window = context;
    vm.createContext(context);
    vm.runInContext(source, context, { filename: 'projects.js' });
    const body = element('project-finding-candidates-body');
    const disclosure = element('project-finding-candidates');
    const formalTable = element('project-vulns-tbody', { innerHTML: 'formal-vulnerabilities' });
    const formalCount = element('project-stats-vulns', { textContent: '7' });
    context.refreshProjectHeaderStats = async () => { headerUpdates.push('header'); };
    function setProject(id) {
        context.chosenProject = id;
        vm.runInContext('currentProjectId = chosenProject', context);
        context.resetProjectFindingCandidates();
    }
    setProject('A');
    return { context, elements, element, body, disclosure, formalTable, formalCount, calls, storageWrites, headerUpdates, setProject,
        state: vm.runInContext('projectFindingCandidatesState', context),
        changeLanguage: next => { lang = next; context.renderProjectFindingCandidates(); } };
}

const candidate = { id: 'candidate-one', title: 'Public metadata', target: 'https://example.com/manifest.json', risk_family: 'information_exposure',
    state: 'observed', priority: 20, reason: 'Only public metadata was observed', evidence_refs: ['artifact:one', { path: 'manifest.json', tool: 'recon' }], updated_at: '2026-10-02T10:00:00Z' };

test('原生可折叠候选区与正式漏洞独立，展开才加载，重开复用当前页且所有请求只读', async () => {
    const f = fixture(async () => response({ candidates: [candidate], limit: 100, offset: 0 }));
    assert.match(template, /<details id="project-finding-candidates"[^>]*ontoggle="onProjectFindingCandidatesToggle\(this\)"/);
    assert.match(template, /不计入正式漏洞数量/);
    assert.equal(f.calls.length, 0);
    assert.match(f.body.innerHTML, /展开后按需加载/);
    f.context.onProjectFindingCandidatesToggle(f.disclosure);
    assert.equal(f.calls.length, 0);
    f.disclosure.open = true;
    f.context.onProjectFindingCandidatesToggle(f.disclosure);
    await tick();
    assert.equal(f.calls.length, 1);
    assert.equal(f.calls[0].url, '/api/projects/A/finding-candidates?limit=100&offset=0');
    assert.equal(f.calls[0].options.method, 'GET');
    assert.match(f.body.innerHTML, /仅观察（非漏洞）/);
    assert.match(f.body.innerHTML, /公开元数据.*不等于漏洞/);
    assert.match(f.body.innerHTML, /本页 1 个候选（1–1）/);
    assert.match(f.body.innerHTML, /artifact:one/);
    assert.match(f.body.innerHTML, /manifest\.json/);
    assert.doesNotMatch(f.body.innerHTML, /createVulnerability|promote|validateCandidate|setCandidateState/);
    f.disclosure.open = false;
    f.context.onProjectFindingCandidatesToggle(f.disclosure);
    f.disclosure.open = true;
    f.context.onProjectFindingCandidatesToggle(f.disclosure);
    assert.equal(f.calls.length, 1);
    assert.equal(f.formalTable.innerHTML, 'formal-vulnerabilities');
    assert.equal(f.formalCount.textContent, '7');
    assert.deepEqual(f.headerUpdates, []);
    assert.deepEqual(f.storageWrites, []);
});

test('六种候选状态全部本地化；validated 仍是候选，不提供自动升格按钮', async () => {
    const candidates = ['observed', 'tentative', 'waiting', 'blocked', 'rejected', 'validated'].map((state, i) => ({ ...candidate, id: 'candidate-' + i, state }));
    const f = fixture(async () => response({ candidates, limit: 100, offset: 0 }));
    await f.context.loadProjectFindingCandidates();
    for (const state of candidates.map(item => item.state)) assert.match(f.body.innerHTML, new RegExp('project-candidate-state--' + state));
    assert.match(f.body.innerHTML, /初步线索（待验证）|等待条件|验证受阻|已排除/);
    assert.match(f.body.innerHTML, /已验证候选（非自动入库）/);
    const count = f.calls.length;
    f.changeLanguage('en-US');
    assert.match(f.body.innerHTML, /Observed only \(not a vulnerability\)/);
    assert.match(f.body.innerHTML, /Validated candidate \(not automatically recorded\)/);
    assert.doesNotMatch(f.body.innerHTML, /projects\.candidate|common\.prevPage|common\.nextPage/);
    assert.equal(f.calls.length, count);
    assert.equal(f.formalCount.textContent, '7');
});

test('候选 ID/标题/目标/类别/优先级/原因/证据和未知状态全部转义且引用不是可执行链接', async () => {
    const unsafe = '<img src=x onerror=unsafe()>';
    const f = fixture(async () => response({ candidates: [{ ...candidate, id: unsafe, title: unsafe, target: 'javascript:unsafe()',
        risk_family: unsafe, priority: unsafe, reason: unsafe, evidence_refs: [unsafe, { raw: '<script>unsafe()</script>' }],
        state: unsafe, updated_at: 'invalid' }], limit: 100, offset: 0 }));
    f.setProject('a/b ?&');
    await f.context.loadProjectFindingCandidates();
    assert.equal(f.calls[0].url, '/api/projects/a%2Fb%20%3F%26/finding-candidates?limit=100&offset=0');
    assert.doesNotMatch(f.body.innerHTML, /<img|<script>|href="javascript:|onclick="unsafe\(|Invalid Date/);
    assert.match(f.body.innerHTML, /&lt;img/);
    assert.match(f.body.innerHTML, /&lt;script/);
    assert.match(f.body.innerHTML, /project-candidate-state--unknown/);
    assert.match(f.body.innerHTML, /未知候选状态/);
    for (const state of ['__proto__', 'constructor', 'toString']) assert.equal(f.context.projectCandidateStatePresentation(state).tone, 'unknown');
});

test('按 limit/offset 分页，无 total 时只标本页数量，整页后允许试读下一页而不声称有更多', async () => {
    const f = fixture(async url => {
        const offset = Number(new URL('https://test.invalid' + url).searchParams.get('offset'));
        return response({ candidates: offset === 0 ? Array.from({ length: 100 }, (_, i) => ({ ...candidate, id: String(i) })) : [], limit: 100, offset });
    });
    await f.context.loadProjectFindingCandidates();
    assert.equal(f.state.hasNext, true);
    assert.match(f.body.innerHTML, /本页 100 个候选（1–100）/);
    assert.match(f.body.innerHTML, /不代表仍有记录/);
    assert.doesNotMatch(f.body.innerHTML, /共 100 个候选/);
    await f.context.changeProjectFindingCandidatesPage(1);
    assert.equal(f.calls[1].url, '/api/projects/A/finding-candidates?limit=100&offset=100');
    assert.equal(f.state.hasNext, false);
    assert.match(f.body.innerHTML, /本页没有更多候选/);
    const count = f.calls.length;
    await f.context.changeProjectFindingCandidatesPage(1);
    assert.equal(f.calls.length, count);
    await f.context.changeProjectFindingCandidatesPage(-1);
    assert.equal(f.calls.at(-1).url, '/api/projects/A/finding-candidates?limit=100&offset=0');
    await f.context.refreshProjectFindingCandidates();
    assert.equal(f.calls.at(-1).url, '/api/projects/A/finding-candidates?limit=100&offset=0');
    assert.ok(f.calls.every(call => call.options.method === 'GET'));
});

test('采用有效服务端游标/页大小，异常游标回退且列表最多 100 条', async () => {
    const pages = [
        { candidates: Array.from({ length: 50 }, () => candidate), limit: 50, offset: 10 },
        { candidates: [candidate], limit: -1, offset: -1 },
        { candidates: Array.from({ length: 120 }, () => candidate), limit: 10000, offset: 0 }
    ];
    const f = fixture(async () => response(pages.shift()));
    await f.context.loadProjectFindingCandidates();
    assert.equal(f.state.offset, 10);
    assert.equal(f.state.limit, 50);
    await f.context.changeProjectFindingCandidatesPage(1);
    assert.equal(f.calls[1].url, '/api/projects/A/finding-candidates?limit=50&offset=60');
    assert.equal(f.state.offset, 60);
    assert.equal(f.state.limit, 50);
    f.setProject('B');
    await f.context.loadProjectFindingCandidates();
    assert.equal(f.state.candidates.length, 100);
    assert.equal(f.state.limit, 100);
});

for (const status of [404, 405, 501, 403, 401, 500]) {
    test('候选接口 HTTP ' + status + ' 独立提示而非空候选或正式漏洞故障，GET 可重试', async () => {
        let fail = true;
        const f = fixture(async () => fail ? { ok: false, status } : response({ candidates: [], limit: 100, offset: 0 }));
        await f.context.loadProjectFindingCandidates();
        const expected = [404, 405, 501].includes(status) ? 'unavailable' : [401, 403].includes(status) ? 'forbidden' : 'error';
        assert.equal(f.state.status, expected);
        assert.equal(f.body.getAttribute('aria-busy'), 'false');
        assert.match(f.body.innerHTML, /refreshProjectFindingCandidates/);
        assert.doesNotMatch(f.body.innerHTML, /该项目暂无候选/);
        assert.equal(f.formalTable.innerHTML, 'formal-vulnerabilities');
        fail = false;
        await f.context.refreshProjectFindingCandidates();
        assert.equal(f.state.status, 'ready');
        assert.match(f.body.innerHTML, /该项目暂无候选/);
        assert.ok(f.calls.every(call => call.options.method === 'GET'));
    });
}

test('加载时清除旧页与数量；网络异常和无效返回不伪装空数据', async () => {
    const pending = deferred();
    let count = 0;
    const f = fixture(() => count++ === 0 ? response({ candidates: [candidate], limit: 100, offset: 0 }) : pending.promise);
    await f.context.loadProjectFindingCandidates();
    const loading = f.context.refreshProjectFindingCandidates();
    assert.equal(f.body.getAttribute('aria-busy'), 'true');
    assert.doesNotMatch(f.body.innerHTML, /Public metadata|本页 1 个/);
    pending.resolve({ ok: true, json: async () => { throw new Error('bad JSON'); } });
    await loading;
    assert.equal(f.state.status, 'error');
    assert.match(f.body.innerHTML, /加载失败/);
    for (const data of [{}, { candidates: null }, { candidates: [null] }, { candidates: [[]] }]) {
        const invalid = fixture(async () => response(data));
        await invalid.context.loadProjectFindingCandidates();
        assert.equal(invalid.state.status, 'error');
        assert.doesNotMatch(invalid.body.innerHTML, /暂无候选/);
    }
    const offline = fixture(async () => { throw new Error('offline'); });
    await offline.context.loadProjectFindingCandidates();
    assert.equal(offline.state.status, 'error');
});

for (const result of ['success', 'failure', 'late-json']) {
    test('项目 A→B→A 后的旧候选 ' + result + ' 响应不能覆盖新的视图且旧请求被取消', async () => {
        const old = deferred(), lateBody = deferred();
        let count = 0;
        const f = fixture(() => count++ === 0 ? old.promise : response({ candidates: [{ ...candidate, title: 'Newest A' }], limit: 100, offset: 0 }));
        const first = f.context.loadProjectFindingCandidates();
        if (result === 'late-json') {
            old.resolve({ ok: true, json: () => lateBody.promise });
            await tick();
        }
        f.disclosure.open = true;
        f.setProject('B');
        assert.equal(f.disclosure.open, false);
        assert.equal(f.calls[0].options.signal.aborted, true);
        assert.equal(f.state.status, 'idle');
        f.setProject('A');
        await f.context.loadProjectFindingCandidates();
        if (result === 'success') old.resolve(response({ candidates: [{ ...candidate, title: 'Old A' }], limit: 100, offset: 0 }));
        if (result === 'failure') old.resolve({ ok: false, status: 500 });
        if (result === 'late-json') lateBody.resolve({ candidates: [{ ...candidate, title: 'Old A' }], limit: 100, offset: 0 });
        await first;
        assert.equal(f.state.status, 'ready');
        assert.equal(f.state.candidates[0].title, 'Newest A');
        assert.match(f.body.innerHTML, /Newest A/);
        assert.doesNotMatch(f.body.innerHTML, /Old A|加载失败/);
        assert.equal(f.state.controller, null);
    });
}

test('真实 selectProject 立即清除并折叠候选区，不等待项目元数据再隔离旧数据', async () => {
    const old = deferred();
    const f = fixture(() => old.promise);
    const loading = f.context.loadProjectFindingCandidates();
    f.disclosure.open = true;
    for (const id of ['project-edit-name', 'project-edit-description', 'project-edit-scope']) f.element(id);
    for (const name of ['setActiveProjectId', 'syncAllProjectsFilterSelects', 'renderProjectsSidebar', 'updateProjectsDetailVisibility',
        'renderProjectDetailTitle', 'renderProjectDetailMeta', 'renderProjectDetailDesc', 'updateProjectStatusPill', 'switchProjectTab']) f.context[name] = () => {};
    const selection = f.context.selectProject('B');
    assert.equal(f.state.projectId, 'B');
    assert.equal(f.state.status, 'idle');
    assert.equal(f.disclosure.open, false);
    assert.equal(f.calls[0].options.signal.aborted, true);
    old.resolve(response({ candidates: [candidate], limit: 100, offset: 0 }));
    await Promise.all([selection, loading]);
    assert.equal(f.state.candidates.length, 0);
    assert.doesNotMatch(f.body.innerHTML, /Public metadata/);
    assert.equal(f.calls.filter(call => call.url.includes('/finding-candidates?')).length, 1);
});

test('候选发现静态与动态文案在中英文中齐全，插值参数保持一致', () => {
    const keys = Object.keys(languages['zh-CN'].projects).filter(key => key.startsWith('candidate'));
    const englishKeys = Object.keys(languages['en-US'].projects).filter(key => key.startsWith('candidate'));
    assert.deepEqual(keys.sort(), englishKeys.sort());
    const parameters = text => [...text.matchAll(/{{(\w+)}}/g)].map(match => match[1]).sort();
    for (const key of keys) {
        assert.equal(typeof languages['en-US'].projects[key], 'string', key);
        assert.deepEqual(parameters(languages['zh-CN'].projects[key]), parameters(languages['en-US'].projects[key]), key);
    }
});
