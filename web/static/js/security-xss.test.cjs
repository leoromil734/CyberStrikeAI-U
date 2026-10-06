'use strict';
// 纯本地回归：不启动服务、不访问目标、不执行 C2 请求。
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const files = ['api-docs', 'assets', 'auth', 'c2', 'chat-files', 'chat', 'info-collect', 'knowledge', 'monitor', 'projects', 'roles', 'skills', 'tasks', 'vulnerability'];
const sources = Object.fromEntries(files.map(file => [file, fs.readFileSync(path.join(__dirname, file + '.js'), 'utf8').replace(/\r\n/g, '\n')]));
const payload = `中文📁'\" onpointerover=\"globalThis.__xss=1\" ><x-xss>&quot;&#39;\\`;
const textEscape = value => String(value ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const decode = value => String(value).replace(/&(amp|lt|gt|quot|#39|#10|#13);/g, (_, entity) => ({ amp: '&', lt: '<', gt: '>', quot: '"', '#39': "'", '#10': '\n', '#13': '\r' })[entity]);

function fn(file, name) {
    const match = sources[file].match(new RegExp('^([ \\t]*)(?:async )?function ' + name + '\\([^]*?^\\1}', 'm'));
    assert.ok(match, file + ': ' + name + ' must come from production source');
    return match[0];
}
function loadFunctions(ctx, file, names) {
    vm.runInContext(names.map(name => fn(file, name)).join('\n'), ctx, { filename: file + '.js' });
}
function loadEscapers(ctx, file) {
    if (file === 'monitor') {
        loadFunctions(ctx, file, ['escapeHtmlLocal', 'escapeAttrLocal', 'escapeJsString', 'escapeJsStringAttr']);
        ctx.escapeHtml = ctx.escapeHtmlLocal;
        return;
    }
    const htmlFile = ['assets', 'chat-files'].includes(file) ? 'auth' : file;
    loadFunctions(ctx, htmlFile, ['escapeHtml']);
    const attrName = file === 'assets' ? 'assetEscapeAttr' : file === 'chat-files' ? 'chatFilesEscapeAttr' : 'escapeAttr';
    loadFunctions(ctx, file, [attrName]);
    if (sources[file].includes('function escapeJsString(')) loadFunctions(ctx, file, ['escapeJsString', 'escapeJsStringAttr']);
}

// 对本回归产生的标签做一次 HTML 属性解析；实体只解码一次，再交给 JS VM。
// 不是浏览器实现，真实浏览器端到端验证仍应由集成测试覆盖。
function tags(html) {
    return Array.from(html.matchAll(/<([a-z][\w:-]*)\b((?:[^<>"']|"[^"]*"|'[^']*')*)>/gi), match => {
        const attrs = {};
        for (const a of match[2].matchAll(/([^\s=/>]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g)) {
            const name = a[1].toLowerCase();
            assert.ok(!(name in attrs), 'duplicate HTML attribute: ' + name);
            attrs[name] = decode(a[2] ?? a[3] ?? a[4] ?? '');
        }
        return { tag: match[1].toLowerCase(), attrs };
    });
}
function assertSafeMarkup(html) {
    assert.ok(!html.includes('<x-xss>'), 'payload must not create an element');
    const parsed = tags(html);
    for (const tag of parsed) {
        assert.notEqual(tag.tag, 'x-xss');
        assert.ok(!('onpointerover' in tag.attrs), 'payload must not introduce an event attribute');
    }
    return parsed;
}
class Element {
    constructor(tag = 'div', attrs = {}) {
        this.tagName = tag; this.attrs = { ...attrs }; this.style = {}; this.dataset = {};
        this.className = attrs.class || ''; this.children = []; this.parentElement = null; this._html = ''; this._text = '';
        this.classList = { add: name => { this.className += ' ' + name; }, remove() {}, contains: name => this.className.split(/\s+/).includes(name) };
    }
    set innerHTML(value) { this._html = String(value); this._text = ''; this.children = []; }
    get innerHTML() { return this._html || textEscape(this._text); }
    set textContent(value) { this._text = String(value ?? ''); this._html = ''; this.children = []; }
    get textContent() { return this._text + this.children.map(child => child.textContent).join(''); }
    appendChild(child) { child.parentElement = this; this.children.push(child); return child; }
    setAttribute(name, value) { this.attrs[name] = String(value); }
    getAttribute(name) { return this.attrs[name] ?? null; }
    contains(child) { return child === this || this.children.some(item => item.contains(child)); }
    matches(selector) {
        if (selector.startsWith('.')) return this.classList.contains(selector.slice(1));
        const attrs = [...selector.matchAll(/\[([^=\]]+)(?:="([^"]*)")?\]/g)];
        return attrs.length > 0 && attrs.every(([, key, value]) => key in this.attrs && (value === undefined || this.attrs[key] === value));
    }
    closest(selector) { return this.matches(selector) ? this : this.parentElement?.closest(selector) || null; }
    querySelector(selector) { return this.children.find(child => child.matches(selector)) || this.children.map(child => child.querySelector(selector)).find(Boolean) || null; }
    querySelectorAll() { return []; }
    addEventListener() {}
    getBoundingClientRect() { return { right: 0, bottom: 0 }; }
}
function fixture(extra = {}) {
    const elements = new Map(), listeners = new Map();
    const document = {
        readyState: 'loading', documentElement: { dataset: {} },
        createElement: tag => new Element(tag), createElementNS: (_, tag) => new Element(tag),
        getElementById: id => elements.get(id) || null, querySelectorAll: () => [],
        addEventListener: (type, listener) => { if (!listeners.has(type)) listeners.set(type, []); listeners.get(type).push(listener); }
    };
    const window = { addEventListener() {}, t: key => key, innerWidth: 1024, innerHeight: 768 };
    const ctx = vm.createContext({ document, window, console, URL, URLSearchParams, Set, Map,
        localStorage: { getItem: () => null, setItem() {} }, setTimeout: () => 0, clearTimeout() {},
        setInterval: () => 0, clearInterval() {}, _t: key => key, _tPlain: key => key,
        apiFetch: () => { throw new Error('This regression must never send a request'); }, ...extra });
    const element = id => { const node = new Element(); elements.set(id, node); return node; };
    function dispatch(type, target, key) {
        const event = { target, key, defaultPrevented: false, preventDefault() { this.defaultPrevented = true; }, stopPropagation() {} };
        for (const listener of listeners.get(type) || []) listener(event);
        return event;
    }
    return { ctx, elements, element, dispatch };
}

for (const file of files) {
    test(file + ': JavaScript 语法保持有效', () => assert.doesNotThrow(() => new vm.Script(sources[file], { filename: file + '.js' })));
    if (file === 'chat') continue;
    test(file + ': 属性编码处理单双引号、实体、HTML 和 Unicode', () => {
        const { ctx } = fixture(); loadEscapers(ctx, file);
        const attr = ctx.assetEscapeAttr || ctx.chatFilesEscapeAttr || ctx.escapeAttrLocal || ctx.escapeAttr;
        for (const value of [payload, "O'Reilly", '&quot;;globalThis.__xss=1;//', '";globalThis.__xss=1;//', '</textarea><x-xss>', '正常📁']) {
            for (const quote of ['"', "'"]) {
                const parsed = assertSafeMarkup(`<div data-value=${quote}${attr(value)}${quote}></div>`);
                assert.equal(parsed[0].attrs['data-value'], value);
                assert.deepEqual(Object.keys(parsed[0].attrs), ['data-value']);
            }
            if (ctx.escapeJsStringAttr) {
                const parsed = assertSafeMarkup(`<button onclick="capture(${ctx.escapeJsStringAttr(value)})"></button>`);
                const calls = []; ctx.capture = arg => calls.push(arg);
                vm.runInContext(parsed[0].attrs.onclick, ctx);
                assert.deepEqual(calls, [value]);
                assert.equal(ctx.__xss, undefined);
            }
        }
    });
}

test('JSON.stringify 单独使用不是 HTML 属性编码', () => {
    const broken = `<button onclick='capture(${JSON.stringify("x' onpointerover='globalThis.__xss=1")})'></button>`;
    assert.ok(tags(broken)[0].attrs.onpointerover);
});

test('聊天分组标签保留图标、名称及本地模型标签，旧恶意数据仅作为文本', () => {
    const { ctx } = fixture({ currentConversationId: '', currentGroupId: '',
        conversationGroupMappingCache: { c: 'g' }, groupsCache: [{ id: 'g', name: payload, icon: '<x-xss>' }],
        safeTruncateText: text => text, formatConversationTimestamp: () => 'time',
        appendConversationAIBadges: (_, parent) => { const badge = new Element(); badge.className = 'local-model-badge'; parent.appendChild(badge); } });
    loadFunctions(ctx, 'chat', ['createConversationListItemWithMenu']);
    const item = ctx.createConversationListItemWithMenu({ id: 'c', title: payload }, false);
    const tag = item.querySelector('.conversation-group-tag');
    assert.equal(tag.querySelector('.group-tag-name').textContent, payload);
    assert.equal(tag.querySelector('.group-tag-icon').textContent, '<x-xss>');
    assert.equal(tag._html, '');
    assert.ok(item.querySelector('.local-model-badge'));
});

test('移动分组菜单保留分组和点击动作，同时禁止名称进入 innerHTML', async () => {
    const moved = [], groups = [{ id: 'target', name: payload, icon: '<x-xss>' }];
    const f = fixture({ groupsCache: groups, contextMenuConversationId: 'c', currentGroupId: '', conversationGroupMappingCache: {},
        submenuVisible: false, submenuLoading: false, clearSubmenuHideTimeout() {},
        apiFetch: async () => ({ ok: true, json: async () => groups }), moveConversationToGroup: (...args) => moved.push(args) });
    const menu = f.element('move-to-group-submenu');
    loadFunctions(f.ctx, 'chat', ['showMoveToGroupSubmenu']);
    await f.ctx.showMoveToGroupSubmenu();
    const groupItem = menu.children[0];
    assert.equal(groupItem.children[0].textContent, payload);
    assert.ok(!groupItem.innerHTML.includes(payload));
    groupItem.onclick(); assert.deepEqual(moved, [['c', 'target']]);
    assert.equal(menu.children.length, 2, '新增分组入口仍然存在');
});

function c2Fixture() {
    const f = fixture(); vm.runInContext(sources.c2, f.ctx, { filename: 'c2.js' });
    f.c2 = f.ctx.window.C2; return f;
}
test('C2 真实文件列表通过 data 属性委托打开/下载，特殊文件名无损传递', () => {
    const f = c2Fixture(), list = f.element('c2-file-list'), calls = [];
    f.c2.openDirectory = name => calls.push(['open', name]);
    f.c2.downloadFile = name => calls.push(['download', name]);
    f.c2.renderFileList('d\tdrwx\t0\t' + payload + '\nf\t-rw-\t10\t' + payload);
    const buttons = assertSafeMarkup(list.innerHTML).filter(tag => tag.attrs['data-c2-file-action']);
    assert.equal(buttons.length, 2);
    for (const button of buttons) {
        assert.ok(!('onclick' in button.attrs));
        assert.equal(button.attrs['data-c2-file-name'], payload);
        f.dispatch('click', new Element(button.tag, button.attrs));
    }
    assert.deepEqual(calls, [['open', payload], ['download', payload]]);
});

test('C2 所有动态操作走白名单委托，未知动作不执行，复制数据不作为代码', () => {
    const f = c2Fixture(), calls = [];
    const actions = { 'session-note-edit': 'beginEditSessionNote', 'session-note-save': 'saveSessionNote',
        'listener-start': 'startListener', 'listener-stop': 'stopListener', 'listener-edit': 'editListener',
        'listener-delete': 'deleteListener', 'listener-save': 'saveListener', 'session-select': 'selectSession',
        'session-delete': 'deleteSessionRecord', 'session-sleep': 'setSessionSleep', 'session-kill': 'killSession',
        'session-tasks-refresh': 'loadSessionTasks', 'task-view': 'viewTask', 'event-view': 'viewEvent',
        'event-delete': 'deleteEventById', 'profile-delete': 'deleteProfile' };
    for (const [action, method] of Object.entries(actions)) {
        f.c2[method] = id => calls.push([action, id]);
        const button = new Element('button', { 'data-c2-action': action, 'data-c2-id': payload });
        f.dispatch('click', button.appendChild(new Element('svg')));
    }
    f.ctx.window.__c2DownloadPayload = id => calls.push(['payload-download', id]);
    f.dispatch('click', new Element('button', { 'data-c2-action': 'payload-download', 'data-c2-id': payload }));
    f.dispatch('click', new Element('button', { 'data-c2-action': 'constructor', 'data-c2-id': payload }));
    assert.equal(calls.length, Object.keys(actions).length + 1);
    assert.ok(calls.every(([, id]) => id === payload));
    f.c2.copyText = value => calls.push(['copy', value]);
    f.dispatch('click', new Element('button', { 'data-c2-copy-value': payload }));
    assert.deepEqual(calls.at(-1), ['copy', payload]);
});

test('C2 表格按钮与复选框不会误触父行；键盘直接激活行仍正常', () => {
    const f = c2Fixture(), calls = [];
    f.c2.viewTask = id => calls.push(['view', id]); f.c2.deleteTaskById = id => calls.push(['delete', id]);
    const row = new Element('tr', { role: 'button', 'data-c2-action': 'task-view', 'data-c2-id': payload });
    const cell = row.appendChild(new Element('td', { 'data-c2-stop-action': '1' }));
    const checkbox = cell.appendChild(new Element('input'));
    const button = cell.appendChild(new Element('button', { 'data-c2-task-action': 'delete', 'data-task-id': payload }));
    f.dispatch('click', checkbox); f.dispatch('keydown', checkbox, ' ');
    assert.deepEqual(calls, []);
    f.dispatch('click', button); assert.deepEqual(calls, [['delete', payload]]);
    f.dispatch('keydown', row, 'Enter'); assert.deepEqual(calls.at(-1), ['view', payload]);
});

test('C2 任务及事件表格的 ID、命令、消息和删除操作均编码', () => {
    const f = c2Fixture();
    f.c2.syncTasksToolbar = () => {}; f.c2.syncEventsToolbar = () => {};
    const tasks = f.element('c2-task-list'), events = f.element('c2-event-list');
    f.c2.tasks = [{ id: payload, sessionId: payload, taskType: 'shell', status: 'queued', payload: { command: payload }, createdAt: '2026-10-06' }];
    f.c2.events = [{ id: payload, sessionId: payload, taskId: payload, message: payload, level: 'info', category: 'session', createdAt: '2026-10-06' }];
    f.c2.renderTasks(); f.c2.renderEvents();
    for (const [node, action] of [[tasks, 'task-view'], [events, 'event-view']]) {
        const parsed = assertSafeMarkup(node.innerHTML);
        const row = parsed.find(tag => tag.attrs['data-c2-action'] === action);
        assert.ok(row, action + ' row exists'); assert.equal(row.attrs['data-c2-id'], payload);
        assert.ok(!('onclick' in row.attrs)); assert.ok(!('onkeydown' in row.attrs));
        assert.ok(parsed.some(tag => tag.attrs.title === payload));
    }
});

test('知识项属性与编辑删除动作保留原值且无注入', () => {
    const { ctx } = fixture({ formatTime: () => '' }); loadEscapers(ctx, 'knowledge');
    loadFunctions(ctx, 'knowledge', ['renderKnowledgeItemCard']);
    const parsed = assertSafeMarkup(ctx.renderKnowledgeItemCard({ id: payload, title: payload, category: payload, content: payload }));
    assert.equal(parsed[0].attrs['data-id'], payload); assert.equal(parsed[0].attrs['data-category'], payload);
    assert.ok(parsed.some(tag => tag.attrs.title === payload));
    const calls = []; ctx.editKnowledgeItem = id => calls.push(id); ctx.deleteKnowledgeItem = id => calls.push(id);
    for (const tag of parsed.filter(tag => tag.attrs.onclick)) vm.runInContext(tag.attrs.onclick, ctx);
    assert.deepEqual(calls, [payload, payload]); assert.equal(ctx.__xss, undefined);
});

test('API 文档参数、textarea 示例与三个测试按钮按各自上下文编码', () => {
    const { ctx } = fixture(); loadEscapers(ctx, 'api-docs'); loadFunctions(ctx, 'api-docs', ['escapeId', 'renderTestSection']);
    const body = { value: '</textarea><x-xss>' + payload };
    const html = ctx.renderTestSection({ method: 'post', path: '/' + payload, operationId: payload,
        parameters: [{ in: 'path', name: payload, description: payload }, { in: 'query', name: payload, description: payload, schema: { default: payload } }],
        requestBody: { content: { 'application/json': { schema: { example: body } } } } });
    const parsed = assertSafeMarkup(html);
    assert.ok(html.includes(textEscape(JSON.stringify(body, null, 2))));
    assert.equal(parsed.filter(tag => tag.tag === 'input')[0].attrs.placeholder, payload);
    assert.equal(parsed.filter(tag => tag.tag === 'input')[1].attrs.value, payload);
    const calls = []; ctx.event = {};
    ctx.testAPI = (...args) => calls.push(args); ctx.copyCurlCommand = (_, ...args) => calls.push(args); ctx.clearTestResult = id => calls.push([id]);
    for (const tag of parsed.filter(tag => tag.attrs.onclick)) vm.runInContext(tag.attrs.onclick, ctx);
    assert.deepEqual(calls[0], ['POST', '/' + payload, payload]);
    assert.deepEqual(calls[1], ['POST', '/' + payload]); assert.equal(ctx.__xss, undefined);
});

test('本地批量任务详情保留模型、证据和原始多行输入且属性安全', () => {
    const f = fixture({ escapeHtml: textEscape, hasPermission: () => true });
    vm.runInContext(sources.tasks, f.ctx, { filename: 'tasks.js' });
    const message = payload + '\nsecond line\r\nliteral\\n';
    const task = { id: payload, conversationId: payload, message, status: 'blocked', result: payload, aiChannelId: 'model-id' };
    const queue = { id: payload, status: 'paused', tasks: [task] }; f.ctx.queue = queue;
    vm.runInContext('batchQueuesState.currentQueue = queue; batchQueuesState.currentQueueId = queue.id;', f.ctx);
    const parsed = assertSafeMarkup(f.ctx.renderBatchDetailTasks(queue));
    const article = parsed.find(tag => tag.tag === 'article');
    assert.equal(article.attrs['data-queue-id'], payload); assert.equal(article.attrs['data-task-id'], payload);
    assert.equal(article.attrs['data-task-message'], message);
    assert.ok(parsed.some(tag => tag.attrs.class === 'batch-task-model-select'));
    assert.ok(parsed.some(tag => tag.attrs['data-task-evidence'] === payload));
});

test('漏洞列表恶意 ID、项目和严重程度安全渲染，四个卡片动作保留原值', () => {
    const f = fixture({ vulnT: key => key, vulnSeverityLabel: value => value, vulnDateLocale: () => 'en-US',
        vulnerabilityFilters: { id: '' }, buildVulnerabilityStatusPicker: () => '',
        vulnAIProvenanceBadges: () => '', vulnAIProvenanceFields: () => '', vulnDetailProjectField: () => '',
        initVulnerabilityStatusPickers() {}, initVulnerabilityProjectBindSelects() {}, restoreExpandedVulnerabilityDetails() {} });
    const list = f.element('vulnerabilities-list');
    loadEscapers(f.ctx, 'vulnerability');
    loadFunctions(f.ctx, 'vulnerability', ['renderVulnerabilities', 'vulnDetailField', 'vulnDetailConversationField', 'vulnNarrativeSection']);
    for (const value of [payload, '\";globalThis.__xss=1;//', '&quot;;globalThis.__xss=1;//', "O'Reilly📁\\path"]) {
        f.ctx.renderVulnerabilities([{ id: value, project_id: value, title: value, severity: value,
            description: value, evidence: value, created_at: '2026-10-06T00:00:00Z' }]);
        const parsed = assertSafeMarkup(list.innerHTML);
        const card = parsed.find(tag => tag.attrs.id === 'vulnerability-card-' + value);
        assert.ok(card, 'card ID must survive one HTML entity decode');
        assert.equal(card.attrs['data-vuln-id'], value);
        assert.equal(card.attrs.class, 'vulnerability-card severity-' + value);
        assert.deepEqual(Object.keys(card.attrs).sort(), ['class', 'data-vuln-id', 'id']);
        const facts = parsed.find(tag => tag.attrs.class === 'vulnerability-related-facts');
        assert.equal(facts.attrs['data-project-id'], value);
        assert.equal(facts.attrs['data-vuln-id'], value);
        assert.ok(list.innerHTML.includes(textEscape(value)), 'visible payload remains escaped text');
        const calls = [];
        const actions = ['toggleVulnerabilityDetails', 'downloadVulnerabilityAsMarkdown', 'editVulnerability', 'deleteVulnerability'];
        for (const action of actions) f.ctx[action] = id => calls.push([action, id]);
        f.ctx.event = { stopPropagation() {} };
        const handlers = parsed.filter(tag => actions.some(action => tag.attrs.onclick?.startsWith(action + '(')));
        assert.equal(handlers.length, 4, 'all original card actions remain available');
        for (const tag of handlers) vm.runInContext(tag.attrs.onclick, f.ctx);
        assert.deepEqual(calls, actions.map(action => [action, value]));
        assert.equal(f.ctx.__xss, undefined, 'injected JavaScript never executes');
    }
});

test('漏洞复制字段和打开对话中的引号、实体不会成为代码', () => {
    const { ctx } = fixture({ vulnT: key => key }); loadEscapers(ctx, 'vulnerability');
    loadFunctions(ctx, 'vulnerability', ['vulnDetailField', 'vulnDetailConversationField']);
    const calls = []; ctx.event = {}; ctx.vulnerabilityCopyEncoded = (_, encoded) => calls.push(decodeURIComponent(encoded));
    ctx.openVulnerabilityConversation = id => calls.push(id);
    for (const html of [ctx.vulnDetailField('label', payload, true), ctx.vulnDetailConversationField(payload)]) {
        for (const tag of assertSafeMarkup(html).filter(tag => tag.attrs.onclick)) vm.runInContext(tag.attrs.onclick, ctx);
    }
    assert.deepEqual(calls, [payload, payload, payload]); assert.equal(ctx.__xss, undefined);
});

test('FOFA 结果属性、链接和操作参数安全，URL 编码中的单引号也不进入事件代码', () => {
    const els = { thead: new Element('thead'), tbody: new Element('tbody') };
    const f = fixture({ getFofaFormElements: () => els, getInfoCollectProvider: () => 'fofa',
        infoCollectState: { selectedRowIndexes: new Set(), hiddenFields: new Set() },
        updateSelectedMeta() {}, saveHiddenFieldsToStorage() {}, setFofaMeta() {}, buildInfoCollectResultsMeta: () => '',
        renderFofaColumnsPanel() {}, syncSelectAllCheckbox() {} });
    loadEscapers(f.ctx, 'info-collect');
    loadFunctions(f.ctx, 'info-collect', ['renderFofaResults', 'inferTargetFromRow', 'normalizeHttpLink']);
    const row = { host: 'https://example.invalid/' + payload, title: payload };
    f.ctx.renderFofaResults({ fields: ['host', 'title'], results: [row] });
    const parsed = assertSafeMarkup(els.tbody.innerHTML);
    assert.equal(parsed.find(tag => tag.tag === 'a').attrs.href, row.host);
    assert.equal(parsed.find(tag => tag.attrs['data-field'] === 'title').attrs['data-full'], payload);
    const calls = []; f.ctx.event = { stopPropagation() {} };
    f.ctx.copyFofaTargetEncoded = value => calls.push(decodeURIComponent(value));
    f.ctx.scanFofaRow = value => calls.push(JSON.parse(decodeURIComponent(value)));
    for (const tag of parsed.filter(tag => tag.attrs['data-fofa-target'] || tag.attrs['data-fofa-row'])) {
        f.ctx.__target = { dataset: { fofaTarget: tag.attrs['data-fofa-target'], fofaRow: tag.attrs['data-fofa-row'] } };
        vm.runInContext('(function(){' + tag.attrs.onclick + '}).call(__target)', f.ctx);
    }
    assert.deepEqual(calls, [row.host, row]);
    assert.equal(f.ctx.normalizeHttpLink('javascript:alert(1)'), '');
    assert.equal(f.ctx.__xss, undefined);
});

test('项目图关系 ID 同时满足 HTML 属性和 JavaScript 字符串上下文', () => {
    const { ctx } = fixture({ tp: key => key }); loadEscapers(ctx, 'projects');
    loadFunctions(ctx, 'projects', ['getGraphEdgesForFact', 'isSyntheticGraphEdge', 'renderGraphEdgesListHtml']);
    const html = ctx.renderGraphEdgesListHtml('self', { edges: [{ id: payload, source: 'self', target: payload, type: payload }] }, payload);
    const parsed = assertSafeMarkup(html); assert.equal(parsed[0].attrs['data-edge-id'], payload);
    const calls = []; ctx.focusProjectFactGraphEdge = id => calls.push(id);
    vm.runInContext(parsed[0].attrs.onclick, ctx);
    assert.deepEqual(calls, [payload]); assert.equal(ctx.__xss, undefined);
});

test('角色名称及图标安全展示，编辑删除功能仍接收原始名称', () => {
    const f = fixture({ roles: [{ name: payload, icon: '<x-xss>', description: payload, tools: [] }],
        rolesSearchKeyword: '', sortRoles: value => value, rolePlainDescription: role => role.description });
    const list = f.element('roles-list'); loadEscapers(f.ctx, 'roles'); loadFunctions(f.ctx, 'roles', ['renderRolesList']);
    f.ctx.renderRolesList(); const parsed = assertSafeMarkup(list.innerHTML);
    const calls = []; f.ctx.editRole = value => calls.push(value); f.ctx.deleteRole = value => calls.push(value);
    for (const tag of parsed.filter(tag => tag.attrs.onclick)) vm.runInContext(tag.attrs.onclick, f.ctx);
    assert.deepEqual(calls, [payload, payload]); assert.equal(f.ctx.__xss, undefined);
});

test('监控执行列表的操作参数与 ID 按上下文编码，详情和终止动作不丢失', () => {
    const rows = [];
    const f = fixture({ monitorState: { selectedExecutions: new Set() }, getStatusText: value => value,
        formatExecutionDuration: () => '1s', formatMonitorToolName: value => value, monitorRenderKey: JSON.stringify,
        updateBatchActionsState() {}, reconcileMonitorExecutionRows: (_, entries) => { rows.push(...entries); return []; } });
    const container = f.element('monitor-executions');
    const table = { querySelector: () => new Element() };
    container.querySelector = selector => selector === '.monitor-table-container' ? { querySelector: () => table } : null;
    loadEscapers(f.ctx, 'monitor'); loadFunctions(f.ctx, 'monitor', ['renderMonitorExecutions']);
    f.ctx.renderMonitorExecutions([{ id: payload, toolName: payload, status: 'running' }]);
    assert.equal(rows.length, 1);
    const parsed = assertSafeMarkup(rows[0].html); assert.equal(parsed[0].attrs['data-execution-id'], payload);
    const calls = []; for (const name of ['toggleExecutionSelection', 'showMCPDetail', 'cancelMCPToolExecution', 'deleteExecution']) f.ctx[name] = id => calls.push([name, id]);
    for (const tag of parsed) {
        const handler = tag.attrs.onclick || tag.attrs.onchange;
        if (handler) vm.runInContext(handler, f.ctx);
    }
    assert.equal(calls.length, 4); assert.ok(calls.every(([, id]) => id === payload));
    assert.equal(f.ctx.__xss, undefined);
});

test('API 参数说明与请求体描述仅作为文本，数字默认值仍保留', () => {
    const { ctx } = fixture(); loadEscapers(ctx, 'api-docs');
    loadFunctions(ctx, 'api-docs', ['renderParameters', 'renderRequestBody', 'renderTestSection', 'escapeId']);
    assertSafeMarkup(ctx.renderParameters({ parameters: [{ name: payload, schema: { type: payload } }] }));
    assertSafeMarkup(ctx.renderRequestBody({ requestBody: { description: payload } }));
    const html = ctx.renderTestSection({ method: 'get', path: '/', parameters: [{ in: 'query', name: 'n', schema: { type: 'number', default: 0 } }] });
    assert.equal(tags(html).find(tag => tag.tag === 'input').attrs.value, '0');
});

test('补丁重点输出点保持使用正确上下文编码，动态 C2 事件不内联值', () => {
    assert.doesNotMatch(sources.c2, /on(?:click|keydown)=[^\n]*\$\{(?:JSON\.stringify|[lsp]\.id|tid|eid)/);
    assert.doesNotMatch(sources.knowledge, /writeText\('\$\{escapeHtml/);
    assert.doesNotMatch(sources.projects, /onclick=[^\n]*JSON\.stringify/);
    assert.match(sources.roles, /handleRoleToolCheckboxChange\(\$\{escapeJsStringAttr\(toolKey\)\}/);
    assert.match(sources.skills, /data-skill-tree-path="\$\{escapeAttr\(path\)\}/);
    assert.match(sources['info-collect'], /data-full="\$\{escapeAttr\(text\)\}/);
    assert.match(sources.assets, /value="\$\{assetEscapeAttr\(project.id\)\}/);
    assert.match(sources['chat-files'], /title="\$\{chatFilesEscapeAttr\(pathForTitle\)\}/);
    assert.match(sources.monitor, /toggleExecutionSelection\(\$\{jsExecId\}, this.checked\)/);
});
