'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const settings = fs.readFileSync(path.join(__dirname, 'settings.js'), 'utf8');
const webshell = fs.readFileSync(path.join(__dirname, 'webshell.js'), 'utf8');
const escapeHtml = text => String(text == null ? '' : text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const decodeAttr = text => text.replace(/&(amp|lt|gt|quot|#39);/g, (_, key) => ({ amp: '&', lt: '<', gt: '>', quot: '"', '#39': "'" }[key]));

class Element {
    constructor() {
        this.value = '';
        this.innerHTML = '';
        this.textContent = '';
        this.className = '';
        this.children = [];
        this.dataset = {};
        this.style = {};
        this.classList = { add() {}, remove() {}, toggle() {}, contains: () => false };
    }
    appendChild(child) { this.children.push(child); return child; }
    contains(child) { return this.children.includes(child); }
    querySelector(selector) { return this.children.find(child => `.${child.className}` === selector) || null; }
    querySelectorAll() { return []; }
    addEventListener() {}
    remove() {}
}

function fixture(source = settings) {
    const elements = new Map();
    const requests = [];
    const document = {
        getElementById: id => elements.get(id) || null,
        querySelector: () => null,
        querySelectorAll: () => [],
        createElement: () => new Element(),
        addEventListener() {},
    };
    const context = vm.createContext({
        document, window: { addEventListener() {} }, console, URL, escapeHtml,
        setTimeout, clearTimeout, setInterval, clearInterval,
        localStorage: { getItem: () => null, setItem() {} },
        alert() {}, confirm: () => true,
        apiFetch: async (url, options) => {
            const body = JSON.parse(options.body);
            requests.push({ url, body });
            return { ok: true, json: async () => ({ success: true, model: 'fixture-model', models: ['fixture-model'], count: 1, ok: true, output: body.command || '' }) };
        },
    });
    vm.runInContext(source, context);
    const add = (id, value = '') => { const el = new Element(); el.value = value; elements.set(id, el); return el; };
    return { context, elements, requests, add };
}

test('model discovery identifies exact channel and scoped or inherited key', () => {
    const f = fixture();
    vm.runInContext("selectedAIChannelId = 'second';", f.context);
    f.add('openai-api-key', '********');
    f.add('openai-provider', 'openai_compatible');
    f.add('openai-base-url', 'https://second.example/v1');
    for (const [scope, prefix] of [['vision', 'vision'], ['hitlAudit', 'hitl-audit-model'], ['knowledgeEmbedding', 'knowledge-embedding']]) {
        const key = f.add(`${prefix}-api-key`, '********');
        f.add(`${prefix}-base-url`, 'https://scoped.example/v1');
        let creds = f.context.resolveModelListCredentials(scope);
        assert.equal(creds.channel_id, 'second');
        assert.equal(creds.credential_scope, scope);
        assert.equal(creds.api_key, '********');
        key.value = '';
        creds = f.context.resolveModelListCredentials(scope);
        assert.equal(creds.credential_scope, 'openai');
        assert.equal(creds.channel_id, 'second');
        assert.equal(creds.base_url, 'https://scoped.example/v1', 'backend must validate the final target, not just the main form URL');
    }
    const main = f.context.resolveModelListCredentials('openai');
    assert.equal(main.credential_scope, 'openai');
    assert.equal(main.channel_id, 'second');
});

test('model discovery still accepts a current result after adding credential metadata', async () => {
    const f = fixture();
    vm.runInContext("selectedAIChannelId = 'second'; populateModelSelect = (scope, models) => { window.models = models; };", f.context);
    f.add('openai-api-key', '********');
    f.add('openai-base-url', 'https://second.example/v1');
    f.add('openai-model', 'fixture-model');
    const result = f.add('fetch-openai-models-result');
    await f.context.fetchModelList('openai');
    assert.equal(f.requests[0].body.channel_id, 'second');
    assert.equal(f.requests[0].body.credential_scope, 'openai');
    assert.deepEqual(Array.from(f.context.window.models), ['fixture-model']);
    assert.notEqual(result.textContent, 'settingsBasic.modelsListFetching');
});

test('connection tests bind selected AI, vision and audit credentials', async () => {
    const f = fixture();
    vm.runInContext("selectedAIChannelId = 'second';", f.context);
    for (const [id, value] of [['openai-api-key', '********'], ['openai-base-url', 'https://second.example/v1'], ['openai-model', 'fixture-model'], ['vision-api-key', '********'], ['vision-model', 'fixture-vision'], ['hitl-audit-model-api-key', '********'], ['hitl-audit-model-name', 'fixture-audit']]) f.add(id, value);
    for (const id of ['test-openai-btn', 'test-openai-result', 'test-vision-result', 'test-hitl-audit-model-btn', 'test-hitl-audit-model-result']) f.add(id);
    await f.context.testOpenAIConnection();
    await f.context.testVisionConnection();
    await f.context.testHitlAuditModelConnection();
    assert.equal(f.requests[0].body.channel_id, 'second');
    assert.equal(f.requests[0].body.credential_scope, 'openai');
    assert.equal(f.requests[1].body.channel_id, 'second');
    assert.equal(f.requests[2].body.credential_scope, 'hitlAudit');
    f.elements.get('hitl-audit-model-api-key').value = '';
    await f.context.testHitlAuditModelConnection();
    assert.equal(f.requests[3].body.credential_scope, 'openai');
});

test('copying a saved channel never treats masked credentials as new secrets', () => {
    const f = fixture();
    vm.runInContext(`currentConfig = {ai: {default_channel:'one', channels:{one:{name:'One', api_key:'********', vision:{api_key:'********'}}}}}; selectedAIChannelId='one';
        readAIChannelFromMainForm = () => currentConfig.ai.channels.one;
        renderAIChannelSelect = () => {}; writeAIChannelToMainForm = () => {}; showAIChannelSaveHint = () => {};`, f.context);
    f.context.copyAIChannelFromForm();
    const copied = JSON.parse(vm.runInContext('JSON.stringify(currentConfig.ai.channels[selectedAIChannelId])', f.context));
    assert.equal(copied.api_key, '');
    assert.equal(copied.vision.api_key, '');
    assert.equal(vm.runInContext('currentConfig.ai.channels.one.api_key', f.context), '********');
});

test('WebShell form testing uses edited ID only for a masked password, batch probe keeps its own ID', async () => {
    const f = fixture(webshell);
    f.add('webshell-url', 'https://shell.example/test');
    const key = f.add('webshell-password', '********');
    f.add('webshell-edit-id', 'ws_edit');
    f.context.testWebshellConnection();
    assert.equal(f.requests[0].body.connection_id, 'ws_edit');
    key.value = 'new-password';
    f.context.testWebshellConnection();
    assert.equal(f.requests[1].body.connection_id, '');
    await f.context.probeWebshellConnection({ id: 'ws_batch', url: 'https://shell.example/batch', password: '********' });
    assert.equal(f.requests[2].body.connection_id, 'ws_batch');
    assert.equal(f.requests[2].body.password, '********');
});

function checkHandlers(html, expected) {
    assert.ok(!html.includes('<img'), 'untrusted text created HTML');
    assert.ok(!html.includes(' onmouseover='), 'untrusted text escaped an attribute');
    const calls = [];
    const sandbox = { event: { stopPropagation() {} }, pwned: false };
    for (const name of ['scrollToExternalMCP', 'scrollToExternalMCPTools', 'handleToolCheckboxChange', 'handleToolAlwaysVisibleChange', 'toggleExternalMCP', 'editExternalMCP', 'deleteExternalMCP', 'loadToolsList', 'changeToolsPageSize']) {
        sandbox[name] = (...args) => calls.push({ name, args });
    }
    for (const match of html.matchAll(/\bon(?:click|change)="([^"]*)"/g)) {
        vm.runInNewContext(decodeAttr(match[1]), sandbox);
    }
    assert.equal(sandbox.pwned, false);
    for (const [name, argument] of expected) {
        const call = calls.find(call => call.name === name);
        assert.ok(call, `Missing ${name} event`);
        assert.equal(call.args[name === 'loadToolsList' ? 1 : 0], argument);
    }
}

test('settings rendered tool, search and MCP inline handlers preserve hostile strings without execution', () => {
    const attacks = ["');globalThis.pwned=true;//", '\\");globalThis.pwned=true;//', '<img src=x onerror="globalThis.pwned=true">', '&quot;\'\n\r\u2028中文'];
    for (const value of attacks) {
        const f = fixture();
        const tools = f.add('tools-list');
        const external = f.add('external-mcp-list');
        vm.runInContext(`updateToolsStats = () => {}; allTools = ${JSON.stringify([{ name: value, external_mcp: value, is_external: true, enabled: true }])};`, f.context);
        f.context.renderToolsList();
        const row = tools.children[0].children[0].innerHTML;
        checkHandlers(row, [['scrollToExternalMCP', value], ['handleToolCheckboxChange', `${value}::${value}`], ['handleToolAlwaysVisibleChange', `${value}::${value}`]]);
        vm.runInContext(`toolsSearchKeyword = ${JSON.stringify(value)}; toolsPagination = {page:1, totalPages:3, total:60, pageSize:20};`, f.context);
        f.context.renderToolsPagination();
        checkHandlers(tools.children[1].innerHTML, [['loadToolsList', value]]);
        f.context.renderExternalMCPList({ [value]: { status: 'connected', tool_count: 1, config: { type: 'http' } } });
        checkHandlers(external.innerHTML, [['scrollToExternalMCPTools', value], ['toggleExternalMCP', value], ['editExternalMCP', value], ['deleteExternalMCP', value]]);
    }
});
