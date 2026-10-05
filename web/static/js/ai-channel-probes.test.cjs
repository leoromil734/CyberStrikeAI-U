'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const ui = require('./ai-channel-probes.js');
const chat = fs.readFileSync(path.join(__dirname, 'chat.js'), 'utf8');
const helper = fs.readFileSync(path.join(__dirname, 'ai-channel-probes.js'), 'utf8');
const translations = JSON.parse(fs.readFileSync(path.join(__dirname, '../i18n/zh-CN.json'), 'utf8'));
const english = JSON.parse(fs.readFileSync(path.join(__dirname, '../i18n/en-US.json'), 'utf8'));
const at = '2026-10-05T06:00:00Z';

class Element {
    constructor(tag = 'div') {
        this.tagName = tag.toUpperCase();
        this.children = [];
        this.parentNode = null;
        this.dataset = {};
        this.attributes = new Map();
        this.listeners = new Map();
        this.style = {};
        this.className = '';
        this.disabled = false;
        this._text = '';
        this._value = '';
        this.classList = {
            contains: name => this.className.split(/\s+/).includes(name),
            add: (...names) => { this.className = [...new Set([...this.className.split(/\s+/).filter(Boolean), ...names])].join(' '); },
            remove: (...names) => { this.className = this.className.split(/\s+/).filter(name => !names.includes(name)).join(' '); },
            toggle: (name, force) => {
                const enabled = force === undefined ? !this.classList.contains(name) : force;
                this.classList[enabled ? 'add' : 'remove'](name);
                return enabled;
            },
        };
    }
    get options() { return this.children.filter(child => child.tagName === 'OPTION'); }
    get value() { return this._value; }
    set value(value) { this._value = String(value); }
    get selectedIndex() { return this.options.findIndex(option => option.value === this.value); }
    get selected() { return this.parentNode?.value === this.value; }
    get textContent() { return this._text + this.children.map(child => child.textContent).join(''); }
    set textContent(value) { this._text = String(value); this.children = []; }
    get innerHTML() { return this._html || ''; }
    set innerHTML(value) { this._html = String(value); this.children = []; this._text = ''; }
    appendChild(child) {
        if (child.parentNode) child.parentNode.children = child.parentNode.children.filter(node => node !== child);
        child.parentNode = this;
        this.children.push(child);
        return child;
    }
    insertBefore(child, reference) {
        child.parentNode = this;
        const index = this.children.indexOf(reference);
        this.children.splice(index < 0 ? this.children.length : index, 0, child);
    }
    setAttribute(name, value) {
        this.attributes.set(name, String(value));
        if (name.startsWith('data-')) this.dataset[name.slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = String(value);
    }
    getAttribute(name) { return this.attributes.get(name) ?? null; }
    addEventListener(type, callback) {
        if (!this.listeners.has(type)) this.listeners.set(type, []);
        this.listeners.get(type).push(callback);
    }
    dispatchEvent(event) { for (const callback of this.listeners.get(event.type) || []) callback(event); }
    querySelectorAll(selector) {
        const matches = node => selector.startsWith('.') ? node.classList.contains(selector.slice(1)) : node.tagName === selector.toUpperCase();
        return this.children.flatMap(child => [...(matches(child) ? [child] : []), ...child.querySelectorAll(selector)]);
    }
    querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
    closest(selector) { return selector.startsWith('.') && this.classList.contains(selector.slice(1)) ? this : this.parentNode?.closest(selector); }
}

function loadFunction(context, name) {
    const start = chat.indexOf('function ' + name + '(');
    assert.ok(start >= 0, 'missing actual chat function: ' + name);
    const end = chat.indexOf('\n}', start) + 2;
    assert.ok(end > start, 'missing closing brace for chat function: ' + name);
    const prefix = chat.slice(start - 6, start) === 'async ' ? 'async ' : '';
    vm.runInContext(prefix + chat.slice(start, end), context, {filename: name + '.js'});
}

function fixture(storedId = '', options = {}) {
    const body = new Element('body');
    const panel = body.appendChild(new Element());
    panel.className = 'conversation-reasoning-card';
    const select = panel.appendChild(new Element('select'));
    select.id = 'chat-ai-channel-select';
    select.setAttribute('aria-describedby', 'existing-help');
    const elements = new Map([[select.id, select]]);
    const events = new Element();
    const requests = [];
    const storage = new Map(storedId ? [['cyberstrike-chat-ai-channel', storedId]] : []);
    const document = {
        createElement: tag => new Element(tag),
        getElementById: id => elements.get(id) || null,
        querySelectorAll: selector => body.querySelectorAll(selector),
        addEventListener: (...args) => events.addEventListener(...args),
        dispatchEvent: event => events.dispatchEvent(event),
    };
    const context = vm.createContext({
        document, Event, console: {warn() {}},
        localStorage: {getItem: key => storage.get(key) || null, setItem: (key, value) => storage.set(key, value), removeItem: key => storage.delete(key)},
        apiFetch: async (url, init) => { requests.push({url, init}); throw new Error('Unexpected API call'); },
        getCurrentTimeLocale: () => 'zh-CN',
        t: key => key.split('.').reduce((obj, name) => obj?.[name], translations) || key,
        updateChatReasoningSummary() {}, refreshConversationAILabels() {},
        syncAgentModeFromValue() {}, restoreChatReasoningControlsFromStorage() {}, syncReasoningRowVisibility() {},
        hasPermission: () => false,
    });
    context.window = context;
    vm.runInContext(chat.slice(chat.indexOf('const AGENT_MODE_STORAGE_KEY'), chat.indexOf('// 人机协同（HITL）会话级配置')), context);
    vm.runInContext('const sessionSettingsSelects = new Map();', context);
    if (options.helper !== false) vm.runInContext(helper, context, {filename: 'ai-channel-probes.js'});
    for (const name of ['sessionSettingsSelectLabel', 'syncSessionSettingsSelect', 'closeSessionSettingsSelect', 'closeAllSessionSettingsSelects', 'enhanceSessionSettingsSelect', 'refreshSessionSettingsSelects', 'normalizeChatAIChannelId', 'resolveChatAIChannelId', 'populateChatAIChannelSelect', 'loadChatAIChannels', 'selectedChatAIChannelId', 'currentChatAIChannelLabel', 'persistChatAIChannelPref', 'chatAgentModeIsEinoSingle', 'chatAgentModeIsEino', 'initChatAgentModeFromConfig']) loadFunction(context, name);
    const eventStart = chat.indexOf("document.addEventListener('ai-channel-probes-updated'");
    vm.runInContext(chat.slice(eventStart, chat.indexOf('// 保存输入框草稿到localStorage（防抖版本）', eventStart)), context);
    context.enhanceSessionSettingsSelect(select);
    const wrapper = select.parentNode;
    return {context, select, wrapper, elements, document, storage, requests, trigger: wrapper.querySelector('.session-settings-select-trigger'), menu: wrapper.querySelector('.session-settings-select-menu')};
}

const channelData = () => ({
    default_channel: 'ready', probes_available: true,
    channels: {
        ready: {name: '可用通道', model: 'same-model', probe: {status: 'ready', success: true, ttft_ms: 0, tested_at: at}},
        failed: {name: '失败通道', model: 'same-model', probe: {status: 'failed', success: false, ttft_ms: null, tested_at: at, error: '上游返回 HTTP 401，请检查模型权限、配额与服务地址'}},
        'stale-channel': {name: '已更改通道', model: 'new-model', probe: {status: 'ready', success: true, stale: true, ttft_ms: 123, tested_at: at}},
        untested: {name: '未测试通道', model: 'model', probe: {status: 'untested', ttft_ms: null}},
    },
});

function currentDetails(f) { return f.wrapper.querySelector('.ai-channel-probe-current'); }
function keyEvent(key) { return {type: 'keydown', key, preventDefault() {}, stopPropagation() {}}; }

test('shared presentation distinguishes all four statuses and never fabricates TTFT or a date', () => {
    const channels = channelData().channels;
    assert.equal(ui.describe(channels.ready).status, 'ready');
    assert.match(ui.describe(channels.ready).summary, /首 token 0 ms/);
    assert.match(ui.describe(channels.failed).details, /失败[\s\S]*测试时间[\s\S]*HTTP 401/);
    assert.doesNotMatch(ui.describe(channels.failed).details, /首 token/);
    assert.equal(ui.describe(channels['stale-channel']).status, 'stale');
    assert.match(ui.describe(channels['stale-channel']).details, /需重测[\s\S]*123 ms/);
    assert.equal(ui.describe(channels.untested).details, '未测试');
    assert.equal(ui.describe({}).details, '未测试');
    for (const invalid of [null, undefined, -1, '45', Infinity, NaN]) {
        const info = ui.describe({probe: {status: 'failed', ttft_ms: invalid, tested_at: 'invalid'}});
        assert.equal(info.ttft, null);
        assert.equal(info.testedAt, '');
        assert.doesNotMatch(info.details, /ms|Invalid Date/);
    }
    assert.equal(ui.describe({probe: {status: 'unexpected'}}).status, 'unknown');
    assert.match(ui.describe({probe: {status: 'unknown'}}).details, /测试记录加载失败/);
});

test('helper writes names, model names and bounded error details as text rather than HTML', () => {
    const unsafe = '<img src=x onerror=alert(1)>';
    const option = new Element('option');
    option.value = 'a';
    const channel = {name: unsafe, model: '<script>', probe: {status: 'failed', error: unsafe + 'x'.repeat(1000)}};
    ui.applyOption(option, channel);
    assert.equal(option.innerHTML, '');
    assert.match(option.textContent, /<img src=x/);
    assert.ok(ui.describe(channel).error.length <= 240);
    const element = new Element();
    ui.renderDetails(element, channel);
    assert.equal(element.innerHTML, '');
    assert.ok(element.textContent.includes(unsafe));
    assert.equal(element.dataset.aiProbeStatus, 'failed');
    assert.equal(ui.optionLabel(channel, 'a'), option.textContent);
});

test('sidebar displays default channel and persisted status, time and error in native and enhanced options', () => {
    const f = fixture('stale_channel');
    f.context.populateChatAIChannelSelect(channelData());
    assert.equal(f.select.value, 'stale-channel');
    assert.equal(f.select.options[0].value, '');
    assert.match(f.select.options[0].textContent, /跟随默认.*可用通道.*可用.*0 ms/);
    assert.match(f.trigger.textContent, /需重测/);
    assert.match(currentDetails(f).textContent, /需重测[\s\S]*123 ms[\s\S]*测试时间/);
    const failed = f.menu.children.find(item => item.dataset.aiProbeStatus === 'failed');
    assert.equal(failed.getAttribute('role'), 'option');
    assert.equal(failed.disabled, false, 'Probe failure must not disable model selection');
    assert.match(failed.textContent, /失败通道[\s\S]*失败[\s\S]*HTTP 401/);
    assert.match(failed.title, /测试时间/);
    assert.match(f.trigger.getAttribute('aria-describedby'), /chat-ai-channel-probe-details/);
    assert.match(f.select.getAttribute('aria-describedby'), /existing-help/);
    assert.equal(currentDetails(f).getAttribute('aria-live'), 'polite');
    assert.equal(f.requests.length, 0, 'Rendering persisted records must not issue requests');
});

test('keyboard and pointer selection still work, including selecting failed/untested models and following default', () => {
    const f = fixture();
    f.context.populateChatAIChannelSelect(channelData());
    f.select.addEventListener('change', () => f.context.persistChatAIChannelPref());
    f.trigger.dispatchEvent(keyEvent('End'));
    assert.equal(f.select.value, 'untested');
    assert.equal(f.storage.get('cyberstrike-chat-ai-channel'), 'untested');
    assert.equal(currentDetails(f).textContent, '未测试');
    const failed = f.menu.children.find(item => item.dataset.aiProbeStatus === 'failed');
    f.menu.dispatchEvent({type: 'click', target: failed, stopPropagation() {}});
    assert.equal(f.select.value, 'failed');
    assert.match(currentDetails(f).textContent, /HTTP 401/);
    f.trigger.dispatchEvent(keyEvent('Home'));
    assert.equal(f.select.value, '');
    assert.equal(f.storage.has('cyberstrike-chat-ai-channel'), false);
    assert.equal(f.context.currentChatAIChannelLabel(), '可用通道');
    assert.match(currentDetails(f).textContent, /可用/);
    f.trigger.dispatchEvent(keyEvent('Enter'));
    assert.equal(f.trigger.getAttribute('aria-expanded'), 'true');
    f.trigger.dispatchEvent(keyEvent('Escape'));
    assert.equal(f.trigger.getAttribute('aria-expanded'), 'false');
    assert.equal(f.requests.length, 0);
});

test('the helper is optional for older pages and empty or removed channels keep default selection', () => {
    const f = fixture('removed', {helper: false});
    f.context.populateChatAIChannelSelect(channelData());
    assert.equal(f.select.value, '');
    assert.equal(currentDetails(f).hidden, true);
    assert.equal(f.select.options.find(option => option.value === 'failed').textContent, '失败通道 · same-model');
    f.context.populateChatAIChannelSelect({channels: {}, probes_available: true});
    assert.equal(f.select.options.length, 1);
    assert.equal(f.select.value, '');
});

test('ordinary chat users load only the credential-free list, independently of admin configuration', async () => {
    const f = fixture();
    f.elements.set('agent-mode-wrapper', new Element());
    f.elements.set('agent-mode-select', new Element('select'));
    f.context.apiFetch = async (url, init) => {
        f.requests.push({url, init});
        assert.equal(url, '/api/config/ai-channels');
        assert.equal(init, undefined);
        return {ok: true, json: async () => channelData()};
    };
    await f.context.initChatAgentModeFromConfig();
    assert.equal(f.requests.length, 1);
    assert.match(f.trigger.textContent, /可用通道/);
});

test('loading a new saved result refreshes details; failures preserve models but mark records unknown', async () => {
    const f = fixture('failed');
    f.context.populateChatAIChannelSelect(channelData());
    const data = channelData();
    data.channels.failed.probe = {status: 'ready', ttft_ms: 32, tested_at: at};
    f.context.apiFetch = async (url, init) => {
        f.requests.push({url, init});
        return {ok: true, json: async () => data};
    };
    await f.context.loadChatAIChannels();
    assert.equal(f.select.value, 'failed');
    assert.match(currentDetails(f).textContent, /可用.*32 ms/);
    f.context.apiFetch = async () => ({ok: false});
    await f.context.loadChatAIChannels();
    assert.equal(f.select.options.length, 5);
    assert.equal(f.select.value, 'failed');
    assert.match(currentDetails(f).textContent, /测试记录加载失败/);
    assert.doesNotMatch(currentDetails(f).textContent, /32 ms|未测试/);
    assert.equal(f.requests[0].url, '/api/config/ai-channels');
});

test('late responses cannot replace a newer channel list or its probe status', async () => {
    const f = fixture();
    let release;
    const delayed = new Promise(resolve => { release = resolve; });
    f.context.apiFetch = () => delayed;
    const oldRequest = f.context.loadChatAIChannels();
    const fresh = channelData();
    fresh.channels.ready.probe.ttft_ms = 999;
    f.context.apiFetch = async () => ({ok: true, json: async () => fresh});
    await f.context.loadChatAIChannels();
    release({ok: true, json: async () => channelData()});
    await oldRequest;
    assert.match(currentDetails(f).textContent, /999 ms/);
});

test('language refresh rerenders saved data without fetching or losing the selected channel', () => {
    const f = fixture('failed');
    f.context.populateChatAIChannelSelect(channelData());
    f.context.t = key => key.split('.').reduce((obj, name) => obj?.[name], english) || key;
    f.document.dispatchEvent(new Event('languagechange'));
    assert.equal(f.select.value, 'failed');
    assert.match(currentDetails(f).textContent, /Failed|failed/);
    assert.equal(f.requests.length, 0);
});

test('settings refresh projects display fields and retrieves probe records rather than keeping credentials', async () => {
    const f = fixture('failed');
    const saved = channelData();
    f.context.apiFetch = async (url, init) => {
        f.requests.push({url, init});
        return {ok: true, json: async () => saved};
    };
    f.context.populateChatAIChannelSelect({default_channel: 'failed', channels: {
        failed: {name: '失败通道', model: 'same-model', api_key: 'secret', base_url: 'https://private.invalid', vision: {api_key: 'vision-secret'}},
    }});
    assert.match(currentDetails(f).textContent, /加载失败/);
    const local = vm.runInContext('JSON.stringify(chatAIChannels)', f.context);
    assert.doesNotMatch(local, /secret|api_key|base_url|vision/);
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(f.requests.map(request => request.url), ['/api/config/ai-channels']);
    assert.match(currentDetails(f).textContent, /HTTP 401/);
});

test('non-model session selectors keep their original labels and accessibility behavior', () => {
    const f = fixture();
    const other = f.wrapper.parentNode.appendChild(new Element('select'));
    other.id = 'chat-reasoning-mode';
    for (const value of ['default', 'on']) {
        const option = other.appendChild(new Element('option'));
        option.value = value;
        option.textContent = value;
    }
    other.value = 'default';
    f.context.enhanceSessionSettingsSelect(other);
    const wrapper = other.parentNode;
    const trigger = wrapper.querySelector('.session-settings-select-trigger');
    assert.equal(wrapper.querySelector('.ai-channel-probe-current'), null);
    assert.equal(trigger.getAttribute('aria-describedby'), null);
    trigger.dispatchEvent(keyEvent('End'));
    assert.equal(other.value, 'on');
    assert.match(trigger.textContent, /on/);
    assert.equal(f.requests.length, 0);
});

test('probe update events reload saved summaries only, with no new test or configuration request', async () => {
    const f = fixture();
    f.context.apiFetch = async (url, init) => {
        f.requests.push({url, init});
        return {ok: true, json: async () => channelData()};
    };
    f.document.dispatchEvent(new Event('ai-channel-probes-updated'));
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(f.requests.map(request => request.url), ['/api/config/ai-channels']);
    assert.ok(f.requests.every(request => request.init === undefined));
    assert.match(f.trigger.textContent, /可用通道/);
});
