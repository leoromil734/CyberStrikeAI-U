'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, 'settings.js'), 'utf8');
const translations = JSON.parse(fs.readFileSync(path.join(__dirname, '../i18n/zh-CN.json'), 'utf8'));

class Element {
    constructor(tag = 'div') {
        this.tagName = tag.toUpperCase();
        this.children = [];
        this.parentNode = null;
        this.dataset = {};
        this.style = {};
        this.attributes = new Map();
        this.listeners = new Map();
        this.className = '';
        this.disabled = false;
        this.checked = false;
        this._value = '';
        this._text = '';
        this.classList = {
            contains: name => this.className.split(/\s+/).includes(name),
            add: (...names) => { this.className = [...new Set([...this.className.split(/\s+/).filter(Boolean), ...names])].join(' '); },
            remove: (...names) => { this.className = this.className.split(/\s+/).filter(name => !names.includes(name)).join(' '); },
            toggle: (name, force) => {
                const on = force === undefined ? !this.classList.contains(name) : force;
                this.classList[on ? 'add' : 'remove'](name);
                return on;
            },
        };
    }
    get options() { return this.children.filter(child => child.tagName === 'OPTION'); }
    get value() { return this._value; }
    set value(value) { this._value = String(value); }
    get selectedIndex() { return this.options.findIndex(option => option.value === this.value); }
    set selectedIndex(index) { this.value = this.options[index]?.value || ''; }
    get index() { return this.parentNode?.options?.indexOf(this) ?? -1; }
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
        if (name.startsWith('data-')) this.dataset[name.slice(5).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())] = String(value);
        if (name === 'class') this.className = String(value);
    }
    getAttribute(name) { return this.attributes.get(name) ?? null; }
    addEventListener(type, handler) {
        if (!this.listeners.has(type)) this.listeners.set(type, []);
        this.listeners.get(type).push(handler);
    }
    dispatchEvent(event) { for (const handler of this.listeners.get(event.type) || []) handler(event); }
    querySelectorAll(selector) {
        const matches = child => selector.startsWith('.')
            ? child.classList.contains(selector.slice(1))
            : child.tagName === selector.toUpperCase();
        return this.children.flatMap(child => [...(matches(child) ? [child] : []), ...child.querySelectorAll(selector)]);
    }
    querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
    closest(selector) { return selector.startsWith('.') && this.classList.contains(selector.slice(1)) ? this : this.parentNode?.closest(selector); }
}

const firstChannel = {
    name: '通道甲', provider: 'openai_compatible', base_url: 'https://gateway-a.invalid/v1', api_key: 'fixture-a', model: 'model-a',
    max_total_tokens: 500000, max_completion_tokens: 16384,
    reasoning: { mode: 'auto', effort: '', profile: 'auto', allow_client_reasoning: true },
};
const secondChannel = {
    name: '通道乙', provider: 'claude', base_url: 'https://gateway-b.invalid', api_key: 'fixture-b', model: 'model-b',
    max_total_tokens: 800000, max_completion_tokens: 32768,
    reasoning: { mode: 'on', effort: 'xhigh', profile: 'output_config_effort', allow_client_reasoning: false, extra_request_fields: { custom_option: 'kept' } },
};
const clone = value => JSON.parse(JSON.stringify(value));

function fixture(channels = { a: firstChannel, b: secondChannel }) {
    const elements = new Map();
    const requests = [];
    const body = new Element('body');
    const document = {
        body, addEventListener() {},
        getElementById: id => elements.get(id) || null,
        createElement: tag => new Element(tag), createElementNS: (_, tag) => new Element(tag),
    };
    const context = vm.createContext({
        document, console, URL, setTimeout, clearTimeout, setInterval, clearInterval, Event,
        localStorage: { getItem: () => null, setItem() {} },
        window: { addEventListener() {}, t: key => key.split('.').reduce((part, name) => part?.[name], translations) || key },
        requirePermission: () => true,
        alert: message => { throw new Error(message); }, confirm: () => true,
        apiFetch: async (url, options) => { requests.push({ url, options }); throw new Error('Unexpected network request'); },
    });
    const add = (id, tag = 'input', options) => {
        const element = new Element(tag);
        element.id = id;
        elements.set(id, element);
        body.appendChild(element);
        for (const [value, text] of options || []) {
            const option = new Element('option');
            option.value = value;
            option.textContent = text;
            element.appendChild(option);
        }
        if (options?.length) element.value = options[0][0];
        return element;
    };
    add('ai-channel-select', 'select');
    for (const id of ['ai-channel-name', 'openai-api-key', 'openai-base-url', 'openai-model', 'openai-max-total-tokens', 'openai-max-completion-tokens', 'openai-reasoning-allow-client']) add(id);
    add('openai-provider', 'select', [['openai_compatible', 'OpenAI 兼容'], ['claude', 'Claude']]);
    add('openai-reasoning-mode', 'select', [['auto', '自动'], ['on', '开启'], ['off', '关闭']]);
    add('openai-reasoning-effort', 'select', [['', '不指定'], ['low', 'low'], ['medium', 'medium'], ['high', 'high'], ['max', 'max'], ['xhigh', 'xhigh']]);
    add('openai-reasoning-profile', 'select', [['auto', 'auto'], ['openai_compat', 'openai_compat'], ['deepseek_compat', 'deepseek_compat'], ['output_config_effort', 'output_config_effort']]);
    add('openai-model-select', 'select', [['', '请选择模型'], ['model-a', 'model-a'], ['model-b', 'model-b']]);
    for (const id of ['ai-channel-save-hint', 'ai-channel-editor-title', 'ai-channel-editor-meta']) add(id, 'div');
    vm.runInContext(source, context, { filename: 'settings.js' });
    vm.runInContext(`currentConfig = ${JSON.stringify({ ai: { default_channel: 'a', channels: clone(channels) } })}; selectedAIChannelId = 'a';`, context);
    context.renderAIChannelSelect();
    context.writeAIChannelToMainForm('a');
    for (const id of ['ai-channel-select', 'openai-provider', 'openai-reasoning-mode', 'openai-reasoning-effort', 'openai-reasoning-profile']) context.enhanceSettingsSelect(elements.get(id));
    elements.get('ai-channel-select').addEventListener('change', () => context.selectAIChannelForEditing(elements.get('ai-channel-select').value));
    const label = id => elements.get(id).parentNode.querySelector('.settings-custom-select-value').textContent;
    const config = () => JSON.parse(vm.runInContext('JSON.stringify(currentConfig)', context));
    return { context, elements, requests, label, config };
}

function assertSecondChannelForm(f, maxOutput = 32768) {
    assert.equal(f.elements.get('ai-channel-name').value, secondChannel.name);
    assert.equal(f.elements.get('openai-model').value, 'model-b');
    assert.equal(f.elements.get('openai-max-total-tokens').value, '800000');
    assert.equal(f.elements.get('openai-max-completion-tokens').value, String(maxOutput));
    assert.equal(f.elements.get('openai-reasoning-mode').value, 'on');
    assert.equal(f.elements.get('openai-reasoning-effort').value, 'xhigh');
    assert.equal(f.elements.get('openai-reasoning-allow-client').checked, false);
    assert.equal(f.label('openai-provider'), 'Claude');
    assert.equal(f.label('openai-reasoning-mode'), '开启');
    assert.equal(f.label('openai-reasoning-effort'), 'xhigh');
    assert.equal(f.label('openai-reasoning-profile'), 'output_config_effort');
}

test('switching channels synchronizes token limits, native values and all visible dropdown labels', () => {
    const f = fixture();
    f.context.selectAIChannelForEditing('b');
    assertSecondChannelForm(f);
    assert.equal(f.requests.length, 0, 'Channel selection must not save or probe the model');
});

test('custom channel dropdown change loads the selected channel parameters', () => {
    const f = fixture();
    const select = f.elements.get('ai-channel-select');
    const menu = select.parentNode.querySelector('.settings-custom-select-menu');
    const item = menu.children.find(node => node.getAttribute('data-index') === '1');
    menu.dispatchEvent({ type: 'click', target: item, stopPropagation() {} });
    assertSecondChannelForm(f);
});

test('switching back retains only the original channel draft and refreshes its labels', () => {
    const f = fixture();
    f.elements.get('openai-max-total-tokens').value = '620000';
    f.elements.get('openai-max-completion-tokens').value = '24576';
    f.elements.get('openai-reasoning-mode').value = 'off';
    f.elements.get('openai-reasoning-effort').value = 'high';
    f.context.selectAIChannelForEditing('b');
    assertSecondChannelForm(f);
    f.context.selectAIChannelForEditing('a');
    assert.equal(f.elements.get('openai-max-total-tokens').value, '620000');
    assert.equal(f.elements.get('openai-max-completion-tokens').value, '24576');
    assert.equal(f.label('openai-reasoning-mode'), '关闭');
    assert.equal(f.label('openai-reasoning-effort'), 'high');
    assert.deepEqual(f.config().ai.channels.b.reasoning, secondChannel.reasoning);
});

test('channels sharing a model name keep independent reasoning settings and credentials', () => {
    const f = fixture({ a: { ...firstChannel, model: 'shared-model' }, b: { ...secondChannel, model: 'shared-model' } });
    f.context.selectAIChannelForEditing('b');
    assert.equal(f.label('openai-reasoning-effort'), 'xhigh');
    assert.equal(f.elements.get('openai-api-key').value, 'fixture-b');
    f.context.selectAIChannelForEditing('a');
    assert.equal(f.label('openai-reasoning-effort'), '不指定');
    assert.equal(f.elements.get('openai-api-key').value, 'fixture-a');
});

test('server refresh updates enhanced dropdowns and leaves server data unchanged until editing', async () => {
    const f = fixture();
    const latest = { ai: { default_channel: 'b', channels: { b: { ...secondChannel, max_completion_tokens: 0 } } } };
    f.context.apiFetch = async url => {
        f.requests.push({ url });
        return { ok: true, json: async () => clone(latest) };
    };
    assert.equal(await f.context.refreshAIChannelsFromServer('b'), true);
    assertSecondChannelForm(f, 16384);
    assert.equal(f.elements.get('openai-max-completion-tokens').value, '16384');
    assert.deepEqual(f.config().ai.channels.b, latest.ai.channels.b, 'Loading the form must not silently modify saved parameters');
    assert.equal(f.requests.length, 1);
});

test('saving the selected channel preserves its reasoning fields without overwriting the other channel', async () => {
    const f = fixture();
    f.context.selectAIChannelForEditing('b');
    let saved;
    f.context.apiFetch = async (url, options = {}) => {
        f.requests.push({ url, options });
        if (options.method === 'PUT') saved = JSON.parse(options.body);
        return { ok: true, json: async () => clone(saved || f.config()) };
    };
    assert.equal(await f.context.persistAIChannelsToServer('saved'), true);
    assert.deepEqual(saved.ai.channels.b.reasoning, secondChannel.reasoning);
    assert.equal(saved.ai.channels.b.max_completion_tokens, 32768);
    assert.deepEqual(saved.ai.channels.a, firstChannel);
    assert.equal(saved.ai.default_channel, 'a', 'Saving a channel must not make it the default');
    assertSecondChannelForm(f);
});

test('keyboard channel selection also synchronizes the visible reasoning controls', () => {
    const f = fixture();
    const trigger = f.elements.get('ai-channel-select').parentNode.querySelector('.settings-custom-select-trigger');
    trigger.dispatchEvent({ type: 'keydown', key: 'End', preventDefault() {} });
    assertSecondChannelForm(f);
    trigger.dispatchEvent({ type: 'keydown', key: 'Home', preventDefault() {} });
    assert.equal(f.elements.get('openai-max-total-tokens').value, '500000');
    assert.equal(f.label('openai-reasoning-mode'), '自动');
    assert.equal(f.label('openai-reasoning-effort'), '不指定');
});

test('the settings script URL is versioned so browsers reload the parameter-sync fix', () => {
    const template = fs.readFileSync(path.join(__dirname, '../../templates/index.html'), 'utf8');
    assert.match(template, /\/static\/js\/settings\.js\?v=20261002-model-params1/);
});

test('programmatic model loading synchronizes the existing model picker without a change event', () => {
    const f = fixture({ a: firstChannel, b: { ...secondChannel, provider: 'openai_compatible' } });
    f.context.enhanceModelPickSelect('openai-model-select');
    f.elements.get('openai-model-select').value = 'model-a';
    f.context.selectAIChannelForEditing('b');
    assert.equal(f.elements.get('openai-model-select').value, 'model-b');
    const label = f.elements.get('openai-model-select').parentNode.querySelector('.model-pick-trigger-label');
    assert.equal(label.textContent, 'model-b');
});
