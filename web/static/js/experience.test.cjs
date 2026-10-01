const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

class Element {
    constructor(tag = 'div') { this.tag = tag; this.children = []; this.value = ''; this.hidden = false; this.listeners = {}; this._text = ''; }
    set textContent(value) { this._text = String(value); }
    get textContent() { return this._text; }
    set innerHTML(_) { throw new Error('Remembered content must never be rendered as HTML'); }
    append(...children) { this.children.push(...children); }
    replaceChildren(...children) { this.children = children; this._text = ''; }
    addEventListener(name, handler) { this.listeners[name] = handler; }
    remove() {}
}
function fixture(fetch, permissions = ['experience:read']) {
    const elements = new Map();
    const calls = [];
    const document = { getElementById(id) { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); }, createElement(tag) { return new Element(tag); }, body: new Element('body') };
    const context = { document, URLSearchParams, URL, setTimeout, JSON, console,
        window: { t: key => key, hasPermission: permission => permissions.includes(permission), notifyApiError: () => {}, applyRBACToUI: () => {} },
        apiFetch: async (url, options) => { calls.push([url, options]); return fetch(url, options); },
        readApiError: async response => (await response.json()).error || 'request failed',
    };
    vm.createContext(context);
    vm.runInContext(fs.readFileSync(path.join(__dirname, 'experience.js'), 'utf8'), context);
    return { manager: context.window.ExperienceMemory, elements, calls, document };
}
const response = data => ({ ok: true, json: async () => data });
const entry = { id: 'memory-id', revision: 1, status: 'verified', scope: 'shared', content: { kind: 'workflow', title: '<script>unsafe()</script>', summary: '<img src=x onerror=unsafe()>', conditions: {}, steps: ['reference data'], verification: 'expected output' } };

test('remembered content is displayed only as text', async () => {
    const f = fixture(async () => response({ items: [entry] }));
    await f.manager.refresh();
    const section = f.elements.get('experience-list').children[0];
    assert.equal(section.children[0].textContent, entry.content.title);
    assert.equal(section.children[1].textContent, entry.content.summary);
});

test('raw evidence uses a scoped experience endpoint and encoded IDs', async () => {
    const f = fixture(async url => url.includes('/evidence/') ? response({ execution: { result: '<script>unsafe()</script>' } }) : response({ entry, evidence: [{ execution_id: '../private?key=x', role: 'validation' }] }));
    await f.manager.open(entry.id);
    const button = f.elements.get('experience-evidence').children[0];
    await button.listeners.click();
    assert.ok(f.calls[1][0].startsWith('/api/experiences/memory-id/evidence/'));
    assert.ok(f.calls[1][0].includes(encodeURIComponent('../private?key=x')));
    assert.ok(!f.calls[1][0].startsWith('/api/monitor/'));
});

test('mutation actions respect front-end permissions', async () => {
    const f = fixture(async () => response({ entry, evidence: [] }));
    await f.manager.open(entry.id);
    const before = f.calls.length;
    f.manager.save(); f.manager.review(); f.manager.exportSkill(); f.manager.confirmOutcome();
    assert.equal(f.calls.length, before);
});

test('stale list responses cannot overwrite newer filters', async () => {
    const pending = [];
    const f = fixture(() => new Promise(resolve => pending.push(resolve)));
    const first = f.manager.refresh();
    const second = f.manager.refresh();
    pending[1](response({ items: [{ ...entry, content: { ...entry.content, title: 'newest' } }] }));
    await second;
    pending[0](response({ items: [entry] }));
    await first;
    assert.equal(f.elements.get('experience-list').children[0].children[0].textContent, 'newest');
});

test('Chinese and English experience translation keys stay aligned', () => {
    const zh = JSON.parse(fs.readFileSync(path.join(__dirname, '../i18n/zh-CN.json'), 'utf8')).experience;
    const en = JSON.parse(fs.readFileSync(path.join(__dirname, '../i18n/en-US.json'), 'utf8')).experience;
    assert.deepEqual(Object.keys(zh).sort(), Object.keys(en).sort());
    const html = fs.readFileSync(path.join(__dirname, '../../templates/index.html'), 'utf8');
    for (const match of html.matchAll(/data-i18n="experience\.([^"]+)"/g)) {
        assert.ok(zh[match[1]], `missing Chinese key ${match[1]}`);
        assert.ok(en[match[1]], `missing English key ${match[1]}`);
    }
});
