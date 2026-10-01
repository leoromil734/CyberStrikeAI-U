const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

class Element {
    constructor(attributes = {}) {
        this.attributes = new Map(Object.entries(attributes));
        this.hidden = false;
        this.classes = new Set();
        this.classList = { toggle: (name, enabled) => enabled ? this.classes.add(name) : this.classes.delete(name) };
    }
    getAttribute(name) { return this.attributes.get(name) || null; }
    setAttribute(name, value) { this.attributes.set(name, String(value)); }
}

function fixture(currentPermissions, storedPermissions = ['knowledge:read']) {
    const nav = {
        knowledge: new Element({ 'data-page': 'knowledge' }),
        experience: new Element({ 'data-page': 'experience-memory' }),
        management: new Element({ 'data-page': 'knowledge-management' }),
        targets: new Element({ 'data-page': 'targets', 'data-require-permission-any': 'target:read' }),
    };
    const storage = new Map([['cyberstrike-auth', JSON.stringify({
        token: 'test-only-existing-session', expiresAt: new Date(Date.now() + 3600000).toISOString(),
        user: { id: 'admin', username: 'admin' }, roles: ['admin'], permissions: storedPermissions, scope: 'all',
    })]]);
    const requests = [];
    const context = {
        Element, Headers, console,
        window: {},
        document: {
            addEventListener() {},
            getElementById() { return null; },
            querySelector() { return null; },
            querySelectorAll(selector) {
                if (selector === '[data-page]') return Object.values(nav);
                if (selector === '[data-require-permission], [data-require-permission-any]') return [nav.targets];
                return [];
            },
        },
        localStorage: {
            getItem: key => storage.get(key) || null,
            setItem: (key, value) => storage.set(key, value),
            removeItem: key => storage.delete(key),
        },
        closeAppModal() {},
        fetch: async (url, options) => {
            requests.push({ url, options });
            return { ok: true, status: 200, json: async () => ({
                user: { id: 'admin', username: 'admin' }, roles: ['admin'], scope: 'all',
                permissions: currentPermissions,
            }) };
        },
    };
    vm.createContext(context);
    vm.runInContext(fs.readFileSync(path.join(__dirname, 'auth.js'), 'utf8'), context);
    context.bootstrapApp = async () => {};
    return { context, nav, storage, requests };
}

test('session validation replaces stale permissions and keeps both new navigation entries visible', async () => {
    const permissions = ['knowledge:read', 'experience:read', 'target:read'];
    const f = fixture(permissions);
    await f.context.initializeApp();
    assert.equal(f.requests[0].url, '/api/auth/validate');
    assert.equal(f.requests[0].options.headers.get('Authorization'), 'Bearer test-only-existing-session');
    for (let i = 0; i < 3; i++) {
        f.context.window.applyRBACToUI();
        assert.equal(f.nav.experience.hidden, false);
        assert.equal(f.nav.targets.hidden, false);
        assert.equal(f.nav.targets.getAttribute('aria-hidden'), 'false');
    }
    assert.deepEqual(JSON.parse(f.storage.get('cyberstrike-auth')).permissions, permissions);
});

test('an admin label never bypasses missing server permissions', async () => {
    const f = fixture(['knowledge:read']);
    await f.context.initializeApp();
    assert.equal(f.nav.experience.hidden, true);
    assert.equal(f.nav.targets.hidden, true);
});

test('empty current permissions remove cached grants from navigation and storage', async () => {
    const f = fixture([], ['experience:read', 'target:read', 'knowledge:read']);
    await f.context.initializeApp();
    assert.equal(f.nav.knowledge.hidden, true);
    assert.equal(f.nav.experience.hidden, true);
    assert.equal(f.nav.targets.hidden, true);
    assert.deepEqual(JSON.parse(f.storage.get('cyberstrike-auth')).permissions, []);
});

test('experience-only permission keeps its parent menu visible without granting knowledge access', async () => {
    const f = fixture(['experience:read']);
    await f.context.initializeApp();
    assert.equal(f.nav.knowledge.hidden, false);
    assert.equal(f.nav.experience.hidden, false);
    assert.equal(f.nav.management.hidden, true);
});

test('released HTML contains both navigation entries and a versioned authorization script', () => {
    const html = fs.readFileSync(path.join(__dirname, '../../templates/index.html'), 'utf8');
    assert.match(html, /data-page="targets" data-require-permission-any="target:read"/);
    assert.match(html, /data-page="experience-memory"/);
    assert.match(html, /src="\/static\/js\/auth\.js\?v=20261002-rbac-refresh1"/);
});
