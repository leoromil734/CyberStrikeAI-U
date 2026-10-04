'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const css = fs.readFileSync(path.join(__dirname, '../css/model-management.css'), 'utf8');
const template = fs.readFileSync(path.join(__dirname, '../../templates/index.html'), 'utf8');
const prefix = '#settings-section-basic ';

function declarations(selector) {
    const start = css.indexOf(prefix + selector + ' {');
    assert.notEqual(start, -1, `Missing scoped layout rule: ${selector}`);
    const block = css.slice(css.indexOf('{', start) + 1, css.indexOf('}', start));
    return Object.fromEntries(block.split(';').map(value => value.trim()).filter(Boolean).map(value => {
        const colon = value.indexOf(':');
        return [value.slice(0, colon).trim(), value.slice(colon + 1).trim()];
    }));
}

test('left sidebar explicitly overrides the legacy horizontal switcher', () => {
    const sidebar = declarations('.ai-channel-switcher');
    assert.equal(sidebar.display, 'flex');
    assert.equal(sidebar['flex-direction'], 'column');
    assert.equal(sidebar['align-items'], 'stretch');
    assert.equal(sidebar['justify-content'], 'flex-start');
    assert.equal(sidebar['min-width'], '0');
});

test('channel picker replaces the legacy 260px minimum with one shrinkable column', () => {
    const field = declarations('.ai-channel-switcher-field');
    assert.equal(field['grid-template-columns'], 'minmax(0, 1fr)');
    assert.equal(field.width, '100%');
    const select = declarations('.ai-channel-switcher-field :is(select, .settings-custom-select)');
    assert.equal(select['min-width'], '0');
    assert.equal(select['max-width'], '100%');
});

test('action buttons use two columns and the long test-all action spans both', () => {
    const actions = declarations('.ai-channel-switcher-actions');
    assert.equal(actions.display, 'grid');
    assert.equal(actions['grid-template-columns'], 'repeat(2, minmax(0, 1fr))');
    assert.equal(declarations('.ai-channel-switcher-actions button:first-child')['grid-column'], '1 / -1');
    assert.equal(declarations('.ai-channel-switcher-actions button')['white-space'], 'normal');
});

test('channel cards occupy the sidebar width without shrinking inside the scroll area', () => {
    assert.equal(declarations('.ai-channel-list').width, '100%');
    assert.equal(declarations('.ai-channel-list')['min-width'], '0');
    assert.equal(declarations('.ai-channel-list-item').flex, '0 0 auto');
    assert.match(css, /@media\s*\(max-width:\s*1000px\)[\s\S]*?\.ai-channel-manager-body\s*\{\s*grid-template-columns:\s*1fr/);
});

test('narrow settings panels stack by available container width, even on desktop', () => {
    assert.equal(declarations('.ai-channel-manager').container, 'ai-channel-manager / inline-size');
    assert.match(css, /@container ai-channel-manager\s*\(max-width:\s*760px\)/);
    assert.match(css, /\.ai-channel-reasoning-grid\s*\{\s*grid-template-columns:\s*minmax\(0,\s*1fr\)/);
});

test('the layout stylesheet uses a new cache version after the broken release', () => {
    const version = template.match(/href="\/static\/css\/model-management\.css\?v=([^"]+)"/);
    assert.ok(version, 'The layout stylesheet must have a cache version');
    assert.notEqual(version[1], '20261003-1');
});
