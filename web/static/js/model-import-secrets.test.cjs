'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, 'model-management.js'), 'utf8');
const settings = fs.readFileSync(path.join(__dirname, 'settings.js'), 'utf8').replace(/\r\n/g, '\n');
const normalize = settings.match(/function normalizeAIChannelId\([^]*?\n}/)[0];
const clone = value => JSON.parse(JSON.stringify(value));
function fixture(channel) {
    const elements = new Map([
        ['ai-import-status', { textContent: '' }],
        ['ai-import-manual', { value: '' }],
        ['ai-import-prefix', { value: 'Fixture ' }]
    ]);
    const requests = [], hints = [];
    const context = vm.createContext({
        console, selectedAIChannelId: 'saved-channel',
        currentConfig: { ai: { channels: { 'saved-channel': clone(channel) } } },
        document: { addEventListener() {}, getElementById: id => elements.get(id) || null },
        readAIChannelFromMainForm: () => clone(channel),
        settingsT: (_key, fallback) => fallback,
        apiFetch: async (url, options) => {
            requests.push({ url, body: JSON.parse(options.body) });
            return { ok: true, json: async () => ({ success: true, models: ['new-model'] }) };
        },
        showAIChannelSaveHint: (message, ok) => hints.push({ message, ok }),
        writeAIChannelToMainForm() {}, renderAIChannelSelect() {}
    });
    vm.runInContext(normalize + '\n' + source, context);
    return { context, elements, requests, hints };
}
const channel = { name: 'Saved', provider: 'openai', base_url: 'https://fixture.invalid/v1', api_key: '********', model: 'old-model' };

test('bulk model discovery identifies the exact saved credential without exposing it', async () => {
    const f = fixture(channel);
    await f.context.fetchAIModelsForImport();
    assert.equal(f.requests.length, 1);
    assert.equal(f.requests[0].body.api_key, '********');
    assert.equal(f.requests[0].body.channel_id, 'saved-channel');
    assert.equal(f.requests[0].body.credential_scope, 'openai');
    assert.equal(f.requests[0].body.base_url, channel.base_url);
});

test('bulk import of masked credentials fails visibly without changing drafts', async () => {
    for (const c of [channel, { ...channel, api_key: 'fixture-only-new-key', vision: { api_key: '********', model: 'vision' } }]) {
        const f = fixture(c);
        const before = clone(f.context.currentConfig);
        await f.context.fetchAIModelsForImport();
        vm.runInContext("aiModelImportState.selected.add('new-model')", f.context);
        f.context.importSelectedAIModels();
        assert.deepEqual(clone(f.context.currentConfig), before);
        assert.equal(f.context.selectedAIChannelId, 'saved-channel');
        assert.equal(f.hints.length, 1);
        assert.equal(f.hints[0].ok, false);
        assert.match(f.hints[0].message, /重新填写/);
        assert.ok(!f.hints[0].message.includes('fixture-only-new-key'));
    }
});

test('the pure import function never copies a credential mask', () => {
    const f = fixture(channel);
    assert.throws(() => f.context.buildAIModelImports({}, channel, ['new-model'], ''), /重新填写/);
    assert.throws(() => f.context.buildAIModelImports({}, { ...channel, api_key: 'fixture-key', vision: { api_key: '********' } }, ['new-model'], ''), /重新填写/);
});

test('unknown masked credentials cannot collapse independently configured channels', () => {
    const f = fixture(channel);
    const existing = { saved: { ...channel, model: 'new-model' } };
    const result = f.context.buildAIModelImports(existing, { ...channel, api_key: 'fixture-only-new-key' }, ['new-model'], 'Imported ');
    assert.equal(result.added.length, 1);
    assert.equal(result.channels.saved.api_key, '********');
    assert.equal(result.channels[result.added[0]].api_key, 'fixture-only-new-key');
    assert.equal(existing.saved.api_key, '********');
});

test('explicitly supplied credentials still import and deduplicate normally', async () => {
    const explicit = { ...channel, api_key: 'fixture-only-new-key' };
    const f = fixture(explicit);
    await f.context.fetchAIModelsForImport();
    vm.runInContext("aiModelImportState.selected.add('new-model')", f.context);
    f.context.importSelectedAIModels();
    const saved = clone(f.context.currentConfig.ai.channels);
    assert.equal(Object.keys(saved).length, 2);
    assert.equal(saved[f.context.selectedAIChannelId].model, 'new-model');
    assert.equal(saved[f.context.selectedAIChannelId].api_key, explicit.api_key);
    assert.equal(f.hints[0].ok, true);
    const again = f.context.buildAIModelImports(saved, explicit, ['new-model'], 'Fixture ');
    assert.equal(again.added.length, 0);
});
