'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, 'tasks.js'), 'utf8');
const language = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'i18n', 'zh-CN.json'), 'utf8'));

function harness() {
    const elements = new Map();
    const requests = [];
    const confirmations = [];
    const context = vm.createContext({
        console, setTimeout, clearTimeout, setInterval, clearInterval,
        localStorage: { getItem: () => null, setItem() {} },
        document: { addEventListener() {}, getElementById: id => elements.get(id) || null },
        window: {
            t(key, params = {}) {
                const value = key.split('.').reduce((part, name) => part && part[name], language) || key;
                return String(value).replace(/{{(\w+)}}/g, (_, name) => String(params[name] ?? ''));
            },
            confirm(message) { confirmations.push(message); return true; }
        },
        escapeHtml: value => String(value ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'),
        requirePermission: () => true,
        alert(message) { throw new Error(message); },
        async apiFetch(url, options) {
            requests.push({ url, options });
            return { ok: true, async json() { return url === '/api/targets/check' ? { hits: [] } : { queueId: 'created' }; } };
        }
    });
    vm.runInContext(source, context, { filename: 'tasks.js' });
    context.refreshBatchFormSelects = () => {};
    context.showBatchQueueDetail = () => {};
    context.refreshBatchQueues = () => {};
    context.closeBatchImportModal = () => {};
    return { context, elements, requests, confirmations };
}

test('paused tasks stay distinct from completed/cancelled progress', () => {
    const { context } = harness();
    const queue = { status: 'paused', executorActive: true, tasks: [{ status: 'paused' }, { status: 'pending' }] };
    const stats = context.batchQueueTaskStats(queue);
    assert.equal(stats.paused, 1);
    assert.equal(stats.completed + stats.failed + stats.cancelled, 0);
    assert.equal(context.batchQueueAllowsSubtaskMutation(queue), false);
    assert.equal(context.batchQueueCanRunSingleTask(queue, queue.tasks[0]), false);
});

test('private mode clears/disables the shared project field', () => {
    const { context, elements } = harness();
    const checkbox = { checked: true };
    const select = { value: 'shared-project', disabled: false };
    elements.set('batch-queue-independent-projects', checkbox);
    elements.set('batch-queue-project-id', select);
    context.handleBatchProjectModeChange();
    assert.equal(select.value, '');
    assert.equal(select.disabled, true);
    checkbox.checked = false;
    context.handleBatchProjectModeChange();
    assert.equal(select.disabled, false);
});

test('submitted-only targets are never labelled as already run', () => {
    const { context } = harness();
    const meta = context.batchTargetReminderMeta({ runCount: 0, submittedCount: 2, lastSubmittedAt: '2026-10-01T06:00:00Z' });
    assert.match(meta, /已登记 2 个任务/);
    assert.match(meta, /尚未运行/);
    assert.doesNotMatch(meta, /跑过/);
});

test('short valid domain names still call the duplicate checker', async () => {
    const { context, requests } = harness();
    await context.batchTargetReminderFetch('a.de');
    assert.equal(requests.length, 1);
    assert.equal(requests[0].url, '/api/targets/check');
});

test('submit rechecks stale empty previews before creating a queue', async () => {
    const { context, elements, requests, confirmations } = harness();
    elements.set('batch-tasks-input', { value: 'test example.com' });
    vm.runInContext("batchTargetReminderLastText = 'test example.com'; batchTargetReminderHits = [];", context);
    context.apiFetch = async (url, options) => {
        requests.push({ url, options });
        return { ok: true, async json() { return { hits: [{ target: 'example.com', runCount: 0, submittedCount: 1 }] }; } };
    };
    context.window.confirm = message => { confirmations.push(message); return false; };
    await context.createBatchQueue();
    assert.equal(requests.length, 1);
    assert.equal(requests[0].url, '/api/targets/check');
    assert.match(confirmations[0], /已登记 1 个任务/);
    assert.doesNotMatch(confirmations[0], /跑过 1 次/);
});

test('private queue payload contains no shared project binding', async () => {
    const { context, elements, requests } = harness();
    elements.set('batch-tasks-input', { value: 'test example.com' });
    elements.set('batch-queue-independent-projects', { checked: true });
    elements.set('batch-queue-project-id', { value: 'shared-project' });
    elements.set('batch-queue-execute-now', { checked: false });
    await context.createBatchQueue();
    const created = requests.find(request => request.url === '/api/batch-tasks');
    assert.ok(created);
    const payload = JSON.parse(created.options.body);
    assert.equal(payload.independentProjects, true);
    assert.equal(payload.projectId, '');
    assert.equal(payload.executeNow, false);
});
