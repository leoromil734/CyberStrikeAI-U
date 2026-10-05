'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, 'tasks.js'), 'utf8');
const probeSource = fs.readFileSync(path.join(__dirname, 'ai-channel-probes.js'), 'utf8');
const zh = JSON.parse(fs.readFileSync(path.join(__dirname, '../i18n/zh-CN.json'), 'utf8'));
const en = JSON.parse(fs.readFileSync(path.join(__dirname, '../i18n/en-US.json'), 'utf8'));
const escape = value => String(value ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
const ok = data => ({ ok: true, json: async () => data });
function fixture() {
    const elements = new Map(), requests = [], copied = [], confirmations = [];
    const ctx = vm.createContext({ console, setTimeout, clearTimeout, setInterval, clearInterval, TextDecoder, AbortController,
        document: { getElementById: id => elements.get(id) || null, addEventListener() {}, querySelectorAll: () => [] },
        navigator: { clipboard: { writeText: async text => copied.push(text) } },
        window: { t: (key, options = {}) => String(key.split('.').reduce((v, k) => v?.[k], zh) || key).replace(/{{(\w+)}}/g, (_, name) => options[name] ?? '') },
        escapeHtml: escape, requirePermission: () => true, hasPermission: () => true,
        confirm: text => { confirmations.push(text); return true; },
        localStorage: { getItem: () => null, setItem() {} },
        isAppModalOpen: () => true, deferModalContent: fn => fn(),
        apiFetch: async (url, options) => { requests.push({ url, options }); return ok({}); },
        alert: message => { throw new Error(message); }
    });
    vm.runInContext(probeSource, ctx);
    vm.runInContext(source, ctx);
    ctx.startBatchQueueRefresh = () => {};
    ctx.stopBatchQueueRefresh = () => {};
    ctx.refreshBatchQueues = () => {};
    const element = (id, props = {}) => {
        const e = { innerHTML: '', value: '', textContent: '', style: {}, dataset: {}, closest: () => null, querySelector: () => null, querySelectorAll: () => [], ...props };
        elements.set(id, e); return e;
    };
    const setQueue = queue => { ctx.queue = queue; vm.runInContext('batchQueuesState.currentQueue = queue; batchQueuesState.currentQueueId = queue.id', ctx); };
    const state = () => vm.runInContext('batchQueuesState', ctx);
    return { ctx, elements, requests, copied, confirmations, element, setQueue, state };
}
function sample() {
    return { id: 'q', status: 'paused', tasks: [
        { id: 'declined', conversationId: 'c0', message: '检查 https://declined.example', status: 'declined' },
        ...Array.from({ length: 2 }, (_, i) => ({ id: 'failed' + i, conversationId: 'cf' + i, message: '检查 https://failed' + i + '.example', status: 'failed' })),
        ...Array.from({ length: 13 }, (_, i) => ({ id: 'blocked' + i, conversationId: 'cb' + i, message: '检查 https://blocked' + i + '.example', status: 'blocked', outcome: i % 2 ? 'tool_blocked' : 'no_execution_evidence' }))
    ] };
}
function buttonFor(queue, task) {
    return { disabled: false, textContent: '', closest: () => ({ getAttribute: name => name === 'data-queue-id' ? queue.id : task.id }) };
}
function stream(events, chunkSize = 7) {
    const bytes = new TextEncoder().encode(events.map(event => 'data: ' + JSON.stringify(event) + '\r\n\r\n').join(''));
    let offset = 0, cancelled = 0;
    return { ok: true, body: { getReader: () => ({ read: async () => {
        if (offset >= bytes.length) return { done: true };
        const value = bytes.slice(offset, offset + chunkSize); offset += chunkSize; return { done: false, value };
    }, cancel: async () => { cancelled++; } }) }, get cancelled() { return cancelled; } };
}

test('3/16 示例状态数量一致，快速筛选精确命中，搜索叠加且原始序号保留', () => {
    const f = fixture(), queue = sample(); f.setQueue(queue);
    assert.equal(f.ctx.batchQueueTaskStats(queue).processed, 3);
    for (const [status, count] of [['all', 16], ['declined', 1], ['failed', 2], ['blocked', 13]]) {
        f.ctx.setBatchDetailFilter(status);
        assert.equal(f.ctx.filteredBatchDetailTasks().length, count);
    }
    f.ctx.setBatchDetailSearch('BLOCKED12.EXAMPLE');
    assert.equal(f.ctx.filteredBatchDetailTasks().length, 1);
    assert.match(f.ctx.renderBatchDetailTasks(queue), /#16/);
    const html = f.ctx.batchQueueOutcomeSummaryHtml(f.ctx.batchQueueTaskStats(queue), true);
    assert.match(html, /data-bq-filter="blocked"[^>]*>13 项待恢复/);
    f.ctx.setBatchDetailSearch('missing');
    assert.match(f.ctx.renderBatchDetailTasks(queue), /没有符合条件的任务/);
    assert.equal(queue.tasks[0].status, 'declined');
});

test('手动续跑作为独立筛选，历史拒绝状态不改写，活跃项/无会话/成功项不入批量', () => {
    const f = fixture(), queue = sample();
    queue.tasks[0].conversationActive = true;
    queue.tasks[1].conversationId = '';
    queue.tasks.push({ id: 'done', status: 'completed', outcome: 'verified_complete', conversationId: 'done' });
    queue.tasks.push({ id: 'duplicate', status: 'failed', conversationId: queue.tasks[2].conversationId });
    f.setQueue(queue);
    f.ctx.setBatchDetailFilter('manual_active');
    assert.equal(f.ctx.filteredBatchDetailTasks()[0].id, 'declined');
    assert.equal(f.ctx.batchTaskFilterKey(queue.tasks[0]), 'declined');
    assert.equal(f.ctx.batchContinuationCandidates(queue, queue.tasks).length, 14);
    assert.equal(f.ctx.batchTaskCanContinue({ ...queue, executorActive: true }, queue.tasks[2]), false);
    f.ctx.hasPermission = permission => permission !== 'chat:write';
    assert.equal(f.ctx.batchTaskCanContinue(queue, queue.tasks[2]), false);
});

test('启动确认解析跨网络块和中文UTF8，200/progress/message_saved均不能伪报成功', async () => {
    const f = fixture();
    const response = stream([{ type: 'message_saved' }, { type: 'progress', message: '正在启动' }, { type: 'task_started', data: { conversationId: 'c' } }], 1);
    assert.equal((await f.ctx.readBatchContinuationStarted(response)).conversationId, 'c');
    assert.equal(response.cancelled, 1);
    for (const events of [[{ type: 'error', message: '已有任务正在执行' }], [{ type: 'done' }], [{ type: 'progress' }]]) {
        const response = stream(events);
        await assert.rejects(f.ctx.readBatchContinuationStarted(response), /已有任务|启动确认/);
        assert.equal(response.cancelled, 1);
    }
    await assert.rejects(f.ctx.readBatchContinuationStarted({ ok: false, json: async () => ({ error: '权限不足' }) }), /权限不足/);
});

test('双击发送只有一次POST，路径编码，不调用重跑/取消且不覆盖历史快照', async () => {
    const f = fixture(), queue = sample(), task = queue.tasks[0];
    queue.id = 'q /'; task.id = 't /'; f.setQueue(queue);
    let resolve;
    f.ctx.apiFetch = (url, options) => { f.requests.push({ url, options }); return new Promise(r => { resolve = r; }); };
    const pending = f.ctx.requestBatchTaskContinue(queue, task);
    await assert.rejects(f.ctx.requestBatchTaskContinue(queue, task), /不能发送继续/);
    assert.equal(f.requests.length, 1);
    assert.equal(f.requests[0].url, '/api/batch-tasks/q%20%2F/tasks/t%20%2F/continue');
    assert.equal(f.requests[0].options.method, 'POST');
    assert.equal(f.requests[0].options.body, undefined);
    resolve(stream([{ type: 'task_started', data: { conversationId: task.conversationId } }]));
    await pending;
    assert.equal(f.state().continuationPending.size, 0);
    assert.equal(task.status, 'declined');
});

test('对筛选失败项批量发送：确认准确数量、部分失败继续处理，成功项和其他状态不触发', async () => {
    const f = fixture(), queue = sample(); f.setQueue(queue); f.ctx.setBatchDetailFilter('failed');
    f.ctx.showBatchQueueDetail = async () => {};
    f.ctx.apiFetch = async (url, options) => {
        f.requests.push({ url, options });
        return url.includes('/failed0/') ? { ok: false, json: async () => ({ error: 'busy' }) }
            : stream([{ type: 'task_started', data: { conversationId: 'cf1' } }]);
    };
    await f.ctx.sendFilteredBatchTaskContinue();
    assert.match(f.confirmations[0], /2 个空闲会话/);
    assert.equal(f.requests.length, 2);
    assert.match(f.state().detailNotice, /已启动 1 项，未启动 1 项/);
    assert.match(f.state().detailNotice, /#2: busy/);
    assert.equal(f.state().continuationBatchRunning, false);
    assert.equal(queue.tasks[2].status, 'failed');
});

test('复制使用服务端首条原文，保留目标、换行、引号、字面量\\n和实体，不复制标题或预览', async () => {
    const f = fixture(), queue = sample(); f.setQueue(queue);
    const original = '  测试 https://example.test/path?a=1&b=2\n"引号" \\n &amp; <script>\n' + '完整原文'.repeat(100);
    f.ctx.apiFetch = async () => ok({ message: original, source: 'conversation' });
    const button = buttonFor(queue, queue.tasks[0]);
    await f.ctx.copyBatchTaskOriginal(button);
    assert.deepEqual(f.copied, [original]);
    assert.equal(button.disabled, false);
    f.ctx.apiFetch = async () => ({ ok: false, json: async () => ({ error: '无权读取' }) });
    await f.ctx.copyBatchTaskOriginal(button);
    assert.equal(f.copied.length, 1);
    assert.equal(f.state().detailNotice, '无权读取');
});

test('HTTP环境剪贴板回退成功/失败均移除临时节点并恢复焦点', async () => {
    const f = fixture(); delete f.ctx.navigator.clipboard;
    let removed = 0, selected = 0, restored = 0, appended;
    f.ctx.document.createElement = () => ({ style: {}, select() { selected++; }, remove() { removed++; } });
    f.ctx.document.body = { appendChild: element => { appended = element; } };
    f.ctx.document.activeElement = { focus: () => { restored++; } };
    f.ctx.document.execCommand = () => true;
    await f.ctx.writeBatchOriginalClipboard('original\nhttps://example.test');
    assert.equal(appended.value, 'original\nhttps://example.test');
    f.ctx.document.execCommand = () => false;
    await assert.rejects(f.ctx.writeBatchOriginalClipboard('other'));
    assert.equal(removed, 2); assert.equal(selected, 2); assert.equal(restored, 2);
});

test('模型列表只读安全接口，默认项展示测试状态，刷新保留已删除的历史通道', async () => {
    const f = fixture();
    f.ctx.apiFetch = async url => { f.requests.push(url); return ok({ default_channel: 'a', channels: {
        a: { name: 'A', model: 'model-A', probe: { status: 'ready', ttft_ms: 0, tested_at: '2026-10-05T00:00:00Z' } },
        b: { name: '<img>', model: 'B', probe: { status: 'stale', error: '<bad>' } }
    } }); };
    await f.ctx.ensureBatchAIChannels(true);
    const html = f.ctx.batchAIChannelOptionsHTML('removed');
    assert.match(html, /可用 · 首 token 0 ms/);
    assert.match(html, /配置已更改，需重测/);
    assert.match(html, /value="removed"[^>]* selected/);
    assert.doesNotMatch(html, /<img>|<bad>/);
    assert.deepEqual(f.requests, ['/api/config/ai-channels']);
    f.ctx.apiFetch = async () => { throw new Error('offline'); };
    await f.ctx.ensureBatchAIChannels(true);
    assert.match(f.ctx.batchAIChannelOptionsHTML('a'), /测试记录加载失败/);
});

test('详情刷新保留筛选，切换集合重置；晚到旧响应或关闭后响应不能重新打开弹窗', async () => {
    const f = fixture();
    f.element('batch-queue-detail-modal'); f.element('batch-queue-detail-title');
    const content = f.element('batch-queue-detail-content');
    f.ctx.ensureBatchAIChannels = async () => {};
    f.ctx.apiFetch = async () => ok({ queue: sample() });
    await f.ctx.showBatchQueueDetail('q');
    f.ctx.setBatchDetailFilter('blocked'); f.ctx.setBatchDetailSearch('blocked12');
    await f.ctx.showBatchQueueDetail('q');
    assert.equal(f.state().detailStatus, 'blocked'); assert.equal(f.state().detailSearch, 'blocked12');
    let resolve;
    f.ctx.apiFetch = () => new Promise(r => { resolve = r; });
    const late = f.ctx.showBatchQueueDetail('old');
    f.ctx.closeAppModal = () => {};
    f.ctx.closeBatchQueueDetailModal();
    const before = content.innerHTML;
    resolve(ok({ queue: { ...sample(), id: 'old' } })); await late;
    assert.equal(content.innerHTML, before); assert.equal(f.state().currentQueueId, null);
});

test('任务操作和模型详情的新增文案在中英文齐全，模板正确加载公共脚本和自适应弹窗', () => {
    const keys = ['filterAll', 'filterBlocked', 'filterDeclined', 'filterFailed', 'filterPaused', 'filterPending', 'filterRunning',
        'filterManualActive', 'filterByStatus', 'filterSearch', 'filterCount', 'filterEmpty', 'filterEmptyHint', 'queueConfiguration',
        'runDetails', 'continueExecution', 'sendContinue', 'sendContinueHint', 'continueActionsHint', 'continueSending', 'continueSent',
        'continueFailed', 'continueUnconfirmed', 'continueUnavailable', 'continueFiltered', 'continueFilteredConfirm', 'continueBatchResult', 'copyOriginalInput', 'modelUnavailable'];
    for (const key of keys) {
        assert.equal(typeof zh.tasks[key], 'string', key); assert.equal(typeof en.tasks[key], 'string', key);
        assert.deepEqual([...zh.tasks[key].matchAll(/{{\w+}}/g)].map(m => m[0]), [...en.tasks[key].matchAll(/{{\w+}}/g)].map(m => m[0]));
    }
    const template = fs.readFileSync(path.join(__dirname, '../../templates/index.html'), 'utf8');
    assert.ok(template.indexOf('/js/ai-channel-probes.js') < template.indexOf('/js/chat.js'));
    assert.match(template, /modal-content bq-detail-dialog/);
    assert.match(template, /aria-describedby="batch-queue-default-model-probe"/);
    assert.match(template, /task-detail.css/);
});
