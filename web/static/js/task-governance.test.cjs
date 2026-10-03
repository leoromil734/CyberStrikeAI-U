'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, 'tasks.js'), 'utf8');
const template = fs.readFileSync(path.join(__dirname, '../../templates/index.html'), 'utf8');
const languages = Object.fromEntries(['zh-CN', 'en-US'].map(lang => [lang, JSON.parse(fs.readFileSync(path.join(__dirname, '../i18n', lang + '.json'), 'utf8'))]));
const escape = value => String(value ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
const response = body => ({ ok: true, json: async () => body });

function fixture(lang = 'zh-CN') {
    const elements = new Map();
    const requests = [], saved = [], refreshes = [];
    const context = vm.createContext({ console, setTimeout, clearTimeout, setInterval, clearInterval,
        document: { addEventListener() {}, getElementById: id => elements.get(id) || null },
        localStorage: { getItem: () => null, setItem: (...args) => saved.push(args) },
        escapeHtml: escape, requirePermission: () => true,
        alert: message => { throw new Error(message); },
        isAppModalOpen: () => true, deferModalContent: callback => callback(),
        window: { t: (key, options = {}) => {
            const text = key.split('.').reduce((part, name) => part?.[name], languages[lang]) || key;
            return String(text).replace(/{{(\w+)}}/g, (_, name) => String(options[name] ?? ''));
        }, confirm: () => true },
        apiFetch: async (url, options) => {
            requests.push({ url, options });
            return response(url === '/api/targets/check' ? { hits: [] } : { queueId: 'created' });
        }
    });
    vm.runInContext(source, context, { filename: 'tasks.js' });
    context.refreshBatchFormSelects = () => {};
    context.closeBatchImportModal = () => {};
    context.refreshBatchQueues = () => {};
    context.ensureBatchAIChannels = async () => {};
    context.startBatchQueueRefresh = id => refreshes.push(id);
    context.stopBatchQueueRefresh = () => refreshes.push('stop');
    const element = (id, props = {}) => {
        const node = { value: '', textContent: '', innerHTML: '', style: {}, dataset: {}, closest: () => null, querySelector: () => null, ...props };
        elements.set(id, node);
        return node;
    };
    return { context, elements, requests, saved, refreshes, element };
}

function freeze(value) {
    if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); }
    return value;
}

for (const mode of ['auto', 'conversation', 'execution', 'comprehensive']) {
    test('创建队列传递评估模式 ' + mode + ' 与显式重复任务选项，不自行丢弃任务行', async () => {
        const f = fixture();
        f.element('batch-tasks-input', { value: 'check example.com\ncheck example.com' });
        f.element('batch-queue-assessment-mode', { value: mode });
        f.element('batch-queue-allow-duplicate-tasks', { checked: true });
        f.context.showBatchQueueDetail = () => {};
        await f.context.createBatchQueue();
        const payload = JSON.parse(f.requests.find(request => request.url === '/api/batch-tasks').options.body);
        assert.equal(payload.assessmentMode, mode);
        assert.equal(payload.allowDuplicateTasks, true);
        assert.equal(payload.tasks.length, 2);
        assert.equal(payload.tasks[0].message, payload.tasks[1].message);
    });
}

test('缺少新表单字段和非法模式均保持 auto/false 默认，不影响旧版创建字段', async () => {
    for (const mode of [undefined, '', 'unexpected', 'toString']) {
        const f = fixture();
        f.element('batch-tasks-input', { value: 'check example.com' });
        if (mode !== undefined) f.element('batch-queue-assessment-mode', { value: mode });
        f.context.showBatchQueueDetail = () => {};
        await f.context.createBatchQueue();
        const payload = JSON.parse(f.requests.find(request => request.url === '/api/batch-tasks').options.body);
        assert.equal(payload.assessmentMode, 'auto');
        assert.equal(payload.allowDuplicateTasks, false);
        assert.equal(payload.agentMode, 'eino_single');
        assert.equal(payload.independentProjects, false);
        assert.equal(payload.projectId, '');
    }
});

test('打开新建表单时重置 auto 与不允许重复，选项文案明确不降低漏洞验证', async () => {
    const f = fixture();
    f.element('batch-import-modal');
    f.element('batch-tasks-input');
    f.element('batch-queue-concurrency');
    const select = f.element('batch-queue-assessment-mode', { value: 'comprehensive' });
    const checkbox = f.element('batch-queue-allow-duplicate-tasks', { checked: true });
    f.context.openAppModal = () => {};
    f.context.refreshBatchProjectSelectOptions = async () => {};
    await f.context.showBatchImportModal();
    assert.equal(select.value, 'auto');
    assert.equal(checkbox.checked, false);
    assert.match(template, /id="batch-queue-assessment-mode"/);
    assert.match(template, /id="batch-queue-allow-duplicate-tasks"/);
    assert.match(languages['zh-CN'].tasks.assessmentModeHint, /不降低漏洞验证要求/);
    assert.match(vm.runInContext('BATCH_IMPORT_FORM_SELECT_IDS.join(",")', f.context), /batch-queue-assessment-mode/);
});

test('准确区分验证完成/交付/缺口/拒绝/失败/阻断，处理进度不是成功率，快照保持不变', () => {
    const f = fixture();
    const queue = freeze({ tasks: [
        { status: 'completed' }, { status: 'completed', outcome: 'verified_complete' },
        { status: 'completed', outcome: 'delivered_with_gaps' }, { status: 'completed', outcome: 'delivered' },
        { status: 'declined' }, { status: 'completed', outcome: 'declined' },
        { status: 'failed' }, { status: 'blocked' },
        { status: 'completed', outcome: 'tool_blocked' }, { status: 'completed', outcome: 'no_execution_evidence' },
        { status: 'running', outcome: 'declined' }, { status: 'pending', outcome: 'verified_complete' },
        { status: 'paused', outcome: 'verified_complete' }, { status: 'cancelled' }, { status: 'timeout' },
        { status: 'completed', outcome: 'future_outcome' }, null
    ] });
    const before = JSON.stringify(queue);
    const stats = f.context.batchQueueTaskStats(queue);
    assert.equal(stats.total, 16);
    assert.equal(stats.completed, 3);
    assert.equal(stats.verifiedComplete, 1);
    assert.equal(stats.legacyCompleted, 1);
    assert.equal(stats.delivered, 1);
    assert.equal(stats.deliveredWithGaps, 1);
    assert.equal(stats.declined, 2);
    assert.equal(stats.blocked, 3);
    assert.equal(stats.failed, 1);
    assert.equal(stats.timeout, 1);
    assert.equal(stats.running, 1);
    assert.equal(stats.pending, 1);
    assert.equal(stats.paused, 1);
    assert.equal(stats.unknown, 1);
    assert.equal(stats.processed, 9);
    assert.equal(JSON.stringify(queue), before);
    assert.equal(f.saved.length, 0);
    const labels = f.context.batchQueueOutcomeSummaryHtml(stats);
    assert.match(labels, /2 项拒绝/);
    assert.match(labels, /1 项有缺口完成/);
    assert.match(labels, /1 项验证完成/);
    assert.match(labels, /1 项记录完成/);
});

for (const lang of ['zh-CN', 'en-US']) {
    test(lang + ' 结果文案和未知字段安全显示，blocked 也显示具体 outcome，旧快照不推断验证成功', () => {
        const f = fixture(lang);
        for (const outcome of ['declined', 'verified_complete', 'delivered_with_gaps', 'delivered', 'tool_blocked', 'no_execution_evidence']) {
            const presentation = f.context.taskGovernancePresentation({ status: 'completed', outcome });
            assert.equal(presentation.result, outcome);
            assert.doesNotMatch(presentation.text, /^tasks\./);
        }
        assert.equal(f.context.taskGovernancePresentation({ status: 'blocked', outcome: 'tool_blocked' }).result, 'tool_blocked');
        assert.equal(f.context.taskGovernancePresentation({ status: 'blocked', outcome: 'no_execution_evidence' }).result, 'no_execution_evidence');
        assert.equal(f.context.taskGovernancePresentation({ status: 'declined', outcome: 'verified_complete' }).result, 'declined');
        assert.equal(f.context.taskGovernancePresentation({ status: 'completed' }).result, 'completed');
        assert.equal(f.context.taskGovernancePresentation({ status: 'completed', outcome: 'future' }).result, 'unknown');
        assert.equal(f.context.batchAssessmentModeLabel(), languages[lang].tasks.assessmentUnrecorded);
        assert.equal(f.context.batchAssessmentModeLabel('toString'), 'toString');
        const html = f.context.renderTaskItem({ status: 'completed', outcome: '<img src=x onerror=unsafe()>', title: '<script>unsafe()</script>' });
        assert.doesNotMatch(html, /<img|<script>/);
        assert.match(html, /&lt;img/);
        assert.match(html, /&lt;script/);
    });
}

test('手动续跑单独显示和计数，不能覆盖历史完成/拒绝，活跃续跑时禁止重复执行与编辑', () => {
    const f = fixture();
    const task = freeze({ status: 'completed', outcome: 'verified_complete', conversationActive: true,
        latestRun: { status: 'running', runId: 'manual-run', assessmentMode: 'execution' } });
    const queue = freeze({ status: 'completed', executorActive: false, tasks: [task, { status: 'pending' }] });
    const before = JSON.stringify(queue);
    const stats = f.context.batchQueueTaskStats(queue);
    assert.equal(stats.verifiedComplete, 1);
    assert.equal(stats.running, 0);
    assert.equal(stats.manualActive, 1);
    assert.equal(f.context.batchQueueCanRunSingleTask(queue, task), false);
    assert.equal(f.context.batchQueueCanRunSingleTask(queue, queue.tasks[1]), false);
    assert.equal(f.context.batchQueueAllowsSubtaskMutation(queue), false);
    assert.match(f.context.batchQueueRunSingleTaskDisabledReason(queue, task), /会话正在执行/);
    assert.match(f.context.renderTaskGovernance(task), /历史状态|正在手动续跑|最近运行/);
    assert.equal(f.context.taskGovernancePresentation(task).result, 'verified_complete');
    const later = { ...task, conversationActive: false, latestRun: { status: 'declined', outcome: 'declined' } };
    assert.equal(f.context.taskGovernancePresentation(later).result, 'verified_complete');
    assert.match(f.context.renderTaskGovernance(later), /已拒绝/);
    assert.equal(f.context.isTaskManualContinuation(later), false);
    assert.equal(f.context.isTaskManualContinuation({ status: 'completed', latestRun: { status: 'running' } }), true);
    assert.equal(JSON.stringify(queue), before);
    assert.equal(f.saved.length, 0);
});

test('最近运行的模式、ID、原因与时间只读并完整转义，未知 outcome 不注入 HTML', () => {
    const f = fixture();
    const malicious = '<img src=x onerror=unsafe()>';
    const html = f.context.renderTaskGovernance({ completionReason: malicious, latestRun: {
        status: 'completed', outcome: malicious, runId: malicious, assessmentId: malicious,
        assessmentMode: malicious, completionReason: malicious, startedAt: 'invalid'
    } });
    assert.doesNotMatch(html, /<img|Invalid Date/);
    assert.match(html, /&lt;img/);
    assert.match(html, /评估 ID/);
    assert.match(html, /结束原因/);
});

test('队列卡片显示拒绝和缺口数量、服务端判重数；结束状态使用中性文案', () => {
    const f = fixture();
    const section = f.element('batch-queues-section');
    const list = f.element('batch-queues-list');
    f.context.renderBatchQueuesPagination = () => {};
    f.context.queue = { id: 'queue', status: 'completed', createdAt: '2026-10-02T10:00:00Z', assessmentMode: 'comprehensive', duplicateTasksSkipped: 2,
        tasks: [{ status: 'declined' }, { status: 'completed', outcome: 'delivered_with_gaps' }] };
    vm.runInContext('batchQueuesState.queues = [queue]', f.context);
    f.context.renderBatchQueues();
    assert.equal(section.style.display, 'block');
    assert.match(list.innerHTML, /本轮已结束/);
    assert.match(list.innerHTML, /1 项拒绝/);
    assert.match(list.innerHTML, /1 项有缺口完成/);
    assert.match(list.innerHTML, /已跳过 2 个重复任务/);
    assert.match(list.innerHTML, /综合评估/);
    assert.match(list.innerHTML, /处理进度 100%/);
    assert.doesNotMatch(list.innerHTML, /batch-queue-status-completed/);
    for (const duplicateTasksSkipped of [undefined, -1, '2', NaN, Infinity]) {
        assert.equal(f.context.batchQueueDuplicatesSkipped({ duplicateTasksSkipped }), null);
    }
    assert.equal(f.context.batchQueueDuplicatesSkipped({ duplicateTasksSkipped: 0 }), 0);
});

test('真实详情渲染旧快照兼容；历史拒绝与正在手动续跑独立展示并触发刷新', async () => {
    const f = fixture();
    f.element('batch-queue-detail-modal');
    f.element('batch-queue-detail-title');
    const content = f.element('batch-queue-detail-content');
    const rerun = f.element('batch-queue-rerun-btn');
    const add = f.element('batch-queue-add-task-btn');
    const remove = f.element('batch-queue-delete-btn');
    const queue = freeze({ id: 'q', status: 'completed', tasks: [{ id: 't', message: 'Original task', status: 'declined', outcome: 'declined',
        conversationActive: true, latestRun: { status: 'running', runId: 'manual', assessmentMode: 'execution' } }] });
    f.context.apiFetch = async () => response({ queue });
    await f.context.showBatchQueueDetail('q');
    assert.match(content.innerHTML, /已拒绝（未交付）/);
    assert.match(content.innerHTML, /会话正在手动续跑/);
    assert.match(content.innerHTML, /最近运行（独立于队列记录）/);
    assert.match(content.innerHTML, /评估模式未记录（旧快照）/);
    assert.match(content.innerHTML, /执行验证/);
    assert.match(content.innerHTML, /batch-task-run-btn" disabled/);
    assert.equal(rerun.disabled, true);
    assert.equal(add.style.display, 'none');
    assert.equal(remove.style.display, 'none');
    assert.deepEqual(f.refreshes, ['q']);
    assert.equal(queue.tasks[0].status, 'declined');
    assert.equal(f.saved.length, 0);

    f.context.apiFetch = async () => response({ queue: { id: 'old', status: 'completed', tasks: [{ id: 'old-t', message: 'Old task', status: 'completed' }] } });
    await f.context.showBatchQueueDetail('old');
    assert.match(content.innerHTML, /记录完成（未标注评估结果）/);
    assert.doesNotMatch(content.innerHTML, /NaN|验证完成|会话正在手动续跑/);
    assert.equal(rerun.disabled, false);
    assert.equal(f.refreshes.at(-1), 'stop');
});

test('定时队列本轮结束不暗示拒绝或有缺口任务成功，交付也不使用验证完成颜色', () => {
    const f = fixture();
    const presentation = f.context.getBatchQueueStatusPresentation({ status: 'completed', scheduleMode: 'cron', scheduleEnabled: true });
    assert.match(presentation.text, /本轮已结束/);
    assert.match(presentation.progressNote, /不代表全部成功/);
    assert.equal(f.context.taskGovernancePresentation({ status: 'completed', outcome: 'delivered' }).class, 'batch-task-status-delivered');
    assert.equal(f.context.taskGovernancePresentation({ status: 'completed', outcome: 'verified_complete' }).class, 'batch-task-status-completed');
});

test('真实历史加载保留服务端拒绝和最近运行字段，旧历史不补写 outcome；列表消失不推断结果', async () => {
    const f = fixture();
    const list = f.element('tasks-list');
    f.context.startDurationUpdates = () => {};
    const backend = freeze([{ conversationId: 'declined', status: 'completed', outcome: 'declined',
        latestRun: { status: 'declined', outcome: 'declined', assessmentMode: 'execution', runId: 'r' } },
    { conversationId: 'legacy', status: 'completed' }]);
    f.context.apiFetch = async url => response({ tasks: url.endsWith('/completed') ? backend : [] });
    await f.context.loadTasks();
    const history = vm.runInContext('tasksState.completedTasksHistory', f.context);
    assert.equal(history[0].outcome, 'declined');
    assert.equal(history[0].latestRun.runId, 'r');
    assert.equal(Object.hasOwn(history[1], 'outcome'), false);
    assert.match(list.innerHTML, /已拒绝（未交付）/);
    assert.match(list.innerHTML, /记录完成（未标注评估结果）/);
    f.context.oldTasks = [{ conversationId: 'stopped-refusal', status: 'declined', outcome: 'declined' },
        { conversationId: 'vanished-running', status: 'running', outcome: 'declined' }];
    vm.runInContext('tasksState.allTasks = oldTasks', f.context);
    f.context.updateCompletedTasksHistory([]);
    const updated = vm.runInContext('tasksState.completedTasksHistory', f.context);
    assert.equal(updated.find(task => task.conversationId === 'stopped-refusal').status, 'declined');
    const vanished = updated.find(task => task.conversationId === 'vanished-running');
    assert.equal(vanished.status, 'unknown');
    assert.equal(Object.hasOwn(vanished, 'outcome'), false);
    assert.equal(f.context.taskGovernanceResult(vanished), 'unknown');
    assert.equal(backend[0].status, 'completed');
});

test('新增治理文案在中英文中齐全，插值参数对齐', () => {
    const keys = ['assessmentModeLabel', 'assessmentAuto', 'assessmentConversation', 'assessmentExecution', 'assessmentComprehensive',
        'assessmentUnrecorded', 'assessmentModeHint', 'allowDuplicateTasks', 'allowDuplicateTasksHint', 'duplicateTasksSkipped',
        'duplicatesSkippedLabel', 'statusQueueEnded', 'statusLegacyCompleted', 'statusVerifiedComplete', 'statusDelivered',
        'statusDeliveredWithGaps', 'statusDeclined', 'statusToolBlocked', 'statusNoExecutionEvidence', 'unknownOutcome',
        'verifiedCompleteCount', 'deliveredCount', 'legacyCompletedCount', 'deliveredWithGapsCount', 'declinedCount',
        'timeoutCount', 'cancelledCount', 'pendingCount', 'runningCount', 'cancellingCount', 'unknownCount', 'processedLabel',
        'processedFraction', 'queueResultsLabel', 'manualActiveCount', 'manualContinuationActive', 'manualContinuationHint',
        'queueHistoricalCountsHint', 'latestRunLabel', 'runIdLabel', 'assessmentIdLabel', 'completionReasonLabel',
        'declinedReasonLabel', 'runSingleTaskUnavailableConversation'];
    const parameters = text => [...text.matchAll(/{{(\w+)}}/g)].map(match => match[1]).sort();
    for (const key of keys) {
        assert.equal(typeof languages['zh-CN'].tasks[key], 'string', key);
        assert.equal(typeof languages['en-US'].tasks[key], 'string', key);
        assert.deepEqual(parameters(languages['zh-CN'].tasks[key]), parameters(languages['en-US'].tasks[key]), key);
    }
});
