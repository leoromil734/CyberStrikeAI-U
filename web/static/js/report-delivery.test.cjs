const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

// 只加载前端源码到 VM；所有 DOM、SSE、HTTP 均为内存夹具，不连接服务或调用模型。
const source = Object.fromEntries(['monitor', 'chat', 'webshell'].map(name =>
    [name, fs.readFileSync(path.join(__dirname, name + '.js'), 'utf8')]));
function fn(file, name) {
    const match = source[file].match(new RegExp('(?:async )?function ' + name + '\\([^]*?\\n}'));
    assert.ok(match, name + ' must be extracted from production source');
    return match[0];
}
function evaluate(ctx, file, names) {
    vm.runInContext(names.map(name => fn(file, name)).join('\n'), ctx);
}

function domFixture() {
    const nodes = new Map();
    class Element {
        constructor(tag = 'div') {
            this.tagName = tag;
            this.dataset = {};
            this.children = [];
            this.style = {};
            this.className = '';
            this._text = '';
            this._html = '';
            this.classList = {
                contains: name => this.className.split(/\s+/).includes(name),
                add: (...names) => { this.className = [...new Set(this.className.split(/\s+/).filter(Boolean).concat(names))].join(' '); },
                remove: (...names) => { this.className = this.className.split(/\s+/).filter(name => !names.includes(name)).join(' '); },
                toggle: (name, value) => {
                    const enabled = value === undefined ? !this.classList.contains(name) : !!value;
                    this.classList[enabled ? 'add' : 'remove'](name);
                    return enabled;
                }
            };
        }
        set id(value) { this._id = value; nodes.set(value, this); }
        get id() { return this._id; }
        set textContent(value) { this._text = String(value || ''); this._html = ''; this.children = []; }
        get textContent() { return this._text + this.children.map(child => child.textContent).join(''); }
        set innerHTML(value) {
            this._html = String(value || ''); this._text = this._html; this.children = [];
            // 仅为生产 UI 所查询的 class 建立节点，正文断言使用 originalContent/innerHTML。
            for (const match of this._html.matchAll(/<([\w-]+)[^>]*class="([^"]+)"[^>]*>/g)) {
                const child = new Element(match[1]); child.className = match[2]; this.appendChild(child);
            }
        }
        get innerHTML() { return this._html; }
        get firstChild() { return this.children[0] || null; }
        get nextSibling() {
            if (!this.parentNode) return null;
            return this.parentNode.children[this.parentNode.children.indexOf(this) + 1] || null;
        }
        appendChild(child) { child.remove(); child.parentNode = this; this.children.push(child); return child; }
        insertBefore(child, before) {
            child.remove(); child.parentNode = this;
            const index = this.children.indexOf(before);
            this.children.splice(index < 0 ? this.children.length : index, 0, child);
            return child;
        }
        remove() {
            if (this.parentNode) this.parentNode.children = this.parentNode.children.filter(child => child !== this);
            this.parentNode = null;
        }
        matches(selector) { return selector.startsWith('.') && selector.slice(1).split('.').every(name => this.classList.contains(name)); }
        querySelectorAll(selector) {
            return this.children.flatMap(child => (child.matches(selector) ? [child] : []).concat(child.querySelectorAll(selector)));
        }
        querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
        closest(selector) { return this.matches(selector) ? this : (this.parentNode && this.parentNode.closest(selector)); }
        setAttribute(name, value) { this[name] = value; }
        addEventListener() {}
    }
    const document = {
        createElement: tag => new Element(tag), createDocumentFragment: () => new Element(),
        getElementById: id => nodes.get(id) || null,
        querySelector: selector => {
            const match = selector.match(/^#([^ ]+) (.+)$/);
            return match && nodes.has(match[1]) ? nodes.get(match[1]).querySelector(match[2]) : null;
        }, querySelectorAll: () => []
    };
    return { document, nodes, Element };
}
const helpers = [
    'isFinalizedResponseData', 'isStoppedReportStatus', 'hasPendingReportWork', 'isPartialReportResponseData',
    'reportDeliveryLabel', 'getResponseDeliveryState', 'hasDeliveredAssistantContent', 'shouldPreserveAssistantBody',
    'markAssistantDeliveryState', 'markAssistantFinalizationState', 'restoreAssistantDeliveryState',
    'hasFinalizationContract', 'finalizationCheckTitle', 'finalizationReasonLabel', 'finalizationMissingCheckLabel',
    'compactStringList', 'finalizationNoticeMarkdown', 'einoMainStreamPlanningTitle', 'timelineAgentBracketPrefix',
    'isEinoEmptyResponsePlaceholder', 'resolveFinalAssistantResponseText'
];
function context() {
    const dom = domFixture();
    const ctx = vm.createContext({ console, window: {}, document: dom.document, TextDecoder, AbortController,
        setTimeout: () => 0, clearTimeout: () => {}, requestAnimationFrame: callback => callback() });
    evaluate(ctx, 'monitor', helpers);
    for (const name of helpers) ctx.window[name] = ctx[name];
    evaluate(ctx, 'chat', ['historicalAssistantContent', 'restoreHistoricalAssistantMessage', 'renderProcessDetails']);
    evaluate(ctx, 'webshell', ['webshellResponseDelivery', 'preserveWebshellAssistantBody', 'applyWebshellResponse',
        'webshellFinalizationNotice', 'webshellFinalizationReasonLabel', 'webshellFinalizationMissingCheckLabel',
        'webshellCandidateTitle', 'renderWebshellHistoricalAssistant', 'isLikelyWebshellAiErrorMessage',
        'renderWebshellAiErrorMessage', 'simplifyWebshellAiError', 'webshellAgentPx', 'buildWebshellTimelineItemFromDetail']);
    vm.runInContext('var webshellStreamingTypingId = 0;', ctx);
    ctx.formatMarkdown = text => text;
    ctx.escapeHtml = text => String(text || '');
    return { ctx, ...dom };
}
const report = '# 阶段报告\n\n已完成部分检查。\n\n## 尚未评估\n覆盖未完成，不能宣称无漏洞。';
const draft = '# 正式最终报告\n\n' + '模型自行宣称所有工作完成。'.repeat(30);
const partial = (overrides = {}) => ({ finalized: false, finalizable: false, status: 'blocked',
    completionReason: 'coverage_incomplete', deliveryAvailable: true, deliveryKind: 'partial_report',
    runTerminated: true, deliveryText: report, pendingExecutionIds: [], ...overrides });

for (const status of ['blocked', 'failed', 'timeout', 'cancelled']) {
    test('严格 partial 合约接受停止状态 ' + status + '，正文只取 deliveryText', () => {
        const { ctx } = context();
        const data = partial({ status });
        const state = ctx.getResponseDeliveryState(data, draft);
        assert.equal(state.kind, 'partial_report');
        assert.equal(state.text, report);
        assert.equal(state.finalized, false);
        assert.equal(data.finalizable, false);
        assert.deepEqual(JSON.parse(JSON.stringify(ctx.webshellResponseDelivery(data, draft))), JSON.parse(JSON.stringify(state)));
        assert.equal(ctx.finalizationCheckTitle(data), '阶段报告 / 评估未完成');
    });
}
for (const [name, overrides] of Object.entries({
    '无 available': { deliveryAvailable: undefined }, '伪布尔 available': { deliveryAvailable: 'true' },
    '无 kind': { deliveryKind: undefined }, '无 terminated': { runTerminated: undefined },
    '仍在运行': { runTerminated: false, status: 'running' }, '伪 terminated': { runTerminated: 'true' },
    '错误停止状态': { status: 'completed' }, '空报告': { deliveryText: '  ' }, '缺正文': { deliveryText: undefined },
    '待完成工具': { pendingExecutionIds: ['tool-1'] }, '畸形 pending': { pendingExecutionIds: 'tool-1' },
    '待完成工具运行': { pendingToolRuns: [{ id: 'tool-run-1' }] },
    '字符串工具运行': { pendingToolRuns: 'tool-run-1' }, '对象工具运行': { pendingToolRuns: {} },
    '布尔工具运行': { pendingToolRuns: false }, '数字工具运行': { pendingToolRuns: 0 },
    'pending 原因': { completionReason: 'pending_tool_executions' }, 'HITL 原因': { completionReason: 'awaiting_hitl' },
    '工作流待审批': { workflowStatus: 'awaiting_hitl' }, 'HITL 标记': { awaitingHitl: true },
    '检查仍有工具': { missingChecks: ['tool execution still queued or running'] },
    '检查待审批': { missingChecks: ['workflow is awaiting HITL approval'] }
})) {
    test('拒绝伪阶段报告：' + name, () => {
        const { ctx } = context();
        const state = ctx.getResponseDeliveryState(partial(overrides), draft);
        assert.equal(state.delivered, false);
        assert.equal(state.finalized, false);
        assert.ok(!state.text.includes(report));
        assert.ok(!state.text.includes(draft));
        assert.equal(ctx.webshellResponseDelivery(partial(overrides), draft).delivered, false);
    });
}
test('无合约的长文本不升级，普通 finalized:true 继续成功交付', () => {
    const { ctx } = context();
    assert.equal(ctx.getResponseDeliveryState({}, draft).kind, 'candidate');
    assert.ok(!ctx.getResponseDeliveryState({}, draft).text.includes(draft));
    const final = ctx.getResponseDeliveryState({ finalized: true, status: 'completed' }, '真正最终回复');
    assert.equal(final.kind, 'final_report');
    assert.equal(final.text, '真正最终回复');
    assert.equal(final.finalized, true);
    assert.equal(ctx.getResponseDeliveryState(partial({ finalized: true }), draft).finalized, false);
});
test('共享模块缺失时 WebShell 保守拒绝 partial，而不是回退为正文', () => {
    const { ctx } = context();
    delete ctx.window.getResponseDeliveryState;
    assert.equal(ctx.webshellResponseDelivery(partial(), draft).delivered, false);
});

function monitorHarness() {
    const h = context();
    const { ctx, Element } = h;
    const timeline = new Element();
    const progress = new Element(); progress.id = 'p';
    const title = new Element(); title.className = 'progress-title'; progress.appendChild(title);
    const timelineItems = [], finalizedTasks = [];
    let assistantId = null, hid = 0, closedTools = 0;
    Object.assign(ctx, {
        acceptSequencedStreamEvent: (_, event) => event,
        resolveStreamTimeline: () => timeline, scrollChatMessagesToBottomIfPinned: () => {},
        mergeMcpExecutionIDLists: (a, b) => [...a, ...b],
        hideProgressMessageForFinalReply: () => hid++, finalizeOutstandingToolCallsForProgress: () => closedTools++,
        integrateProgressToMCPSection: () => {}, applyBackendMessageIdToAssistantDom: () => {},
        collapseAllProgressDetails: () => {}, loadConversations: () => {}, loadActiveTasks: () => {},
        resolveEventBackendMessageId: () => '', clearCsTaskReplay: () => {},
        finalizeProgressTask: (_, label) => finalizedTasks.push(label),
        formatAssistantMarkdownContent: text => text, wrapTablesInBubble: () => {},
        addMessage: (_, text) => {
            const element = new Element(); element.id = 'assistant';
            const host = new Element(); host.className = 'message-content'; element.appendChild(host);
            const bubble = new Element(); bubble.className = 'message-bubble'; host.appendChild(bubble);
            element.dataset.originalContent = text; bubble.innerHTML = text;
            return element.id;
        },
        addTimelineItem: (_, type, opts) => {
            const item = new Element(); item.id = 'timeline-' + timelineItems.length;
            const body = new Element(); body.className = 'timeline-item-content'; body.textContent = opts.message; item.appendChild(body);
            const head = new Element(); head.className = 'timeline-item-title'; head.textContent = opts.title; item.appendChild(head);
            timeline.appendChild(item); timelineItems.push({ type, ...opts }); return item.id;
        },
        buildMainResponseStreamIdentity: () => '', extractIterationTagFromStreamIdentity: () => '',
        shouldReuseMainResponseStream: () => false, streamBufferFromAccumulated: data => data.accumulated ?? null,
        mergeStreamBuffer: (current, delta, data) => data.accumulated ?? current + delta,
        scheduleStreamPlainTextUpdate: (element, text) => { element.textContent = text; },
        flushStreamPlainTextUpdate: () => {}, setTimelineItemContentStreamPlain: (element, text) => { element.textContent = text; }
    });
    vm.runInContext(`const progressTaskState = new Map([['p', {}]]);
        const responseStreamStateByProgressId = new Map(), thinkingStreamStateByProgressId = new Map();
        const einoAgentReplyStreamStateByProgressId = new Map(), mainIterationStateByProgressId = new Map();
        const toolResultStreamStateByKey = new Map(), streamSequenceStateByProgressId = new Map();`, ctx);
    evaluate(ctx, 'monitor', ['acceptSequencedStreamEvent', 'updateAssistantBubbleContent', 'finalizeMainResponseStreamItem', 'handleStreamEvent']);
    const send = (type, data = {}, message = '') => ctx.handleStreamEvent({ type, data, message }, progress, 'p',
        () => assistantId, id => { assistantId = id; }, () => [], () => {});
    return { ...h, send, title, timelineItems, finalizedTasks, get assistant() { return h.nodes.get(assistantId); },
        hidden: () => hid, closedTools: () => closedTools };
}
for (const eventType of ['response', 'finalization_check', 'done']) {
    test('主聊天真实事件分发：' + eventType + ' 交付阶段报告且 done 不显示成功', () => {
        const h = monitorHarness();
        h.send(eventType, partial({ streamId: 'report', streamSeq: 1, accumulated: draft }), '内部检查 coverage_incomplete');
        assert.equal(h.assistant.dataset.originalContent, report);
        assert.equal(h.assistant.dataset.deliveryKind, 'partial_report');
        assert.equal(h.assistant.dataset.finalized, 'false');
        assert.equal(h.assistant.dataset.finalizationStatus, 'blocked');
        assert.equal(h.assistant.querySelector('.report-delivery-label').textContent, '阶段报告 / 评估未完成');
        assert.ok(!h.assistant.querySelector('.message-bubble').innerHTML.includes('仍在验证'));
        h.send('done');
        assert.ok(!h.title.textContent.includes('✅'));
        assert.equal(h.finalizedTasks.at(-1), '阶段报告 / 评估未完成');
    });
}
test('真实分发器：partial 之后的 start/delta/planning/response/error/cancelled 不能覆盖交付', () => {
    const h = monitorHarness();
    h.send('response', partial(), draft);
    h.send('response_start', { orchestration: 'deep' });
    h.send('response_delta', {}, draft);
    h.send('planning', { finalized: true }, draft);
    h.send('response', {}, draft);
    h.send('error', {}, '晚到错误');
    h.send('cancelled', {}, '晚到取消');
    assert.equal(h.assistant.dataset.originalContent, report);
    assert.equal(h.assistant.dataset.deliveryKind, 'partial_report');
    assert.equal(h.assistant.dataset.finalized, 'false');
    assert.ok(h.timelineItems.filter(item => item.type === 'planning' || item.type === 'thinking')
        .every(item => item.title.includes('候选输出（尚未交付）')));
});
test('真实分发器：运行中或有 pending 的伪 partial 不隐藏进度、不关闭工具、不显示报告', () => {
    for (const data of [partial({ status: 'running', runTerminated: false }), partial({ pendingExecutionIds: ['pending'] }), {}]) {
        const h = monitorHarness(); h.send('response', data, draft);
        assert.equal(h.assistant.dataset.deliveryAvailable, 'false');
        assert.ok(!h.assistant.dataset.originalContent.includes(report));
        assert.ok(!h.assistant.dataset.originalContent.includes(draft));
        assert.equal(h.hidden(), 0); assert.equal(h.closedTools(), 0);
    }
});
test('真实分发器：普通成功仍交付最终回复', () => {
    const h = monitorHarness(); h.send('response', { finalized: true, status: 'completed' }, '最终正文'); h.send('done');
    assert.equal(h.assistant.dataset.originalContent, '最终正文');
    assert.equal(h.assistant.dataset.finalized, 'true');
    assert.equal(h.assistant.dataset.deliveryKind, 'final_report');
    assert.match(h.title.textContent, /✅/);
});

test('历史正文与懒加载：只恢复 finalization_check 状态，不用草稿、检查或 deliveryText 覆盖数据库 Markdown', () => {
    const h = monitorHarness();
    const saved = '# 数据库中的阶段报告\n\n详细正文，保留原样。';
    h.send('response', partial({ deliveryText: saved }));
    const element = h.assistant;
    delete element.dataset.deliveryKind; delete element.dataset.deliveryAvailable;
    const message = { content: saved, processDetails: [
        { eventType: 'planning', message: draft, data: { finalized: true } },
        { eventType: 'error', message: 'coverage_incomplete' }
    ] };
    assert.equal(h.ctx.historicalAssistantContent(message), saved);
    h.ctx.restoreHistoricalAssistantMessage(element, message);
    assert.equal(element.dataset.deliveryKind, undefined);
    Object.assign(h.ctx, { getMessageReasoningContent: () => '', messageHasConversationContent: () => true,
        ensureMcpCallSectionChrome: () => null });
    h.ctx.renderProcessDetails(element.id, [{ eventType: 'finalization_check', message: '仍在验证', data: partial() }]);
    assert.equal(element.dataset.deliveryKind, 'partial_report');
    assert.equal(element.dataset.originalContent, saved);
    h.ctx.renderProcessDetails(element.id, [{ eventType: 'finalization_check', data: { finalized: false, status: 'running' } }], { prepend: true });
    h.send('response', {}, draft);
    assert.equal(element.dataset.originalContent, saved);
    assert.equal(element.dataset.finalizationStatus, 'blocked');
    assert.equal(element.dataset.finalized, 'false');
});
test('历史未带 processDetails 时保留正文，旧 planning 自称最终报告不升级状态', () => {
    const { ctx, Element } = context();
    const element = new Element(); element.dataset.originalContent = report;
    ctx.restoreHistoricalAssistantMessage(element, { content: report });
    ctx.restoreAssistantDeliveryState(element, [{ eventType: 'planning', message: draft, data: partial() }]);
    assert.equal(element.dataset.deliveryKind, undefined);
    assert.equal(ctx.shouldPreserveAssistantBody(element, { delivered: false }), true);
    assert.equal(element.dataset.originalContent, report);
});

test('WebShell 主正文、历史状态与错误保留使用同一交付规则', () => {
    const { ctx, Element } = context(); const element = new Element();
    ctx.applyWebshellResponse(element, partial(), draft);
    assert.equal(element.dataset.originalContent, report);
    assert.equal(element.dataset.finalized, 'false');
    assert.equal(ctx.applyWebshellResponse(element, {}, draft), null);
    ctx.renderWebshellAiErrorMessage(element, '执行失败: later');
    assert.equal(element.dataset.originalContent, report);
    assert.equal(element.querySelector('.report-delivery-label').textContent, '阶段报告 / 评估未完成');
    const historical = new Element();
    const saved = '# 阶段报告\n\n某工具执行失败：API key/unauthorized。';
    ctx.renderWebshellHistoricalAssistant(historical, { content: saved, processDetails: [
        { eventType: 'error', message: '执行失败' }, { eventType: 'finalization_check', data: partial() }
    ] });
    assert.equal(historical.dataset.originalContent, saved);
    assert.equal(historical.innerHTML, saved);
    assert.equal(historical.dataset.deliveryKind, 'partial_report');
    const lazy = new Element(); ctx.renderWebshellHistoricalAssistant(lazy, { content: saved });
    assert.equal(lazy.innerHTML, saved);
    assert.ok(!lazy.classList.contains('webshell-ai-msg-error'));
    assert.match(ctx.buildWebshellTimelineItemFromDetail({ eventType: 'planning', message: draft, data: { finalized: true } }), /候选输出（尚未交付）/);
});

async function webshellStream(events) {
    const h = context(); const { ctx, Element } = h;
    const messages = new Element();
    const reads = events.map(event => ({ done: false, value: new TextEncoder().encode('data: ' + JSON.stringify(event) + '\n\n') }));
    const reader = { read: async () => reads.shift() || { done: true } };
    Object.assign(ctx, {
        apiFetch: async () => ({ ok: true, body: { getReader: () => reader } }),
        resolveWebshellAiStreamRequest: async () => ({ path: '/fixture-only' }),
        wsSetAiSendingState: () => {}, getCurrentRole: () => '', getWebshellAiProjectSelection: () => '',
        wsTOr: (_, fallback) => fallback
    });
    vm.runInContext('var webshellAiSending = false, webshellAiConvMap = {}, webshellAiAbortController = null, webshellAiStreamReader = null;', ctx);
    evaluate(ctx, 'webshell', ['runWebshellAiSend']);
    await ctx.runWebshellAiSend({ id: 'fixture' }, { value: '离线夹具' }, {}, messages);
    return { ...h, messages, assistant: messages.querySelector('.webshell-ai-msg.assistant') };
}
test('WebShell 真实 SSE 消费：草稿只在过程区，阶段报告后晚到流和错误不能覆盖正文', async () => {
    const h = await webshellStream([
        { type: 'response_start', data: { orchestration: 'deep' } }, { type: 'response_delta', message: draft },
        { type: 'finalization_check', data: partial(), message: '内部检查 coverage_incomplete' },
        { type: 'response', data: partial(), message: draft },
        { type: 'response_start' }, { type: 'response_delta', message: '晚到草稿' },
        { type: 'response', data: {}, message: '晚到草稿' }, { type: 'error', message: '晚到失败' }, { type: 'done' }
    ]);
    assert.equal(h.assistant.dataset.originalContent, report);
    assert.equal(h.assistant.dataset.deliveryKind, 'partial_report');
    assert.equal(h.assistant.dataset.finalized, 'false');
    assert.equal(h.assistant.querySelector('.report-delivery-label').textContent, '阶段报告 / 评估未完成');
    assert.ok(h.messages.querySelectorAll('.webshell-ai-timeline-planning').length >= 2);
});
test('WebShell 真实 SSE 消费：只有草稿后 EOF 不等于交付', async () => {
    const h = await webshellStream([{ type: 'response_start' }, { type: 'response_delta', message: draft }]);
    assert.equal(h.assistant.dataset.deliveryAvailable, 'false');
    assert.ok(!h.assistant.dataset.originalContent.includes(draft));
});

test('pendingToolRuns 缺省、null 或空数组允许阶段报告', () => {
    const { ctx } = context();
    for (const pendingToolRuns of [undefined, null, []]) {
        assert.equal(ctx.isPartialReportResponseData(partial({ pendingToolRuns })), true);
    }
});
test('主聊天 done-only 更新已有候选正文，并保留未完成状态', () => {
    const h = monitorHarness();
    h.send('response', {}, draft);
    const original = h.assistant;
    h.send('done', partial({ status: 'timeout' }), '内部终态说明');
    assert.equal(h.assistant, original);
    assert.equal(h.assistant.dataset.originalContent, report);
    assert.equal(h.assistant.dataset.finalizationStatus, 'timeout');
    assert.equal(h.assistant.dataset.finalized, 'false');
    assert.doesNotMatch(h.title.textContent, /✅/);
});
test('主聊天裸 done、无交付的 check/done 和伪 partial 均不显示成功', () => {
    for (const data of [{}, { status: 'completed' }, partial({ deliveryAvailable: false }),
        partial({ pendingToolRuns: ['pending'] }), partial({ pendingToolRuns: {} }),
        partial({ pendingExecutionIds: ['pending'] }), partial({ awaitingHitl: true }),
        partial({ workflowStatus: 'awaiting_hitl' })]) {
        const h = monitorHarness();
        h.send('done', data, draft);
        assert.equal(h.assistant, undefined);
        assert.doesNotMatch(h.title.textContent, /✅/);
        assert.ok(!h.finalizedTasks.includes('已完成'));
    }
    const h = monitorHarness();
    h.send('finalization_check', { finalized: false, completionReason: 'report_not_submitted_via_exit' });
    h.send('done');
    assert.equal(h.assistant, undefined);
    assert.doesNotMatch(h.title.textContent, /✅/);
});
test('主聊天 done 明确成功合约可标成功，但 pending 优先阻止成功', () => {
    const h = monitorHarness();
    h.send('done', { finalized: true, status: 'completed' });
    assert.match(h.title.textContent, /✅/);
    h.send('done', { finalized: true, pendingToolRuns: ['pending'] });
    assert.doesNotMatch(h.title.textContent, /✅/);
});
test('done 合约恢复历史状态及实时重放均不能覆盖数据库正文', () => {
    const h = monitorHarness();
    const saved = '# 数据库权威正文';
    h.send('response', partial({ deliveryText: saved }));
    h.ctx.restoreHistoricalAssistantMessage(h.assistant, { content: saved });
    h.send('done', partial());
    assert.equal(h.assistant.dataset.originalContent, saved);
    assert.equal(h.assistant.dataset.deliveryKind, 'partial_report');
    const historical = new h.Element();
    historical.dataset.originalContent = saved;
    h.ctx.restoreHistoricalAssistantMessage(historical, { content: saved, processDetails: [
        { eventType: 'done', data: partial() }
    ] });
    assert.equal(historical.dataset.originalContent, saved);
    assert.equal(historical.dataset.deliveryKind, 'partial_report');
    const ws = new h.Element();
    h.ctx.renderWebshellHistoricalAssistant(ws, { content: saved, processDetails: [{ eventType: 'done', data: partial() }] });
    assert.equal(ws.dataset.deliveryKind, 'partial_report');
    h.ctx.applyWebshellResponse(ws, partial(), '');
    assert.equal(ws.dataset.originalContent, saved);
    assert.equal(ws.innerHTML, saved);
});
test('WebShell 真实 SSE done-only 创建报告，也可替换候选提示且抵抗晚到草稿', async () => {
    for (const prefix of [[], [{ type: 'response', data: {}, message: draft }]]) {
        const h = await webshellStream(prefix.concat([
            { type: 'done', data: partial({ status: 'failed' }), message: '内部终态说明' },
            { type: 'response_start' }, { type: 'response_delta', message: draft },
            { type: 'response', data: {}, message: draft }, { type: 'done' }
        ]));
        assert.equal(h.assistant.dataset.originalContent, report);
        assert.equal(h.assistant.dataset.finalized, 'false');
        assert.equal(h.assistant.dataset.finalizationStatus, 'failed');
        assert.equal(h.assistant.querySelector('.report-delivery-label').textContent, '阶段报告 / 评估未完成');
    }
});
test('WebShell 真实 SSE done 拒绝 pendingToolRuns、HITL 和缺合约', async () => {
    for (const data of [{}, partial({ pendingToolRuns: ['pending'] }), partial({ pendingToolRuns: {} }),
        partial({ pendingExecutionIds: ['pending'] }), partial({ workflowStatus: 'awaiting_hitl' })]) {
        const h = await webshellStream([{ type: 'done', data, message: draft }]);
        assert.notEqual(h.assistant.dataset.deliveryAvailable, 'true');
        assert.notEqual(h.assistant.dataset.finalized, 'true');
        assert.ok(!(h.assistant.dataset.originalContent || '').includes(report));
        assert.ok(!h.assistant.textContent.includes(draft));
    }
});
test('未通过 exit 提交报告的原因在主聊天和 WebShell 都有中文标签', () => {
    const { ctx } = context();
    assert.equal(ctx.finalizationReasonLabel('report_not_submitted_via_exit'), '报告未通过 exit 提交');
    assert.equal(ctx.webshellFinalizationReasonLabel('report_not_submitted_via_exit'), '报告未通过 exit 提交');
});
