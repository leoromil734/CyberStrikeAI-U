const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const monitor = fs.readFileSync(path.join(__dirname, 'monitor.js'), 'utf8');
const chat = fs.readFileSync(path.join(__dirname, 'chat.js'), 'utf8').replace(/\r\n/g, '\n');
const router = fs.readFileSync(path.join(__dirname, 'router.js'), 'utf8');
function fn(source, name) {
    const match = source.match(new RegExp('(?:async )?function ' + name + '\\([^]*?\\n}'));
    assert.ok(match, name + ' must be extracted from production source');
    return match[0];
}
function deferred() {
    let resolve, reject;
    const promise = new Promise((a, b) => { resolve = a; reject = b; });
    return { promise, resolve, reject };
}
const tick = () => new Promise(resolve => setImmediate(resolve));
const ok = body => ({ ok: true, json: async () => body });
function context(globals = {}) {
    return vm.createContext({ console, AbortController, TextDecoder, URLSearchParams, setTimeout, clearTimeout,
        requestAnimationFrame: cb => setImmediate(cb), window: {}, ...globals });
}
function run(ctx, source) { return vm.runInContext(source, ctx); }
function sequenceContext() {
    const ctx = context();
    run(ctx, 'const streamSequenceStateByProgressId = new Map();\n' +
        ['normalizeStreamingDeltaJs', 'streamBufferFromAccumulated', 'mergeStreamBuffer', 'acceptSequencedStreamEvent']
            .map(name => fn(monitor, name)).join('\n'));
    return ctx;
}
for (const type of ['response_delta', 'thinking_stream_delta', 'reasoning_chain_stream_delta', 'eino_agent_reply_stream_delta']) {
    test(type + ' 纯增量、重复序号、丢帧冻结与稀疏快照恢复', () => {
        const ctx = sequenceContext();
        let buffer = '';
        const consume = (seq, message, snapshot, streamId = 'one') => {
            const data = { streamId, streamSeq: seq };
            if (snapshot !== undefined) data.accumulated = snapshot;
            const event = ctx.acceptSequencedStreamEvent('progress', { type, message, data });
            if (event) buffer = ctx.mergeStreamBuffer(buffer, event.message, event.data);
            return buffer;
        };
        assert.equal(consume(1, '哈', '哈'), '哈');
        assert.equal(consume(2, '哈'), '哈哈');
        assert.equal(consume(2, '哈', '旧快照'), '哈哈');
        assert.equal(consume(4, '错误'), '哈哈');
        assert.equal(consume(5, '继续错误'), '哈哈');
        assert.equal(consume(6, '恢复', '完整恢复'), '完整恢复');
        assert.equal(consume(7, '!'), '完整恢复!');
        assert.equal(consume(1, '新流', '新流', 'two'), '新流');
    });
}
test('订阅从中间开始时等待快照，终态全文恢复，旧协议保持归一化', () => {
    const ctx = sequenceContext();
    assert.equal(ctx.acceptSequencedStreamEvent('p', { type: 'response_delta', message: '坏', data: { streamId: 's', streamSeq: 8 } }), null);
    const terminal = ctx.acceptSequencedStreamEvent('p', { type: 'response', message: '', data: { streamId: 's', streamSeq: 9, accumulated: '最终全文' } });
    assert.equal(terminal.message, '最终全文');
    assert.equal(ctx.mergeStreamBuffer('你好', '你好世界', {}), '你好世界');
    assert.equal(ctx.mergeStreamBuffer('你好', '', { accumulated: '' }), '');
    assert.equal(ctx.acceptSequencedStreamEvent('p', { type: 'response', data: {} }).type, 'response');
});

function paginationContext(fetcher) {
    const message = { id: 'msg', dataset: {} };
    const container = { dataset: {}, querySelectorAll: () => [] };
    const nodes = new Map([['msg', message], ['process-details-msg', container]]);
    const rendered = [], pages = [], urls = [];
    const ctx = context({ document: { getElementById: id => nodes.get(id) || null },
        apiFetch: (url, options) => { urls.push(url); return fetcher(url, options); },
        renderProcessDetails: (...args) => rendered.push(args),
        updateProcessDetailsPaginationButtons: (...args) => pages.push(args),
        scrollProcessDetailsToLatest: () => {} });
    run(ctx, 'let loadConversationRequestSeq = 1; const PROCESS_DETAILS_PAGE_SIZE = 50; const processDetailsSummaryCache = new WeakMap();\n' +
        ['fetchProcessDetailsSummaryOnce', 'applyProcessDetailsToolSummary', 'loadProcessDetailsPaginated'].map(name => fn(monitor, name)).join('\n'));
    return { ctx, nodes, container, rendered, pages, urls };
}
test('初次/恢复仅一次 latest=1&limit=50&include_summary=false，并采用服务端 offset', async () => {
    const h = paginationContext(async () => ok({ processDetails: Array.from({ length: 50 }, (_, i) => ({ id: i })), offset: 1950, total: 2000, hasMore: false }));
    await h.ctx.loadProcessDetailsPaginated('msg', 'backend');
    assert.deepEqual(h.urls, ['/api/messages/backend/process-details?latest=1&limit=50&include_summary=false']);
    assert.equal(h.container.dataset.prevOffset, '1900');
    assert.equal(h.container.dataset.nextOffset, '2000');
    assert.equal(h.pages[0][2].hasPrev, true);
    assert.equal(h.pages[0][2].hasNext, false);
});
test('上滚按需请求更早页，分页不请求全量摘要', async () => {
    const h = paginationContext(async () => ok({ processDetails: [{ id: 'old' }], offset: 100, total: 201, hasMore: true }));
    h.container.dataset.prevOffset = '100';
    h.container.dataset.nextOffset = '201';
    await h.ctx.loadProcessDetailsPaginated('msg', 'backend', { prepend: true });
    assert.match(h.urls[0], /limit=50&include_summary=false&offset=100$/);
    assert.equal(h.urls.length, 1);
    assert.equal(h.rendered[0][2].prepend, true);
    assert.equal(h.container.dataset.nextOffset, '201');
});
test('旧历史请求在 A→B→A 后返回，不渲染、不更新分页', async () => {
    const response = deferred();
    const h = paginationContext(() => response.promise);
    const promise = h.ctx.loadProcessDetailsPaginated('msg', 'backend');
    run(h.ctx, 'loadConversationRequestSeq += 2');
    response.resolve(ok({ processDetails: [{ id: 'stale' }], offset: 0 }));
    await promise;
    assert.equal(h.rendered.length, 0);
    assert.equal(h.pages.length, 0);
});
test('分页渲染后、下一帧前切换会话，不更新新容器', async () => {
    const h = paginationContext(async () => ok({ processDetails: [{ id: 'old' }], offset: 0 }));
    h.ctx.requestAnimationFrame = cb => {
        run(h.ctx, 'loadConversationRequestSeq++');
        setImmediate(cb);
    };
    await h.ctx.loadProcessDetailsPaginated('msg', 'backend');
    assert.equal(h.rendered.length, 1);
    assert.equal(h.pages.length, 0);
});

function replayContext() {
    const calls = [], readers = [], histories = [], dispatched = [];
    const nodes = new Map();
    const ctx = context({ window: { currentConversationId: 'A' },
        document: { getElementById: id => nodes.get(id) || null },
        shouldSkipTaskEventReplayAttach: () => false,
        findLastAssistantMessageElInChat: () => ({ id: 'msg', dataset: { backendMessageId: 'backend' } }),
        loadProcessDetailsPaginated: (...args) => { const d = deferred(); d.options = args[2]; histories.push(d); return d.promise; },
        expandProcessDetailsTimeline: () => {},
        registerProgressTask: () => {},
        handleStreamEvent: event => dispatched.push(event),
        processSseDataLinesYielding: async (lines, dispatch) => { for (const line of lines) if (line.startsWith('data: ')) dispatch(JSON.parse(line.slice(6))); },
        mergeMcpExecutionIDLists: (a, b) => [...a, ...b],
        apiFetch: (url, options) => {
            const d = deferred(); calls.push({ url, options, ...d }); return d.promise;
        } });
    run(ctx, `const taskEventReplayAttachState = { session: null, conversationId: null, inFlightPromise: null };
        const progressTaskState = new Map(); const thinkingStreamStateByProgressId = new Map();
        const responseStreamStateByProgressId = new Map(); const einoAgentReplyStreamStateByProgressId = new Map();
        const streamSequenceStateByProgressId = new Map();\n` +
        ['createTaskReplayHistoryGate', 'clearCsTaskReplay', 'taskReplayProgressId', 'beginCsTaskReplay', 'cancelTaskEventReplaySubscription', 'taskReplayHistoryKey', 'seedTaskReplayHistory', 'attachRunningTaskEventStream']
            .map(name => fn(monitor, name)).join('\n'));
    function openStream(call) {
        let read = deferred();
        const reader = { cancels: 0,
            read: () => read.promise,
            send: event => { const prev = read; read = deferred(); prev.resolve({ done: false, value: new TextEncoder().encode('data: ' + JSON.stringify(event) + '\n\n') }); },
            cancel: () => { reader.cancels++; read.resolve({ done: true }); return Promise.resolve(); } };
        readers.push(reader);
        call.resolve({ ok: true, body: { getReader: () => reader } });
        return reader;
    }
    const active = id => ok({ tasks: [{ conversationId: id, status: 'running' }] });
    return { ctx, calls, readers, histories, dispatched, openStream, active };
}
test('A→B→A 取消旧 AbortController；旧 finally 不清除新的 A 订阅', async () => {
    const h = replayContext();
    const first = h.ctx.attachRunningTaskEventStream('A');
    h.ctx.window.currentConversationId = 'B';
    const second = h.ctx.attachRunningTaskEventStream('B');
    h.ctx.window.currentConversationId = 'A';
    const third = h.ctx.attachRunningTaskEventStream('A');
    assert.equal(h.calls[0].options.signal.aborted, true);
    assert.equal(h.calls[1].options.signal.aborted, true);
    assert.equal(h.calls[2].options.signal.aborted, false);
    h.calls[0].resolve(h.active('A'));
    h.calls[1].resolve(h.active('B'));
    await Promise.all([first, second]);
    assert.equal(run(h.ctx, 'taskEventReplayAttachState.conversationId'), 'A');
    assert.equal(h.calls[2].options.signal.aborted, false);
    h.ctx.cancelTaskEventReplaySubscription();
    h.calls[2].resolve(h.active('A'));
    await third;
    assert.equal(h.calls.length, 3);
});
for (const switchAt of ['none', 'before404', 'duringHistory']) {
    test('活跃检查后订阅 404 回退最新历史和审批，切换时机：' + switchAt, async () => {
        const h = replayContext();
        const approvals = [];
        h.ctx.window.restoreHitlInlineForConversation = async id => { approvals.push(id); };
        const pending = h.ctx.attachRunningTaskEventStream('A');
        h.calls[0].resolve(h.active('A'));
        await tick();
        assert.match(h.calls[1].url, /task-events/);
        if (switchAt === 'before404') h.ctx.window.currentConversationId = 'B';
        h.calls[1].resolve({ ok: false, status: 404 });
        await tick();
        assert.equal(h.histories.length, switchAt === 'before404' ? 0 : 1);
        if (h.histories.length) {
            assert.equal(h.histories[0].options.isCurrent(), true);
            assert.equal(h.histories[0].options.autoLoadAll, undefined);
            assert.deepEqual(approvals, []);
            if (switchAt === 'duringHistory') {
                h.ctx.window.currentConversationId = 'B';
                h.ctx.cancelTaskEventReplaySubscription();
                assert.equal(h.histories[0].options.isCurrent(), false);
                assert.equal(h.histories[0].options.signal.aborted, true);
            }
            h.histories[0].resolve([]);
        }
        assert.equal(await pending, false);
        assert.deepEqual(approvals, switchAt === 'none' ? ['A'] : []);
        assert.equal(h.readers.length, 0);
        assert.equal(h.calls.length, 2);
        assert.equal(h.calls.some(c => /cancel|stop/.test(c.url)), false);
        assert.equal(run(h.ctx, 'taskEventReplayAttachState.session'), null);
    });
}

test('SSE 先连接，历史加载期间缓冲；重叠工具事件仅展示一次，取消释放 reader', async () => {
    const h = replayContext();
    const promise = h.ctx.attachRunningTaskEventStream('A');
    h.calls[0].resolve(h.active('A'));
    await tick();
    assert.match(h.calls[1].url, /task-events/);
    assert.equal(h.histories.length, 0);
    const reader = h.openStream(h.calls[1]);
    await tick();
    assert.equal(h.histories.length, 1);
    reader.send({ type: 'tool_call', message: 'old', data: { processDetailId: 'old-id' } });
    await tick();
    reader.send({ type: 'response_delta', message: 'new', data: { streamId: 's', streamSeq: 1, accumulated: 'new' } });
    await tick();
    assert.equal(h.dispatched.length, 0);
    h.histories[0].resolve([{ id: 'old-id', eventType: 'tool_call', message: 'old', data: {} }]);
    await tick();
    assert.deepEqual(h.dispatched.map(e => e.type), ['response_delta']);
    h.ctx.cancelTaskEventReplaySubscription();
    await promise;
    assert.equal(reader.cancels, 1);
    assert.equal(h.calls[1].options.signal.aborted, true);
    assert.equal(h.calls.some(c => /cancel|stop/.test(c.url)), false);
});
test('取消后旧历史返回，不重放旧缓冲事件、不清新会话状态', async () => {
    const h = replayContext();
    const old = h.ctx.attachRunningTaskEventStream('A');
    h.calls[0].resolve(h.active('A')); await tick();
    const reader = h.openStream(h.calls[1]); await tick();
    reader.send({ type: 'progress', message: 'old' }); await tick();
    h.ctx.window.currentConversationId = 'B';
    const next = h.ctx.attachRunningTaskEventStream('B');
    await old;
    h.histories[0].resolve([]); await tick();
    assert.equal(h.dispatched.length, 0);
    assert.equal(run(h.ctx, 'taskEventReplayAttachState.conversationId'), 'B');
    h.ctx.cancelTaskEventReplaySubscription();
    h.calls[2].resolve(h.active('B')); await next;
});
test('旧会话详情响应在新会话/离开页面后返回时不能改 UI', async () => {
    const response = deferred(); let cancelled = 0;
    const ctx = context({ window: { cancelTaskEventReplaySubscription: () => cancelled++ },
        chatTargetReminderHide: () => {}, getConversationLiteFromCache: () => null,
        apiFetch: () => response.promise });
    run(ctx, 'let loadConversationRequestSeq = 0; let chatTargetReminderAcknowledgedText; let chatTargetReminderHits;\n' +
        fn(chat, 'invalidateChatView') + '\n' + fn(chat, 'loadConversation'));
    const loading = ctx.loadConversation('A');
    ctx.invalidateChatView();
    response.resolve(ok({ messages: [{ role: 'assistant', content: 'stale' }] }));
    await loading;
    assert.equal(cancelled, 2);
    assert.equal(run(ctx, 'loadConversationRequestSeq'), 2);
});
test('新会话立即取消订阅，异步初始化返回时不得覆盖后来选择的会话', async () => {
    const init = deferred(); let cancelled = 0;
    const ctx = context({ window: { cancelTaskEventReplaySubscription: () => cancelled++ },
        ensureDefaultActiveProjectForNewChat: () => init.promise });
    run(ctx, 'let loadConversationRequestSeq = 0; let currentGroupId = null; let currentConversationId = "A"; let currentConversationGroupId;\n' +
        fn(chat, 'invalidateChatView') + '\n' + fn(chat, 'startNewConversation'));
    const pending = ctx.startNewConversation();
    assert.equal(cancelled, 1);
    assert.equal(run(ctx, 'currentConversationId'), null);
    ctx.invalidateChatView();
    init.resolve();
    await pending; // 没有提供 document：若旧初始化仍操作 UI，此处会直接失败。
});

test('历史流快照播种序号和正文，后续流式事件复用同一条目', () => {
    const h = replayContext();
    h.ctx.document.getElementById = () => ({ querySelectorAll: () => [{ id: 'historic-item', dataset: { streamId: 'stream' } }] });
    h.ctx.seedTaskReplayHistory('p', 'msg', [{ eventType: 'reasoning_chain', message: '持久化全文', data: { streamId: 'stream', streamSeq: 20, accumulated: '较早周期快照' } }]);
    assert.equal(run(h.ctx, 'thinkingStreamStateByProgressId.get("p").get("stream").buffer'), '持久化全文');
    assert.equal(run(h.ctx, 'streamSequenceStateByProgressId.get("p").get("stream").seq'), 20);
});

test('真实事件分发器的四类流均恢复缺失 start，重复和丢帧不会污染 DOM', () => {
    for (const type of ['response_delta', 'thinking_stream_delta', 'reasoning_chain_stream_delta', 'eino_agent_reply_stream_delta']) {
        const ctx = sequenceContext();
        const nodes = new Map();
        const timeline = {};
        Object.assign(ctx, {
            document: { getElementById: id => nodes.get(id) || null },
            resolveStreamTimeline: () => timeline,
            timelineAgentBracketPrefix: () => '',
            scrollChatMessagesToBottomIfPinned: () => {},
            scheduleStreamPlainTextUpdate: (el, text) => { el.textContent = text; },
            setTimelineItemContentStreamPlain: (el, text) => { el.textContent = text; },
            flushStreamPlainTextUpdate: () => {},
            buildMainResponseStreamIdentity: () => '', extractIterationTagFromStreamIdentity: () => '',
            shouldReuseMainResponseStream: () => false, einoMainStreamPlanningTitle: () => 'response',
            mergeMcpExecutionIDLists: (a, b) => [...a, ...b],
            addTimelineItem: (tl, kind, opts) => {
                const id = 'item-' + nodes.size;
                const content = { textContent: opts.message };
                nodes.set(id, { id, dataset: {}, querySelector: () => content });
                return id;
            }
        });
        run(ctx, 'const progressTaskState = new Map(); const thinkingStreamStateByProgressId = new Map(); const responseStreamStateByProgressId = new Map(); const einoAgentReplyStreamStateByProgressId = new Map();\n' + fn(monitor, 'handleStreamEvent'));
        const send = (seq, text, accumulated, eventType = type) => ctx.handleStreamEvent({ type: eventType, message: text,
            data: { streamId: 'stream', streamSeq: seq, ...(accumulated === undefined ? {} : { accumulated }) } },
            null, 'p', () => 'msg', () => {}, () => [], () => {});
        send(4, 'ignored');
        assert.equal(nodes.size, 0);
        send(5, 'first', '完整');
        assert.equal(nodes.size, 1);
        const content = [...nodes.values()][0].querySelector();
        assert.equal(content.textContent, '完整');
        send(6, '完整');
        assert.equal(content.textContent, '完整完整');
        send(6, 'bad', 'bad');
        send(8, 'gap');
        send(9, 'bad');
        assert.equal(content.textContent, '完整完整');
        send(10, '', '恢复');
        assert.equal(content.textContent, '恢复');
        if (type !== 'response_delta') {
            const terminal = type === 'eino_agent_reply_stream_delta' ? 'eino_agent_reply_stream_end'
                : type === 'thinking_stream_delta' ? 'thinking' : 'reasoning_chain';
            send(11, '', '终态全文', terminal);
            assert.equal(content.textContent, '终态全文');
        }
    }
});

test('主响应不同 streamId 即使元数据一致也必须创建新流', () => {
    const ctx = context({ sameMainResponseStreamMeta: () => true });
    run(ctx, fn(monitor, 'shouldReuseMainResponseStream'));
    assert.equal(ctx.shouldReuseMainResponseStream('p', { itemId: 'i', streamId: 'old' }, { streamId: 'new' }, ''), false);
    assert.equal(ctx.shouldReuseMainResponseStream('p', { itemId: 'i', streamId: 'same' }, { streamId: 'same' }, ''), true);
});

test('分页游标优先采用原始行 nextOffset，去重后的空页也可继续翻页', async () => {
    let page = 0;
    const h = paginationContext(async () => ok(page++ === 0
        ? { processDetails: [], offset: 0, nextOffset: 50, total: 100, hasMore: true }
        : { processDetails: [{ id: 'deduped' }], offset: 50, nextOffset: 100, total: 100, hasMore: false }));
    await h.ctx.loadProcessDetailsPaginated('msg', 'backend', { autoLoadAll: true });
    assert.equal(h.urls.length, 2);
    assert.match(h.urls[1], /offset=50$/);
    assert.equal(h.container.dataset.nextOffset, '100');
});

test('跨页工具摘要每个容器只请求一次，后续分页复用终态', async () => {
    const h = paginationContext(async url => ok(url.includes('summary=1')
        ? { summary: { toolExecutions: [{ processDetailId: 'call', status: 'completed' }] } }
        : { processDetails: [{ id: 'call', eventType: 'tool_call', data: {} }], offset: 100, nextOffset: 150, total: 150 }));
    await h.ctx.loadProcessDetailsPaginated('msg', 'backend');
    await tick();
    await h.ctx.loadProcessDetailsPaginated('msg', 'backend', { prepend: true });
    await tick();
    await h.ctx.fetchProcessDetailsSummaryOnce('msg', 'backend');
    assert.equal(h.urls.filter(url => url.includes('summary=1')).length, 1);
    assert.equal(h.rendered[1][2].toolExecutions[0].status, 'completed');
});

test('摘要补齐历史工具终态，不能覆盖更晚的实时失败结果', () => {
    const ctx = context();
    run(ctx, fn(monitor, 'applyProcessDetailsToolSummary'));
    const classes = new Set(['tool-call-incomplete']);
    const item = { dataset: { processDetailId: 'call' }, title: 'unknown', classList: {
        contains: name => classes.has(name), add: name => classes.add(name), remove: (...names) => names.forEach(name => classes.delete(name))
    } };
    const container = { querySelectorAll: () => [item] };
    ctx.applyProcessDetailsToolSummary(container, [{ processDetailId: 'call', status: 'completed' }]);
    assert.equal(classes.has('tool-call-completed'), true);
    assert.equal(classes.has('tool-call-incomplete'), false);
    classes.delete('tool-call-completed'); classes.add('tool-call-failed'); item.dataset.toolDisplayStatus = 'failed';
    ctx.applyProcessDetailsToolSummary(container, [{ processDetailId: 'call', status: 'completed' }]);
    assert.equal(item.dataset.toolDisplayStatus, 'failed');
});

test('历史帧数和字节上限触发转实时，已缓冲和触发帧全部保留且顺序不变', async () => {
    for (const options of [{ maxEvents: 2 }, { maxBytes: 10 }]) {
        const ctx = context(); run(ctx, fn(monitor, 'createTaskReplayHistoryGate'));
        const seen = []; let fallbacks = 0;
        const gate = ctx.createTaskReplayHistoryGate(event => seen.push(event), () => fallbacks++, options);
        gate.receive('one'); gate.receive('two'); gate.receive('three');
        await gate.settled;
        assert.equal(fallbacks, 1);
        assert.deepEqual(seen, ['one', 'two', 'three']);
        gate.complete(() => { throw new Error('late history must not replay'); });
        gate.receive('four');
        assert.equal(seen[3], 'four');
    }
});

test('历史超时转实时仍按序号等待快照，空 message 的 streamFinal delta 恢复全文', async () => {
    const ctx = sequenceContext(); run(ctx, fn(monitor, 'createTaskReplayHistoryGate'));
    let buffer = ''; let fallbacks = 0;
    const consume = event => {
        const accepted = ctx.acceptSequencedStreamEvent('p', event);
        if (accepted) buffer = ctx.mergeStreamBuffer(buffer, accepted.message, accepted.data);
    };
    const gate = ctx.createTaskReplayHistoryGate(consume, () => fallbacks++, { timeoutMs: 5 });
    gate.receive({ type: 'response_delta', message: '不能拼接', data: { streamId: 's', streamSeq: 8 } });
    await gate.settled;
    assert.equal(fallbacks, 1);
    assert.equal(buffer, '');
    gate.receive({ type: 'response_delta', message: '', data: { streamId: 's', streamSeq: 9, accumulated: '最终全文', streamFinal: true } });
    assert.equal(buffer, '最终全文');
});

test('真实订阅缓冲超限只取消历史，不取消 SSE 或后端任务，晚到历史无效', async () => {
    const h = replayContext();
    const pending = h.ctx.attachRunningTaskEventStream('A');
    h.calls[0].resolve(h.active('A')); await tick();
    const reader = h.openStream(h.calls[1]); await tick();
    for (let i = 0; i < 257; i++) { reader.send({ type: 'progress', message: String(i) }); await tick(); }
    assert.equal(h.histories[0].options.signal.aborted, true);
    assert.equal(h.calls[1].options.signal.aborted, false);
    assert.equal(reader.cancels, 0);
    assert.equal(h.dispatched.length, 257);
    h.histories[0].resolve([]); await tick();
    assert.equal(h.dispatched.length, 257);
    h.ctx.cancelTaskEventReplaySubscription(); await pending;
});

test('取消历史请求后晚到响应不得绘制，取消信号不影响新视图', async () => {
    const response = deferred(); const controller = new AbortController();
    const h = paginationContext(() => response.promise);
    const pending = h.ctx.loadProcessDetailsPaginated('msg', 'backend', { signal: controller.signal });
    controller.abort();
    response.resolve(ok({ processDetails: [{ id: 'late' }], offset: 0, nextOffset: 50 }));
    await pending;
    assert.equal(h.rendered.length, 0);
});

test('正常任务终态清理序号状态', () => {
    const ctx = sequenceContext();
    ctx.document = { getElementById: () => null };
    run(ctx, 'const progressTaskState = new Map();\n' + fn(monitor, 'clearStreamSequenceState') + '\n' + fn(monitor, 'finalizeProgressTask'));
    run(ctx, 'streamSequenceStateByProgressId.set("post", new Map()); progressTaskState.set("post", {});');
    ctx.finalizeProgressTask('post', 'done');
    assert.equal(run(ctx, 'streamSequenceStateByProgressId.size'), 0);
    assert.equal(run(ctx, 'progressTaskState.size'), 0);
});

test('实时工具结果能附加到 replay 历史卡片，而无需旧的 POST 工具映射', () => {
    const timeline = {}; const item = {}; let merged;
    const ctx = context({ document: { getElementById: () => null }, getToolCallMapping: () => null,
        resolveStreamTimeline: () => timeline,
        findToolCallItemById: root => root === timeline ? item : null,
        mergeToolResultIntoCallItem: (target, data) => { merged = { target, data }; } });
    run(ctx, fn(monitor, 'attachToolResultToCall'));
    assert.equal(ctx.attachToolResultToCall('replay', 'call', { success: true }), true);
    assert.equal(merged.target, item);
    assert.equal(merged.data.success, true);
});

test('普通 POST 流 EOF 和读失败都会清理序号状态，EOF 在接续 replay 前清理', async () => {
    const start = chat.indexOf('        window.__csAgentLiveStream = {\n            active: true');
    const end = chat.indexOf('        // 消息发送成功后', start);
    assert.ok(start > 0 && end > start);
    for (const fail of [false, true]) {
        const ctx = sequenceContext();
        run(ctx, fn(monitor, 'clearStreamSequenceState'));
        ctx.window.clearStreamSequenceState = ctx.clearStreamSequenceState;
        ctx.window.attachRunningTaskEventStream = async () => {
            assert.equal(run(ctx, 'streamSequenceStateByProgressId.size'), 0);
            return true;
        };
        Object.assign(ctx, { streamConversationId: 'A', progressId: 'post', body: {},
            response: { body: { getReader: () => ({ read: async () => { if (fail) throw new Error('read failed'); return { done: true }; } }) } },
            isStreamStillVisibleForRequest: () => true });
        run(ctx, 'streamSequenceStateByProgressId.set("post", new Map());\nasync function consumePost() {\n' + chat.slice(start, end) + '\n}');
        if (fail) await assert.rejects(ctx.consumePost(), /read failed/); else await ctx.consumePost();
        assert.equal(run(ctx, 'streamSequenceStateByProgressId.size'), 0);
    }
});

test('离开聊天页立即使展示订阅及历史请求过期', () => {
    let invalidations = 0;
    const target = { classList: { contains: () => false, add: () => {} } };
    const ctx = context({ window: { location: { hash: '#chat' }, invalidateChatView: () => invalidations++ },
        document: { getElementById: () => target, querySelectorAll: () => [] },
        buildHashForPage: id => id, updateNavState: () => {}, initPage: () => {} });
    run(ctx, "let currentPage = 'chat';\n" + fn(router, 'switchPage'));
    ctx.switchPage('dashboard');
    assert.equal(invalidations, 1);
});
