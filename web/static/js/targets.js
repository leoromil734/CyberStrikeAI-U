// 目标历史页面功能
// 注意：本文件依赖 tasks.js 已先行加载（其中定义了全局 _t / _tPlain / escapeHtml）。
// 这里做防御性兜底，避免其它页面单独引用本文件时缺失这些全局函数。

if (typeof window._t !== 'function') {
    window._t = function _t(key, opts) {
        return typeof window.t === 'function' ? window.t(key, opts) : key;
    };
}

/** 插值不转 HTML 实体（避免时间里的 / 等字符被二次转义） */
if (typeof window._tPlain !== 'function') {
    window._tPlain = function _tPlain(key, opts) {
        if (typeof window.t !== 'function') return key;
        const base = opts && typeof opts === 'object' ? opts : {};
        const interp = base.interpolation && typeof base.interpolation === 'object' ? base.interpolation : {};
        return window.t(key, { ...base, interpolation: { escapeValue: false, ...interp } });
    };
}

if (typeof window.escapeHtml !== 'function') {
    window.escapeHtml = function escapeHtml(text) {
        if (text == null) return '';
        return String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    };
}

/** 目标历史页面状态 */
const targetsPageState = {
    bound: false, page: 1, pageSize: 50, keyword: '', total: 0, totalPages: 1,
    targets: [], expanded: new Set(), eventsCache: {}, sequence: 0, listStatus: 'idle'
};

/** 将 RFC3339 时间格式化为 MM-DD HH:mm，无法解析时返回空串 */
function formatTargetTime(value) {
    if (!value) return '';
    const d = new Date(value);
    if (isNaN(d.getTime())) return '';
    const pad = (n) => (n < 10 ? '0' + n : String(n));
    return pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes());
}

/** 轻量提示：优先用全局通知，退化到 notifyApiError / alert */
function targetsNotify(message, type) {
    if (typeof window.showNotification === 'function') { window.showNotification(message, type || 'info'); return; }
    if (typeof window.notifyApiError === 'function' && type === 'error') { window.notifyApiError(message); return; }
    window.alert(message);
}

/** 仅使用固定 SVG 路径，目标、对话标题等动态文本始终转义。 */
function targetsIcon(name) {
    const paths = {
        target: '<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3"/>',
        chevron: '<path d="m9 5 7 7-7 7"/>',
        restart: '<path d="M20 7v5h-5M6 6a8 8 0 1 1-2 8"/>',
        delete: '<path d="M3 6h18M9 6V3h6v3M5 6l1 15h12l1-15M10 10v7M14 10v7"/>',
        error: '<path d="M12 8v5M12 16h.01M10 3h4l8 17H2L10 3Z"/>',
        open: '<path d="M14 3h7v7M21 3l-9 9M10 3H3v18h18v-7"/>',
        search: '<circle cx="11" cy="11" r="7"/><path d="m16 16 4 4"/>'
    };
    return '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + (paths[name] || paths.target) + '</svg>';
}

/** 总数属于当前筛选；运行/登记概览仅统计当前页，不冒充全量指标。 */
function updateTargetsTotalLabel() {
    const available = targetsPageState.listStatus === 'ready';
    const el = document.getElementById('targets-total');
    if (el) el.textContent = available ? _t('targets.total', { count: targetsPageState.total }) : '—';
    const executed = targetsPageState.targets.filter(item => (parseInt(item && item.runCount, 10) || 0) > 0).length;
    const values = { total: targetsPageState.total, executed: executed, registered: targetsPageState.targets.length - executed };
    for (const [key, count] of Object.entries(values)) {
        const counter = document.getElementById('targets-stat-' + key);
        if (counter) counter.textContent = available ? String(count) : '—';
    }
}

function updateTargetsSearchControls() {
    const clear = document.getElementById('targets-search-clear');
    const input = document.getElementById('targets-search');
    if (clear) clear.hidden = !(input ? input.value : targetsPageState.keyword);
}

/** 可恢复的加载、空态和错误态；明细错误只重试对应目标的只读请求。 */
function targetsStateHtml(type, inline, target) {
    const loading = type === 'loading';
    const failed = type === 'error';
    const filtered = !!targetsPageState.keyword.trim();
    const title = inline ? _t(loading ? 'targets.loading' : failed ? 'targets.eventsFailed' : 'targets.runEventsEmpty')
        : _t(loading ? 'targets.loading' : failed ? 'targets.loadFailed' : filtered ? 'targets.noMatches' : 'targets.emptyTitle');
    const hint = inline ? '' : _t(loading ? 'targets.loadingHint' : failed ? 'targets.loadFailedHint' : filtered ? 'targets.noMatchesHint' : 'targets.emptyHint');
    const symbol = loading ? '<span class="targets-loader" aria-hidden="true"></span>'
        : '<span class="targets-state-icon">' + targetsIcon(failed ? 'error' : filtered ? 'search' : 'target') + '</span>';
    const retry = failed ? '<button type="button" class="btn-secondary targets-btn" data-action="' + (inline ? 'retry-runs' : 'retry-list') + '"' + (inline ? ' data-target="' + escapeHtml(target) + '"' : '') + '>' + escapeHtml(_t('targets.retry')) + '</button>'
        : !inline && !loading && filtered ? '<button type="button" class="btn-secondary targets-btn" data-action="clear-search">' + escapeHtml(_t('common.clearSearch')) + '</button>' : '';
    return '<div class="targets-state' + (inline ? ' targets-state-inline' : '') + (failed ? ' targets-error' : '') + '">' + symbol +
        '<div><strong>' + escapeHtml(title) + '</strong>' + (hint ? '<p>' + escapeHtml(hint) + '</p>' : '') + '</div>' + retry + '</div>';
}

/** 渲染目标表格（含展开的明细行）；窄屏由 CSS 转为卡片，无重复的操作控件。 */
function renderTargetsTable() {
    const container = document.getElementById('targets-table-body');
    if (!container) return;
    const focused = container.contains(document.activeElement) ? document.activeElement.closest('[data-action]') : null;
    const focusAction = focused && focused.getAttribute('data-action');
    const focusTarget = focused && focused.getAttribute('data-target');
    container.setAttribute('aria-busy', String(targetsPageState.listStatus === 'loading'));
    if (targetsPageState.listStatus === 'loading' || targetsPageState.listStatus === 'error' || !targetsPageState.targets.length) {
        container.innerHTML = targetsStateHtml(targetsPageState.listStatus === 'ready' ? 'empty' : targetsPageState.listStatus);
        return;
    }
    const head = '<table class="data-table targets-table" role="table"><thead><tr>' +
        '<th scope="col" data-i18n="targets.columnTarget">' + escapeHtml(_t('targets.columnTarget')) + '</th>' +
        '<th scope="col" data-i18n="targets.columnRuns">' + escapeHtml(_t('targets.columnRuns')) + '</th>' +
        '<th scope="col" data-i18n="targets.columnLastRun">' + escapeHtml(_t('targets.columnLastRun')) + '</th>' +
        '<th scope="col" class="col-actions" data-i18n="targets.columnActions">' + escapeHtml(_t('targets.columnActions')) + '</th>' +
        '</tr></thead>';
    container.innerHTML = head + '<tbody>' + targetsPageState.targets.map((item) => buildTargetRow(item)).join('') + '</tbody></table>';
    if (typeof window.applyTranslations === 'function') window.applyTranslations(container);
    if (typeof rbacAfterDynamicRender === 'function') rbacAfterDynamicRender(container);
    if (focusAction) {
        const replacement = Array.from(container.querySelectorAll('[data-action]')).find(button => button.getAttribute('data-action') === focusAction && button.getAttribute('data-target') === focusTarget);
        if (replacement && !replacement.hidden && !replacement.disabled) replacement.focus({ preventScroll: true });
    }
}

/** 构建单个目标行（以及展开时的明细行） */
function buildTargetRow(item) {
    const target = String(item && item.target != null ? item.target : '');
    const safeTarget = escapeHtml(target);
    const runCount = Math.max(0, parseInt(item && item.runCount, 10) || 0);
    const submittedCount = Math.max(0, parseInt(item && item.submittedCount, 10) || 0);
    const lastTime = formatTargetTime(item && item.lastRunAt);
    const lastSubmittedTime = formatTargetTime(item && item.lastSubmittedAt);
    const isExpanded = targetsPageState.expanded.has(target);
    const status = runCount > 0 ? _t('targets.runsUnit', { count: runCount }) : _t('targets.registeredNotRun');
    const submissionMeta = submittedCount > 0 ? '<div class="targets-muted targets-submission-meta">' + escapeHtml(_t('targets.reminderSubmitted', { count: submittedCount })) + '</div>' : '';
    const lastCell = lastTime ? '<span class="targets-last-time">' + escapeHtml(_tPlain('targets.lastRun', { time: lastTime })) + '</span>'
        : lastSubmittedTime ? '<span class="targets-last-time">' + escapeHtml(_tPlain('targets.reminderLastSubmitted', { time: lastSubmittedTime })) + '</span>' : '<span class="targets-muted">—</span>';
    const toggleLabel = isExpanded ? _t('targets.hideRuns') : _t('targets.viewRuns');
    const detailId = 'target-runs-' + encodeURIComponent(target);
    const mainRow = '<tr class="targets-row' + (isExpanded ? ' is-expanded' : '') + '">' +
        '<td class="targets-target-cell"><div class="targets-identity"><span class="targets-row-icon">' + targetsIcon('target') + '</span><code class="targets-domain">' + safeTarget + '</code></div></td>' +
        '<td data-label="' + escapeHtml(_t('targets.columnRuns')) + '"><span class="targets-runs' + (runCount > 0 ? ' targets-runs--executed' : ' targets-runs--registered') + '">' + escapeHtml(status) + '</span>' + submissionMeta + '</td>' +
        '<td data-label="' + escapeHtml(_t('targets.columnLastRun')) + '">' + lastCell + '</td>' +
        '<td class="col-actions"><div class="targets-actions">' +
            '<button type="button" class="btn-secondary targets-btn targets-toggle" data-action="toggle-runs" data-target="' + safeTarget + '" aria-expanded="' + isExpanded + '"' + (isExpanded ? ' aria-controls="' + escapeHtml(detailId) + '"' : '') + ' aria-label="' + escapeHtml(_tPlain(isExpanded ? 'targets.hideRunsFor' : 'targets.viewRunsFor', { target: target })) + '">' + targetsIcon('chevron') + '<span>' + escapeHtml(toggleLabel) + '</span></button>' +
            '<button type="button" class="btn-secondary targets-btn targets-restart" data-action="restart" data-target="' + safeTarget + '" aria-label="' + escapeHtml(_tPlain('targets.restartFor', { target: target })) + '">' + targetsIcon('restart') + '<span>' + escapeHtml(_t('targets.restart')) + '</span></button>' +
            '<button type="button" class="btn-secondary targets-btn targets-btn-danger" data-action="delete" data-target="' + safeTarget + '" data-require-permission="target:delete" aria-label="' + escapeHtml(_tPlain('targets.deleteFor', { target: target })) + '">' + targetsIcon('delete') + '<span>' + escapeHtml(_t('targets.delete')) + '</span></button>' +
        '</div></td></tr>';
    if (!isExpanded) return mainRow;
    return mainRow + '<tr class="targets-detail-row"><td colspan="4"><div id="' + escapeHtml(detailId) + '" class="targets-detail">' + buildTargetDetail(item) + '</div></td></tr>';
}

/** 构建展开的明细区域 */
function buildTargetDetail(item) {
    const target = String(item && item.target != null ? item.target : '');
    const metaParts = [];
    const firstTime = formatTargetTime(item && item.firstRunAt);
    const lastTime = formatTargetTime(item && item.lastRunAt);
    if (firstTime) metaParts.push(_tPlain('targets.firstRun', { time: firstTime }));
    if (lastTime) metaParts.push(_tPlain('targets.lastRun', { time: lastTime }));
    const submittedTime = formatTargetTime(item && item.lastSubmittedAt);
    if (submittedTime) metaParts.push(_tPlain('targets.reminderLastSubmitted', { time: submittedTime }));
    if (item && item.lastTaskTitle) metaParts.push(_tPlain('targets.lastTask', { title: String(item.lastTaskTitle) }));
    const metaHtml = '<div class="targets-detail-heading"><strong>' + escapeHtml(_t('targets.viewRuns')) + '</strong><p>' + escapeHtml(_t('targets.eventsHint')) + '</p></div>' +
        (metaParts.length ? '<div class="targets-detail-meta">' + metaParts.map((part) => '<span>' + escapeHtml(part) + '</span>').join('') + '</div>' : '');
    const cache = targetsPageState.eventsCache[target];
    if (!cache || cache.status === 'loading') return metaHtml + targetsStateHtml('loading', true, target);
    if (cache.status === 'error') return metaHtml + targetsStateHtml('error', true, target);
    if (!cache.items.length) return metaHtml + targetsStateHtml('empty', true, target);
    const events = cache.items.map((ev) => {
        const conversationId = String(ev && ev.conversationId != null ? ev.conversationId : '');
        const title = ev && ev.conversationTitle ? String(ev.conversationTitle) : '';
        const label = title || conversationId;
        const time = formatTargetTime(ev && ev.startedAt);
        return '<div class="targets-event"><span class="targets-event-dot" aria-hidden="true"></span>' +
            '<span class="targets-event-time">' + escapeHtml(time || '—') + '</span>' +
            '<span class="targets-event-title" title="' + escapeHtml(label) + '">' + escapeHtml(label) + '</span>' +
            '<button type="button" class="targets-event-open" data-action="open-conversation" data-conversation="' + escapeHtml(conversationId) + '" aria-label="' + escapeHtml(_tPlain('targets.openConversationFor', { title: label })) + '"><span>' + escapeHtml(_t('targets.openConversation')) + '</span>' + targetsIcon('open') + '</button></div>';
    }).join('');
    return metaHtml + '<div class="targets-events">' + events + '</div>';
}

/** 渲染分页控件（保留首页、上一页、下一页、末页） */
function renderTargetsPagination() {
    const container = document.getElementById('targets-pagination');
    if (!container) return;
    const { page, pageSize, total, totalPages, listStatus } = targetsPageState;
    if (listStatus !== 'ready' || total === 0) { container.innerHTML = ''; return; }
    const start = (page - 1) * pageSize + 1;
    const end = Math.min(page * pageSize, total);
    const pages = totalPages || 1;
    container.innerHTML = '<div class="pagination"><div class="pagination-info"><span>' + escapeHtml(_t('tasks.paginationShow', { start: start, end: end, total: total })) + '</span></div><div class="pagination-controls">' +
        '<button type="button" class="btn-secondary" data-targets-page="1" ' + (page <= 1 ? 'disabled' : '') + '>' + escapeHtml(_t('tasks.paginationFirst')) + '</button>' +
        '<button type="button" class="btn-secondary" data-targets-page="' + (page - 1) + '" ' + (page <= 1 ? 'disabled' : '') + '>' + escapeHtml(_t('tasks.paginationPrev')) + '</button>' +
        '<span class="pagination-page">' + escapeHtml(_t('tasks.paginationPage', { current: page, total: pages })) + '</span>' +
        '<button type="button" class="btn-secondary" data-targets-page="' + (page + 1) + '" ' + (page >= pages ? 'disabled' : '') + '>' + escapeHtml(_t('tasks.paginationNext')) + '</button>' +
        '<button type="button" class="btn-secondary" data-targets-page="' + pages + '" ' + (page >= pages ? 'disabled' : '') + '>' + escapeHtml(_t('tasks.paginationLast')) + '</button>' +
        '</div></div>';
    if (typeof window.applyTranslations === 'function') window.applyTranslations(container);
}

/** 加载指定页的目标列表；过期响应不覆盖新的关键字或分页状态。 */
async function loadTargetsPage(page) {
    const p = Math.max(1, parseInt(page, 10) || 1);
    const sequence = ++targetsPageState.sequence;
    targetsPageState.page = p; targetsPageState.listStatus = 'loading';
    renderTargetsTable(); renderTargetsPagination(); updateTargetsTotalLabel(); updateTargetsSearchControls();
    const params = new URLSearchParams();
    params.set('page', String(p)); params.set('page_size', String(targetsPageState.pageSize));
    const keyword = (targetsPageState.keyword || '').trim();
    if (keyword) params.set('keyword', keyword);
    try {
        const response = await apiFetch('/api/targets?' + params.toString());
        if (!response.ok) throw new Error('HTTP ' + response.status);
        const data = await response.json();
        if (sequence !== targetsPageState.sequence) return;
        targetsPageState.targets = Array.isArray(data.targets) ? data.targets : [];
        targetsPageState.total = parseInt(data.total, 10) || 0;
        targetsPageState.page = parseInt(data.page, 10) || p;
        targetsPageState.pageSize = parseInt(data.page_size, 10) || targetsPageState.pageSize;
        targetsPageState.totalPages = parseInt(data.total_pages, 10) || 1;
        targetsPageState.expanded.clear(); targetsPageState.eventsCache = {};
        targetsPageState.listStatus = 'ready';
    } catch (err) {
        if (sequence !== targetsPageState.sequence) return;
        console.warn('加载目标历史失败:', err);
        targetsPageState.listStatus = 'error';
    }
    renderTargetsTable(); renderTargetsPagination(); updateTargetsTotalLabel();
}

/** 重置到第一页并重新加载 */
function refreshTargetsPage() {
    targetsPageState.expanded.clear(); targetsPageState.eventsCache = {};
    return loadTargetsPage(1);
}

/** 展开 / 收起某目标的运行明细 */
async function toggleTargetRuns(target) {
    if (!target) return;
    const expanded = targetsPageState.expanded;
    if (expanded.has(target)) { expanded.delete(target); renderTargetsTable(); return; }
    expanded.add(target);
    const cache = targetsPageState.eventsCache[target];
    if (!cache || cache.status === 'error') {
        const sequence = targetsPageState.sequence;
        targetsPageState.eventsCache[target] = { status: 'loading', items: [] };
        renderTargetsTable();
        try {
            const response = await apiFetch('/api/targets/' + encodeURIComponent(target) + '/events?page=1&page_size=50');
            if (!response.ok) throw new Error('HTTP ' + response.status);
            const data = await response.json();
            if (sequence !== targetsPageState.sequence) return;
            targetsPageState.eventsCache[target] = { status: 'ok', items: Array.isArray(data.events) ? data.events : [] };
        } catch (err) {
            if (sequence !== targetsPageState.sequence) return;
            console.warn('加载运行记录失败:', err);
            targetsPageState.eventsCache[target] = { status: 'error', items: [] };
        }
    }
    if (targetsPageState.listStatus === 'ready' && targetsPageState.expanded.has(target)) renderTargetsTable();
}

/** 打开某次运行对应的对话 */
function openTargetConversation(conversationId) {
    if (!conversationId) return;
    if (typeof navigateToConversation === 'function') { navigateToConversation(conversationId); return; }
    if (typeof window.switchPage === 'function') window.switchPage('chat');
    if (typeof window.loadConversation === 'function') window.loadConversation(conversationId);
}

/** 把目标补进「新建任务」输入框并打开弹窗：只填表，不提交任务。 */
function restartTargetTask(target) {
    if (!target) return;
    const text = '对 ' + target + ' 做全面 完整 深度的渗透测试 漏洞挖掘，包括品牌资产 子资产 子域名 IP等';
    if (typeof showBatchImportModal !== 'function') { window.alert(_t('targets.reminderRestored')); return; }
    Promise.resolve(showBatchImportModal()).then(() => {
        const input = document.getElementById('batch-tasks-input');
        if (!input) return;
        input.value = text; input.dispatchEvent(new Event('input', { bubbles: true }));
    }).catch((err) => { console.warn('打开新建任务弹窗失败:', err); });
}

/** 删除某目标的历史记录：保留服务端权限名称与原确认流程。 */
function deleteTargetRun(target) {
    if (!target) return;
    if (typeof requirePermission === 'function' && !requirePermission('target:delete')) return;
    if (!window.confirm(_t('targets.deleteConfirm', { target: target }))) return;
    apiFetch('/api/targets/' + encodeURIComponent(target), { method: 'DELETE' })
        .then((response) => { if (!response.ok) throw new Error('HTTP ' + response.status); return response.json(); })
        .then(() => { targetsNotify(_t('targets.deleteSuccess', { target: target }), 'success'); refreshTargetsPage(); })
        .catch((err) => { console.warn('删除目标历史失败:', err); targetsNotify(_t('targets.deleteFailed'), 'error'); });
}

/** 表格操作按钮事件委托，原 data-action / data-target 绑定保持不变。 */
function onTargetsTableClick(event) {
    const btn = event.target && event.target.closest ? event.target.closest('[data-action]') : null;
    if (!btn) return;
    const action = btn.getAttribute('data-action');
    const target = btn.getAttribute('data-target') || '';
    if (action === 'toggle-runs') void toggleTargetRuns(target);
    else if (action === 'restart') restartTargetTask(target);
    else if (action === 'delete') deleteTargetRun(target);
    else if (action === 'open-conversation') openTargetConversation(btn.getAttribute('data-conversation') || '');
    else if (action === 'retry-list') void loadTargetsPage(targetsPageState.page);
    else if (action === 'clear-search') clearTargetsSearch();
    else if (action === 'retry-runs') { targetsPageState.expanded.delete(target); void toggleTargetRuns(target); }
}

/** 分页按钮事件委托 */
function onTargetsPaginationClick(event) {
    const btn = event.target && event.target.closest ? event.target.closest('[data-targets-page]') : null;
    if (!btn || btn.disabled) return;
    const p = parseInt(btn.getAttribute('data-targets-page'), 10);
    if (p && p !== targetsPageState.page) loadTargetsPage(p);
}

/** 搜索框输入（保留防抖 300ms） */
let targetsSearchTimer = null;
function onTargetsSearchInput(event) {
    const value = event && event.target ? (event.target.value || '') : '';
    updateTargetsSearchControls();
    if (targetsSearchTimer) clearTimeout(targetsSearchTimer);
    targetsSearchTimer = setTimeout(() => {
        targetsSearchTimer = null; targetsPageState.keyword = value; loadTargetsPage(1);
    }, 300);
}

function clearTargetsSearch() {
    if (targetsSearchTimer) clearTimeout(targetsSearchTimer);
    targetsSearchTimer = null;
    const input = document.getElementById('targets-search');
    if (input) input.value = '';
    targetsPageState.keyword = '';
    return loadTargetsPage(1);
}

/** 初始化目标历史页面（事件只绑定一次，数据每次进入都刷新） */
function initTargetsPage() {
    const state = targetsPageState;
    if (!state.bound) {
        const searchInput = document.getElementById('targets-search');
        if (searchInput) searchInput.addEventListener('input', onTargetsSearchInput);
        const tableBody = document.getElementById('targets-table-body');
        if (tableBody) tableBody.addEventListener('click', onTargetsTableClick);
        const pagination = document.getElementById('targets-pagination');
        if (pagination) pagination.addEventListener('click', onTargetsPaginationClick);
        state.bound = true;
    }
    const searchInput = document.getElementById('targets-search');
    if (searchInput && (searchInput.value || '') !== state.keyword) state.keyword = searchInput.value || '';
    return loadTargetsPage(state.page || 1);
}

document.addEventListener('languagechange', () => {
    if (targetsPageState.listStatus === 'idle') return;
    renderTargetsTable(); renderTargetsPagination(); updateTargetsTotalLabel(); updateTargetsSearchControls();
});

// 导出到全局，供 router.js / 其它脚本调用
window.initTargetsPage = initTargetsPage;
window.refreshTargetsPage = refreshTargetsPage;
window.loadTargetsPage = loadTargetsPage;
window.toggleTargetRuns = toggleTargetRuns;
window.restartTargetTask = restartTargetTask;
window.deleteTargetRun = deleteTargetRun;
window.openTargetConversation = openTargetConversation;
window.formatTargetTime = formatTargetTime;
window.clearTargetsSearch = clearTargetsSearch;
