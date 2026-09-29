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
        return window.t(key, {
            ...base,
            interpolation: { escapeValue: false, ...interp }
        });
    };
}

if (typeof window.escapeHtml !== 'function') {
    window.escapeHtml = function escapeHtml(text) {
        if (text == null) return '';
        return String(text)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    };
}

/** 目标历史页面状态 */
const targetsPageState = {
    bound: false,
    page: 1,
    pageSize: 50,
    keyword: '',
    total: 0,
    totalPages: 1,
    targets: [],
    expanded: new Set(),
    eventsCache: {}
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
    if (typeof window.showNotification === 'function') {
        window.showNotification(message, type || 'info');
        return;
    }
    if (typeof window.notifyApiError === 'function' && type === 'error') {
        window.notifyApiError(message);
        return;
    }
    window.alert(message);
}

/** 更新顶部总数标签 */
function updateTargetsTotalLabel() {
    const el = document.getElementById('targets-total');
    if (!el) return;
    el.textContent = _t('targets.total', { count: targetsPageState.total });
}

/** 渲染目标表格（含展开的明细行） */
function renderTargetsTable() {
    const container = document.getElementById('targets-table-body');
    if (!container) return;

    if (!targetsPageState.targets.length) {
        container.innerHTML = '<div class="targets-state">' + escapeHtml(_t('targets.empty')) + '</div>';
        return;
    }

    const head =
        '<table class="data-table targets-table">' +
            '<thead><tr>' +
                '<th data-i18n="targets.columnTarget">目标</th>' +
                '<th data-i18n="targets.columnRuns">跑过次数</th>' +
                '<th data-i18n="targets.columnLastRun">最近一次</th>' +
                '<th class="col-actions" data-i18n="targets.columnActions">操作</th>' +
            '</tr></thead>';

    const rows = targetsPageState.targets.map((item) => buildTargetRow(item)).join('');

    container.innerHTML = head + '<tbody>' + rows + '</tbody></table>';

    if (typeof window.applyTranslations === 'function') {
        window.applyTranslations(container);
    }
    if (typeof rbacAfterDynamicRender === 'function') {
        rbacAfterDynamicRender(container);
    }
}

/** 构建单个目标行（以及展开时的明细行） */
function buildTargetRow(item) {
    const target = String(item && item.target != null ? item.target : '');
    const safeTarget = escapeHtml(target);
    const runCount = parseInt(item && item.runCount, 10) || 0;
    const lastTime = formatTargetTime(item && item.lastRunAt);
    const isExpanded = targetsPageState.expanded.has(target);

    const lastCell = lastTime
        ? escapeHtml(_tPlain('targets.lastRun', { time: lastTime }))
        : '<span class="targets-muted">—</span>';

    const toggleLabel = isExpanded ? _t('targets.hideRuns') : _t('targets.viewRuns');

    const mainRow =
        '<tr class="targets-row' + (isExpanded ? ' is-expanded' : '') + '">' +
            '<td><code class="targets-domain">' + safeTarget + '</code></td>' +
            '<td><span class="targets-runs">' + escapeHtml(_t('targets.runsUnit', { count: runCount })) + '</span></td>' +
            '<td>' + lastCell + '</td>' +
            '<td class="col-actions targets-actions">' +
                '<button type="button" class="btn-secondary targets-btn" data-action="toggle-runs" data-target="' + safeTarget + '">' +
                    escapeHtml(toggleLabel) +
                '</button>' +
                '<button type="button" class="btn-secondary targets-btn" data-action="restart" data-target="' + safeTarget + '">' +
                    escapeHtml(_t('targets.restart')) +
                '</button>' +
                '<button type="button" class="btn-secondary targets-btn targets-btn-danger" data-action="delete" data-target="' + safeTarget + '" data-require-permission="target:delete">' +
                    escapeHtml(_t('targets.delete')) +
                '</button>' +
            '</td>' +
        '</tr>';

    if (!isExpanded) {
        return mainRow;
    }

    return mainRow +
        '<tr class="targets-detail-row"><td colspan="4">' +
            buildTargetDetail(item) +
        '</td></tr>';
}

/** 构建展开的明细区域 */
function buildTargetDetail(item) {
    const target = String(item && item.target != null ? item.target : '');
    const metaParts = [];
    const firstTime = formatTargetTime(item && item.firstRunAt);
    const lastTime = formatTargetTime(item && item.lastRunAt);
    if (firstTime) metaParts.push(_tPlain('targets.firstRun', { time: firstTime }));
    if (lastTime) metaParts.push(_tPlain('targets.lastRun', { time: lastTime }));
    const metaHtml = metaParts.length
        ? '<div class="targets-detail-meta">' + metaParts.map((s) => escapeHtml(s)).join(' · ') + '</div>'
        : '';

    const cache = targetsPageState.eventsCache[target];

    if (!cache || cache.status === 'loading') {
        return metaHtml + '<div class="targets-state targets-state-inline">' + escapeHtml(_t('targets.loading')) + '</div>';
    }
    if (cache.status === 'error') {
        return metaHtml + '<div class="targets-state targets-state-inline targets-error">' + escapeHtml(_t('targets.eventsFailed')) + '</div>';
    }
    if (!cache.items.length) {
        return metaHtml + '<div class="targets-state targets-state-inline">' + escapeHtml(_t('targets.runEventsEmpty')) + '</div>';
    }

    const events = cache.items.map((ev) => {
        const conversationId = String(ev && ev.conversationId != null ? ev.conversationId : '');
        const title = ev && ev.conversationTitle ? String(ev.conversationTitle) : '';
        const label = title || conversationId;
        const time = formatTargetTime(ev && ev.startedAt);
        return (
            '<div class="targets-event">' +
                '<span class="targets-event-time">' + escapeHtml(time || '—') + '</span>' +
                '<span class="targets-event-title" title="' + escapeHtml(label) + '">' + escapeHtml(label) + '</span>' +
                '<button type="button" class="targets-event-open" data-action="open-conversation" data-conversation="' + escapeHtml(conversationId) + '">' +
                    escapeHtml(_t('targets.openConversation')) +
                '</button>' +
            '</div>'
        );
    }).join('');

    return metaHtml + '<div class="targets-events">' + events + '</div>';
}

/** 渲染分页控件（上一页 / 第 x/y 页 / 下一页） */
function renderTargetsPagination() {
    const container = document.getElementById('targets-pagination');
    if (!container) return;

    const { page, pageSize, total, totalPages } = targetsPageState;
    if (total === 0) {
        container.innerHTML = '';
        return;
    }

    const start = (page - 1) * pageSize + 1;
    const end = Math.min(page * pageSize, total);
    const pages = totalPages || 1;

    container.innerHTML =
        '<div class="pagination">' +
            '<div class="pagination-info">' +
                '<span>' + escapeHtml(_t('tasks.paginationShow', { start: start, end: end, total: total })) + '</span>' +
            '</div>' +
            '<div class="pagination-controls">' +
                '<button class="btn-secondary" data-targets-page="1" ' + (page <= 1 ? 'disabled' : '') + '>' + escapeHtml(_t('tasks.paginationFirst')) + '</button>' +
                '<button class="btn-secondary" data-targets-page="' + (page - 1) + '" ' + (page <= 1 ? 'disabled' : '') + '>' + escapeHtml(_t('tasks.paginationPrev')) + '</button>' +
                '<span class="pagination-page">' + escapeHtml(_t('tasks.paginationPage', { current: page, total: pages })) + '</span>' +
                '<button class="btn-secondary" data-targets-page="' + (page + 1) + '" ' + (page >= pages ? 'disabled' : '') + '>' + escapeHtml(_t('tasks.paginationNext')) + '</button>' +
                '<button class="btn-secondary" data-targets-page="' + pages + '" ' + (page >= pages ? 'disabled' : '') + '>' + escapeHtml(_t('tasks.paginationLast')) + '</button>' +
            '</div>' +
        '</div>';

    if (typeof window.applyTranslations === 'function') {
        window.applyTranslations(container);
    }
}

/** 加载指定页的目标列表 */
async function loadTargetsPage(page) {
    const container = document.getElementById('targets-table-body');
    const p = Math.max(1, parseInt(page, 10) || 1);
    targetsPageState.page = p;

    if (container) {
        container.innerHTML = '<div class="targets-state">' + escapeHtml(_t('targets.loading')) + '</div>';
    }

    const params = new URLSearchParams();
    params.set('page', String(p));
    params.set('page_size', String(targetsPageState.pageSize));
    const keyword = (targetsPageState.keyword || '').trim();
    if (keyword) params.set('keyword', keyword);

    try {
        const response = await apiFetch('/api/targets?' + params.toString());
        if (!response.ok) {
            throw new Error('HTTP ' + response.status);
        }
        const data = await response.json();
        targetsPageState.targets = Array.isArray(data.targets) ? data.targets : [];
        targetsPageState.total = parseInt(data.total, 10) || 0;
        targetsPageState.page = parseInt(data.page, 10) || p;
        targetsPageState.pageSize = parseInt(data.page_size, 10) || targetsPageState.pageSize;
        targetsPageState.totalPages = parseInt(data.total_pages, 10) || 1;
        targetsPageState.expanded.clear();
        targetsPageState.eventsCache = {};

        renderTargetsTable();
        renderTargetsPagination();
    } catch (err) {
        console.warn('加载目标历史失败:', err);
        if (container) {
            container.innerHTML = '<div class="targets-state targets-error">' + escapeHtml(_t('targets.loadFailed')) + '</div>';
        }
        const pagination = document.getElementById('targets-pagination');
        if (pagination) pagination.innerHTML = '';
    }

    updateTargetsTotalLabel();
}

/** 重置到第一页并重新加载 */
function refreshTargetsPage() {
    targetsPageState.expanded.clear();
    targetsPageState.eventsCache = {};
    loadTargetsPage(1);
}

/** 展开 / 收起某目标的运行明细 */
async function toggleTargetRuns(target) {
    if (!target) return;

    const expanded = targetsPageState.expanded;
    if (expanded.has(target)) {
        expanded.delete(target);
        renderTargetsTable();
        return;
    }

    expanded.add(target);
    const cache = targetsPageState.eventsCache[target];
    if (!cache || cache.status === 'error') {
        targetsPageState.eventsCache[target] = { status: 'loading', items: [] };
        renderTargetsTable();
        try {
            const response = await apiFetch(
                '/api/targets/' + encodeURIComponent(target) + '/events?page=1&page_size=50'
            );
            if (!response.ok) {
                throw new Error('HTTP ' + response.status);
            }
            const data = await response.json();
            targetsPageState.eventsCache[target] = {
                status: 'ok',
                items: Array.isArray(data.events) ? data.events : []
            };
        } catch (err) {
            console.warn('加载运行记录失败:', err);
            targetsPageState.eventsCache[target] = { status: 'error', items: [] };
        }
    }

    // 用户可能在请求期间已收起，仅当仍展开时重绘
    if (targetsPageState.expanded.has(target)) {
        renderTargetsTable();
    }
}

/** 打开某次运行对应的对话 */
function openTargetConversation(conversationId) {
    if (!conversationId) return;
    if (typeof navigateToConversation === 'function') {
        navigateToConversation(conversationId);
        return;
    }
    if (typeof window.switchPage === 'function') {
        window.switchPage('chat');
    }
    if (typeof window.loadConversation === 'function') {
        window.loadConversation(conversationId);
    }
}

/** 把目标补进「新建任务」输入框并打开弹窗 */
function restartTargetTask(target) {
    if (!target) return;
    const text = '对 ' + target + ' 做全面 完整 深度的渗透测试 漏洞挖掘，包括品牌资产 子资产 子域名 IP等';

    if (typeof showBatchImportModal !== 'function') {
        window.alert(_t('targets.reminderRestored'));
        return;
    }

    Promise.resolve(showBatchImportModal()).then(() => {
        const input = document.getElementById('batch-tasks-input');
        if (!input) return;
        input.value = text;
        input.dispatchEvent(new Event('input', { bubbles: true }));
    }).catch((err) => {
        console.warn('打开新建任务弹窗失败:', err);
    });
}

/** 删除某目标的历史记录 */
function deleteTargetRun(target) {
    if (!target) return;
    if (typeof requirePermission === 'function' && !requirePermission('target:delete')) return;
    if (!window.confirm(_t('targets.deleteConfirm', { target: target }))) return;

    apiFetch('/api/targets/' + encodeURIComponent(target), { method: 'DELETE' })
        .then((response) => {
            if (!response.ok) throw new Error('HTTP ' + response.status);
            return response.json();
        })
        .then(() => {
            targetsNotify(_t('targets.deleteSuccess', { target: target }), 'success');
            refreshTargetsPage();
        })
        .catch((err) => {
            console.warn('删除目标历史失败:', err);
            targetsNotify(_t('targets.deleteFailed'), 'error');
        });
}

/** 表格操作按钮事件委托 */
function onTargetsTableClick(event) {
    const btn = event.target && event.target.closest ? event.target.closest('[data-action]') : null;
    if (!btn) return;
    const action = btn.getAttribute('data-action');
    const target = btn.getAttribute('data-target') || '';
    if (action === 'toggle-runs') {
        void toggleTargetRuns(target);
    } else if (action === 'restart') {
        restartTargetTask(target);
    } else if (action === 'delete') {
        deleteTargetRun(target);
    } else if (action === 'open-conversation') {
        openTargetConversation(btn.getAttribute('data-conversation') || '');
    }
}

/** 分页按钮事件委托 */
function onTargetsPaginationClick(event) {
    const btn = event.target && event.target.closest ? event.target.closest('[data-targets-page]') : null;
    if (!btn || btn.disabled) return;
    const p = parseInt(btn.getAttribute('data-targets-page'), 10);
    if (p && p !== targetsPageState.page) {
        loadTargetsPage(p);
    }
}

/** 搜索框输入（防抖 300ms） */
let targetsSearchTimer = null;
function onTargetsSearchInput(event) {
    const value = event && event.target ? (event.target.value || '') : '';
    if (targetsSearchTimer) clearTimeout(targetsSearchTimer);
    targetsSearchTimer = setTimeout(() => {
        targetsSearchTimer = null;
        targetsPageState.keyword = value;
        loadTargetsPage(1);
    }, 300);
}

/** 初始化目标历史页面（事件只绑定一次，数据每次进入都刷新） */
function initTargetsPage() {
    const state = targetsPageState;

    if (!state.bound) {
        const searchInput = document.getElementById('targets-search');
        if (searchInput) {
            searchInput.addEventListener('input', onTargetsSearchInput);
        }
        const tableBody = document.getElementById('targets-table-body');
        if (tableBody) {
            tableBody.addEventListener('click', onTargetsTableClick);
        }
        const pagination = document.getElementById('targets-pagination');
        if (pagination) {
            pagination.addEventListener('click', onTargetsPaginationClick);
        }
        state.bound = true;
    }

    const searchInput = document.getElementById('targets-search');
    if (searchInput && (searchInput.value || '') !== state.keyword) {
        state.keyword = searchInput.value || '';
    }

    loadTargetsPage(state.page || 1);
}

// 导出到全局，供 router.js / 其它脚本调用
window.initTargetsPage = initTargetsPage;
window.refreshTargetsPage = refreshTargetsPage;
window.loadTargetsPage = loadTargetsPage;
window.toggleTargetRuns = toggleTargetRuns;
window.restartTargetTask = restartTargetTask;
window.deleteTargetRun = deleteTargetRun;
window.openTargetConversation = openTargetConversation;
window.formatTargetTime = formatTargetTime;
