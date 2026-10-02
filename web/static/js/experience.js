// All remembered text is rendered with textContent, never as HTML or script.
(() => {
    'use strict';
    const state = { entry: null, offset: 0, sequence: 0, busy: false, items: [], listStatus: 'idle', error: '' };
    const pageSize = 25;
    const element = id => document.getElementById(id);
    const value = id => (element(id)?.value || '').trim();
    const tr = (key, options = {}) => typeof window.t === 'function' ? window.t(`experience.${key}`, { ...options, interpolation: { escapeValue: false } }) : key;
    const projectQuery = () => value('experience-project') ? `?project_id=${encodeURIComponent(value('experience-project'))}` : '';
    const permitted = permission => typeof window.hasPermission === 'function' && window.hasPermission(permission);
    const pretty = object => JSON.stringify(object, null, 2);
    const notify = error => window.notifyApiError?.(error?.message || String(error));
    const statusKeys = { candidate: 'candidate', verified: 'verified', needs_review: 'needsReview', deprecated: 'deprecated' };
    const scopeKeys = { private: 'private', project: 'projectScope', shared: 'shared' };
    const kindKeys = { tool_repair: 'toolRepair', vulnerability_method: 'vulnerability', workflow: 'workflow', negative_result: 'negative' };
    const knownKey = (map, key) => Object.prototype.hasOwnProperty.call(map, key) ? map[key] : null;
    const translatedValue = (map, key) => knownKey(map, key) ? tr(map[key]) : String(key || '—');
    function node(tag, className, text) {
        const result = document.createElement(tag);
        if (className) result.className = className;
        if (text != null) result.textContent = text;
        return result;
    }
    function mark(kind) {
        const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        for (const [name, content] of Object.entries({ viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '1.8', 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true' })) svg.setAttribute(name, content);
        const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        path.setAttribute('d', kind === 'error' ? 'M12 8v5M12 16h.01M10 3h4l8 17H2L10 3Z' : 'M4 4h6l2 2 2-2h6v16h-6l-2 1-2-1H4V4ZM12 6v15');
        svg.append(path);
        return svg;
    }
    async function request(path, method = 'GET', body) {
        const response = await apiFetch(path, { method, ...(body ? { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) } : {}) });
        if (!response.ok) throw new Error(await readApiError(response, tr('failed')));
        return response;
    }
    function button(label, action) {
        const result = node('button', 'btn-secondary', label);
        result.type = 'button'; result.addEventListener('click', action); return result;
    }
    function metadata(entry) {
        const meta = node('div', 'experience-item-meta');
        const status = node('span', 'experience-badge' + (knownKey(statusKeys, entry.status) ? ` experience-badge--${entry.status}` : ''), translatedValue(statusKeys, entry.status));
        meta.append(status, node('span', 'experience-scope', translatedValue(scopeKeys, entry.scope)), node('span', 'experience-kind', translatedValue(kindKeys, entry.content?.kind)));
        return meta;
    }
    function renderSummary() {
        // The list endpoint is paginated. These counters deliberately describe this page, not the whole library.
        const available = state.listStatus === 'ready';
        const counts = {
            count: state.items.length,
            verified: state.items.filter(item => item.status === 'verified').length,
            review: state.items.filter(item => item.status === 'candidate' || item.status === 'needs_review').length,
            shared: state.items.filter(item => item.scope === 'shared').length,
        };
        for (const [key, count] of Object.entries(counts)) {
            const counter = element(`experience-stat-${key}`);
            if (counter) counter.textContent = available ? String(count) : '—';
        }
        const meta = element('experience-list-meta');
        if (meta) meta.textContent = available && state.items.length ? tr('pageRange', { start: state.offset + 1, end: state.offset + state.items.length }) : '';
    }
    function renderPagination() {
        const pager = element('experience-pagination');
        if (!pager) return;
        pager.replaceChildren();
        pager.hidden = state.listStatus !== 'ready' || !state.items.length;
        if (pager.hidden) return;
        const previous = button(tr('previous'), () => { state.offset = Math.max(0, state.offset - pageSize); void refresh(false); });
        previous.disabled = state.offset === 0;
        const next = button(tr('next'), () => { state.offset += pageSize; void refresh(false); });
        next.disabled = state.items.length < pageSize;
        pager.append(previous, node('span', 'experience-page-number', tr('pageNumber', { page: Math.floor(state.offset / pageSize) + 1 })), next);
    }
    function renderList() {
        const list = element('experience-list'); if (!list) return;
        list.replaceChildren(); list.setAttribute('aria-busy', String(state.listStatus === 'loading'));
        renderSummary(); renderPagination();
        if (state.listStatus !== 'ready' || !state.items.length) {
            const loading = state.listStatus === 'loading';
            const failed = state.listStatus === 'error';
            const panel = node('div', `experience-state${failed ? ' experience-state--error' : ''}`);
            const symbol = node('span', loading ? 'experience-loader' : 'experience-state-mark');
            if (!loading) symbol.append(mark(failed ? 'error' : 'empty'));
            panel.append(symbol, node('h3', '', tr(loading ? 'loading' : failed ? 'loadFailed' : 'empty')));
            panel.append(node('p', '', loading ? tr('loadingHint') : failed ? state.error : tr('emptyHint')));
            if (!loading) panel.append(button(tr(failed ? 'retry' : 'resetFilters'), failed ? () => void refresh(false) : resetFilters));
            list.append(panel); return;
        }
        state.items.forEach(entry => {
            const content = entry.content || {};
            const section = node('section', 'experience-item');
            const heading = node('div', 'experience-item-heading');
            const title = node('h3', '', content.title || tr('untitled'));
            heading.append(title, node('span', 'experience-revision', tr('revision', { revision: entry.revision ?? '—' })));
            const summary = node('p', 'experience-item-summary', content.summary || tr('noSummary'));
            const footer = node('div', 'experience-item-footer');
            const project = node('span', 'experience-item-project', entry.origin_project_id ? tr('originProject', { project: entry.origin_project_id }) : translatedValue(scopeKeys, entry.scope));
            const view = button(tr('view'), () => open(entry.id));
            view.setAttribute('aria-label', tr('viewEntry', { title: content.title || tr('untitled') }));
            footer.append(project, view);
            section.append(heading, metadata(entry), summary, footer); list.append(section);
        });
    }
    async function mutate(action) {
        if (state.busy) return;
        state.busy = true;
        try { await action(); } catch (error) { notify(error); } finally { state.busy = false; }
    }
    async function refresh(reset = true) {
        if (reset) state.offset = 0;
        const sequence = ++state.sequence;
        if (!element('experience-list')) return;
        state.listStatus = 'loading'; state.error = ''; renderList();
        const query = new URLSearchParams({ limit: String(pageSize), offset: String(state.offset), status: value('experience-status'), kind: value('experience-kind'), query: value('experience-query'), project_id: value('experience-project') });
        try {
            const response = await request(`/api/experiences?${query}`);
            const data = await response.json(); if (sequence !== state.sequence) return;
            state.items = Array.isArray(data.items) ? data.items : [];
            state.listStatus = 'ready'; renderList();
        } catch (error) {
            if (sequence === state.sequence) { state.listStatus = 'error'; state.error = error.message || tr('failed'); renderList(); }
        }
    }
    function resetFilters() {
        ['experience-status', 'experience-kind', 'experience-project', 'experience-query'].forEach(id => { if (element(id)) element(id).value = ''; });
        return refresh();
    }
    function renderDetailHeading() {
        const entry = state.entry;
        const title = element('experience-detail-title');
        if (title) title.textContent = entry ? entry.content?.title || tr('untitled') : tr('new');
        const meta = element('experience-detail-meta');
        if (meta) {
            meta.replaceChildren();
            if (entry) meta.append(metadata(entry), node('span', 'experience-revision', tr('revision', { revision: entry.revision ?? '—' })));
        }
        if (element('experience-history')) element('experience-history').disabled = !entry;
        if (element('experience-export')) element('experience-export').disabled = !entry || !permitted('experience:export');
        if (element('experience-review-fields')) element('experience-review-fields').hidden = !entry;
        if (element('experience-review-draft-hint')) element('experience-review-draft-hint').hidden = !!entry;
    }
    function renderEvidence(items) {
        const evidence = element('experience-evidence'); evidence.replaceChildren();
        const count = element('experience-evidence-count');
        if (count) count.textContent = tr('evidenceCount', { count: items.length });
        if (!items.length) evidence.append(node('p', 'experience-panel-note', tr('noEvidence')));
        const entry = state.entry;
        items.forEach(item => evidence.append(button(`${item.role}: ${item.execution_id}`, async () => {
            try { const response = await request(`/api/experiences/${encodeURIComponent(entry.id)}/evidence/${encodeURIComponent(item.execution_id)}${projectQuery()}`); element('experience-detail-json').textContent = pretty(await response.json()); } catch (error) { notify(error); }
        })));
    }
    function showDetail(detail) {
        state.entry = detail.entry;
        const entry = detail.entry;
        element('experience-detail').hidden = false;
        element('experience-detail-json').textContent = pretty(entry);
        element('experience-editor').value = pretty({ content: entry.content, origin_project_id: entry.origin_project_id || '', evidence: detail.evidence || [] });
        element('experience-review-scope').value = entry.scope;
        element('experience-review-note').value = '';
        const conditions = entry.content.conditions || {};
        element('experience-outcome').value = pretty({ revision: entry.revision, execution_id: '', result: 'inconclusive', note: '', environment: { product: conditions.product || '', version: conditions.versions?.[0] || '', tool_name: conditions.tool_name || '', tool_schema_hash: conditions.tool_schema_hash || '', platform: conditions.platform || '', facts: conditions.required || {}, project_id: value('experience-project') } });
        renderEvidence(detail.evidence || []);
        if (typeof window.applyRBACToUI === 'function') window.applyRBACToUI(element('experience-detail'));
        renderDetailHeading();
        element('experience-detail').scrollIntoView?.({ block: 'start' });
    }
    async function open(id) {
        try { const response = await request(`/api/experiences/${encodeURIComponent(id)}${projectQuery()}`); showDetail(await response.json()); }
        catch (error) { notify(error); }
    }
    function newProposal() {
        if (!permitted('experience:write')) return;
        state.entry = null; element('experience-detail').hidden = false; element('experience-detail-json').textContent = tr('newHint'); renderEvidence([]);
        element('experience-editor').value = pretty({ content: { kind: 'workflow', title: '', summary: '', conditions: { required: {} }, steps: [], verification: '', failure_notes: [], cleanup: '', sources: [], artifacts: [] }, evidence: [], origin_project_id: value('experience-project') });
        window.applyRBACToUI?.(element('experience-detail'));
        renderDetailHeading();
        element('experience-detail').scrollIntoView?.({ block: 'start' });
    }
    function close() { state.entry = null; element('experience-detail').hidden = true; }
    function save() {
        if (!permitted('experience:write')) return;
        void mutate(async () => {
            const body = JSON.parse(value('experience-editor'));
            const current = state.entry;
            if (current) body.revision = current.revision;
            const response = await request(current ? `/api/experiences/${encodeURIComponent(current.id)}` : '/api/experiences', current ? 'PUT' : 'POST', body);
            const entry = await response.json(); await refresh(false); await open(entry.id);
        });
    }
    function review() {
        if (!state.entry || !permitted('experience:review')) return;
        void mutate(async () => {
            const current = state.entry;
            await request(`/api/experiences/${encodeURIComponent(current.id)}/review`, 'POST', { revision: current.revision, status: value('experience-review-status'), scope: value('experience-review-scope'), note: value('experience-review-note') });
            await refresh(false); await open(current.id);
        });
    }
    function history() {
        if (!state.entry) return;
        void mutate(async () => { const response = await request(`/api/experiences/${encodeURIComponent(state.entry.id)}/revisions${projectQuery()}`); element('experience-detail-json').textContent = pretty(await response.json()); });
    }
    function confirmOutcome() {
        if (!state.entry || !permitted('experience:review')) return;
        void mutate(async () => { const current = state.entry; const body = JSON.parse(value('experience-outcome')); await request(`/api/experiences/${encodeURIComponent(current.id)}/confirmed-outcomes`, 'POST', body); await open(current.id); await refresh(false); });
    }
    function exportSkill() {
        if (!state.entry || !permitted('experience:export')) return;
        void mutate(async () => {
            const current = state.entry; const response = await request(`/api/experiences/${encodeURIComponent(current.id)}/skill${projectQuery()}`);
            const blob = await response.blob(); const url = URL.createObjectURL(blob); const link = document.createElement('a');
            link.href = url; link.download = `experience-${current.id}-r${current.revision}.zip`; document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
        });
    }
    document.addEventListener('languagechange', () => {
        if (state.listStatus !== 'idle') renderList();
        if (!element('experience-detail')?.hidden) {
            renderDetailHeading();
            if (!state.entry) element('experience-detail-json').textContent = tr('newHint');
            const count = element('experience-evidence-count');
            if (count) count.textContent = tr('evidenceCount', { count: element('experience-evidence').querySelectorAll('button').length });
            const empty = element('experience-evidence').querySelector('p');
            if (empty) empty.textContent = tr('noEvidence');
        }
    });
    window.ExperienceMemory = { refresh, open, newProposal, close, save, review, history, confirmOutcome, exportSkill, resetFilters };
})();
