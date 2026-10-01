// All remembered text is rendered with textContent, never as HTML or script.
(() => {
    'use strict';
    const state = { entry: null, offset: 0, sequence: 0, busy: false };
    const pageSize = 25;
    const element = id => document.getElementById(id);
    const value = id => (element(id)?.value || '').trim();
    const tr = key => typeof window.t === 'function' ? window.t(`experience.${key}`) : key;
    const projectQuery = () => value('experience-project') ? `?project_id=${encodeURIComponent(value('experience-project'))}` : '';
    const permitted = permission => typeof window.hasPermission === 'function' && window.hasPermission(permission);
    const pretty = object => JSON.stringify(object, null, 2);
    const notify = error => window.notifyApiError?.(error?.message || String(error));
    async function request(path, method = 'GET', body) {
        const response = await apiFetch(path, { method, ...(body ? { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) } : {}) });
        if (!response.ok) throw new Error(await readApiError(response, tr('failed')));
        return response;
    }
    function button(label, action) {
        const node = document.createElement('button'); node.type = 'button'; node.className = 'btn-secondary'; node.textContent = label;
        node.addEventListener('click', action); return node;
    }
    async function mutate(action) {
        if (state.busy) return;
        state.busy = true;
        try { await action(); } catch (error) { notify(error); } finally { state.busy = false; }
    }
    async function refresh(reset = true) {
        if (reset) state.offset = 0;
        const sequence = ++state.sequence;
        const list = element('experience-list'); if (!list) return;
        list.textContent = tr('loading');
        const query = new URLSearchParams({ limit: String(pageSize), offset: String(state.offset), status: value('experience-status'), kind: value('experience-kind'), query: value('experience-query'), project_id: value('experience-project') });
        try {
            const response = await request(`/api/experiences?${query}`);
            const data = await response.json(); if (sequence !== state.sequence) return;
            list.replaceChildren();
            const items = Array.isArray(data.items) ? data.items : [];
            if (!items.length) list.textContent = tr('empty');
            items.forEach(entry => {
                const section = document.createElement('section'); section.className = 'experience-item';
                const title = document.createElement('h3'); title.textContent = entry.content.title;
                const summary = document.createElement('p'); summary.textContent = entry.content.summary;
                const meta = document.createElement('p'); meta.textContent = `${entry.status} · ${entry.scope} · r${entry.revision} · ${entry.content.kind}`;
                section.append(title, summary, meta, button(tr('view'), () => open(entry.id))); list.append(section);
            });
            const pager = element('experience-pagination'); pager.replaceChildren();
            if (state.offset > 0) pager.append(button(tr('previous'), () => { state.offset = Math.max(0, state.offset - pageSize); void refresh(false); }));
            if (items.length === pageSize) pager.append(button(tr('next'), () => { state.offset += pageSize; void refresh(false); }));
        } catch (error) { if (sequence === state.sequence) list.textContent = error.message; }
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
        const evidence = element('experience-evidence'); evidence.replaceChildren();
        (detail.evidence || []).forEach(item => evidence.append(button(`${item.role}: ${item.execution_id}`, async () => {
            try { const response = await request(`/api/experiences/${encodeURIComponent(entry.id)}/evidence/${encodeURIComponent(item.execution_id)}${projectQuery()}`); element('experience-detail-json').textContent = pretty(await response.json()); } catch (error) { notify(error); }
        })));
        if (typeof window.applyRBACToUI === 'function') window.applyRBACToUI(element('experience-detail'));
    }
    async function open(id) {
        try { const response = await request(`/api/experiences/${encodeURIComponent(id)}${projectQuery()}`); showDetail(await response.json()); }
        catch (error) { notify(error); }
    }
    function newProposal() {
        if (!permitted('experience:write')) return;
        state.entry = null; element('experience-detail').hidden = false; element('experience-detail-json').textContent = tr('newHint'); element('experience-evidence').replaceChildren();
        element('experience-editor').value = pretty({ content: { kind: 'workflow', title: '', summary: '', conditions: { required: {} }, steps: [], verification: '', failure_notes: [], cleanup: '', sources: [], artifacts: [] }, evidence: [], origin_project_id: value('experience-project') });
        window.applyRBACToUI?.(element('experience-detail'));
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
    window.ExperienceMemory = { refresh, open, newProposal, close, save, review, history, confirmOutcome, exportSkill };
})();
