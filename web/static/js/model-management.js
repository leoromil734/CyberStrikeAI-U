// 模型管理：每个通道包含一个型号；同一地址与密钥可导入多个独立通道。
let savedAIChannelSnapshots = {};
let aiChannelProbeRunning = false;
let aiModelImportState = null;
let aiModelImportRequest = 0;

function cloneModelConfig(value) { return JSON.parse(JSON.stringify(value)); }

function canonicalAIChannel(channel) {
    const c = channel || {}, r = c.reasoning || {};
    const v = c.vision;
    const vision = v == null ? null : {
        enabled:!!v.enabled, provider:v.provider || '', base_url:v.base_url || '', api_key:v.api_key || '', model:v.model || '',
        timeout_seconds:v.timeout_seconds || 60, max_image_bytes:v.max_image_bytes || 5242880,
        max_dimension:v.max_dimension || 2048, jpeg_quality:v.jpeg_quality || 82,
        max_payload_bytes:v.max_payload_bytes || 524288, skip_preprocess_below_bytes:v.skip_preprocess_below_bytes ?? 2097152,
        detail:v.detail || 'low'
    };
    return JSON.stringify({name:c.name || '', provider:c.provider === 'claude' ? 'claude' : 'openai',
        api_key:c.api_key || '', base_url:c.base_url || '', model:c.model || '',
        max_total_tokens:c.max_total_tokens || 120000, max_completion_tokens:c.max_completion_tokens || 16384,
        reasoning:{mode:r.mode || 'auto', effort:r.effort || '', profile:r.profile || 'auto', allow_client_reasoning:r.allow_client_reasoning !== false},
        vision});
}

function rememberSavedAIChannels(ai) { savedAIChannelSnapshots = cloneModelConfig(ai?.channels || {}); }

function collectAIChannelVision() {
    return document.getElementById('vision-inherit-global')?.checked ? null : collectVisionConfigFromForm();
}

function fillAIChannelVision(channel) {
    const inherit = channel.vision == null;
    const checkbox = document.getElementById('vision-inherit-global');
    if (checkbox) checkbox.checked = inherit;
    fillVisionConfigFromCurrent(inherit ? (currentConfig?.vision || {}) : channel.vision);
    syncAIChannelVisionInheritance();
}

function syncAIChannelVisionInheritance() {
    const inherit = document.getElementById('vision-inherit-global')?.checked === true;
    if (inherit) fillVisionConfigFromCurrent(currentConfig?.vision || {});
    const enabled = document.getElementById('vision-enabled');
    if (enabled) enabled.disabled = inherit;
    if (!inherit) document.querySelectorAll('#vision-fields-panel input, #vision-fields-panel select, #vision-fields-panel button').forEach(el => { el.disabled = false; });
    syncVisionFormEnabled();
    if (inherit) document.querySelectorAll('#vision-fields-panel input, #vision-fields-panel select, #vision-fields-panel button').forEach(el => { el.disabled = true; });
    const label = document.getElementById('vision-channel-label');
    if (label) label.textContent = currentConfig?.ai?.channels?.[selectedAIChannelId]?.name || selectedAIChannelId;
}

function resetAIChannelTransientUI() {
    aiModelImportRequest++;
    aiModelImportState = null;
    const importList = document.getElementById('ai-import-models');
    if (importList) importList.innerHTML = '';
    const importStatus = document.getElementById('ai-import-status');
    if (importStatus) importStatus.textContent = '';
    ['openai', 'vision'].forEach(scope => {
        const select = document.getElementById(scope + '-model-select');
        if (select) { select.innerHTML = ''; syncModelPickDropdown(scope + '-model-select'); }
        ['test-' + scope + '-result', 'fetch-' + scope + '-models-result'].forEach(id => {
            const result = document.getElementById(id);
            if (result) result.textContent = '';
        });
    });
}

function getAIChannelProbeDisplay(id) {
    const probe = aiChannelProbeResults[id];
    if (!probe) return null;
    if (probe.status === 'testing') return probe;
    const draft = currentConfig?.ai?.channels?.[id];
    const stale = probe.stale || (draft && canonicalAIChannel(draft) !== canonicalAIChannel(savedAIChannelSnapshots[id]));
    if (stale) return {...probe, status:'stale', message:settingsT('modelManagement.stale', '配置已更改，需重测')};
    const message = probe.error || (probe.success
        ? settingsT('modelManagement.ready', '可用') + (probe.ttft_ms != null ? ` · ${settingsT('modelManagement.firstToken', '首 token')} ${probe.ttft_ms} ms` : '')
        : probe.message || settingsT('modelManagement.failed', '失败'));
    return {...probe, message};
}

async function loadSavedAIChannelProbes() {
    try {
        const response = await apiFetch('/api/config/ai-channel-probes');
        if (!response.ok) throw new Error('读取测试记录失败');
        const data = await response.json();
        if (aiChannelProbeRunning) return;
        Object.keys(aiChannelProbeResults).forEach(id => delete aiChannelProbeResults[id]);
        Object.assign(aiChannelProbeResults, data.results || {});
        renderAIChannelSelect();
        renderAIChannelProbeTable();
        if (typeof document.dispatchEvent === 'function') document.dispatchEvent(new Event('ai-channel-probes-updated'));
    } catch (error) {
        const status = document.getElementById('ai-probe-progress');
        if (status) status.textContent = settingsT('modelManagement.loadFailed', '测试记录加载失败，请刷新重试');
    }
}

function renderAIChannelProbeTable() {
    const root = document.getElementById('ai-probe-results');
    if (!root || !currentConfig?.ai?.channels) return;
    const esc = escapeAIChannelHtml;
    root.innerHTML = Object.entries(currentConfig.ai.channels).map(([id, channel]) => {
        const p = getAIChannelProbeDisplay(id);
        const status = !p ? settingsT('modelManagement.untested', '未测试') : p.status === 'testing' ? settingsT('settingsBasic.testing', '测试中…') : p.status === 'stale' ? settingsT('modelManagement.stale', '配置已更改，需重测') : p.success ? settingsT('modelManagement.ready', '可用') : settingsT('modelManagement.failed', '失败');
        const date = p?.tested_at ? new Date(p.tested_at).toLocaleString() : '—';
        return `<tr><td><strong>${esc(channel.name || id)}</strong><small>${esc(channel.model || '—')}</small></td><td><span class="model-probe-status ${esc(p?.status || 'untested')}">${esc(status)}</span></td><td>${p?.ttft_ms == null ? '—' : esc(p.ttft_ms) + ' ms'}</td><td>${p?.latency_ms == null ? '—' : esc(p.latency_ms) + ' ms'}</td><td>${esc(date)}</td><td class="model-probe-error">${esc(p?.error || p?.message || '')}</td></tr>`;
    }).join('');
}

async function testSavedAIChannels(forceAll = false) {
    if (typeof requirePermission === 'function' && !requirePermission('config:write')) return;
    if (aiChannelProbeRunning) return;
    aiChannelProbeRunning = true;
    const progress = document.getElementById('ai-probe-progress');
    document.querySelectorAll('[data-model-probe-button]').forEach(button => { button.disabled = true; });
    try {
        if (selectedAIChannelId && currentConfig?.ai?.channels?.[selectedAIChannelId]) currentConfig.ai.channels[selectedAIChannelId] = readAIChannelFromMainForm(selectedAIChannelId);
        const response = await apiFetch('/api/config');
        if (!response.ok) throw new Error('无法读取已保存的模型');
        const saved = await response.json();
        const ai = ensureAIConfigShape(saved);
        rememberSavedAIChannels(ai);
        const checked = selectedAIChannelBulkIds.size ? Array.from(selectedAIChannelBulkIds) : [selectedAIChannelId];
        const ids = Object.keys(ai.channels).filter(id => forceAll || checked.includes(id));
        for (const id of ids) {
            if (!currentConfig.ai.channels[id]) currentConfig.ai.channels[id] = cloneModelConfig(ai.channels[id]);
        }
        if (!ids.length) throw new Error('没有已保存的选中通道，请先保存配置');
        let cursor = 0, completed = 0, passed = 0;
        ids.forEach(id => { aiChannelProbeResults[id] = {status:'testing'}; });
        renderAIChannelSelect();
        const update = () => { if (progress) progress.textContent = `${completed}/${ids.length} · ${passed} ${settingsT('modelManagement.ready', '可用')}`; };
        update();
        await Promise.all(Array.from({length:Math.min(AI_CHANNEL_PROBE_CONCURRENCY, ids.length)}, async () => {
            while (cursor < ids.length) {
                const id = ids[cursor++];
                try {
                    const response = await apiFetch('/api/config/ai-channels/' + encodeURIComponent(id) + '/test', {method:'POST'});
                    const result = await response.json();
                    if (!response.ok) throw new Error(result.error || '测试请求失败');
                    aiChannelProbeResults[id] = result;
                    if (result.success) passed++;
                } catch (error) {
                    aiChannelProbeResults[id] = {status:'failed', error:error.message, message:settingsT('modelManagement.notSaved', '请求失败，结果未保存')};
                }
                completed++;
                updateAIChannelSelectOption(id);
                renderAIChannelList();
                renderAIChannelProbeTable();
                update();
            }
        }));
    } catch (error) {
        if (progress) progress.textContent = error.message;
    } finally {
        aiChannelProbeRunning = false;
        document.querySelectorAll('[data-model-probe-button]').forEach(button => { button.disabled = false; });
        if (typeof document.dispatchEvent === 'function') document.dispatchEvent(new Event('ai-channel-probes-updated'));
    }
}

// Pure import logic: same endpoint/key/model is skipped, distinct keys remain
// independent channels, and normalization collisions receive unique suffixes.
function buildAIModelImports(channels, source, models, prefix) {
    const masked = value => String(value || '').trim() === '********';
    if (masked(source?.api_key) || masked(source?.vision?.api_key)) {
        throw new Error('已保存的密钥不会回显。批量创建新通道前，请重新填写主模型及独立视觉模型的 API Key，然后重新获取模型列表。');
    }
    const next = cloneModelConfig(channels || {}), added = [];
    const endpoint = c => JSON.stringify([c.provider === 'claude' ? 'claude' : 'openai', String(c.base_url || '').trim().replace(/\/+$/, ''), String(c.api_key || '').trim(), String(c.model || '').trim()]);
    // Identical masks do not establish that two saved channels share a key.
    const known = new Set(Object.values(next).filter(c => !masked(c.api_key)).map(endpoint));
    for (const model of [...new Set(models.map(value => String(value).trim()).filter(Boolean))]) {
        const channel = {...cloneModelConfig(source), name:String(prefix || '') + model, model};
        const key = endpoint(channel);
        if (known.has(key)) continue;
        const base = normalizeAIChannelId(channel.name);
        let id = base, suffix = 2;
        while (Object.prototype.hasOwnProperty.call(next, id)) id = `${base}-${suffix++}`;
        next[id] = channel;
        known.add(key);
        added.push(id);
    }
    return {channels:next, added};
}

async function fetchAIModelsForImport() {
    const request = ++aiModelImportRequest;
    const channelID = selectedAIChannelId;
    const source = readAIChannelFromMainForm(channelID);
    const status = document.getElementById('ai-import-status');
    const manual = (document.getElementById('ai-import-manual')?.value || '').split(/[\n,，]+/).map(s => s.trim()).filter(Boolean);
    if (!source.api_key || !source.base_url) { if (status) status.textContent = '请先在连接信息中填写地址与密钥'; return; }
    if (status) status.textContent = settingsT('settingsBasic.modelsListFetching', '正在获取模型列表…');
    try {
        let models = manual;
        if (!models.length) {
            const response = await apiFetch('/api/config/list-models', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({provider:source.provider, base_url:source.base_url, api_key:source.api_key, channel_id:channelID, credential_scope:'openai'})});
            const data = await response.json();
            if (!response.ok || !data.success) throw new Error(data.error || '获取模型失败，可手动粘贴型号列表');
            models = data.models || [];
        }
        if (request !== aiModelImportRequest) return;
        aiModelImportState = {source:cloneModelConfig(source), models:[...new Set(models)].sort(), selected:new Set()};
        const prefix = document.getElementById('ai-import-prefix');
        if (prefix && !prefix.value) prefix.value = (source.name || 'AI') + ' / ';
        renderAIModelImports();
    } catch (error) {
        if (request === aiModelImportRequest && status) status.textContent = error.message;
    }
}

function renderAIModelImports() {
    const list = document.getElementById('ai-import-models');
    if (!list || !aiModelImportState) return;
    const query = (document.getElementById('ai-import-search')?.value || '').trim().toLowerCase();
    list.innerHTML = '';
    for (const model of aiModelImportState.models.filter(model => model.toLowerCase().includes(query))) {
        const label = document.createElement('label'), checkbox = document.createElement('input'), name = document.createElement('span');
        checkbox.type = 'checkbox'; checkbox.checked = aiModelImportState.selected.has(model);
        checkbox.addEventListener('change', () => { if (checkbox.checked) aiModelImportState.selected.add(model); else aiModelImportState.selected.delete(model); updateAIModelImportStatus(); });
        name.textContent = model; label.appendChild(checkbox); label.appendChild(name); list.appendChild(label);
    }
    updateAIModelImportStatus();
}

function updateAIModelImportStatus() {
    const status = document.getElementById('ai-import-status');
    if (status && aiModelImportState) status.textContent = settingsT('modelManagement.selection', '已选 {selected} / {total} 个模型').replace('{selected}', aiModelImportState.selected.size).replace('{total}', aiModelImportState.models.length);
}

function selectAIModelImports(all) {
    if (!aiModelImportState) return;
    const query = (document.getElementById('ai-import-search')?.value || '').trim().toLowerCase();
    for (const model of aiModelImportState.models.filter(model => model.toLowerCase().includes(query))) {
        if (all) aiModelImportState.selected.add(model); else aiModelImportState.selected.delete(model);
    }
    renderAIModelImports();
}

function importSelectedAIModels() {
    if (!aiModelImportState || !aiModelImportState.selected.size) { showAIChannelSaveHint('请先勾选要导入的模型', false); return; }
    const current = readAIChannelFromMainForm(selectedAIChannelId);
    const source = aiModelImportState.source;
    if (['provider', 'base_url', 'api_key'].some(key => current[key] !== source[key])) {
        showAIChannelSaveHint('连接信息已修改，请重新获取可导入模型', false);
        return;
    }
    let result;
    try {
        // Validate before changing the drafts: a masked key cannot be copied
        // into a new channel or treated as a reusable credential.
        result = buildAIModelImports({...currentConfig.ai.channels, [selectedAIChannelId]:current}, source, [...aiModelImportState.selected], document.getElementById('ai-import-prefix')?.value || '');
    } catch (error) {
        showAIChannelSaveHint(error.message, false);
        return;
    }
    currentConfig.ai.channels = result.channels;
    if (result.added.length) {
        selectedAIChannelId = result.added[0];
        writeAIChannelToMainForm(selectedAIChannelId);
        renderAIChannelSelect();
    }
    showAIChannelSaveHint(`已导入 ${result.added.length} 个新通道（重复项已跳过），请点击「保存更改」持久化。`, true);
}

if (typeof document !== 'undefined') {
    document.addEventListener('input', event => {
        if (event.target?.closest?.('.ai-channel-editor, #vision-channel-config')) syncAIChannelEditorPreview();
    });
    document.addEventListener('change', event => {
        if (event.target?.closest?.('#vision-channel-config')) syncAIChannelEditorPreview();
    });
}
