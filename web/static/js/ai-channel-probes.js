// Shared, read-only presentation for the credential-free /api/config/ai-channels response.
// This helper never fetches configuration or starts a model test. All DOM text is
// assigned through textContent; callers producing HTML must escape returned strings.
(function (root, factory) {
    const ui = factory(root);
    if (typeof module === 'object' && module.exports) module.exports = ui;
    if (root) root.AIChannelProbeUI = ui;
})(typeof globalThis !== 'undefined' ? globalThis : this, function (root) {
    function translate(key, fallback) {
        const t = root && (root.t || (root.window && root.window.t));
        const value = typeof t === 'function' ? t(key) : '';
        return value && value !== key ? value : fallback;
    }

    function describe(channel) {
        const probe = channel && channel.probe;
        let status = probe && probe.status || 'untested';
        if (probe && probe.stale === true) status = 'stale';
        if (!['untested', 'ready', 'failed', 'stale', 'unknown'].includes(status)) status = 'unknown';
        const labels = {
            untested: translate('modelManagement.untested', '未测试'),
            ready: translate('modelManagement.ready', '可用'),
            failed: translate('modelManagement.failed', '失败'),
            stale: translate('modelManagement.stale', '配置已更改，需重测'),
            unknown: translate('modelManagement.loadFailed', '测试记录加载失败，请刷新重试'),
        };
        const label = labels[status];
        const hasRecord = ['ready', 'failed', 'stale'].includes(status);
        const ttft = hasRecord && typeof probe.ttft_ms === 'number' && Number.isFinite(probe.ttft_ms) && probe.ttft_ms >= 0
            ? probe.ttft_ms : null;
        const summary = label + (ttft == null ? '' : ' · ' + translate('modelManagement.firstToken', '首 token') + ' ' + ttft + ' ms');
        const date = hasRecord && probe.tested_at ? new Date(probe.tested_at) : null;
        const locale = root && typeof root.getCurrentTimeLocale === 'function' ? root.getCurrentTimeLocale() : undefined;
        const testedAt = date && Number.isFinite(date.getTime()) ? date.toLocaleString(locale) : '';
        // The server returns allowlisted errors. Bound even unexpected/legacy text
        // here as a defense against overly long tooltips, not as secret redaction.
        const error = hasRecord && probe.error ? Array.from(String(probe.error)).slice(0, 240).join('') : '';
        const details = [summary];
        if (testedAt) details.push(translate('modelManagement.testedAt', '测试时间') + ': ' + testedAt);
        if (error) details.push(translate('modelManagement.resultDetail', '结果详情') + ': ' + error);
        return {status, label, summary, details: details.join('\n'), ttft, testedAt, error};
    }

    function channelLabel(channel, id) {
        const ch = channel || {};
        return String(ch.name || id || '') + (ch.model ? ' · ' + ch.model : '');
    }

    function optionLabel(channel, id, baseLabel) {
        const base = baseLabel == null ? channelLabel(channel, id) : String(baseLabel);
        return base + ' · ' + describe(channel).summary;
    }

    function applyOption(option, channel, baseLabel) {
        const base = baseLabel == null ? channelLabel(channel, option.value) : String(baseLabel);
        const info = describe(channel);
        option.textContent = base + ' · ' + info.summary;
        option.title = base + '\n' + info.details;
        option.dataset.aiChannelLabel = base;
        option.dataset.aiProbeStatus = info.status;
        option.dataset.aiProbeDetails = info.details;
        return info;
    }

    function renderDetails(element, channel) {
        const info = describe(channel);
        element.textContent = info.details;
        element.dataset.aiProbeStatus = info.status;
        return info;
    }

    return {describe, channelLabel, optionLabel, applyOption, renderDetails};
});
