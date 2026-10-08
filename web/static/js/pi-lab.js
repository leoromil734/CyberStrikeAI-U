/* PI platform tasks and backward-compatible HTTP probe diagnostics. */
(function (root, factory) {
    'use strict';
    const library = factory();
    if (typeof module === 'object' && module.exports) module.exports = library;
    if (root && root.document) {
        // auth.js owns this extensible map; keep this optional page's registration local.
        if (typeof PAGE_PERMISSION_MAP !== 'undefined') PAGE_PERMISSION_MAP['pi-lab'] = 'agent:execute';
        root.PiLab = library.createController({
            document: root.document,
            apiFetch: (url, options) => root.apiFetch(url, options),
            ensureAuthenticated: () => root.ensureAuthenticated(),
            hasPermission: () => typeof root.hasPermission === 'function' && root.hasPermission('agent:execute'),
            getOwner: () => typeof authUser === 'undefined' || !authUser ? '' : String(authUser.id || authUser.username || ''),
            setTimeout: root.setTimeout.bind(root), clearTimeout: root.clearTimeout.bind(root),
            AbortController: root.AbortController, URL: root.URL, Blob: root.Blob,
            openProject: id => {
                root.switchPage('projects');
                // The shared router drops project hash parameters. Use the existing selection API.
                if (typeof root.selectProject === 'function') void root.selectProject(id);
            },
        });
        root.addEventListener('pagehide', () => root.PiLab.stop());
    }
})(typeof window === 'undefined' ? null : window, function () {
    'use strict';
    const API = '/api/pi-lab';
    const SVG_NS = 'http://www.w3.org/2000/svg';
    const PLATFORM_ROLE = '渗透测试';
    const MODES = { platform: '平台正式任务', probe: 'HTTP 兼容诊断' };
    const LIMITS = {
        probe: { max_parallel: [1, 4], max_agents: [1, 12], timeout_seconds: [60, 1800] },
        platform: { max_parallel: [1, 8], max_agents: [1, 32], timeout_seconds: [60, 21600], max_turns: [1, 500], max_tool_calls: [1, 2000] },
    };
    const DEFAULTS = {
        probe: { max_parallel: 2, max_agents: 4, timeout_seconds: 300 },
        platform: { max_parallel: 3, max_agents: 12, timeout_seconds: 3600, max_turns: 120, max_tool_calls: 600 },
    };
    const BUDGET_FIELDS = { max_parallel: 'parallel', max_agents: 'max-agents', timeout_seconds: 'timeout', max_turns: 'max-turns', max_tool_calls: 'max-tool-calls' };
    const BUDGET_LABELS = { max_parallel: '并发数', max_agents: '子 Agent 数', timeout_seconds: '时限（秒）', max_turns: '模型轮次', max_tool_calls: '工具调用数' };
    const STATUS = { queued: '排队中', running: '运行中', completed: '已完成', partial: '部分完成', failed: '失败', cancelled: '已取消', interrupted: '已中断' };
    const SEVERITY = { critical: '严重', high: '高', medium: '中', low: '低', info: '信息', informational: '信息' };
    const KIND = { target: '目标', scope: '授权范围', surface: '测试入口', tool: '工具执行', agent: 'Agent', route: '路线', action: '动作', finding: '发现', hypothesis: '候选', observation: '观察', observed: '观察' };
    const own = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
    const array = value => Array.isArray(value) ? value.filter(item => item && typeof item === 'object') : [];
    const text = value => value == null ? '' : typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value);
    const label = (map, value) => own(map, text(value)) ? map[value] : text(value) || '未知';
    const activeRun = run => !!run && (run.status === 'queued' || run.status === 'running');
    const short = (value, length = 30) => { const chars = Array.from(text(value)); return chars.length > length ? chars.slice(0, length).join('') + '…' : chars.join(''); };
    const time = value => { const date = new Date(value); return value && !Number.isNaN(date.getTime()) ? date.toLocaleString('zh-CN', { hour12: false }) : text(value) || '—'; };

    function safeURL(value) {
        if (typeof value !== 'string' || !/^https?:\/\//i.test(value) || /[\u0000-\u0020\\]/.test(value)) return '';
        try {
            const url = new URL(value);
            return ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password ? url.href : '';
        } catch (_) { return ''; }
    }

    function parseScope(value) {
        const lines = text(value).split(/\r?\n/).map(line => line.trim()).filter(Boolean);
        if (!lines.length) throw new Error('请填写至少一个已授权的精确 HTTP(S) origin。');
        const origins = lines.map((line, index) => {
            // Validate the original spelling too: URL normalization must not hide a path or credentials.
            if (!/^https?:\/\/[^\s/?#\\]+\/?$/i.test(line) || /[\u0000-\u0020]/.test(line)) {
                throw new Error(`目标范围第 ${index + 1} 行不是精确 origin；请仅填写协议、主机和可选端口，不含路径、查询或片段。`);
            }
            const href = safeURL(line);
            if (!href) throw new Error(`目标范围第 ${index + 1} 行无效，禁止凭据或非 HTTP(S) 地址。`);
            const url = new URL(href);
            if (url.hostname.includes('*')) throw new Error('目标范围不支持通配符；每个子域名必须单独授权。');
            return url.origin;
        });
        return [...new Set(origins)];
    }

    function parsePlatformScope(value) {
        const lines = text(value).split(/\r?\n/).map(line => line.trim()).filter(Boolean);
        if (!lines.length) throw new Error('请逐行填写明确的已授权目标范围。');
        if (lines.length > 20) throw new Error('授权范围不能超过 20 行。');
        // These are task constraints, not a browser-enforced network allowlist.
        return lines;
    }

    function limitMax(source, key, mode = 'probe') {
        const [min, max] = LIMITS[mode][key];
        const candidate = source && source.limits && source.limits[key];
        return Number.isInteger(candidate) && candidate >= min ? Math.min(candidate, max) : max;
    }

    const validProjectId = value => typeof value === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$/.test(value);
    function normalizeProjects(data) {
        if (!Array.isArray(data.projects)) throw new Error('项目列表格式无效。');
        const projects = new Map();
        data.projects.forEach(item => {
            if (!item || !validProjectId(item.id) || typeof item.name !== 'string' || !item.name.trim()) return;
            // Do not inspect scope_json, credentials, or any project configuration.
            if (!projects.has(item.id)) projects.set(item.id, { id: item.id, name: item.name.trim() });
        });
        return [...projects.values()];
    }

    function normalizeProfile(data) {
        if (typeof data.available !== 'boolean') throw new Error('平台能力配置格式无效。');
        const role = data.role && typeof data.role.name === 'string' ? { name: data.role.name, description: typeof data.role.description === 'string' ? data.role.description : '' } : { name: '', description: '' };
        const catalog = items => array(items).filter(item => typeof item.name === 'string' && item.name.trim()).map(item => ({ name: item.name, description: typeof item.description === 'string' ? item.description : '' }));
        const limits = {};
        Object.keys(LIMITS.platform).forEach(key => { if (Number.isInteger(data.limits && data.limits[key])) limits[key] = data.limits[key]; });
        return { available: data.available, reason: text(data.reason), role, skills: catalog(data.skills), tools: catalog(data.tools), limits };
    }

    function platformIssue(profile) {
        if (!profile) return '平台能力配置尚未读取成功，请手动刷新。';
        if (!profile.available) return profile.reason || '平台角色、技能或工具当前不可用。';
        if (!profile.role || profile.role.name !== PLATFORM_ROLE) return '平台未返回可用的“渗透测试”角色，请检查后端配置。';
        return '';
    }

    function buildPayload(input, status, profile = null, projects = []) {
        const mode = input.mode || 'platform';
        if (!own(MODES, mode)) throw new Error('请选择有效的 PI 运行模式。');
        if (!status || status.enabled !== true || status.ready !== true) throw new Error('PI 未启用或原生运行时尚未就绪，当前仅可查看历史。');
        if (mode === 'platform' && platformIssue(profile)) throw new Error(platformIssue(profile));
        if (input.authorized !== true) throw new Error('请明确勾选已获得目标授权。');
        const title = text(input.title).trim();
        const prompt = text(input.prompt).trim();
        if (!title || !prompt) throw new Error('请填写任务标题和测试需求。');
        if (Array.from(title).length > 120) throw new Error('任务标题不能超过 120 个字符。');
        if (new TextEncoder().encode(prompt).byteLength > 16384) throw new Error('测试需求不能超过 16 KiB（中文按 UTF-8 字节计数）。');
        const payload = { mode, title, prompt, scope: mode === 'platform' ? parsePlatformScope(input.scope) : parseScope(input.scope), ai_channel: text(input.ai_channel), authorized: true };
        if (payload.scope.length > 20) throw new Error('授权范围不能超过 20 个精确 origin。');
        if (mode === 'platform') {
            if (!validProjectId(input.project_id)) throw new Error('平台正式任务必须选择一个已授权项目。');
            if (!projects.some(project => project.id === input.project_id)) throw new Error('所选项目不在当前可读的活动项目列表中，请刷新或重新选择。');
            payload.project_id = input.project_id;
            payload.role = PLATFORM_ROLE;
        }
        const source = mode === 'platform' ? profile : status;
        for (const key of Object.keys(LIMITS[mode])) {
            const value = Number(input[key]);
            const max = limitMax(source, key, mode);
            if (!Number.isInteger(value) || value < LIMITS[mode][key][0] || value > max) {
                throw new Error(`${BUDGET_LABELS[key]}必须为 ${LIMITS[mode][key][0]}–${max} 的整数。`);
            }
            payload[key] = value;
        }
        if (payload.max_parallel > payload.max_agents) throw new Error('并发数不能超过子 Agent 数。');
        return payload;
    }

    function mergeEventPage(existing, cursor, page) {
        if (!page || !Array.isArray(page.events) || !Number.isSafeInteger(page.cursor) || page.cursor < 0 || typeof page.has_more !== 'boolean') {
            throw new Error('事件响应格式无效，请刷新重试。');
        }
        const bySequence = new Map(existing.map(event => [event.seq, event]));
        let nextCursor = Math.max(cursor, page.cursor);
        for (const event of page.events) {
            if (!event || !Number.isSafeInteger(event.seq) || event.seq <= 0) throw new Error('事件序号无效。');
            if (!bySequence.has(event.seq)) bySequence.set(event.seq, event);
            nextCursor = Math.max(nextCursor, event.seq);
        }
        if (page.has_more && nextCursor <= cursor) throw new Error('事件游标没有前进，已暂停连续翻页；可手动刷新重试。');
        return { events: [...bySequence.values()].sort((a, b) => a.seq - b.seq), cursor: nextCursor, hasMore: page.has_more };
    }

    function normalizeRun(run) {
        if (!run || typeof run.id !== 'string' || !run.id) throw new Error('任务响应缺少有效 ID。');
        // Allowlisted projection keeps configuration and unrelated response fields out of local state/export.
        const result = {};
        ['id', 'title', 'prompt', 'ai_channel', 'model', 'status', 'created_at', 'updated_at', 'error', 'report', 'project_id', 'conversation_id', 'role'].forEach(key => { result[key] = text(run[key]); });
        result.mode = run.mode == null || run.mode === '' ? 'probe' : text(run.mode);
        ['skills', 'execution_ids'].forEach(key => { result[key] = Array.isArray(run[key]) ? run[key].filter(item => typeof item === 'string') : []; });
        result.scope = Array.isArray(run.scope) ? run.scope.map(text) : [];
        result.limits = {};
        ['max_parallel', 'max_agents', 'timeout_seconds', 'max_requests', 'max_turns', 'max_tool_calls'].forEach(key => { if (Number.isFinite(run.limits && run.limits[key])) result.limits[key] = run.limits[key]; });
        result.event_count = Number.isSafeInteger(run.event_count) && run.event_count >= 0 ? run.event_count : 0;
        const fields = {
            agents: ['id', 'role', 'task', 'parent_id', 'status', 'summary'],
            nodes: ['id', 'kind', 'label', 'detail', 'status', 'url', 'parent_id'],
            edges: ['id', 'source', 'target', 'label'],
            findings: ['id', 'title', 'severity', 'status', 'url', 'evidence', 'remediation'],
        };
        Object.entries(fields).forEach(([key, keys]) => { result[key] = array(run[key]).map(item => Object.fromEntries(keys.map(field => [field, text(item[field])]))); });
        return result;
    }

    function graphLayout(nodes, edges) {
        const unique = new Map(array(nodes).filter(node => node.id).map(node => [node.id, node]));
        const degree = new Map([...unique.keys()].map(id => [id, 0]));
        const outgoing = new Map([...unique.keys()].map(id => [id, new Set()]));
        const levels = new Map([...unique.keys()].map(id => [id, 0]));
        const connect = (source, target) => {
            if (source === target || !unique.has(source) || !unique.has(target) || outgoing.get(source).has(target)) return;
            outgoing.get(source).add(target); degree.set(target, degree.get(target) + 1);
        };
        array(edges).forEach(edge => connect(edge.source, edge.target));
        unique.forEach(node => connect(node.parent_id, node.id));
        const queue = [...unique.keys()].filter(id => degree.get(id) === 0);
        for (let index = 0; index < queue.length; index++) {
            const source = queue[index];
            outgoing.get(source).forEach(target => {
                levels.set(target, Math.max(levels.get(target), levels.get(source) + 1));
                degree.set(target, degree.get(target) - 1);
                if (degree.get(target) === 0) queue.push(target);
            });
        }
        // Cycles remain visible in column zero rather than causing recursive layout failure.
        const rows = new Map(); const points = new Map();
        unique.forEach((node, id) => {
            const level = degree.get(id) > 0 ? 0 : levels.get(id);
            const row = rows.get(level) || 0; rows.set(level, row + 1);
            points.set(id, { node, x: 24 + level * 268, y: 30 + row * 108 });
        });
        return { points, width: Math.max(520, ...[...points.values()].map(point => point.x + 250)), height: Math.max(170, ...[...points.values()].map(point => point.y + 104)) };
    }

    function createView(document, actions) {
        const $ = id => document.getElementById('pi-lab-' + id);
        const element = (tag, className, content) => {
            const node = document.createElement(tag);
            if (className) node.className = className;
            if (content != null) node.textContent = text(content);
            return node;
        };
        const clear = node => { if (node) node.replaceChildren(); return node; };
        const set = (id, value) => { if ($(id)) $(id).textContent = text(value); };
        const empty = (node, message) => node.appendChild(element(['OL', 'UL'].includes(node.tagName) ? 'li' : 'p', 'pi-lab-empty', message));
        const badge = status => element('span', 'pi-lab-badge ' + (own(STATUS, status) ? 'pi-lab-status-' + status : ''), label(STATUS, status));
        const link = (parent, value) => {
            const href = safeURL(value);
            if (!href) { if (value) parent.appendChild(element('span', 'pi-lab-muted', '不可打开的地址：' + text(value))); return; }
            const anchor = element('a', 'pi-lab-link', value);
            anchor.href = href; anchor.target = '_blank'; anchor.rel = 'noopener noreferrer';
            parent.appendChild(anchor);
        };
        const paragraph = (parent, heading, value) => {
            if (!value) return;
            parent.appendChild(element('h5', '', heading));
            parent.appendChild(element('pre', 'pi-lab-plain', value));
        };
        let bound = false; let graphSignature = ''; let selectedNodeId = ''; let currentNodes = []; let graphGroups = new Map();
        let timelineSignature = '';

        function bind() {
            if (bound || !$('form')) return;
            bound = true;
            $('form').addEventListener('submit', event => {
                event.preventDefault();
                if (!$('form').reportValidity()) return;
                void actions.createRun({
                    mode: $('mode').value, project_id: $('project').value,
                    title: $('title').value, scope: $('scope').value, prompt: $('prompt').value,
                    ai_channel: $('channel').value, max_parallel: $('parallel').value,
                    max_agents: $('max-agents').value, timeout_seconds: $('timeout').value,
                    max_turns: $('max-turns').value, max_tool_calls: $('max-tool-calls').value, authorized: $('authorized').checked,
                });
            });
            $('mode').addEventListener('change', () => actions.setMode($('mode').value));
            $('project').addEventListener('change', () => actions.setProject($('project').value));
            $('authorized').addEventListener('change', actions.renderControls);
            $('refresh').addEventListener('click', () => { void actions.refresh(true); });
            $('cancel').addEventListener('click', () => { void actions.cancelRun(); });
            $('export').addEventListener('click', actions.exportRun);
            $('copy').addEventListener('click', actions.copyRun);
            $('new').addEventListener('click', actions.newRun);
        }

        function controls(state, allowed) {
            const platform = state.mode === 'platform';
            const ready = allowed && !state.checkingSetup && state.status && state.status.enabled === true && state.status.ready === true
                && (!platform || (!platformIssue(state.profile) && !state.errors.projects && state.projects.some(project => project.id === state.projectId)));
            if ($('submit')) $('submit').disabled = !ready || state.creating || state.cancelling || !$('authorized').checked;
            if ($('submit')) $('submit').textContent = state.creating ? '正在创建…' : platform ? '启动平台任务' : '启动兼容诊断';
            if ($('cancel')) $('cancel').disabled = !allowed || !activeRun(state.run) || state.cancelling || state.creating;
            if ($('cancel')) $('cancel').textContent = state.cancelling ? '正在取消…' : '取消任务';
            if ($('export')) $('export').disabled = !allowed || !state.run;
            if ($('copy')) $('copy').disabled = !allowed || !state.run || !own(MODES, state.run.mode) || state.creating || state.cancelling;
            if ($('new')) $('new').disabled = !allowed || state.creating || state.cancelling;
            if ($('mode')) $('mode').disabled = !allowed || state.creating || state.cancelling;
            if ($('project')) $('project').disabled = !platform || state.creating || state.cancelling;
            if ($('refresh')) $('refresh').disabled = !allowed || state.refreshing || state.creating || state.cancelling;
            set('sync', state.refreshing ? '正在刷新完整状态与增量事件…' : state.updatedAt ? '本页同步于 ' + time(state.updatedAt) : '等待同步');
            set('form-error', state.errors.form);
            if ($('form-error')) $('form-error').hidden = !state.errors.form;
            set('form-notice', state.formNotice);
            if ($('form-notice')) $('form-notice').hidden = !state.formNotice;
        }

        function status(state) {
            const result = state.status;
            let message = '正在检查 PI 运行时…';
            if (state.errors.status) message = '无法读取 PI 状态：' + state.errors.status + '。创建已禁用，仍可尝试读取本人历史。';
            else if (result) {
                const reason = text(result.reason);
                if (!result.enabled) message = 'PI 开关未启用。' + (reason || '请由管理员配置并启用后端 PI 运行时。') + ' 当前只读浏览历史。';
                else if (!result.ready) message = '原生 PI 运行时未就绪。' + (reason || '请由管理员检查 PI 运行时与模型配置。') + ' 创建已禁用，历史仍可查看。';
                else message = '原生 PI 运行时已就绪。' + (reason ? ' ' + reason : ' 请确认运行模式、项目与明确授权范围后启动。');
            }
            set('runtime-status', message);
            if ($('runtime-status')) $('runtime-status').classList.toggle('is-ready', !!(result && result.enabled && result.ready));
            set('runtime-detail', result ? '运行时：' + (text(result.runtime) || '未声明') + '。依赖检查仅在进入页面和手动刷新时执行。' : '运行时信息尚不可用。');
            mode(state);
        }

        function mode(state, resetBudgets = false) {
            const platform = state.mode === 'platform';
            const source = platform ? state.profile : state.status;
            if ($('mode')) $('mode').value = state.mode;
            if ($('project-field')) $('project-field').hidden = !platform;
            if ($('project')) $('project').required = platform;
            if ($('platform-budgets')) $('platform-budgets').hidden = !platform;
            if ($('profile-panel')) $('profile-panel').hidden = !platform;
            set('scope-label', platform ? '明确授权范围（每行一项，最多 20 行）' : '授权目标范围（每行一个精确 origin）');
            set('scope-hint', platform ? '可填写内网地址、URL 路径、CIDR 网段或明确的授权范围描述。范围是任务约束，不是网络层强隔离；请写明允许事项与停止条件。' : '仅协议、主机、可选端口；不含凭据、路径、查询、片段或通配符。诊断仍只检查需求中明示的公网 URL。');
            if ($('scope')) $('scope').placeholder = platform ? 'https://app.example.test/api/ 已授权测试接口\n10.20.0.0/24 内部测试网段（排除网关）' : 'https://example.test\nhttps://app.example.test:8443';
            set('mode-hint', platform ? '使用原生 PI 执行平台任务，复用后端提供的渗透测试角色、skills（技能）与现有工具；不再限于 GET/HEAD。工具继承平台现有权限及工作目录。' : '兼容旧版 HTTP 诊断，仅 GET/HEAD 响应头与内容哈希检查，不分析正文，不联动平台角色、skills 或现有工具。');
            set('authorization-text', platform ? '我确认已获得上述范围的测试授权，已明确允许的操作及停止条件，并理解工具使用现有平台权限及工作目录，范围声明不构成网络层隔离。' : '我确认已获得上述精确目标范围的测试授权，同意仅进行低影响 HTTP 检查，并理解候选与观察不等于已确认漏洞。');
            const tools = state.status && Array.isArray(state.status.tools) ? state.status.tools.map(tool => typeof tool === 'string' ? tool : text(tool && (tool.name || tool.id))).filter(Boolean) : [];
            set('tools', platform ? '平台能力索引见下方；角色与技能正文由后端加载，本页不内置或编辑。' : '诊断内置工具：' + (tools.join('、') || '暂无可用工具') + '。旧版 GET/HEAD 与 URL 检查语义保持不变。');
            Object.entries(BUDGET_FIELDS).forEach(([key, id]) => {
                const node = $(id); if (!node) return;
                const enabled = own(LIMITS[state.mode], key);
                node.disabled = !enabled; node.required = enabled;
                if (!enabled) return;
                node.min = String(LIMITS[state.mode][key][0]); node.max = String(limitMax(source, key, state.mode));
                if (resetBudgets) node.value = String(Math.min(DEFAULTS[state.mode][key], Number(node.max)));
            });
            set('limit-hint', '当前模式上限：' + Object.keys(LIMITS[state.mode]).map(key => `${BUDGET_LABELS[key]} ${limitMax(source, key, state.mode)}`).join(' · ') + '。子 Agent 数不含协调 Agent；以后端校验为准。');
        }

        function profile(state) {
            const value = state.profile;
            const issue = state.errors.profile || platformIssue(value);
            set('profile-status', issue ? '平台模式不可提交：' + issue : '平台能力可用。' + (value.reason || '复用当前平台配置。'));
            if ($('profile-status')) $('profile-status').classList.toggle('is-ready', !issue);
            set('profile-role', value && value.role.name ? '角色：' + value.role.name + (value.role.description ? ' · ' + short(value.role.description, 240) : '') : '尚未取得可用角色。');
            ['skills', 'tools'].forEach(key => {
                const rows = value ? value[key] : [];
                set(key + '-count', rows.length);
                const list = clear($('catalog-' + key)); if (!list) return;
                if (!rows.length) { empty(list, issue ? '能力索引暂不可用。' : '当前未返回可用条目。'); return; }
                rows.forEach(row => {
                    const item = element('li', 'pi-lab-catalog-item');
                    item.appendChild(element('strong', '', row.name));
                    if (row.description) item.appendChild(element('span', 'pi-lab-muted', short(row.description, 180)));
                    list.appendChild(item);
                });
            });
        }

        function projects(state) {
            const select = clear($('project')); if (!select) return;
            const placeholder = element('option', '', '请选择已授权项目（必填）'); placeholder.value = ''; select.appendChild(placeholder);
            state.projects.forEach(project => {
                const option = element('option', '', project.name); option.value = project.id; select.appendChild(option);
            });
            const missing = state.projectId && !state.projects.some(project => project.id === state.projectId);
            if (missing) {
                const option = element('option', '', '原项目不可用：' + state.projectId); option.value = state.projectId; option.disabled = true; select.appendChild(option);
            }
            select.value = state.projectId;
            set('project-hint', state.errors.projects ? '项目列表读取失败：' + state.errors.projects + '。平台模式已禁用；请确认项目读取权限后手动刷新。' : missing ? '原项目当前不可读或已归档，请重新选择活动项目；不会自动替换项目或范围。' : state.projects.length ? '只展示当前可读的活动项目。范围须单独明确填写，不自动采用项目配置。' : '暂无可读的活动项目；请在项目管理中创建项目或确认读取权限后刷新。');
        }

        function fillForm(state, config) {
            if ($('form')) $('form').reset();
            mode(state, true); projects(state); channels(state);
            if (config) {
                ['title', 'prompt'].forEach(key => { if ($(key)) $(key).value = config[key]; });
                if ($('scope')) $('scope').value = config.scope.join('\n');
                Object.entries(BUDGET_FIELDS).forEach(([key, id]) => { if ($(id) && own(LIMITS[state.mode], key) && Number.isFinite(config.limits[key])) $(id).value = String(config.limits[key]); });
                if ($('channel') && config.ai_channel) {
                    if (!state.channels.some(channel => channel.id === config.ai_channel)) {
                        const option = element('option', '', '原渠道（当前列表不可用）：' + config.ai_channel); option.value = config.ai_channel; $('channel').appendChild(option);
                    }
                    $('channel').value = config.ai_channel;
                }
            }
            if ($('authorized')) $('authorized').checked = false;
            if ($('title')) $('title').focus();
            if ($('form')) $('form').scrollIntoView({ block: 'nearest' });
        }

        function channels(state) {
            const select = $('channel'); if (!select) return;
            const selected = select.value; clear(select);
            const defaultChannel = state.channels.find(channel => channel.id === state.defaultChannel);
            const fallback = element('option', '', '默认模型' + (defaultChannel ? ` · ${defaultChannel.name || defaultChannel.id} / ${defaultChannel.model || '未声明模型'}` : '（由后端选择）'));
            fallback.value = ''; select.appendChild(fallback);
            state.channels.forEach(channel => {
                const option = element('option', '', `${channel.name || channel.id} · ${channel.model || '未声明模型'}`);
                option.value = channel.id; select.appendChild(option);
            });
            if (selected && !state.channels.some(channel => channel.id === selected)) {
                const option = element('option', '', '原渠道（当前列表不可用）：' + selected); option.value = selected; select.appendChild(option);
            }
            select.value = selected || '';
            set('channel-hint', state.errors.channels ? '模型列表读取失败：' + state.errors.channels + '。可使用默认模型，或保留原渠道交由后端校验。仅提交渠道 ID，不读取或编辑凭据。' : '仅引用已有模型渠道 ID；留在默认项时由后端选择。');
        }

        function runs(state) {
            const list = clear($('runs')); if (!list) return;
            set('runs-count', state.runs.length);
            set('list-error', state.errors.list ? '任务列表读取失败：' + state.errors.list + '。可使用顶部刷新重试。' : '');
            if ($('list-error')) $('list-error').hidden = !state.errors.list;
            if (!state.runs.length) { empty(list, state.errors.list ? '当前无可用历史列表。' : state.refreshing ? '正在读取本人任务…' : '暂无 PI 任务。确认运行模式、项目与授权范围后可创建。'); return; }
            state.runs.forEach(run => {
                const button = element('button', 'pi-lab-run-row' + (run.id === state.selectedId ? ' is-selected' : ''));
                button.type = 'button'; button.setAttribute('aria-pressed', String(run.id === state.selectedId));
                button.appendChild(element('strong', '', run.title || '未命名任务'));
                button.appendChild(badge(run.status));
                button.appendChild(element('small', '', label(MODES, run.mode) + ' · ' + time(run.created_at)));
                button.addEventListener('click', () => { void actions.selectRun(run.id); });
                list.appendChild(button);
            });
        }

        function nodeDetail() {
            const box = clear($('node-detail')); if (!box) return;
            const node = currentNodes.find(item => item.id === selectedNodeId);
            graphGroups.forEach((group, id) => { group.classList.toggle('is-selected', id === selectedNodeId); group.setAttribute('aria-pressed', String(id === selectedNodeId)); });
            if (!node) { empty(box, '选择路线节点查看完整描述与地址；节点不会自动访问目标。'); return; }
            box.appendChild(element('h4', '', node.label || node.id));
            box.appendChild(element('p', 'pi-lab-muted', `${label(KIND, node.kind)} · ${label(STATUS, node.status)} · ID：${node.id}`));
            paragraph(box, '描述', node.detail); link(box, node.url);
        }

        function graph(run) {
            const nodes = run ? run.nodes : []; const edges = run ? run.edges : [];
            const signature = JSON.stringify([run && run.id, nodes, edges]);
            if (signature === graphSignature) return;
            graphSignature = signature; currentNodes = nodes;
            if (!nodes.some(node => node.id === selectedNodeId)) selectedNodeId = '';
            graphGroups = new Map(); const box = clear($('graph')); if (!box) return;
            if (!nodes.length) { empty(box, run ? '尚未产生路线节点。排队、失败或取消的任务可能没有路线图。' : '选择一个任务后显示探索路线与脆弱面。'); nodeDetail(); return; }
            const layout = graphLayout(nodes, edges);
            const svg = (tag, attributes = {}, content) => {
                const node = document.createElementNS(SVG_NS, tag);
                Object.entries(attributes).forEach(([key, value]) => node.setAttribute(key, String(value)));
                if (content != null) node.textContent = text(content);
                return node;
            };
            const canvas = svg('svg', { viewBox: `0 0 ${layout.width} ${layout.height}`, width: layout.width, height: layout.height, role: 'group', 'aria-label': '任务路线图，可使用 Tab 选择节点' });
            const defs = svg('defs'); const marker = svg('marker', { id: 'pi-lab-route-arrow', viewBox: '0 0 10 10', refX: 9, refY: 5, markerWidth: 6, markerHeight: 6, orient: 'auto-start-reverse' });
            marker.appendChild(svg('path', { d: 'M 0 0 L 10 5 L 0 10 z', class: 'pi-lab-graph-arrow' })); defs.appendChild(marker); canvas.appendChild(defs);
            edges.forEach(edge => {
                const source = layout.points.get(edge.source); const target = layout.points.get(edge.target);
                if (!source || !target) return;
                const x1 = source.x + 220; const y1 = source.y + 34; const x2 = target.x; const y2 = target.y + 34;
                const curve = svg('path', { d: `M ${x1} ${y1} C ${x1 + 32} ${y1}, ${x2 - 32} ${y2}, ${x2} ${y2}`, class: 'pi-lab-graph-edge', 'marker-end': 'url(#pi-lab-route-arrow)' });
                curve.appendChild(svg('title', {}, edge.label || '路线关系')); canvas.appendChild(curve);
                if (edge.label) canvas.appendChild(svg('text', { x: (x1 + x2) / 2, y: (y1 + y2) / 2 - 8, class: 'pi-lab-edge-label', 'text-anchor': 'middle' }, short(edge.label, 16)));
            });
            layout.points.forEach(({ node, x, y }, id) => {
                const group = svg('g', { class: 'pi-lab-graph-node', transform: `translate(${x},${y})`, role: 'button', tabindex: 0, 'aria-label': `${node.label || node.id}，${label(KIND, node.kind)}` });
                group.appendChild(svg('title', {}, `${node.label || node.id}\n${node.detail || ''}`));
                group.appendChild(svg('rect', { width: 220, height: 70, rx: 10 }));
                group.appendChild(svg('text', { x: 12, y: 27, class: 'pi-lab-node-label' }, short(node.label || node.id, 20)));
                group.appendChild(svg('text', { x: 12, y: 51, class: 'pi-lab-node-meta' }, short(`${label(KIND, node.kind)} · ${label(STATUS, node.status)}`, 27)));
                const choose = () => { selectedNodeId = id; nodeDetail(); };
                group.addEventListener('click', choose);
                group.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); choose(); } });
                graphGroups.set(id, group); canvas.appendChild(group);
            });
            box.appendChild(canvas); nodeDetail();
        }

        function agents(run) {
            const box = clear($('agents')); if (!box) return;
            if (!run || !run.agents.length) { empty(box, '尚无 Agent 派发记录。运行后将在此显示角色、任务、父子关系与最终摘要。'); return; }
            const byId = new Map(run.agents.map(agent => [agent.id, agent])); const visited = new Set();
            const visit = (agent, depth) => {
                if (visited.has(agent.id)) return; visited.add(agent.id);
                const card = element('article', 'pi-lab-agent-card'); card.style.marginLeft = Math.min(depth, 4) * 14 + 'px';
                const head = element('div', 'pi-lab-card-head');
                head.appendChild(element('h4', '', agent.role || 'Agent')); head.appendChild(badge(agent.status)); card.appendChild(head);
                card.appendChild(element('p', 'pi-lab-muted', `ID：${agent.id} · ${agent.parent_id ? '父 Agent：' + agent.parent_id + (byId.has(agent.parent_id) ? '' : '（未返回父记录）') : '根 Agent'}`));
                paragraph(card, '派发任务', agent.task); paragraph(card, '最终摘要', agent.summary || '尚未返回摘要。');
                box.appendChild(card);
                run.agents.filter(child => child.parent_id === agent.id).forEach(child => visit(child, depth + 1));
            };
            run.agents.filter(agent => !byId.has(agent.parent_id)).forEach(agent => visit(agent, 0));
            run.agents.forEach(agent => visit(agent, 0));
        }

        function findings(run) {
            const box = clear($('findings')); if (!box) return;
            const all = run ? run.findings : [];
            const groups = [
                ['hypothesis', '候选（hypothesis）', '仅为待验证假设，不代表存在漏洞。'],
                ['observed', '观察（observed）', '已记录现象或证据，仍不是已确认漏洞。'],
                ['other', '未分类结果', '状态未识别，不能作为已确认漏洞。'],
            ];
            groups.forEach(([type, heading, hint]) => {
                const rows = all.filter(finding => type === 'other' ? !['hypothesis', 'observed'].includes(finding.status) : finding.status === type);
                if (type === 'other' && !rows.length) return;
                const section = element('section', 'pi-lab-finding-group'); section.appendChild(element('h4', '', `${heading} · ${rows.length}`));
                section.appendChild(element('p', 'pi-lab-muted', hint));
                if (!rows.length) empty(section, '暂无' + (type === 'hypothesis' ? '候选假设。' : '观察结果。'));
                rows.forEach(finding => {
                    const card = element('article', 'pi-lab-finding-card');
                    card.appendChild(element('h5', '', finding.title || finding.id || '未命名发现'));
                    card.appendChild(element('p', 'pi-lab-muted', `模型建议等级：${label(SEVERITY, finding.severity)} · 状态：${type === 'other' ? finding.status || '未知' : heading}`));
                    link(card, finding.url); paragraph(card, '证据 / 依据', finding.evidence || '尚未提供证据。'); paragraph(card, '建议', finding.remediation);
                    section.appendChild(card);
                });
                box.appendChild(section);
            });
        }

        function metadata(state) {
            const box = clear($('run-links')); const value = state.run;
            set('run-role', value ? '模式：' + label(MODES, value.mode) + ' · 角色：' + (value.role || (value.mode === 'probe' ? '旧版诊断（未使用平台角色）' : '未返回')) : '选择任务后显示模式与角色。');
            set('run-skills', value && value.skills.length ? '本次技能：' + value.skills.join('、') : '本次技能：未返回');
            set('run-executions', value && value.execution_ids.length ? value.execution_ids.join('\n') : '尚未返回关联执行记录。');
            set('run-integration', value && value.mode === 'platform' ? '平台工具执行结果与发现使用已有项目、漏洞和工具监控模块记录；是否确认为漏洞，以对应模块的证据与审核状态为准。' : '兼容诊断记录独立保存；历史记录缺少 mode 时按 probe 展示。');
            if (!box || !value) return;
            const internalLink = (caption, href, onClick) => {
                const anchor = element('a', 'pi-lab-link', caption); anchor.href = href;
                if (onClick) anchor.addEventListener('click', event => { if (!event.ctrlKey && !event.metaKey && !event.shiftKey && !event.altKey) { event.preventDefault(); onClick(); } });
                box.appendChild(anchor);
            };
            if (validProjectId(value.project_id)) {
                const project = state.projects.find(item => item.id === value.project_id);
                internalLink('关联项目：' + (project ? project.name + ' · ' : '') + value.project_id, '#projects?id=' + encodeURIComponent(value.project_id), () => actions.openProject(value.project_id));
            } else box.appendChild(element('span', 'pi-lab-muted', value.project_id ? '关联项目 ID 无效：' + value.project_id : '未关联项目'));
            if (value.conversation_id) internalLink('关联对话：' + value.conversation_id, '#chat?conversation=' + encodeURIComponent(value.conversation_id));
            else box.appendChild(element('span', 'pi-lab-muted', '未返回关联对话'));
            if (value.mode === 'platform') {
                internalLink('查看项目漏洞', '#vulnerabilities' + (value.project_id ? '?project_id=' + encodeURIComponent(value.project_id) : ''));
                internalLink('查看工具监控', '#mcp-monitor');
            }
        }

        function run(state) {
            const value = state.run;
            metadata(state);
            set('run-title', value ? value.title || '未命名任务' : state.selectedId ? '正在读取任务…' : '选择或创建一个 PI 任务');
            const statusBox = clear($('run-status')); if (statusBox && value) statusBox.appendChild(badge(value.status));
            set('run-meta', value ? `创建于 ${time(value.created_at)} · 更新于 ${time(value.updated_at)} · 模型：${value.model || '未声明'} · 渠道：${value.ai_channel || '默认'}` : '历史数据由后端按属主隔离，仅可读取本人任务。');
            set('run-error', state.errors.run ? '完整状态读取失败：' + state.errors.run + (value ? '。以下为上次成功读取的状态。' : '。请刷新或选择其他任务。') : value && value.error ? '任务说明：' + value.error : '');
            if ($('run-error')) $('run-error').hidden = !state.errors.run && !(value && value.error);
            set('agent-count', value ? value.agents.length : 0); set('node-count', value ? value.nodes.length : 0);
            set('hypothesis-count', value ? value.findings.filter(item => item.status === 'hypothesis').length : 0);
            set('observed-count', value ? value.findings.filter(item => item.status === 'observed').length : 0);
            set('run-scope', value ? value.scope.join('\n') || '未返回范围。' : '尚未选择任务。');
            set('run-prompt', value ? value.prompt || '未返回测试需求。' : '尚未选择任务。');
            set('run-limits', value ? `并发 ${value.limits.max_parallel ?? '—'} · 子 Agent ${value.limits.max_agents ?? '—'} · 时限 ${value.limits.timeout_seconds ?? '—'} 秒` + (value.mode === 'platform' ? ` · 模型轮次 ${value.limits.max_turns ?? '—'} · 工具调用 ${value.limits.max_tool_calls ?? '—'}` : ` · HTTP 请求上限 ${value.limits.max_requests ?? '—'}`) : '运行限制将显示在这里。');
            set('report', value && value.report ? value.report : '暂无最终报告；这里仅呈现原始纯文本，不执行 HTML 或 Markdown。');
            agents(value); graph(value); findings(value);
        }

        function events(state) {
            set('event-error', state.errors.events ? '事件读取失败：' + state.errors.events + '。完整任务状态仍会独立刷新。' : '');
            if ($('event-error')) $('event-error').hidden = !state.errors.events;
            set('event-count', `已获取 ${state.events.length} 条 · 游标 ${state.cursor}` + (state.hasMore ? ' · 正在补齐后续事件' : '') + (state.events.length > 200 ? ' · 界面仅显示最近 200 条，导出包含本地已获取事件' : ''));
            const signature = JSON.stringify([state.selectedId, state.events]);
            if (signature === timelineSignature) return; timelineSignature = signature;
            const box = clear($('events')); if (!box) return;
            if (!state.events.length) { empty(box, '暂无事件。仅展示完整事件文本，不进行 token 流式拼接。'); return; }
            state.events.slice(-200).reverse().forEach(event => {
                const item = element('li', 'pi-lab-event'); const details = element('details');
                details.appendChild(element('summary', '', `#${event.seq} · ${time(event.time)} · ${text(event.type) || '事件'}${event.agent_id ? ' · Agent ' + text(event.agent_id) : ''}`));
                details.appendChild(element('pre', 'pi-lab-plain', text(event.data) || '无附加数据。'));
                item.appendChild(details); box.appendChild(item);
            });
        }
        return { bind, controls, status, mode, profile, projects, fillForm, channels, runs, run, events,
            resetAuthorization() { if ($('authorized')) $('authorized').checked = false; },
            resetForm() { if ($('form')) $('form').reset(); },
        };
    }

    function createController(env) {
        let state;
        const resetState = () => { state = { mode: 'platform', projectId: '', profile: null, projects: [], checkingSetup: false, formNotice: '', status: null, runs: [], selectedId: '', run: null, events: [], cursor: 0, hasMore: false, channels: [], defaultChannel: '', updatedAt: '', errors: {}, refreshing: false, creating: false, cancelling: false }; };
        resetState();
        let active = false; let generation = 0; let owner = null; let timer = null; let cycle = null; let boot = null;
        let createOperation = null; let cancelOperation = null;
        const reads = new Set(); const mutations = new Set();
        const allowed = () => env.hasPermission();
        const ownerNow = () => text(env.getOwner());
        const current = epoch => {
            if (!active || generation !== epoch) return false;
            // An expired session or an account switch must also clear the previous owner's cached UI.
            if (owner !== ownerNow() || !allowed()) { checkAccess(); return false; }
            return true;
        };
        const view = createView(env.document, { createRun, cancelRun, selectRun, refresh, exportRun, renderControls, setMode, setProject, copyRun, newRun,
            openProject(id) { if (active && checkAccess() && validProjectId(id) && env.openProject) env.openProject(id); },
        });
        function renderControls() { view.controls(state, allowed()); }
        function renderAll() { view.status(state); view.profile(state); view.projects(state); view.channels(state); view.runs(state); view.run(state); view.events(state); renderControls(); }
        function setMode(mode) {
            if (!active || !checkAccess() || !own(MODES, mode) || createOperation || cancelOperation) return;
            state.mode = mode; state.errors.form = ''; state.formNotice = '运行模式已切换，请核对范围与预算并重新确认授权。';
            view.resetAuthorization(); view.mode(state, true); view.profile(state); renderControls();
        }
        function setProject(id) {
            if (!active || !checkAccess() || createOperation || cancelOperation) return;
            state.projectId = text(id); state.errors.form = '';
            view.resetAuthorization(); view.projects(state); renderControls();
        }
        function newRun() {
            if (!active || !checkAccess() || createOperation || cancelOperation) return;
            state.mode = 'platform'; state.projectId = ''; state.errors.form = ''; state.formNotice = '';
            view.fillForm(state); renderControls();
        }
        function copyRun() {
            if (!active || !checkAccess() || !state.run || !own(MODES, state.run.mode) || createOperation || cancelOperation) return;
            state.mode = state.run.mode; state.projectId = state.mode === 'platform' ? state.run.project_id : '';
            state.errors.form = ''; state.formNotice = '已复制配置到新建表单，尚未提交。请检查当前可用项目、渠道与预算，并重新勾选授权；原任务保持不变。';
            view.fillForm(state, state.run); renderControls();
        }
        function invalidateReads() {
            if (state.checkingSetup) {
                // A history selection may abort setup reads. Do not re-enable creation from old readiness.
                state.status = null; state.profile = null;
                state.errors.status = '运行依赖检查未完成，请手动刷新后再创建';
                state.errors.profile = '平台能力检查未完成，请手动刷新';
            }
            generation++;
            if (timer !== null) env.clearTimeout(timer); timer = null;
            reads.forEach(controller => controller.abort()); reads.clear(); cycle = null;
            state.refreshing = false; state.checkingSetup = false;
            return generation;
        }
        function stop() {
            active = false; invalidateReads();
            mutations.forEach(controller => controller.abort()); mutations.clear(); boot = null;
        }
        function checkAccess() {
            if (owner === ownerNow() && allowed()) return true;
            stop(); resetState(); view.resetForm();
            state.errors.status = '登录身份或权限已变化，请重新进入 PI 任务页'; renderAll();
            return false;
        }
        async function request(path, options, epoch, mutation = false) {
            if (!current(epoch)) throw new Error('页面已切换，请求已失效。');
            const controller = new env.AbortController(); const pool = mutation ? mutations : reads;
            pool.add(controller);
            try {
                const response = await env.apiFetch(path, { ...options, signal: controller.signal });
                const data = await response.json().catch(() => null);
                if (!response.ok) {
                    const error = new Error(`HTTP ${response.status}：` + (text(data && (data.error || data.message || data.reason)) || '请求失败'));
                    error.status = response.status; throw error;
                }
                if (!data || typeof data !== 'object') throw new Error('服务器未返回有效 JSON。');
                return data;
            } finally { pool.delete(controller); }
        }
        async function load(key, path, epoch, assign) {
            try {
                const data = await request(path, {}, epoch);
                if (!current(epoch)) return false;
                assign(data); state.errors[key] = ''; return true;
            } catch (error) {
                if (!current(epoch)) return false;
                state.errors[key] = text(error.message);
                if (key === 'status') state.status = null;
                if (key === 'profile') state.profile = null;
                if (key === 'projects') state.projects = [];
                if (key === 'channels') { state.channels = []; state.defaultChannel = ''; }
                if (key === 'run' && [403, 404].includes(error.status)) { state.run = null; state.events = []; state.cursor = 0; state.hasMore = false; }
                return false;
            }
        }
        function applyRun(value) {
            const run = normalizeRun(value);
            if (run.id !== state.selectedId) throw new Error('后端返回了不同任务的状态，已拒绝更新。');
            state.run = run;
            const index = state.runs.findIndex(item => item.id === run.id);
            if (index < 0) state.runs.unshift(run); else state.runs[index] = run;
        }
        async function loadEvents(epoch, id) {
            try {
                // Bound each burst so a large history cannot monopolize the page.
                for (let page = 0; page < 8 && current(epoch); page++) {
                    const data = await request(`${API}/runs/${encodeURIComponent(id)}/events?after=${state.cursor}`, {}, epoch);
                    if (!current(epoch)) return;
                    const projected = { ...data, events: Array.isArray(data.events) ? data.events.map(event => event && ({ seq: event.seq, time: text(event.time), type: text(event.type), agent_id: text(event.agent_id), data: event.data })) : data.events };
                    Object.assign(state, mergeEventPage(state.events, state.cursor, projected));
                    state.errors.events = ''; view.events(state);
                    if (!state.hasMore) break;
                }
            } catch (error) { if (current(epoch)) { state.errors.events = text(error.message); view.events(state); } }
        }
        function schedule(epoch) {
            if (!current(epoch)) return;
            if (timer !== null) env.clearTimeout(timer);
            const delay = state.hasMore && !state.errors.events ? 100 : activeRun(state.run) ? 2000 : 10000;
            timer = env.setTimeout(() => { timer = null; void refresh(false); }, delay);
        }
        function refresh(includeSetup = false) {
            if (!active || !checkAccess()) return Promise.resolve();
            if (createOperation || cancelOperation) return Promise.resolve();
            if (cycle) return cycle.promise;
            if (timer !== null) env.clearTimeout(timer); timer = null;
            const epoch = generation; const ticket = {}; cycle = ticket;
            state.refreshing = true; state.checkingSetup = includeSetup; renderControls();
            ticket.promise = (async () => {
                // Runtime readiness imports the SDK in a separate process. Check it
                // on entry/manual refresh, not on every two-second event poll.
                const requests = [];
                if (includeSetup) requests.push(
                    load('status', API + '/status', epoch, data => {
                        if (typeof data.enabled !== 'boolean' || typeof data.ready !== 'boolean') throw new Error('PI 状态格式无效。');
                        state.status = { enabled: data.enabled, ready: data.ready, reason: text(data.reason), runtime: text(data.runtime), isolation: text(data.isolation), limits: data.limits || {}, tools: Array.isArray(data.tools) ? data.tools : [] };
                    }),
                    load('profile', API + '/profile', epoch, data => { state.profile = normalizeProfile(data); }),
                    load('projects', '/api/projects?status=active&limit=500', epoch, data => { state.projects = normalizeProjects(data); })
                );
                requests.push(
                    load('list', API + '/runs', epoch, data => {
                        if (!Array.isArray(data.runs)) throw new Error('任务列表格式无效。');
                        state.runs = data.runs.map(normalizeRun);
                        if (!state.selectedId && state.runs.length) { state.selectedId = state.runs[0].id; state.run = null; state.events = []; state.cursor = 0; state.hasMore = false; }
                    })
                );
                if (includeSetup) requests.push(load('channels', '/api/config/ai-channels', epoch, data => {
                    if (!data.channels || typeof data.channels !== 'object' || Array.isArray(data.channels)) throw new Error('模型列表格式无效。');
                    state.channels = Object.entries(data.channels).filter(([, value]) => value && typeof value === 'object').map(([id, value]) => ({ id, name: text(value.name), model: text(value.model) }));
                    state.defaultChannel = text(data.default_channel);
                }));
                await Promise.all(requests);
                if (!current(epoch)) return;
                state.checkingSetup = false;
                view.status(state); view.runs(state);
                if (includeSetup) { view.profile(state); view.projects(state); view.channels(state); }
                renderControls();
                const id = state.selectedId;
                if (id) {
                    const loaded = await load('run', `${API}/runs/${encodeURIComponent(id)}`, epoch, applyRun);
                    if (!current(epoch)) return;
                    view.run(state); view.runs(state); renderControls();
                    if (loaded) await loadEvents(epoch, id);
                    else view.events(state);
                }
                if (current(epoch)) state.updatedAt = new Date().toISOString();
            })().finally(() => {
                if (cycle === ticket) cycle = null;
                if (!current(epoch)) return;
                state.refreshing = false; state.checkingSetup = false; view.runs(state); renderControls(); schedule(epoch);
            });
            return ticket.promise;
        }
        function init() {
            const page = env.document.getElementById('page-pi-lab');
            if (!page || !page.classList.contains('active')) return Promise.resolve();
            if (active) return boot || (cycle && cycle.promise) || Promise.resolve();
            active = true; const epoch = invalidateReads(); view.bind();
            // Clear the previous principal before authentication can suspend; never flash their cached history.
            if (owner !== ownerNow()) { resetState(); view.resetForm(); owner = ownerNow(); }
            state.status = null; state.profile = null; state.errors.status = ''; state.errors.profile = ''; view.resetAuthorization(); renderAll();
            boot = (async () => {
                await env.ensureAuthenticated();
                if (!active || generation !== epoch) return;
                if (owner !== ownerNow()) { resetState(); view.resetForm(); owner = ownerNow(); }
                if (!allowed()) { state.errors.status = '当前账号缺少 agent:execute 权限'; renderAll(); active = false; return; }
                state.status = null; state.profile = null; state.errors.status = ''; state.errors.profile = ''; view.resetAuthorization(); renderAll();
                await refresh(true);
            })().catch(error => { if (active && generation === epoch) { state.errors.status = text(error.message); renderAll(); } });
            return boot;
        }
        function selectRun(id) {
            if (!active || !checkAccess()) return Promise.resolve();
            invalidateReads();
            state.selectedId = text(id); state.run = null; state.events = []; state.cursor = 0; state.hasMore = false;
            state.errors.run = ''; state.errors.events = ''; state.errors.form = '';
            view.run(state); view.events(state); view.runs(state); renderControls();
            return refresh(false);
        }
        async function createRun(input) {
            if (!active || !checkAccess() || createOperation || cancelOperation) return;
            let payload;
            try {
                if (state.checkingSetup) throw new Error('正在刷新运行依赖，请等待检查完成后再提交。');
                if ((input.mode || 'platform') === 'platform' && state.errors.projects) throw new Error('项目列表读取失败：' + state.errors.projects);
                if ((input.mode || 'platform') === 'platform' && state.errors.profile) throw new Error('平台能力配置读取失败：' + state.errors.profile);
                payload = buildPayload(input, state.status, state.profile, state.projects);
            }
            catch (error) { state.errors.form = text(error.message); renderControls(); return; }
            const epoch = invalidateReads(); const operation = {}; createOperation = operation;
            state.creating = true; state.errors.form = ''; state.formNotice = ''; renderControls();
            try {
                const data = normalizeRun(await request(API + '/runs', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }, epoch, true));
                if (!current(epoch)) return;
                state.selectedId = data.id; state.events = []; state.cursor = 0; state.hasMore = false;
                state.errors.run = ''; state.errors.events = ''; applyRun(data);
                view.resetAuthorization(); view.run(state); view.events(state); view.runs(state);
            } catch (error) { if (current(epoch)) state.errors.form = '创建失败：' + text(error.message) + '。若网络中断，请先刷新历史确认是否已创建，避免重复提交。'; }
            finally {
                if (createOperation === operation) createOperation = null;
                state.creating = false;
                if (active && checkAccess()) { renderControls(); void refresh(false); }
            }
        }
        async function cancelRun() {
            if (!active || !checkAccess() || !activeRun(state.run) || createOperation || cancelOperation) return;
            const id = state.selectedId; const epoch = invalidateReads(); const operation = {}; cancelOperation = operation;
            state.cancelling = true; state.errors.form = ''; renderControls();
            try {
                const data = await request(`${API}/runs/${encodeURIComponent(id)}/cancel`, { method: 'POST' }, epoch, true);
                if (!current(epoch)) return;
                applyRun(data); state.errors.run = ''; view.run(state); view.runs(state);
            } catch (error) { if (current(epoch)) state.errors.form = '取消请求失败：' + text(error.message) + '。请刷新确认最新状态。'; }
            finally {
                if (cancelOperation === operation) cancelOperation = null;
                state.cancelling = false;
                if (active && checkAccess()) { renderControls(); void refresh(false); }
            }
        }
        function exportRun() {
            if (!active || !checkAccess() || !state.run) return;
            const payload = { schema_version: 1, exported_at: new Date().toISOString(), run: state.run, events: state.events, cursor: state.cursor, has_more: state.hasMore, event_error: state.errors.events || '', note: '仅导出本页已获取的状态与事件，不保证含有后端全部事件。本页候选与观察不是已确认漏洞；平台任务结果在关联项目、漏洞和工具监控模块中查看。' };
            const blob = new env.Blob([JSON.stringify(payload, null, 2)], { type: 'application/json;charset=utf-8' });
            const url = env.URL.createObjectURL(blob); const anchor = env.document.createElement('a');
            anchor.href = url; anchor.download = 'pi-lab-run-' + new Date().toISOString().replace(/[^0-9T]/g, '-') + '.json';
            env.document.body.appendChild(anchor); anchor.click(); anchor.remove();
            // Object-URL cleanup is not a polling timer and must complete even after leaving the page.
            env.setTimeout(() => env.URL.revokeObjectURL(url), 1000);
        }
        return { init, stop, refresh, selectRun, createRun, cancelRun, exportRun, setMode, setProject, copyRun, newRun, getSnapshot: () => JSON.parse(JSON.stringify(state)) };
    }
    return { createController, parseScope, parsePlatformScope, safeURL, buildPayload, mergeEventPage, normalizeRun, normalizeProfile, normalizeProjects, graphLayout };
});
