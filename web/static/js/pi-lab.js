/* Independent PI experiments. No task, Eino, shell, or existing-tool integration. */
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
        });
        root.addEventListener('pagehide', () => root.PiLab.stop());
    }
})(typeof window === 'undefined' ? null : window, function () {
    'use strict';
    const API = '/api/pi-lab';
    const SVG_NS = 'http://www.w3.org/2000/svg';
    const LIMITS = { max_parallel: [1, 4], max_agents: [1, 12], timeout_seconds: [60, 1800] };
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

    function limitMax(status, key) {
        const candidate = status && status.limits && status.limits[key];
        return Number.isInteger(candidate) && candidate >= LIMITS[key][0] ? Math.min(candidate, LIMITS[key][1]) : LIMITS[key][1];
    }

    function buildPayload(input, status) {
        if (!status || status.enabled !== true || status.ready !== true) throw new Error('实验未启用或原生 PI 运行时尚未就绪，当前仅可查看历史。');
        if (input.authorized !== true) throw new Error('请明确勾选已获得目标授权。');
        const title = text(input.title).trim();
        const prompt = text(input.prompt).trim();
        if (!title || !prompt) throw new Error('请填写试验标题和测试需求。');
        if (Array.from(title).length > 120) throw new Error('试验标题不能超过 120 个字符。');
        if (new TextEncoder().encode(prompt).byteLength > 16384) throw new Error('测试需求不能超过 16 KiB（中文按 UTF-8 字节计数）。');
        const payload = { title, prompt, scope: parseScope(input.scope), ai_channel: text(input.ai_channel), authorized: true };
        if (payload.scope.length > 20) throw new Error('授权范围不能超过 20 个精确 origin。');
        for (const key of Object.keys(LIMITS)) {
            const value = Number(input[key]);
            const max = limitMax(status, key);
            if (!Number.isInteger(value) || value < LIMITS[key][0] || value > max) {
                throw new Error(`${{ max_parallel: '并发数', max_agents: '子 Agent 数', timeout_seconds: '时限（秒）' }[key]}必须为 ${LIMITS[key][0]}–${max} 的整数。`);
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
        if (!run || typeof run.id !== 'string' || !run.id) throw new Error('试验响应缺少有效 ID。');
        // Allowlisted projection keeps configuration and unrelated response fields out of local state/export.
        const result = {};
        ['id', 'title', 'prompt', 'ai_channel', 'model', 'status', 'created_at', 'updated_at', 'error', 'report'].forEach(key => { result[key] = text(run[key]); });
        result.scope = Array.isArray(run.scope) ? run.scope.map(text) : [];
        result.limits = {};
        ['max_parallel', 'max_agents', 'timeout_seconds', 'max_requests'].forEach(key => { if (Number.isFinite(run.limits && run.limits[key])) result.limits[key] = run.limits[key]; });
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
                    title: $('title').value, scope: $('scope').value, prompt: $('prompt').value,
                    ai_channel: $('channel').value, max_parallel: $('parallel').value,
                    max_agents: $('max-agents').value, timeout_seconds: $('timeout').value, authorized: $('authorized').checked,
                });
            });
            $('authorized').addEventListener('change', actions.renderControls);
            $('refresh').addEventListener('click', () => { void actions.refresh(true); });
            $('cancel').addEventListener('click', () => { void actions.cancelRun(); });
            $('export').addEventListener('click', actions.exportRun);
            $('new').addEventListener('click', () => { $('title').focus(); $('form').scrollIntoView({ block: 'nearest' }); });
        }

        function controls(state, allowed) {
            const ready = allowed && state.status && state.status.enabled === true && state.status.ready === true;
            if ($('submit')) $('submit').disabled = !ready || state.creating || state.cancelling || !$('authorized').checked;
            if ($('submit')) $('submit').textContent = state.creating ? '正在创建…' : '启动独立试验';
            if ($('cancel')) $('cancel').disabled = !allowed || !activeRun(state.run) || state.cancelling || state.creating;
            if ($('cancel')) $('cancel').textContent = state.cancelling ? '正在取消…' : '取消试验';
            if ($('export')) $('export').disabled = !allowed || !state.run;
            if ($('refresh')) $('refresh').disabled = !allowed || state.refreshing || state.creating || state.cancelling;
            set('sync', state.refreshing ? '正在刷新完整状态与增量事件…' : state.updatedAt ? '本页同步于 ' + time(state.updatedAt) : '等待同步');
            set('form-error', state.errors.form);
            if ($('form-error')) $('form-error').hidden = !state.errors.form;
        }

        function status(state) {
            const result = state.status;
            let message = '正在检查 PI 实验运行时…';
            if (state.errors.status) message = '无法读取实验状态：' + state.errors.status + '。创建已禁用，仍可尝试读取本人历史。';
            else if (result) {
                const reason = text(result.reason);
                if (!result.enabled) message = '实验开关未启用（默认关闭）。' + (reason || '请由管理员配置并启用后端 PI 实验运行时。') + ' 当前只读浏览历史。';
                else if (!result.ready) message = '原生 PI 运行时未就绪。' + (reason || '请由管理员检查 PI 运行时与模型配置。') + ' 创建已禁用，历史仍可查看。';
                else message = '原生 PI 运行时已就绪。' + (reason ? ' ' + reason : ' 仅在明确授权范围内启动低影响试验。');
            }
            set('runtime-status', message);
            if ($('runtime-status')) $('runtime-status').classList.toggle('is-ready', !!(result && result.enabled && result.ready));
            set('runtime-detail', result ? '运行时：' + (text(result.runtime) || '未声明') + ' · 隔离说明：' + (text(result.isolation) || '应用层隔离，不是操作系统安全沙箱') : '运行时信息尚不可用。');
            const tools = result && Array.isArray(result.tools) ? result.tools.map(tool => typeof tool === 'string' ? tool : text(tool.name || tool.id)).filter(Boolean) : [];
            set('tools', '内置工具：' + (tools.join('、') || '暂无可用工具') + '。仅授权范围 GET/HEAD 低影响 HTTP 检查；无 Shell，无现有工具或任务联动。');
            set('limit-hint', `后端上限：并发 ${limitMax(result, 'max_parallel')}，子 Agent ${limitMax(result, 'max_agents')}（不含协调 Agent），时限 ${limitMax(result, 'timeout_seconds')} 秒` + (result && result.limits && Number.isFinite(result.limits.max_requests) ? `，HTTP 请求 ${result.limits.max_requests} 次。` : '。'));
            [['parallel', 'max_parallel'], ['max-agents', 'max_agents'], ['timeout', 'timeout_seconds']].forEach(([id, key]) => { if ($(id)) $(id).max = String(limitMax(result, key)); });
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
            select.value = state.channels.some(channel => channel.id === selected) ? selected : '';
            set('channel-hint', state.errors.channels ? '模型列表暂不可用，仍可使用默认模型。仅提交渠道 ID，不读取或编辑凭据。' : '仅引用已有模型渠道 ID；留在默认项时由后端选择。');
        }

        function runs(state) {
            const list = clear($('runs')); if (!list) return;
            set('runs-count', state.runs.length);
            set('list-error', state.errors.list ? '试验列表读取失败：' + state.errors.list + '。可使用顶部刷新重试。' : '');
            if ($('list-error')) $('list-error').hidden = !state.errors.list;
            if (!state.runs.length) { empty(list, state.errors.list ? '当前无可用历史列表。' : state.refreshing ? '正在读取本人试验…' : '暂无独立试验。启用运行时后可创建；不会导入现有任务。'); return; }
            state.runs.forEach(run => {
                const button = element('button', 'pi-lab-run-row' + (run.id === state.selectedId ? ' is-selected' : ''));
                button.type = 'button'; button.setAttribute('aria-pressed', String(run.id === state.selectedId));
                button.appendChild(element('strong', '', run.title || '未命名试验'));
                button.appendChild(badge(run.status));
                button.appendChild(element('small', '', time(run.created_at)));
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
            if (!nodes.length) { empty(box, run ? '尚未产生路线节点。排队、失败或取消的试验可能没有路线图。' : '选择一个试验后显示探索路线与脆弱面。'); nodeDetail(); return; }
            const layout = graphLayout(nodes, edges);
            const svg = (tag, attributes = {}, content) => {
                const node = document.createElementNS(SVG_NS, tag);
                Object.entries(attributes).forEach(([key, value]) => node.setAttribute(key, String(value)));
                if (content != null) node.textContent = text(content);
                return node;
            };
            const canvas = svg('svg', { viewBox: `0 0 ${layout.width} ${layout.height}`, width: layout.width, height: layout.height, role: 'group', 'aria-label': '试验路线图，可使用 Tab 选择节点' });
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

        function run(state) {
            const value = state.run;
            set('run-title', value ? value.title || '未命名试验' : state.selectedId ? '正在读取试验…' : '选择或创建一个独立试验');
            const statusBox = clear($('run-status')); if (statusBox && value) statusBox.appendChild(badge(value.status));
            set('run-meta', value ? `创建于 ${time(value.created_at)} · 更新于 ${time(value.updated_at)} · 模型：${value.model || '未声明'} · 渠道：${value.ai_channel || '默认'}` : '历史数据由后端按属主隔离，仅可读取本人试验。');
            set('run-error', state.errors.run ? '完整状态读取失败：' + state.errors.run + (value ? '。以下为上次成功读取的状态。' : '。请刷新或选择其他试验。') : value && value.error ? '试验说明：' + value.error : '');
            if ($('run-error')) $('run-error').hidden = !state.errors.run && !(value && value.error);
            set('agent-count', value ? value.agents.length : 0); set('node-count', value ? value.nodes.length : 0);
            set('hypothesis-count', value ? value.findings.filter(item => item.status === 'hypothesis').length : 0);
            set('observed-count', value ? value.findings.filter(item => item.status === 'observed').length : 0);
            set('run-scope', value ? value.scope.join('\n') || '未返回范围。' : '尚未选择试验。');
            set('run-prompt', value ? value.prompt || '未返回测试需求。' : '尚未选择试验。');
            set('run-limits', value ? `并发 ${value.limits.max_parallel ?? '—'} · 子 Agent ${value.limits.max_agents ?? '—'} · 时限 ${value.limits.timeout_seconds ?? '—'} 秒 · 请求上限 ${value.limits.max_requests ?? '—'}` : '运行限制将显示在这里。');
            set('report', value && value.report ? value.report : '暂无最终报告；这里仅呈现原始纯文本，不执行 HTML 或 Markdown。');
            agents(value); graph(value); findings(value);
        }

        function events(state) {
            set('event-error', state.errors.events ? '事件读取失败：' + state.errors.events + '。完整试验状态仍会独立刷新。' : '');
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
        return { bind, controls, status, channels, runs, run, events,
            resetAuthorization() { if ($('authorized')) $('authorized').checked = false; },
            resetForm() { if ($('form')) $('form').reset(); },
        };
    }

    function createController(env) {
        let state;
        const resetState = () => { state = { status: null, runs: [], selectedId: '', run: null, events: [], cursor: 0, hasMore: false, channels: [], defaultChannel: '', updatedAt: '', errors: {}, refreshing: false, creating: false, cancelling: false }; };
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
        const view = createView(env.document, { createRun, cancelRun, selectRun, refresh, exportRun, renderControls });
        function renderControls() { view.controls(state, allowed()); }
        function renderAll() { view.status(state); view.channels(state); view.runs(state); view.run(state); view.events(state); renderControls(); }
        function invalidateReads() {
            generation++;
            if (timer !== null) env.clearTimeout(timer); timer = null;
            reads.forEach(controller => controller.abort()); reads.clear(); cycle = null;
            state.refreshing = false;
            return generation;
        }
        function stop() {
            active = false; invalidateReads();
            mutations.forEach(controller => controller.abort()); mutations.clear(); boot = null;
        }
        function checkAccess() {
            if (owner === ownerNow() && allowed()) return true;
            stop(); resetState(); view.resetForm();
            state.errors.status = '登录身份或权限已变化，请重新进入实验室'; renderAll();
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
                    const error = new Error(text(data && (data.error || data.message)) || `请求失败（HTTP ${response.status}）`);
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
                if (key === 'channels') { state.channels = []; state.defaultChannel = ''; }
                if (key === 'run' && [403, 404].includes(error.status)) { state.run = null; state.events = []; state.cursor = 0; state.hasMore = false; }
                return false;
            }
        }
        function applyRun(value) {
            const run = normalizeRun(value);
            if (run.id !== state.selectedId) throw new Error('后端返回了不同试验的状态，已拒绝更新。');
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
        function refresh(includeChannels = false) {
            if (!active || !checkAccess()) return Promise.resolve();
            if (createOperation || cancelOperation) return Promise.resolve();
            if (cycle) return cycle.promise;
            if (timer !== null) env.clearTimeout(timer); timer = null;
            const epoch = generation; const ticket = {}; cycle = ticket;
            state.refreshing = true; renderControls();
            ticket.promise = (async () => {
                // Runtime readiness imports the SDK in a separate process. Check it
                // on entry/manual refresh, not on every two-second event poll.
                const requests = [];
                if (includeChannels || !state.status) requests.push(
                    load('status', API + '/status', epoch, data => {
                        if (typeof data.enabled !== 'boolean' || typeof data.ready !== 'boolean') throw new Error('实验状态格式无效。');
                        state.status = { enabled: data.enabled, ready: data.ready, reason: text(data.reason), runtime: text(data.runtime), isolation: text(data.isolation), limits: data.limits || {}, tools: Array.isArray(data.tools) ? data.tools : [] };
                    })
                );
                requests.push(
                    load('list', API + '/runs', epoch, data => {
                        if (!Array.isArray(data.runs)) throw new Error('试验列表格式无效。');
                        state.runs = data.runs.map(normalizeRun);
                        if (!state.selectedId && state.runs.length) { state.selectedId = state.runs[0].id; state.run = null; state.events = []; state.cursor = 0; state.hasMore = false; }
                    })
                );
                if (includeChannels) requests.push(load('channels', '/api/config/ai-channels', epoch, data => {
                    if (!data.channels || typeof data.channels !== 'object' || Array.isArray(data.channels)) throw new Error('模型列表格式无效。');
                    state.channels = Object.entries(data.channels).filter(([, value]) => value && typeof value === 'object').map(([id, value]) => ({ id, name: text(value.name), model: text(value.model) }));
                    state.defaultChannel = text(data.default_channel);
                }));
                await Promise.all(requests);
                if (!current(epoch)) return;
                view.status(state); view.runs(state); if (includeChannels) view.channels(state); renderControls();
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
                state.refreshing = false; view.runs(state); renderControls(); schedule(epoch);
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
            state.status = null; state.errors.status = ''; renderAll();
            boot = (async () => {
                await env.ensureAuthenticated();
                if (!active || generation !== epoch) return;
                if (owner !== ownerNow()) { resetState(); view.resetForm(); owner = ownerNow(); }
                if (!allowed()) { state.errors.status = '当前账号缺少 agent:execute 权限'; renderAll(); active = false; return; }
                state.status = null; state.errors.status = ''; renderAll();
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
            try { payload = buildPayload(input, state.status); }
            catch (error) { state.errors.form = text(error.message); renderControls(); return; }
            const epoch = invalidateReads(); const operation = {}; createOperation = operation;
            state.creating = true; state.errors.form = ''; renderControls();
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
            const payload = { schema_version: 1, exported_at: new Date().toISOString(), run: state.run, events: state.events, cursor: state.cursor, has_more: state.hasMore, event_error: state.errors.events || '', note: '仅导出本页已获取的状态与事件，不保证含有后端全部事件。发现是候选或观察，不是已确认漏洞。' };
            const blob = new env.Blob([JSON.stringify(payload, null, 2)], { type: 'application/json;charset=utf-8' });
            const url = env.URL.createObjectURL(blob); const anchor = env.document.createElement('a');
            anchor.href = url; anchor.download = 'pi-lab-run-' + new Date().toISOString().replace(/[^0-9T]/g, '-') + '.json';
            env.document.body.appendChild(anchor); anchor.click(); anchor.remove();
            // Object-URL cleanup is not a polling timer and must complete even after leaving the page.
            env.setTimeout(() => env.URL.revokeObjectURL(url), 1000);
        }
        return { init, stop, refresh, selectRun, createRun, cancelRun, exportRun, getSnapshot: () => JSON.parse(JSON.stringify(state)) };
    }
    return { createController, parseScope, safeURL, buildPayload, mergeEventPage, normalizeRun, graphLayout };
});
