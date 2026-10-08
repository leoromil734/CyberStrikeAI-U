export const SDK_VERSION = '1.0.4';
export const MAX_INPUT_BYTES = 1024 * 1024;
export const MAX_TEXT = 24000;
export const EVENT_TYPES = new Set([
  'agent_start', 'agent_end', 'message', 'tool_start', 'tool_end',
  'node', 'edge', 'finding', 'report', 'complete', 'error',
]);

// Only deliberately public, constant messages may cross the process boundary.
export class PublicError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'PublicError';
    this.code = code;
  }
}

export function publicMessage(error, fallback = '运行失败；底层错误详情已隐藏以保护凭据。') {
  return error instanceof PublicError ? error.message : fallback;
}

export function text(value, field, max = 4000) {
  if (typeof value !== 'string' || !value.trim() || value.length > max) {
    throw new PublicError('invalid_input', `${field} 必须是非空字符串，且不超过 ${max} 字符。`);
  }
  return value.trim();
}

function integer(value, fallback, name, min, max) {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result < min || result > max) {
    throw new PublicError('invalid_input', `${name} 必须是 ${min} 至 ${max} 的整数。`);
  }
  return result;
}

export function parseHttpUrl(value) {
  if (typeof value !== 'string' || value.length > 4096 || /[\s\\\x00-\x1f\x7f]/u.test(value)) {
    throw new PublicError('invalid_url', 'URL 必须是无空白的绝对 HTTP(S) URL。');
  }
  let url;
  try { url = new URL(value); } catch { throw new PublicError('invalid_url', 'URL 格式无效。'); }
  const authority = value.match(/^https?:\/\/([^/?#]*)/i)?.[1];
  if (!authority || authority.includes('@') || !['http:', 'https:'].includes(url.protocol) || url.username || url.password || !url.hostname) {
    throw new PublicError('invalid_url', '仅允许无 userinfo 的绝对 HTTP(S) URL。');
  }
  url.hash = '';
  return url;
}

// Keep protocol validation free of SDK imports so --check and malformed stdin
// still return controlled output when dependencies are not installed.
export function validateBridgeUrl(value) {
  const match = typeof value === 'string' && /^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})\/tools\/call$/.exec(value);
  if (!match || Number(match[1]) > 65535) {
    throw new PublicError('invalid_bridge', 'platform.bridge.url 必须是 http://127.0.0.1:<port>/tools/call；不允许其他主机、userinfo、查询、片段或路径。');
  }
  return value;
}

const reservedToolNames = new Set(['delegate_agents', 'record_surface', 'record_finding', 'inspect_http', 'codemode', 'tool_search']);
function object(value, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new PublicError('invalid_platform', `${field} 必须是 JSON 对象。`);
  return value;
}
function string(value, field, max) {
  if (typeof value !== 'string' || value.length > max) throw new PublicError('invalid_platform', `${field} 必须是字符串，且不超过 ${max} 字符。`);
  return value;
}
function validatePlatform(value) {
  const platform = object(value, 'platform');
  const bridge = object(platform.bridge, 'platform.bridge');
  const token = string(bridge.token, 'platform.bridge.token', 16384);
  if (!/^[\x21-\x7e]+$/.test(token)) throw new PublicError('invalid_bridge', 'platform.bridge.token 必须是非空、无空白的 ASCII 凭据。');
  if (!Array.isArray(platform.skills) || platform.skills.length > 256) throw new PublicError('invalid_platform', 'platform.skills 必须是至多 256 项的数组。');
  if (!Array.isArray(platform.tools) || platform.tools.length < 1 || platform.tools.length > 256) throw new PublicError('invalid_platform', 'platform.tools 必须是 1 至 256 项的数组。');
  const names = new Set();
  const tools = platform.tools.map((value) => {
    const tool = object(value, 'platform.tools[]');
    const name = string(tool.name, 'platform.tools[].name', 64);
    if (!/^[a-zA-Z0-9_-]{1,64}$/.test(name) || reservedToolNames.has(name) || name.startsWith('mcp__') || names.has(name)) {
      throw new PublicError('invalid_platform', '平台工具名称无效、重复或与运行时保留工具冲突。');
    }
    names.add(name);
    const schema = object(tool.input_schema, 'platform.tools[].input_schema');
    if (schema.type !== 'object' || JSON.stringify(schema).length > 65536) throw new PublicError('invalid_platform', '工具参数必须是至多 65536 字符的 object JSON Schema。');
    return { name, description: string(tool.description, 'platform.tools[].description', 16000), input_schema: structuredClone(schema) };
  });
  return {
    role_name: text(platform.role_name, 'platform.role_name', 200),
    instructions: text(platform.instructions, 'platform.instructions', 128000),
    worker_instructions: string(platform.worker_instructions, 'platform.worker_instructions', 128000),
    project_id: string(platform.project_id, 'platform.project_id', 256),
    conversation_id: string(platform.conversation_id, 'platform.conversation_id', 256),
    workspace: text(platform.workspace, 'platform.workspace', 4096),
    skills: platform.skills.map((value) => {
      const skill = object(value, 'platform.skills[]');
      return { name: text(skill.name, 'platform.skills[].name', 200), description: string(skill.description, 'platform.skills[].description', 8000) };
    }),
    tools, bridge: { url: validateBridgeUrl(bridge.url), token },
  };
}

export function configSecrets(config) {
  return [config.model.api_key, config.model.base_url, ...(config.mode === 'platform' ? [config.platform.bridge.token, config.platform.bridge.url, new URL(config.platform.bridge.url).origin] : [])];
}

export function validateInput(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new PublicError('invalid_input', 'stdin 必须提供一个 JSON 对象。');
  }
  const mode = input.mode ?? 'probe';
  if (!['probe', 'platform'].includes(mode)) throw new PublicError('invalid_input', 'mode 仅支持 probe 或 platform。');
  const formal = mode === 'platform';
  const run_id = text(input.run_id, 'run_id', 128);
  const prompt = text(input.prompt, 'prompt', 48000);
  if (!Array.isArray(input.scope) || input.scope.length < 1 || input.scope.length > 32) {
    throw new PublicError('invalid_scope', formal ? 'scope 必须包含 1 至 32 项明确授权范围与排除说明。' : 'scope 必须包含 1 至 32 个明确授权 URL。');
  }
  // Platform scope is an authorization contract, not the probe URL filter.
  // Network/tool/workspace permissions are enforced by the Go execution layer.
  const scope = [...new Set(input.scope.map((value) => formal ? text(value, 'scope[]', 4096) : parseHttpUrl(value).href))];
  const limits = input.limits ?? {};
  if (typeof limits !== 'object' || Array.isArray(limits)) {
    throw new PublicError('invalid_input', 'limits 必须是 JSON 对象。');
  }
  const model = input.model;
  if (!model || !['openai', 'claude'].includes(model.provider)) {
    throw new PublicError('invalid_model', 'model.provider 仅支持 openai 或 claude。');
  }
  const base = parseHttpUrl(text(model.base_url, 'model.base_url', 4096));
  if (base.search || new URL(model.base_url).hash) {
    throw new PublicError('invalid_model', 'model.base_url 不允许查询参数或片段。');
  }
  const context_window = integer(model.context_window, 128000, 'context_window', 1024, 2000000);
  const max_tokens = integer(model.max_tokens, 4096, 'max_tokens', 1, Math.min(32768, context_window));
  return {
    mode, run_id, prompt, scope,
    ...(formal ? { platform: validatePlatform(input.platform) } : {}),
    limits: {
      max_parallel: integer(limits.max_parallel, 2, 'max_parallel', 1, 8),
      max_agents: integer(limits.max_agents, 6, 'max_agents', formal ? 1 : 0, 32),
      timeout_seconds: integer(limits.timeout_seconds, 900, 'timeout_seconds', formal ? 60 : 1, formal ? 21600 : 3600),
      ...(formal ? {} : { max_requests: integer(limits.max_requests, 80, 'max_requests', 0, 1000) }),
      max_turns: formal ? integer(limits.max_turns, 120, 'max_turns', 1, 500) : 20,
      max_tool_calls: formal ? integer(limits.max_tool_calls, 600, 'max_tool_calls', 1, 2000) : 256,
    },
    model: {
      provider: model.provider,
      base_url: base.href.replace(/\/$/, ''),
      api_key: text(model.api_key, 'model.api_key', 16384),
      id: text(model.id, 'model.id', 256),
      context_window, max_tokens,
    },
  };
}

export function createRedactor(secrets = []) {
  const needles = [...new Set(secrets.filter((v) => typeof v === 'string' && v.length > 0).flatMap((value) => [
    value, encodeURIComponent(value), Buffer.from(value).toString('base64'),
  ]))].sort((a, b) => b.length - a.length);
  function redact(value) {
    if (typeof value === 'string') {
      for (const needle of needles) value = value.split(needle).join('[REDACTED]');
      return value.replace(/\b(Bearer\s+)[^\s"'<>]+/gi, '$1[REDACTED]')
        .replace(/([?&](?:api[_-]?key|access[_-]?token|token|password|secret)=)[^\s&#"'<>]*/gi, '$1[REDACTED]');
    }
    if (Array.isArray(value)) return value.map(redact);
    if (value && typeof value === 'object') {
      return Object.fromEntries(Object.entries(value).map(([key, item]) => [
        key, /^(?:api[_-]?key|authorization|password|secret|access[_-]?token)$/i.test(key) ? '[REDACTED]' : redact(item),
      ]));
    }
    return value;
  }
  return redact;
}

export function createEmitter(write, redact = createRedactor()) {
  let completed = false;
  return (type, agent_id, data) => {
    if (completed) return;
    if (!EVENT_TYPES.has(type)) throw new Error('Unexpected event type');
    const safeData = redact(data);
    // Protocol identity/enum fields are generated or validated by the runtime,
    // not secret-bearing model text. Preserve them even if a poorly chosen API
    // key happens to equal "coordinator" or "completed".
    for (const key of ['id', 'parent_id', 'source', 'target', 'kind', 'status', 'severity']) {
      if (Object.hasOwn(data, key)) safeData[key] = data[key];
    }
    let line = JSON.stringify({ type, agent_id, data: safeData }) + '\n';
    // The Go reader caps each UTF-8 NDJSON line at 96 KiB. Character limits
    // alone are insufficient (e.g. escaped control characters need 6 bytes).
    while (Buffer.byteLength(line) >= 96 * 1024) {
      const largest = Object.keys(safeData).filter((key) => typeof safeData[key] === 'string' && !['id', 'parent_id', 'source', 'target', 'kind', 'status', 'severity'].includes(key))
        .sort((a, b) => safeData[b].length - safeData[a].length)[0];
      if (!largest || safeData[largest].length < 64) throw new PublicError('event_size', '事件超出安全输出上限。');
      safeData[largest] = clip(safeData[largest], Math.floor(safeData[largest].length / 2));
      line = JSON.stringify({ type, agent_id, data: safeData }) + '\n';
    }
    write(line);
    if (type === 'complete') completed = true;
  };
}

export function clip(value, max = MAX_TEXT) {
  const suffix = '\n[输出已截断]';
  return value.length <= max ? value : value.slice(0, Math.max(0, max - suffix.length)) + suffix.slice(0, max);
}

export async function readInput(stream, signal) {
  const chunks = [];
  let bytes = 0;
  const onAbort = () => stream.destroy(new PublicError('cancelled', '读取输入已取消或超时。'));
  if (signal?.aborted) throw new PublicError('cancelled', '读取输入已取消或超时。');
  signal?.addEventListener('abort', onAbort, { once: true });
  try {
    for await (const chunk of stream) {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      bytes += buffer.length;
      if (bytes > MAX_INPUT_BYTES) throw new PublicError('invalid_input', 'stdin 超出 1 MiB 上限。');
      chunks.push(buffer);
    }
    const raw = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks));
    const line = raw.replace(/\r?\n$/, '');
    if (!line.trim() || /[\r\n]/.test(line)) throw new PublicError('invalid_input', 'stdin 必须恰好包含一个 JSON 行，随后 EOF。');
    try { return JSON.parse(line); } catch { throw new PublicError('invalid_input', 'stdin JSON 无效。'); }
  } finally {
    signal?.removeEventListener('abort', onAbort);
    for (const chunk of chunks) chunk.fill(0);
  }
}
