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

export function validateInput(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new PublicError('invalid_input', 'stdin 必须提供一个 JSON 对象。');
  }
  const run_id = text(input.run_id, 'run_id', 128);
  const prompt = text(input.prompt, 'prompt', 48000);
  if (!Array.isArray(input.scope) || input.scope.length < 1 || input.scope.length > 32) {
    throw new PublicError('invalid_scope', 'scope 必须包含 1 至 32 个明确授权 URL。');
  }
  const scope = [...new Set(input.scope.map((value) => parseHttpUrl(value).href))];
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
    run_id, prompt, scope,
    limits: {
      max_parallel: integer(limits.max_parallel, 2, 'max_parallel', 1, 8),
      max_agents: integer(limits.max_agents, 6, 'max_agents', 0, 32),
      timeout_seconds: integer(limits.timeout_seconds, 900, 'timeout_seconds', 1, 3600),
      max_requests: integer(limits.max_requests, 80, 'max_requests', 0, 1000),
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
    write(JSON.stringify({ type, agent_id, data: safeData }) + '\n');
    if (type === 'complete') completed = true;
  };
}

export function clip(value, max = MAX_TEXT) {
  return value.length <= max ? value : value.slice(0, max) + '\n[输出已截断]';
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
