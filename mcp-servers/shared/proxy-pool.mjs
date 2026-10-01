import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isIP } from 'node:net';
import { randomBytes, randomUUID } from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import { Server } from 'proxy-chain';

const PROTOCOLS = new Set(['http', 'https', 'socks5', 'socks5h']);
const SAFE_ERROR = 'Proxy gateway request failed';
const DEFAULT_CONFIG_PATH = fileURLToPath(new URL('./proxy.local.json', import.meta.url));

function invalid(field) {
  // Never include the invalid value, file contents, path, or original error.
  return new Error(`Invalid proxy configuration: ${field}`);
}

function countryCode(value, field = 'country') {
  if (typeof value !== 'string' || !/^[a-z]{2}$/i.test(value)) throw invalid(field);
  return value.toUpperCase();
}

function integer(value, fallback, min, max, field) {
  const result = value === undefined ? fallback : value;
  if (!Number.isInteger(result) || result < min || result > max) throw invalid(field);
  return result;
}

function normalizeConfig(input = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw invalid('object');
  const enabled = input.enabled ?? false;
  if (typeof enabled !== 'boolean') throw invalid('enabled');
  const protocol = input.protocol ?? 'http';
  if (typeof protocol !== 'string' || !PROTOCOLS.has(protocol.toLowerCase())) throw invalid('protocol');
  let host = input.host ?? '';
  if (typeof host !== 'string') throw invalid('host');
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  if ((enabled && !host) || (host && !isIP(host) && !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/i.test(host))) {
    throw invalid('host');
  }
  const countriesInput = input.countries ?? ['US'];
  if (!Array.isArray(countriesInput)) throw invalid('countries');
  const countries = [...new Set(countriesInput.map((value) => countryCode(value, 'countries')))];
  const defaultCountry = countryCode(input.default_country ?? countries[0] ?? 'US', 'default_country');
  const templates = {};
  for (const field of ['username_template', 'password_template']) {
    const value = input[field] ?? '';
    if (typeof value !== 'string' || /[\r\n\0]/.test(value)) throw invalid(field);
    try { encodeURIComponent(value); } catch { throw invalid(field); }
    templates[field] = value;
  }
  return Object.freeze({
    enabled,
    protocol: protocol.toLowerCase(),
    host: host.toLowerCase(),
    port: integer(input.port, protocol.toLowerCase() === 'https' ? 443 : protocol.toLowerCase().startsWith('socks') ? 1080 : 80, 1, 65535, 'port'),
    ...templates,
    default_country: defaultCountry,
    countries: Object.freeze(countries),
    // This is the caller's worker count, not a limit on independent leases.
    pool_size: integer(input.pool_size, 2, 1, 8, 'pool_size'),
    lease_ttl_seconds: integer(input.lease_ttl_seconds, 300, 30, 3600, 'lease_ttl_seconds'),
    max_leases: integer(input.max_leases, 16, 1, 64, 'max_leases'),
  });
}

/** Synchronous; absent configuration disables proxying even if credential overrides exist. */
export function loadProxyConfig(env = process.env) {
  const path = env.CYBERSTRIKE_PROXY_CONFIG
    ? resolve(env.CYBERSTRIKE_PROXY_CONFIG)
    : DEFAULT_CONFIG_PATH;
  let contents;
  try {
    contents = readFileSync(path, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') return normalizeConfig({ enabled: false });
    throw new Error('Unable to read proxy configuration');
  }
  let input;
  try { input = JSON.parse(contents); } catch { throw invalid('JSON'); }
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw invalid('object');
  input = { ...input };
  if (env.CYBERSTRIKE_PROXY_PASSWORD !== undefined) input.password_template = env.CYBERSTRIKE_PROXY_PASSWORD;
  if (env.CYBERSTRIKE_PROXY_USERNAME_TEMPLATE !== undefined) input.username_template = env.CYBERSTRIKE_PROXY_USERNAME_TEMPLATE;
  return normalizeConfig(input);
}

function renderTemplate(template, country, session) {
  return template.replace(/\{(country|session)\}/g, (_, name) => name === 'country' ? country : session);
}

/** Internal-use only: this URL contains upstream credentials. socks5[h] are supported natively. */
export function renderProxyUrl(config, { country, session }) {
  const normalized = normalizeConfig(config);
  const selectedCountry = countryCode(country ?? normalized.default_country);
  if (typeof session !== 'string' || !session || /[\r\n\0]/.test(session)) throw invalid('session');
  if (!normalized.host) throw invalid('host');
  try {
    const username = encodeURIComponent(renderTemplate(normalized.username_template, selectedCountry, session));
    const password = encodeURIComponent(renderTemplate(normalized.password_template, selectedCountry, session));
    const auth = username || password ? `${username}:${password}@` : '';
    const host = isIP(normalized.host) === 6 ? `[${normalized.host}]` : normalized.host;
    return `${normalized.protocol}://${auth}${host}:${normalized.port}`;
  } catch { throw invalid('templates'); }
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Clean URLs, Basic authorization, credential fields, and raw/escaped rendered templates. */
export function redactSecrets(value, config = {}) {
  let result;
  try {
    result = typeof value === 'string' ? value : value instanceof Error ? `${value.name}: ${value.message}` : JSON.stringify(value);
    result ??= String(value);
  } catch { return '[Unserializable value]'; }
  result = result.replace(/\b((?:https?|socks5h?):\/\/)[^\s/?#]*@/gi, '$1[REDACTED]@')
    .replace(/\bBasic\s+[a-z0-9+/=]+/gi, 'Basic [REDACTED]')
    .replace(/("(?:username(?:_template)?|password(?:_template)?|proxy-authorization)"\s*:\s*")(?:\\.|[^"\\\r\n])*(")/gi, '$1[REDACTED]$2');
  for (const template of [config.username_template, config.password_template]) {
    if (typeof template !== 'string' || !template) continue;
    const pieces = template.split(/\{(?:country|session)\}/g);
    if (!pieces.some(Boolean)) continue;
    for (const encode of [String, encodeURIComponent]) {
      try {
        const pattern = pieces.map((part) => escapeRegex(encode(part))).join('[^\\s"\'<>]*');
        result = result.replace(new RegExp(pattern, 'g'), '[REDACTED]');
      } catch { /* Invalid user-supplied text is never included in an error. */ }
    }
  }
  return result;
}

// proxy-chain normally includes target URLs / errors in some RequestError responses.
// Override its documented response hook and logging so those never reach clients/logs.
class SafeGateway extends Server {
  constructor(options, onFailure, onHttpRequest) {
    super(options);
    this.onFailure = onFailure;
    this.onHttpRequest = onHttpRequest;
  }
  onRequest(request, response) {
    this.onHttpRequest(request, response);
    return super.onRequest(request, response);
  }
  onConnect(request, socket, head) {
    // proxy-chain 3.0.1's SOCKS CONNECT path ends the socket directly with the
    // upstream error, bypassing sendSocketResponse. Sanitize only the handshake;
    // restore the methods before any successful tunnel bytes can be forwarded.
    const write = socket.write;
    const end = socket.end;
    const restore = () => {
      socket.write = write;
      socket.end = end;
      socket.removeListener('close', restore);
    };
    const onFailure = this.onFailure;
    socket.once('close', restore);
    socket.write = function (chunk, ...args) {
      if (/^HTTP\/1\.1 200\b/.test(String(chunk))) restore();
      return write.call(this, chunk, ...args);
    };
    socket.end = function (chunk, ...args) {
      const match = /^HTTP\/1\.1 ([45]\d\d)\b/.exec(String(chunk));
      if (match) {
        onFailure();
        chunk = `HTTP/1.1 ${match[1]} Proxy Gateway Error\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: ${Buffer.byteLength(SAFE_ERROR)}\r\n\r\n${SAFE_ERROR}`;
      }
      return end.call(this, chunk, ...args);
    };
    return super.onConnect(request, socket, head);
  }
  log() {}
  failRequest(request, error) {
    if (request.method !== 'CONNECT') this.onFailure();
    const status = Number.isInteger(error?.statusCode) && error.statusCode >= 400 && error.statusCode <= 599
      ? error.statusCode : 502;
    this.sendSocketResponse(request.socket, status);
  }
  sendSocketResponse(socket, statusCode = 502) {
    super.sendSocketResponse(socket, statusCode, {}, SAFE_ERROR);
  }
}

/**
 * Share one instance in a process; every lease owns its own localhost gateway.
 * No OS proxy/env mutation, prewarming, request retry, or automatic session rotation.
 * TTL is idle time: requests renew it; HTTP requests in flight and observed tunnel
 * byte traffic keep a lease alive. An idle CONNECT eventually expires too.
 */
export class ProxyPool {
  #leases = new Map();
  #queue = Promise.resolve();
  #closed = false;
  #closePromise;
  #timer;

  constructor(config) {
    this.config = normalizeConfig(config);
    // Do not let a caller change credentials or policy underneath existing sessions.
    Object.defineProperty(this, 'config', { writable: false });
    if (this.config.enabled) {
      this.#timer = setInterval(() => {
        void this.#run(() => this.#reap()).catch(() => {});
      }, 1000);
      this.#timer.unref();
    }
  }

  #run(operation) {
    const result = this.#queue.then(operation);
    this.#queue = result.catch(() => {});
    return result;
  }

  #touch(lease) {
    lease.expiresAt = Date.now() + this.config.lease_ttl_seconds * 1000;
  }

  #traffic(lease) {
    const ids = new Set(lease.gateway.getConnectionIds());
    let changed = false;
    for (const id of ids) {
      const stats = lease.gateway.getConnectionStats(id);
      const bytes = (stats?.srcTxBytes ?? 0) + (stats?.srcRxBytes ?? 0);
      if (bytes > (lease.lastBytes.get(id) ?? 0)) changed = true;
      lease.lastBytes.set(id, bytes);
    }
    for (const id of lease.lastBytes.keys()) {
      if (!ids.has(id)) lease.lastBytes.delete(id);
    }
    if (changed) this.#touch(lease);
  }

  async #dispose(lease) {
    lease.closed = true;
    this.#leases.delete(lease.id);
    lease.httpAgent.destroy();
    lease.httpsAgent.destroy();
    try { await lease.gateway.close(true); } catch { /* Never expose a gateway error. */ }
  }

  async #reap() {
    for (const lease of this.#leases.values()) {
      this.#traffic(lease);
      if (lease.activeHttp === 0 && lease.expiresAt <= Date.now()) await this.#dispose(lease);
    }
  }

  #public(lease) {
    const proxyUrl = `http://127.0.0.1:${lease.gateway.port}`;
    return {
      lease_id: lease.id,
      proxy_url: proxyUrl,
      country: lease.country,
      session_id: lease.session,
      expires_at: new Date(lease.expiresAt).toISOString(),
      env: {
        HTTP_PROXY: proxyUrl,
        HTTPS_PROXY: proxyUrl,
        ALL_PROXY: proxyUrl,
        NO_PROXY: 'localhost,127.0.0.1,::1',
      },
    };
  }

  async acquire({ country, leaseId, rotate = false } = {}) {
    const selectedCountry = country === undefined ? undefined : countryCode(country);
    if (typeof rotate !== 'boolean') throw new Error('Invalid proxy rotation option');
    if (leaseId !== undefined && (typeof leaseId !== 'string' || !leaseId || leaseId.length > 128)) {
      throw new Error('Invalid proxy lease ID');
    }
    return this.#run(async () => {
      if (this.#closed) throw new Error('Proxy pool is closed');
      if (!this.config.enabled) throw new Error('Proxy pool is disabled');
      await this.#reap();
      if (leaseId !== undefined) {
        const lease = this.#leases.get(leaseId);
        if (!lease) throw new Error('Proxy lease not found or expired');
        const nextCountry = selectedCountry ?? lease.country;
        if (rotate || nextCountry !== lease.country) {
          // Destroy only this lease's client tunnels AND upstream connection pools.
          lease.gateway.closeConnections();
          lease.httpAgent.destroy();
          lease.httpsAgent.destroy();
          lease.httpAgent = new http.Agent({ keepAlive: false });
          lease.httpsAgent = new https.Agent({ keepAlive: false });
          lease.country = nextCountry;
          lease.session = randomBytes(8).toString('hex');
          lease.lastBytes.clear();
        }
        this.#touch(lease);
        return this.#public(lease);
      }
      if (this.#leases.size >= this.config.max_leases) throw new Error('Proxy lease capacity reached');
      const lease = {
        id: randomUUID(), country: selectedCountry ?? this.config.default_country,
        session: randomBytes(8).toString('hex'), closed: false,
        activeHttp: 0, lastBytes: new Map(), failures: 0,
        httpAgent: new http.Agent({ keepAlive: false }),
        httpsAgent: new https.Agent({ keepAlive: false }),
      };
      lease.gateway = new SafeGateway({
        host: '127.0.0.1', port: 0, verbose: false,
        prepareRequestFunction: () => {
          if (lease.closed || this.#closed) throw new Error(SAFE_ERROR);
          this.#touch(lease);
          return {
            requestAuthentication: false,
            upstreamProxyUrl: renderProxyUrl(this.config, { country: lease.country, session: lease.session }),
            httpAgent: lease.httpAgent, httpsAgent: lease.httpsAgent,
          };
        },
      }, () => { lease.failures++; }, (request, response) => {
        lease.activeHttp++;
        let finished = false;
        const done = () => {
          if (finished) return;
          finished = true;
          lease.activeHttp--;
          request.socket.removeListener('close', done);
          if (!lease.closed) {
            this.#traffic(lease);
            this.#touch(lease);
          }
        };
        response.once('finish', done);
        response.once('close', done);
        request.socket.once('close', done);
      });
      lease.gateway.on('tunnelConnectFailed', () => { lease.failures++; });
      lease.gateway.on('requestFailed', () => { lease.failures++; });
      try { await lease.gateway.listen(); }
      catch {
        await this.#dispose(lease);
        throw new Error('Unable to start local proxy gateway');
      }
      this.#touch(lease);
      this.#leases.set(lease.id, lease);
      return this.#public(lease);
    });
  }

  async rotate(leaseId, { country } = {}) {
    if (leaseId === undefined) throw new Error('Proxy lease ID is required');
    return this.acquire({ leaseId, country, rotate: true });
  }

  async release(leaseId) {
    return this.#run(async () => {
      const lease = this.#leases.get(leaseId);
      if (!lease) return false;
      await this.#dispose(lease);
      return true;
    });
  }

  status() {
    return {
      enabled: this.config.enabled,
      available: this.config.enabled && !this.#closed,
      closed: this.#closed,
      protocol: this.config.protocol,
      default_country: this.config.default_country,
      countries: [...this.config.countries],
      pool_size: this.config.pool_size,
      max_leases: this.config.max_leases,
      lease_ttl_seconds: this.config.lease_ttl_seconds,
      lease_count: this.#leases.size,
      leases: [...this.#leases.values()].map((lease) => ({
        lease_id: lease.id, country: lease.country, session_id: lease.session,
        expires_at: new Date(lease.expiresAt).toISOString(),
        connections: lease.gateway.getConnectionIds().length, failures: lease.failures,
      })),
    };
  }

  async close() {
    if (!this.#closePromise) {
      this.#closed = true;
      clearInterval(this.#timer);
      this.#closePromise = this.#run(async () => {
        await Promise.all([...this.#leases.values()].map((lease) => this.#dispose(lease)));
      });
    }
    return this.#closePromise;
  }
}
