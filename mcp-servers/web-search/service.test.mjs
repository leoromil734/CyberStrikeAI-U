import test from 'node:test';
import assert from 'node:assert/strict';
import { classifyFailure, normalizeResults, deduplicateResults, parseUpstream, researchPlan, SCENARIOS } from './policy.mjs';
import { SearchService, upstreamEnvironment } from './service.mjs';

const result = payload => ({ content: [{ type: 'text', text: JSON.stringify(payload) }] });
const row = (url = 'https://example.com/advisory') => ({ title: 'Vendor advisory', url, description: 'Affected versions and patch' });
function fixture(fn, config = {}) {
  const calls = [];
  const pool = { config: { enabled: true, pool_size: 2, default_country: 'US', ...config } };
  const service = new SearchService(pool, { intervalMs: 0, workerFactory: () => ({
    call: async (name, args, options) => { calls.push({ name, args, options }); return fn(name, args, options); }, close: async () => {},
  }) });
  return { service, calls };
}

test('classifies IP/network issues separately from authentication, quota, challenge and missing pages', () => {
  for (const [message, category] of [ ['HTTP 407', 'proxy_auth'], ['upstream 597', 'proxy_auth'], ['HTTP 429', 'rate_limit'],
    ['HTTP 401', 'authentication'], ['404 Not Found', 'not_found'], ['captcha', 'browser_or_challenge'],
    ['HTTP 403', 'access_denied'], ['unsafe private URL', 'invalid_target_or_parameter'] ]) {
    assert.deepEqual(classifyFailure(new Error(message)), { category, retry: false });
  }
  assert.deepEqual(classifyFailure(new Error('ECONNRESET')), { category: 'network', retry: true });
});

test('parses protocol errors and removes malformed/credentialed search links', () => {
  assert.throws(() => parseUpstream({ isError: true, content: [{ type: 'text', text: 'timeout' }] }), /timeout/);
  assert.equal(normalizeResults({ results: [row(), row('javascript:alert(1)'), row('https://user:secret@example.com/')] }, 'bing').length, 1);
});

test('deduplicates multi-engine URLs without losing engine provenance', () => {
  const data = [ ...normalizeResults([row('https://example.com/a?utm_source=test')], 'bing'),
    ...normalizeResults([row('https://example.com/a#section')], 'duckduckgo') ];
  assert.equal(deduplicateResults(data, 10).length, 1);
  assert.deepEqual(deduplicateResults(data, 10)[0].engines, ['bing', 'duckduckgo']);
});

test('all requested security scenarios return bounded plans and explicit applicability checks', () => {
  for (const scenario of SCENARIOS) {
    const plan = researchPlan({ scenario, subject: 'Apache example', version: '1.2.3', cve: 'CVE-2021-44228' });
    assert.ok(plan.queries.length >= 2 && plan.queries.length <= 4);
    assert.ok(plan.workflow.some(x => x.includes('不得自动执行')));
    assert.ok(plan.workflow.some(x => x.includes('空结果不等于无漏洞')));
    assert.ok(plan.authoritative_sources[0].url.includes('CVE-2021-44228'));
  }
  assert.throws(() => researchPlan({ subject: 'x', cve: 'CVE-invalid' }), /Invalid CVE/);
});

test('upstream subprocess receives neither residential secrets nor inherited global proxies', () => {
  const env = upstreamEnvironment('http://127.0.0.1:1234', { HTTP_PROXY: 'http://secret:pass@host:123',
    CYBERSTRIKE_PROXY_PASSWORD: 'credential', API_KEY: 'credential', WEB_SEARCH_MODE: 'request' });
  assert.equal(env.PROXY_URL, 'http://127.0.0.1:1234');
  for (const key of ['HTTP_PROXY', 'CYBERSTRIKE_PROXY_PASSWORD', 'API_KEY']) assert.equal(env[key], undefined);
  assert.equal(env.MODE, 'stdio');
  assert.equal(upstreamEnvironment(undefined, {}).USE_PROXY, 'false');
});

test('connection failure retries auto requests once with proxy, preserving diagnostics', async () => {
  const { service, calls } = fixture((name, args, options) => {
    if (options.route === 'direct') throw new Error('ECONNRESET');
    return result({ results: [row()] });
  });
  const data = await service.search({ query: 'CVE test', engines: ['bing'] });
  assert.equal(data.status, 'partial');
  assert.deepEqual(calls.map(x => x.options.route), ['direct', 'proxy']);
  assert.equal(data.attempts[0].category, 'network');
  await service.close();
});

test('explicit proxy connection failure rotates only that worker on the single retry', async () => {
  const { service, calls } = fixture((name, args, options) => {
    if (!options.rotate) throw new Error('ETIMEDOUT');
    return result({ results: [row()] });
  });
  const data = await service.search({ query: 'proxy test', engines: ['bing'], network: 'proxy', country: 'JP' });
  assert.equal(data.results.length, 1);
  assert.deepEqual(calls.map(x => x.options.rotate), [false, true]);
  assert.equal(calls[1].options.country, 'JP');
  await service.close();
});

test('429, 407, 403 and CAPTCHA switch engine rather than rotate the same query', async () => {
  for (const failure of ['429', '407', '403', 'captcha']) {
    const { service, calls } = fixture(() => result({ results: [], partialFailures: [{ engine: 'bing', message: failure }] }));
    const data = await service.search({ query: 'framework history', engines: ['bing'], network: 'proxy' });
    assert.equal(data.status, 'unavailable');
    assert.equal(calls.length, 2); // one Bing call, one alternate Brave call
    assert.ok(calls.every(x => !x.options.rotate));
    assert.ok(data.attempts.every(x => x.category === classifyFailure(failure).category));
    await service.close();
  }
});

test('successful empty queries are not cached or described as no vulnerabilities', async () => {
  const { service, calls } = fixture(() => result({ results: [] }));
  const data = await service.search({ query: 'obscure framework', engines: ['bing'] });
  assert.equal(data.status, 'empty');
  assert.ok(data.warning.includes('空结果不代表没有漏洞'));
  await service.search({ query: 'obscure framework', engines: ['bing'] });
  assert.equal(calls.length, 4);
  await service.close();
});

test('successful results cache with a timestamp and fresh bypasses cache', async () => {
  const { service, calls } = fixture(() => result({ results: [row()] }));
  const first = await service.search({ query: 'vendor advisory', engines: ['bing', 'duckduckgo'] });
  assert.equal(first.status, 'ok');
  assert.equal(first.total_results, 1);
  const second = await service.search({ query: 'vendor advisory', engines: ['bing', 'duckduckgo'] });
  assert.equal(second.cached, true);
  assert.equal(second.retrieved_at, first.retrieved_at);
  assert.equal(calls.length, 2);
  await service.search({ query: 'vendor advisory', engines: ['bing', 'duckduckgo'], fresh: true });
  assert.equal(calls.length, 4);
  await service.close();
});

test('single bad engine preserves good results as partial, fetch 404 does not retry', async () => {
  const { service } = fixture((name, args) => {
    if (name !== 'search') throw new Error('HTTP 404');
    if (args.engines[0] === 'bing') throw new Error('HTTP 429');
    return result({ results: [row()] });
  });
  const search = await service.search({ query: 'history', engines: ['bing', 'duckduckgo'] });
  assert.equal(search.status, 'partial');
  assert.equal(search.results.length, 1);
  const fetch = await service.fetch({ url: 'https://example.com/missing' });
  assert.equal(fetch.category, 'not_found');
  assert.equal(fetch.attempts.length, 1);
  await service.close();
});

test('worker concurrency is bounded and queued requests are cancellable', async () => {
  let active = 0; let highest = 0;
  const { service } = fixture(async () => {
    active++; highest = Math.max(highest, active);
    await new Promise(resolve => setTimeout(resolve, 25)); active--;
    return result({ results: [row()] });
  }, { pool_size: 1 });
  const first = service.search({ query: 'first', engines: ['bing'] });
  const cancel = new AbortController();
  const second = service.search({ query: 'second', engines: ['bing'] }, cancel.signal);
  cancel.abort();
  await assert.rejects(second, /cancelled|aborted/i);
  await first;
  assert.equal(highest, 1);
  await service.close();
});
