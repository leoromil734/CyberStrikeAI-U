#!/usr/bin/env node
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import { parseUpstream } from './policy.mjs';

const transport = new StdioClientTransport({ command: process.execPath,
  args: [fileURLToPath(new URL('./server.mjs', import.meta.url))], stderr: 'pipe',
  env: Object.fromEntries(['CYBERSTRIKE_PROXY_CONFIG', 'WEB_SEARCH_MODE', 'FAKE_IP_CIDRS', 'NODE_EXTRA_CA_CERTS']
    .filter(key => process.env[key]).map(key => [key, process.env[key]])) });
transport.stderr?.on('data', () => {});
const client = new Client({ name: 'cyberstrike-mcp-smoke', version: '1.0.0' });
const expected = ['web_search', 'web_fetch', 'github_readme', 'research_plan', 'proxy_status', 'proxy_get', 'proxy_rotate', 'proxy_release', 'proxy_healthcheck'];
const invoke = async (name, args = {}) => {
  const response = await client.callTool({ name, arguments: args }, undefined, { timeout: 180000 });
  return parseUpstream({ ...response, isError: false });
};
try {
  await client.connect(transport, { timeout: 20000 });
  const listed = await client.listTools();
  for (const name of expected) assert.ok(listed.tools.some(x => x.name === name), `Missing tool: ${name}`);
  console.log(`stdio initialization: OK (${listed.tools.length} tools)`);
  const plan = await invoke('research_plan', { scenario: 'nday', subject: 'Apache Log4j', cve: 'CVE-2021-44228' });
  assert.equal(plan.queries.length, 4);
  console.log('Nday/PoC research plan: OK');
  const status = await invoke('proxy_status');
  console.log(`shared proxy configuration: ${status.enabled ? 'enabled' : 'disabled'}; credentials hidden`);
  if (process.argv.includes('--live')) {
    const search = await invoke('web_search', { query: 'CVE-2021-44228 Apache Log4j security advisory', engines: ['bing', 'duckduckgo'], fresh: true });
    console.log(JSON.stringify({ search_status: search.status, results: search.total_results,
      attempts: search.attempts.map(x => ({ engine: x.engine, route: x.route, status: x.status, category: x.category })) }));
    assert.ok(search.results.length > 0, 'Live search returned no results');
    const fetched = await invoke('web_fetch', { url: 'https://raw.githubusercontent.com/Aas-ee/open-webSearch/main/package.json', maxChars: 4000 });
    console.log(JSON.stringify({ fetch_status: fetched.status, category: fetched.category, attempts: fetched.attempts }));
    assert.equal(fetched.status, 'ok');
    assert.ok(fetched.content.length > 0);
    console.log(`public source fetch: OK (${fetched.content.length} chars)`);
    for (const url of ['http://127.0.0.1/', 'http://198.18.0.1/']) {
      const blocked = await invoke('web_fetch', { url, maxChars: 1000, network: 'direct' });
      assert.equal(blocked.status, 'unavailable', 'Literal private/fake-IP targets must remain blocked');
    }
    console.log('literal private/fake-IP URL protection: OK');
  }
  if (process.argv.includes('--proxy')) {
    let lease;
    try {
      lease = await invoke('proxy_get', { country: 'US' });
      assert.ok(/^http:\/\/127\.0\.0\.1:\d+$/.test(lease.proxy_url));
      const first = await invoke('proxy_healthcheck', { lease_id: lease.lease_id });
      console.log(`住宅代理上游检测: ${first.status}; failure category: ${first.category ?? 'none'}; error: ${first.error ?? 'none'}`);
      assert.equal(first.status, 'ok');
      const rotated = await invoke('proxy_rotate', { lease_id: lease.lease_id });
      assert.notEqual(rotated.session_id, lease.session_id);
      const second = await invoke('proxy_healthcheck', { lease_id: lease.lease_id });
      assert.equal(second.status, 'ok');
      console.log(`Residential upstream exit health: OK; SID rotation: OK; exit IP changed: ${first.exit_ip !== second.exit_ip}`);
    } finally { if (lease) await invoke('proxy_release', { lease_id: lease.lease_id }); }
  }
} catch (error) {
  // 不打印来自网络或代理的原始异常，避免提供商返回正文带回凭据。
  console.error(`smoke test failed: ${error.code ?? error.name}; inspect tool diagnostics (secrets are redacted)`);
  process.exitCode = 1;
} finally { await client.close(); }
