import test from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { ProxyPool } from '../shared/proxy-pool.mjs';
import { parseArguments } from '../shared/with-proxy.mjs';
import { createServer } from './server.mjs';
import { parseUpstream } from './policy.mjs';

const fakeConfig = { enabled: true, protocol: 'socks5', host: 'example.com', port: 1080,
  username_template: 'PLACEHOLDER-region-{country}-sid-{session}', password_template: 'PLACEHOLDER-password',
  default_country: 'US', pool_size: 1, max_leases: 8, lease_ttl_seconds: 30 };

test('MCP protocol advertises all research tools and creates isolated local proxy leases without upstream credentials', async t => {
  const pool = new ProxyPool(fakeConfig);
  const instance = createServer({ pool });
  const client = new Client({ name: 'offline-protocol-test', version: '1.0.0' });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  t.after(async () => { await client.close(); await instance.close(); });
  await instance.server.connect(serverTransport);
  await client.connect(clientTransport);
  const tools = await client.listTools();
  assert.equal(tools.tools.length, 9);
  const invoke = async (name, args = {}) => parseUpstream(await client.callTool({ name, arguments: args }));
  const plan = await invoke('research_plan', { subject: 'framework', scenario: 'framework_history', version: '1.0' });
  assert.equal(plan.scenario, 'framework_history');
  const first = await invoke('proxy_get', { country: 'US' });
  const second = await invoke('proxy_get', { country: 'JP' });
  assert.notEqual(first.lease_id, second.lease_id);
  assert.notEqual(first.proxy_url, second.proxy_url);
  assert.match(first.proxy_url, /^http:\/\/127\.0\.0\.1:\d+$/);
  assert.ok(!JSON.stringify(first).includes('PLACEHOLDER'));
  const status = await invoke('proxy_status');
  assert.equal(status.protocol, 'socks5');
  assert.equal(status.lease_count, 2);
  assert.ok(!JSON.stringify(status).includes(first.lease_id));
  assert.ok(!JSON.stringify(status).includes(second.session_id));
  const changed = await invoke('proxy_rotate', { lease_id: first.lease_id, country: 'GB' });
  assert.equal(changed.country, 'GB');
  assert.notEqual(changed.session_id, first.session_id);
  assert.equal((await invoke('proxy_release', { lease_id: first.lease_id })).released, true);
  assert.equal((await invoke('proxy_status')).lease_count, 1);
});

test('single-process proxy launcher requires an explicit command and validates protocol/country', () => {
  assert.deepEqual(parseArguments(['--country', 'JP', '--protocol', 'socks5', '--', 'curl.exe', 'https://example.com']), {
    options: { country: 'JP', protocol: 'socks5' }, command: 'curl.exe', args: ['https://example.com'],
  });
  for (const args of [ [], ['--'], ['--protocol', 'ftp', '--', 'curl'], ['--country', 'USA', '--', 'curl'], ['--country', '--', 'curl'] ]) {
    assert.throws(() => parseArguments(args));
  }
});
