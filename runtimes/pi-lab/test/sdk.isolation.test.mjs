import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { Type } from 'typebox';
import { createPiSession, checkRuntime } from '../lib/sdk.mjs';
import { RunControl } from '../lib/control.mjs';
import { input, root, temporaryDirectory } from '../test-support/fixtures.mjs';

test('dependency lock contains only exact 1.0.4 same-scope PI packages and no old SDK', async () => {
  const manifest = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
  const lock = JSON.parse(await readFile(join(root, 'package-lock.json'), 'utf8'));
  assert.equal(manifest.dependencies['@earendil-works/pi-coding-agent'], '1.0.4');
  assert.equal(manifest.engines.node, '>=22.19.0');
  const pi = [];
  for (const [path, entry] of Object.entries(lock.packages)) {
    assert(!path.includes('@mariozechner/'), path);
    const name = path.match(/node_modules\/(@earendil-works\/[^/]+)$/)?.[1];
    if (!name) continue;
    pi.push(name);
    assert.equal(entry.version, '1.0.4', name);
    assert.equal(manifest.dependencies[name] ?? manifest.overrides[name], '1.0.4', name);
  }
  assert(pi.includes('@earendil-works/pi-telemetry'));
  assert(pi.includes('@earendil-works/pi-mcp'));
});

test('REAL SDK: only explicit tools are registered/callable; no resources, MCP, warming or setup network', async (t) => {
  const cwd = await temporaryDirectory(t);
  const config = input();
  const control = new RunControl(config.limits);
  const previousFetch = globalThis.fetch;
  let networkCalls = 0;
  globalThis.fetch = () => { networkCalls++; throw new Error('unexpected setup network'); };
  t.after(async () => { globalThis.fetch = previousFetch; await control.close(); });
  const tool = { name: 'record_surface', label: 'Record surface', description: 'Offline fixture', parameters: Type.Object({}), execute: async () => ({ content: [{ type: 'text', text: '{}' }], details: {} }) };
  const session = await createPiSession({ config: config.model, cwd, systemPrompt: 'Explicit test prompt', tools: [tool], control });
  try {
    assert.deepEqual(session.getActiveToolNames(), ['record_surface']);
    assert.deepEqual(session.getCallableToolNames(), ['record_surface']);
    assert.deepEqual(session.getAllTools().map((tool) => tool.name), ['record_surface']);
    session.setActiveToolsByName(['bash', 'read', 'write', 'codemode', 'tool_search', 'mcp__host__tool', 'record_surface']);
    assert.deepEqual(session.getActiveToolNames(), ['record_surface']);
    assert.equal(session.settingsManager.getCacheWarmingMode(), 'off');
    assert.equal(session.cacheWarmingStatus.reason, 'cache warming disabled');
    const loader = session.resourceLoader;
    assert.deepEqual(loader.getExtensions().extensions, []);
    assert.deepEqual(loader.getExtensions().runtime.mcpServers.list(), []);
    assert.deepEqual(loader.getAgentsFiles().agentsFiles, []);
    assert.deepEqual(loader.getSkills().skills, []);
    assert.deepEqual(loader.getPrompts().prompts, []);
    assert.deepEqual(loader.getAppendSystemPromptSources(), []);
    assert.equal(loader.getSystemPromptSource(), undefined);
    assert.equal((await session.modelRuntime.getAuth(session.model)).auth.apiKey, config.model.api_key);
    assert.equal(session.model.api, 'openai-completions');
    assert.equal(session.model.baseUrl, config.model.base_url);
  } finally { await session.dispose(); }
  assert.deepEqual(await session.modelRuntime.listCredentials(), []);
  assert.equal(await session.modelRuntime.getAuth('openai'), undefined, 'native provider has no environment credential fallback');
  assert.deepEqual(await checkRuntime(), { ready: true, runtime: 'pi-coding-agent', version: '1.0.4' });
  assert.equal(networkCalls, 0);
  assert.deepEqual(await readdir(cwd), []);
});
