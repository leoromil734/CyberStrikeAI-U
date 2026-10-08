import { join } from 'node:path';
import { Agent, fetch as undiciFetch } from 'undici';
import { InMemoryCredentialStore, createProvider, envApiKeyAuth } from '@earendil-works/pi-ai';
import { openAICompletionsApi } from '@earendil-works/pi-ai/api/openai-completions.lazy';
import { anthropicMessagesApi } from '@earendil-works/pi-ai/api/anthropic-messages.lazy';
import { SDK_VERSION, PublicError, parseHttpUrl } from './protocol.mjs';
import { checkAbort, combineSignals } from './control.mjs';

let sdkPromise;
export async function loadSDK() {
  const [major, minor] = process.versions.node.split('.').map(Number);
  if (major < 22 || (major === 22 && minor < 19)) {
    throw new PublicError('node_version', 'PI Lab 需要 Node.js 22.19 或更新版本。');
  }
  sdkPromise ??= import('@earendil-works/pi-coding-agent');
  const sdk = await sdkPromise;
  if (sdk.VERSION !== SDK_VERSION) throw new PublicError('sdk_version', 'PI SDK 版本不匹配，请在运行目录执行 npm ci。');
  for (const name of ['createAgentSession', 'createExtensionRuntime', 'ModelRuntime', 'SettingsManager', 'SessionManager']) {
    if (typeof sdk[name] !== 'function') throw new PublicError('sdk_api', '已安装 PI SDK 缺少所需接口。');
  }
  return sdk;
}

// A ResourceLoader implemented entirely in memory. DefaultResourceLoader is
// deliberately not constructed: even its no* flags still discover packages.
export function emptyResourceLoader(sdk, systemPrompt) {
  const extensions = { extensions: [], errors: [], runtime: sdk.createExtensionRuntime() };
  return {
    getExtensions: () => extensions,
    getSkills: () => ({ skills: [], diagnostics: [] }),
    getPrompts: () => ({ prompts: [], diagnostics: [] }),
    getThemes: () => ({ themes: [], diagnostics: [] }),
    getAgentsFiles: () => ({ agentsFiles: [] }),
    getSystemPrompt: () => systemPrompt,
    getSystemPromptSource: () => undefined,
    getAppendSystemPrompt: () => [],
    getAppendSystemPromptSources: () => [],
    extendResources: () => { throw new PublicError('resources_disabled', '外部资源加载已禁用。'); },
    reload: async () => {},
  };
}

export async function createMemoryModelRuntime(sdk) {
  return sdk.ModelRuntime.create({
    credentials: new InMemoryCredentialStore(),
    modelsPath: null, // undefined would read the user's models.json.
    allowModelNetwork: false,
    refreshOnCreate: false,
  });
}

export async function createPiSession({ config, cwd, systemPrompt, tools, control, mode = 'probe' }) {
  const sdk = await loadSDK();
  checkAbort(control.signal);
  const provider = config.provider === 'claude' ? 'anthropic' : 'openai';
  const modelRuntime = await createMemoryModelRuntime(sdk);
  const model = {
    id: config.id, name: config.id, provider,
    api: provider === 'anthropic' ? 'anthropic-messages' : 'openai-completions',
    baseUrl: config.base_url,
    reasoning: false,
    input: ['text'],
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
    contextWindow: config.context_window, maxTokens: config.max_tokens,
    ...(provider === 'openai' ? { compat: { supportsDeveloperRole: false, supportsStore: false } } : {}),
  };
  // Explicit native provider: no OAuth, environment fallback, catalog refresh,
  // config-value interpolation or implicit switch to OpenAI Responses.
  modelRuntime.registerNativeProvider(createProvider({
    id: provider, name: provider, baseUrl: config.base_url,
    auth: { apiKey: envApiKeyAuth('PI Lab stdin key', []) },
    models: [model],
    api: provider === 'anthropic' ? anthropicMessagesApi() : openAICompletionsApi(),
  }));
  await modelRuntime.setRuntimeApiKey(provider, config.api_key, { signal: control.signal });
  const settingsManager = sdk.SettingsManager.inMemory({
    cacheWarming: 'off',
    // Supported SDK compaction runs through the same modelRuntime.streamSimple
    // wrapper below, so summary requests share auth, cancellation and turn limits.
    // Scale down for small configured windows rather than retaining a 20k tail.
    compaction: mode === 'platform' ? {
      enabled: true,
      reserveTokens: Math.min(16384, Math.floor(config.context_window / 4)),
      keepRecentTokens: Math.min(20000, Math.floor(config.context_window / 4)),
    } : { enabled: false },
    retry: { enabled: false, maxRetries: 0, provider: { maxRetries: 0, timeoutMs: 90000, maxRetryDelayMs: 0 } },
    enableInstallTelemetry: false,
    enableSkillCommands: false,
    images: { blockImages: true },
    packages: [], extensions: [], skills: [], prompts: [], themes: [],
  });
  const { session } = await sdk.createAgentSession({
    cwd,
    // This path is never read or created. All storage and discovery are supplied.
    agentDir: join(cwd, '.pi-disabled'),
    modelRuntime, model,
    thinkingLevel: 'off',
    noTools: 'builtin',
    tools: tools.map((tool) => tool.name),
    // In 1.0.4 a normal allowlist can retain deferred MCP tools.
    excludeTools: ['mcp__*', 'codemode', 'tool_search'],
    customTools: tools,
    settingsManager,
    sessionManager: sdk.SessionManager.inMemory(cwd),
    resourceLoader: emptyResourceLoader(sdk, systemPrompt),
  });
  const expected = JSON.stringify(tools.map((tool) => tool.name).sort());
  const toolSets = [session.getActiveToolNames(), session.getCallableToolNames(), session.getAllTools().map((tool) => tool.name)];
  if (toolSets.some((names) => JSON.stringify(names.sort()) !== expected)) {
    session.dispose();
    await modelRuntime.removeRuntimeApiKey(provider);
    throw new PublicError('unsafe_tools', 'PI SDK 工具白名单校验失败。');
  }
  const stream = modelRuntime.streamSimple.bind(modelRuntime);
  modelRuntime.streamSimple = (activeModel, context, options = {}) => {
    control.takeTurn(); // Shared across coordinator and every worker; no retry bypass.
    return stream(activeModel, context, {
      ...options,
      signal: combineSignals(options.signal, control.signal),
      maxTokens: mode === 'platform' ? Math.min(config.max_tokens, options.maxTokens ?? config.max_tokens) : config.max_tokens,
      cacheRetention: 'none',
      maxRetries: 0,
    });
  };
  const dispose = session.dispose.bind(session);
  session.dispose = async () => {
    session.agent.state.messages = [];
    dispose();
    await modelRuntime.removeRuntimeApiKey(provider);
  };
  return session;
}

// The runner is a single-run process. Confine SDK fetch to the configured model
// origin, stop redirects, ignore ambient proxy dispatchers, and require TLS
// verification even if NODE_TLS_REJECT_UNAUTHORIZED is set by the host.
// Target HTTP tools use their separate, DNS-checked transport.
export function installModelFetch(baseUrl, signal) {
  const origin = parseHttpUrl(baseUrl).origin;
  const previous = globalThis.fetch;
  const dispatcher = new Agent({
    connect: { rejectUnauthorized: true, timeout: 10000 },
    maxResponseSize: 8 * 1024 * 1024,
    maxHeaderSize: 16384,
  });
  globalThis.fetch = (input, init = {}) => {
    const value = typeof input === 'string' || input instanceof URL ? String(input) : input.url;
    const url = parseHttpUrl(value);
    if (url.origin !== origin) throw new PublicError('model_origin', '模型请求 origin 与显式配置不一致。');
    return undiciFetch(input, {
      ...init, dispatcher, redirect: 'error',
      signal: combineSignals(signal, init.signal, input?.signal),
    });
  };
  return async () => {
    globalThis.fetch = previous;
    await dispatcher.destroy();
  };
}

export async function checkRuntime() {
  const sdk = await loadSDK();
  await createMemoryModelRuntime(sdk);
  sdk.SettingsManager.inMemory({ enableInstallTelemetry: false });
  sdk.SessionManager.inMemory(process.cwd());
  return { ready: true, runtime: 'pi-coding-agent', version: SDK_VERSION };
}
