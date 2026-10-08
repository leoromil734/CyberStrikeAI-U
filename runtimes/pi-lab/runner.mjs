#!/usr/bin/env node
// No static third-party imports: even a missing installation produces a clean
// machine-readable --check result / NDJSON failure, never an SDK stack trace.
import { createEmitter, createRedactor, publicMessage, PublicError, readInput, validateInput, SDK_VERSION } from './lib/protocol.mjs';

// stdout is exclusively the protocol. SDK/provider debug logging is not an
// output channel (and could contain request credentials), so discard console.
for (const name of Object.keys(console)) {
  if (typeof console[name] === 'function') console[name] = () => {};
}
const write = process.stdout.write.bind(process.stdout);
const cancelled = new AbortController();
let outputBroken = false;
process.stdout.on('error', () => {
  outputBroken = true;
  process.exitCode = 1;
  cancelled.abort(new PublicError('output_closed', '输出接收端已关闭。'));
});
const output = (line) => { if (!outputBroken) write(line); };
const terminate = () => cancelled.abort(new PublicError('cancelled', '运行已收到终止信号。'));
process.on('SIGTERM', terminate);
process.on('SIGINT', terminate);
let emit = createEmitter(output);

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === '--check') {
    try {
      const { checkRuntime } = await import('./lib/sdk.mjs');
      output(JSON.stringify(await checkRuntime()) + '\n');
      return 0;
    } catch (error) {
      output(JSON.stringify({ ready: false, runtime: 'pi-coding-agent', version: SDK_VERSION, error: publicMessage(error, 'PI SDK 无法导入；请检查 Node 版本并在运行目录执行 npm ci。') }) + '\n');
      return 1;
    }
  }
  let inputTimer;
  try {
    if (args.length) throw new PublicError('arguments', '运行仅支持无参数或 --check。');
    const inputTimeout = new AbortController();
    inputTimer = setTimeout(() => inputTimeout.abort(), 30000);
    const input = await readInput(process.stdin, AbortSignal.any([cancelled.signal, inputTimeout.signal]));
    clearTimeout(inputTimer);
    const config = validateInput(input);
    emit = createEmitter(output, createRedactor([config.model.api_key, config.model.base_url]));
    const { runLab } = await import('./lib/runtime.mjs');
    const result = await runLab(config, { signal: cancelled.signal, write: output });
    // Strings cannot be guaranteed to be zeroed in V8; release our references.
    config.model.api_key = '';
    if (input.model) input.model.api_key = '';
    return result.exitCode;
  } catch (error) {
    emit('error', 'coordinator', { message: publicMessage(error) });
    emit('report', 'coordinator', { text: '运行未完成，未生成有效模型报告。请根据错误修正配置或限制后重试。' });
    emit('complete', 'coordinator', { status: 'partial' });
    return error instanceof PublicError && error.code.startsWith('invalid') ? 2 : 1;
  } finally { clearTimeout(inputTimer); }
}

try { process.exitCode = await main(); }
catch {
  emit('error', 'coordinator', { message: '运行异常终止；内部错误详情已隐藏。' });
  emit('complete', 'coordinator', { status: 'partial' });
  process.exitCode = 1;
} finally {
  process.off('SIGTERM', terminate);
  process.off('SIGINT', terminate);
}
