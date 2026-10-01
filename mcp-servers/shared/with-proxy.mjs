#!/usr/bin/env node
// 在单个子进程中使用共享住宅代理；不修改父进程、系统代理或其他 Agent。
import { spawn } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { loadProxyConfig, ProxyPool } from './proxy-pool.mjs';

export function parseArguments(args) {
  const separator = args.indexOf('--');
  if (separator < 0 || !args[separator + 1]) throw new Error('用法: node with-proxy.mjs [--country US] [--protocol http|socks5] -- command args...');
  const options = {};
  for (let i = 0; i < separator; i += 2) {
    if (!['--country', '--protocol'].includes(args[i]) || !args[i + 1] || i + 1 >= separator) throw new Error('无效代理启动参数');
    options[args[i].slice(2)] = args[i + 1];
  }
  if (options.country && !/^[a-zA-Z]{2}$/.test(options.country)) throw new Error('country 必须是两字母国家代码');
  if (options.protocol && !['http', 'https', 'socks5', 'socks5h'].includes(options.protocol)) throw new Error('无效上游代理协议');
  return { options, command: args[separator + 1], args: args.slice(separator + 2) };
}

export async function runWithProxy(args = process.argv.slice(2)) {
  const parsed = parseArguments(args);
  const config = { ...loadProxyConfig(), ...(parsed.options.protocol ? { protocol: parsed.options.protocol } : {}) };
  const pool = new ProxyPool(config);
  let child;
  const forward = signal => () => child?.kill(signal);
  const interrupt = forward('SIGINT'); const terminate = forward('SIGTERM');
  try {
    const lease = await pool.acquire({ country: parsed.options.country });
    const env = { ...process.env, ...lease.env, http_proxy: lease.proxy_url, https_proxy: lease.proxy_url,
      all_proxy: lease.proxy_url, no_proxy: lease.env.NO_PROXY };
    delete env.CYBERSTRIKE_PROXY_PASSWORD; delete env.CYBERSTRIKE_PROXY_USERNAME_TEMPLATE;
    process.on('SIGINT', interrupt); process.on('SIGTERM', terminate);
    return await new Promise((resolve, reject) => {
      child = spawn(parsed.command, parsed.args, { env, stdio: 'inherit', shell: false });
      child.on('error', reject);
      child.on('exit', (code, signal) => resolve(code ?? (signal === 'SIGINT' ? 130 : 1)));
    });
  } finally {
    process.removeListener('SIGINT', interrupt); process.removeListener('SIGTERM', terminate);
    await pool.close();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { process.exitCode = await runWithProxy(); }
  catch { process.stderr.write('按需代理启动失败，请检查参数、共享配置与命令路径；凭据不会打印。\n'); process.exitCode = 1; }
}
