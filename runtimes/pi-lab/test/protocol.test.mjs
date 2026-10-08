import test from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { spawn } from 'node:child_process';
import { join } from 'node:path';
import { readInput, validateInput, createEmitter, createRedactor, MAX_INPUT_BYTES, EVENT_TYPES } from '../lib/protocol.mjs';
import { root, input, temporaryDirectory } from '../test-support/fixtures.mjs';

export async function cli(args = [], stdin = '', cwd = root, env = process.env) {
  const child = spawn(process.execPath, [join(root, 'runner.mjs'), ...args], { cwd, env, stdio: ['pipe', 'pipe', 'pipe'] });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (chunk) => { stdout += chunk; });
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  child.stdin.on('error', () => {});
  child.stdin.end(stdin);
  const code = await new Promise((resolve, reject) => { child.once('error', reject); child.once('close', resolve); });
  return { code, stdout, stderr };
}

test('one JSON line followed by EOF, no multiline/second payload, input bound', async () => {
  const valid = JSON.stringify(input());
  assert.equal((await readInput(Readable.from([valid + '\r\n']))).run_id, 'offline-test');
  assert.equal((await readInput(Readable.from([valid]))).run_id, 'offline-test');
  for (const invalid of ['', '{}\n{}\n', '{\n}\n', '{}\n\n', 'not JSON']) {
    await assert.rejects(readInput(Readable.from([invalid])));
  }
  await assert.rejects(readInput(Readable.from([Buffer.alloc(MAX_INPUT_BYTES + 1, 65)])), /1 MiB/);
});

test('strict model and limits validation, no error reflects secrets', () => {
  assert.equal(validateInput(input()).model.provider, 'openai');
  for (const bad of [
    input({ model: { ...input().model, api_key: '' } }),
    input({ model: { ...input().model, provider: 'environment' } }),
    input({ model: { ...input().model, base_url: 'https://secret:KEY@models.invalid' } }),
    input({ limits: { max_parallel: 0 } }), input({ limits: { max_agents: 100000 } }),
    input({ scope: [] }), input({ scope: ['file:///secret'] }),
  ]) assert.throws(() => validateInput(bad));
});

test('events are NDJSON, redact credentials, complete is final and unique', () => {
  const key = input().model.api_key;
  const output = [];
  const emit = createEmitter((line) => output.push(line), createRedactor([key, input().model.base_url]));
  emit('message', 'coordinator', { text: `${key}\n${encodeURIComponent(key)} ${Buffer.from(key).toString('base64')} ${input().model.base_url}`, api_key: key });
  emit('complete', 'coordinator', { status: 'partial' });
  emit('error', 'coordinator', { message: 'late' });
  assert.equal(output.length, 2);
  for (const line of output) {
    assert.equal(line.split('\n').length, 2);
    const event = JSON.parse(line);
    assert.deepEqual(Object.keys(event).sort(), ['agent_id', 'data', 'type']);
    assert(EVENT_TYPES.has(event.type));
  }
  assert(!output.join('').includes(key));
  assert(!output.join('').includes(input().model.base_url));
});

test('--check imports exact SDK without stdin or any model call', async (t) => {
  const cwd = await temporaryDirectory(t);
  const checked = await cli(['--check'], '', cwd);
  assert.equal(checked.code, 0, checked.stderr + checked.stdout);
  assert.deepEqual(JSON.parse(checked.stdout), { ready: true, runtime: 'pi-coding-agent', version: '1.0.4' });
  assert.equal(checked.stdout.trim().split('\n').length, 1);
  assert.equal(checked.stderr, '');
});

test('redaction preserves protocol enums and IDs even when a key equals those literals', () => {
  const lines = [];
  const emit = createEmitter((line) => lines.push(line), createRedactor(['coordinator', 'completed']));
  emit('complete', 'coordinator', { status: 'completed' });
  assert.deepEqual(JSON.parse(lines[0]), { type: 'complete', agent_id: 'coordinator', data: { status: 'completed' } });
});

test('CLI rejects malformed input with error and final partial, no stack trace', async () => {
  const checked = await cli([], '{not-json}\n');
  assert.notEqual(checked.code, 0);
  const events = checked.stdout.trim().split('\n').map((line) => JSON.parse(line));
  assert.equal(events[0].type, 'error');
  assert.deepEqual(events.at(-1), { type: 'complete', agent_id: 'coordinator', data: { status: 'partial' } });
  assert.equal(checked.stderr, '');
});
