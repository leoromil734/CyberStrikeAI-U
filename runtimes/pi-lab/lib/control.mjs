import { PublicError } from './protocol.mjs';

export function cancelled() {
  return new PublicError('cancelled', '运行已取消。');
}

export function checkAbort(signal) {
  if (signal?.aborted) throw signal.reason instanceof PublicError ? signal.reason : cancelled();
}

export function combineSignals(...signals) {
  return AbortSignal.any(signals.filter(Boolean));
}

// Abort waiters too: a cancelled run must not later start queued work.
export class Semaphore {
  constructor(limit) {
    this.limit = limit;
    this.active = 0;
    this.queue = [];
  }
  async acquire(signal) {
    checkAbort(signal);
    if (this.active < this.limit) {
      this.active++;
      return this.releaseOnce();
    }
    return new Promise((resolve, reject) => {
      const waiter = { resolve, reject, signal };
      waiter.abort = () => {
        const index = this.queue.indexOf(waiter);
        if (index >= 0) this.queue.splice(index, 1);
        reject(cancelled());
      };
      signal?.addEventListener('abort', waiter.abort, { once: true });
      this.queue.push(waiter);
    });
  }
  releaseOnce() {
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.active--;
      while (this.queue.length) {
        const waiter = this.queue.shift();
        waiter.signal?.removeEventListener('abort', waiter.abort);
        if (waiter.signal?.aborted) { waiter.reject(cancelled()); continue; }
        this.active++;
        waiter.resolve(this.releaseOnce());
        break;
      }
    };
  }
}

export async function abortable(promise, signal) {
  checkAbort(signal);
  let listener;
  const abort = new Promise((_, reject) => {
    listener = () => { try { checkAbort(signal); } catch (error) { reject(error); } };
    signal?.addEventListener('abort', listener, { once: true });
  });
  try { return await Promise.race([promise, abort]); }
  finally { signal?.removeEventListener('abort', listener); }
}

export async function settleWithin(promise, milliseconds = 1500) {
  let timer;
  try {
    await Promise.race([
      Promise.resolve(promise).catch(() => {}),
      new Promise((resolve) => { timer = setTimeout(resolve, milliseconds); }),
    ]);
  } finally { clearTimeout(timer); }
}

export class RunControl {
  constructor(limits, externalSignal, { maxTurns = limits.max_turns ?? 20 } = {}) {
    this.controller = new AbortController();
    this.signal = this.controller.signal;
    this.issues = new Map();
    this.sessions = new Set();
    this.aborts = new Set();
    this.turns = 0;
    this.maxTurns = maxTurns;
    this.externalSignal = externalSignal;
    this.externalAbort = () => this.cancel(new PublicError('cancelled', '运行已收到取消信号。'));
    externalSignal?.addEventListener('abort', this.externalAbort, { once: true });
    if (externalSignal?.aborted) this.externalAbort();
    this.timer = setTimeout(() => this.cancel(new PublicError('timeout', '运行达到总时间预算。')), limits.timeout_seconds * 1000);
  }
  mark(code, message) { this.issues.set(code, message); }
  takeTurn() {
    checkAbort(this.signal);
    if (this.turns >= this.maxTurns) throw new PublicError('turn_budget', '运行达到模型轮次预算。');
    this.turns++;
    if (this.turns === this.maxTurns) this.mark('turn_budget', '运行达到模型轮次预算。');
  }
  abortSession(session) {
    try {
      const promise = Promise.resolve(session.abort()).catch(() => {});
      this.aborts.add(promise);
      promise.finally(() => this.aborts.delete(promise));
    } catch { /* Cancellation must continue through every session. */ }
  }
  add(session) {
    this.sessions.add(session);
    if (this.signal.aborted) this.abortSession(session);
  }
  cancel(reason = cancelled()) {
    if (this.signal.aborted) return;
    this.mark(reason.code, reason.message);
    this.controller.abort(reason);
    for (const session of this.sessions) this.abortSession(session);
  }
  async close() {
    clearTimeout(this.timer);
    this.externalSignal?.removeEventListener('abort', this.externalAbort);
    for (const session of this.sessions) this.abortSession(session);
    await settleWithin(Promise.allSettled([...this.aborts]));
    await Promise.allSettled([...this.sessions].map((session) => Promise.resolve().then(() => session.dispose())));
    this.sessions.clear();
  }
}
