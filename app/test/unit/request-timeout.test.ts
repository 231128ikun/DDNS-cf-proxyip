import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { createRequestTimeout, waitWithSignal } from '../../src/util/request-timeout';

beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());

it('distinguishes its own deadline from caller cancellation and cleans timers', async () => {
  const caller = new AbortController();
  const timeout = createRequestTimeout(10, caller.signal);
  await vi.advanceTimersByTimeAsync(10);
  expect(timeout.signal.aborted).toBe(true);
  expect(timeout.didTimeout()).toBe(true);
  caller.abort();
  expect(timeout.didTimeout()).toBe(false);
  timeout.cleanup();
  expect(vi.getTimerCount()).toBe(0);
});

it('preserves an already cancelled caller reason and never calls it a local timeout', async () => {
  const caller = new AbortController();
  caller.abort('cancelled');
  const timeout = createRequestTimeout(10, caller.signal);
  expect(timeout.signal.reason).toBe('cancelled');
  expect(timeout.didTimeout()).toBe(false);
  timeout.cleanup();
  await vi.advanceTimersByTimeAsync(20);
  expect(timeout.didTimeout()).toBe(false);
});

it('stops waiting for a hung operation and consumes a late rejection', async () => {
  let reject!: (error: Error) => void;
  const task = new Promise<never>((_, fail) => { reject = fail; });
  const timeout = createRequestTimeout(10);
  const pending = waitWithSignal(task, timeout.signal).catch(error => error);
  await vi.advanceTimersByTimeAsync(10);
  expect(await pending).toBe(timeout.signal.reason);
  reject(new Error('late failure'));
  await Promise.resolve();
  timeout.cleanup();
  expect(vi.getTimerCount()).toBe(0);
});

it('removes its abort listener after normal completion', async () => {
  const caller = new AbortController();
  const remove = vi.spyOn(caller.signal, 'removeEventListener');
  expect(await waitWithSignal(Promise.resolve(42), caller.signal)).toBe(42);
  expect(remove).toHaveBeenCalledWith('abort', expect.any(Function));
});

it('rejects immediately with a cancelled signal while still consuming the operation', async () => {
  const caller = new AbortController();
  caller.abort('cancelled');
  await expect(waitWithSignal(Promise.reject(new Error('late failure')), caller.signal)).rejects.toBe('cancelled');
});
