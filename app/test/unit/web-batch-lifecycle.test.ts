import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { ConfigResponse } from '../../src/contracts/config';
import type { PoolCheckItemResponse, PoolCheckProgressEvent, PoolCheckResponse } from '../../src/contracts/pool-check';
import type { ApiClient } from '../../web/src/api/client';

const hooks = vi.hoisted(() => {
  let slots: unknown[] = [];
  let cursor = 0;
  return {
    reset: () => { slots = []; cursor = 0; },
    begin: () => { cursor = 0; },
    useState: (initial: unknown) => {
      const index = cursor++;
      if (!(index in slots)) slots[index] = initial;
      return [slots[index], (next: unknown) => { slots[index] = next; }];
    },
    useRef: (initial: unknown) => {
      const index = cursor++;
      if (!(index in slots)) slots[index] = { current: initial };
      return slots[index];
    },
  };
});
vi.mock('preact/hooks', () => ({ ...hooks, useEffect: () => undefined, useCallback: (callback: unknown) => callback }));
vi.mock('../../web/src/state/batch-resume', async importOriginal => {
  const actual = await importOriginal<typeof import('../../web/src/state/batch-resume')>();
  return { ...actual, createBatchSource: vi.fn(actual.createBatchSource) };
});
const hookPath = '../../web/src/state/use-batch-check';
const { useBatchCheck } = await import(hookPath);
const { createBatchSource } = await import('../../web/src/state/batch-resume');

function item(address: string): PoolCheckItemResponse {
  return { address, status: 'alive', exitFamily: 'ipv4', line: address };
}
function setup() {
  const runs: { signal: AbortSignal | undefined; progress: ((event: PoolCheckProgressEvent) => void) | undefined; finish: () => void; text: string }[] = [];
  const client = { checkBatch: vi.fn((text: string, signal?: AbortSignal, progress?: (event: PoolCheckProgressEvent) => void) =>
    new Promise<PoolCheckResponse>(resolve => runs.push({ text, signal, progress,
      finish: () => resolve({ total: 0, alive: 0, dead: 0, unknown: 0, items: [], invalid: [] }) }))) };
  const options = { client: client as unknown as ApiClient, config: { status: 'ready' as const, data: {} as ConfigResponse },
    webCheckConcurrency: 2, notify: vi.fn(), appendConsoleLog: vi.fn(), onInterrupt: vi.fn() };
  const render = () => { hooks.begin(); return useBatchCheck(options); };
  const progress = (run: number, sourceIndex: number, address: string, sourceComplete = true) => runs[run]!.progress?.({
    type: 'progress', completed: sourceIndex + 1, total: 1000, sourceIndex, sourceComplete, item: item(address),
  });
  return { render, runs, progress, client };
}
beforeEach(() => { hooks.reset(); vi.mocked(createBatchSource).mockClear(); });

describe('batch source lifecycle', () => {
  it('creates one source snapshot for 1000 progress events', async () => {
    const ui = setup();
    ui.render().replaceIpText(Array.from({ length: 1000 }, (_, index) => `node-${index}.example.com`).join('\n'));
    ui.render().handleCheckBatch();
    expect(createBatchSource).toHaveBeenCalledTimes(1);
    for (let index = 0; index < 1000; index++) ui.progress(0, index, `node-${index}.example.com:443`);
    const state = ui.render();
    expect(state.batchReport.items).toHaveLength(1000);
    expect(state.batchReport.incomplete).toEqual([]);
    expect(createBatchSource).toHaveBeenCalledTimes(1);
    ui.runs[0]!.finish();
    await Promise.resolve();
    expect(ui.render().batch.status).toBe('ready');
    expect(createBatchSource).toHaveBeenCalledTimes(1);
  });

  it('reuses the original source for cancellation and replaces a partial domain group on resume', async () => {
    const ui = setup();
    ui.render().replaceIpText('edge.example.com\n203.0.113.20:443');
    ui.render().handleCheckBatch();
    ui.progress(0, 0, '203.0.113.10:443', false);
    ui.render().handleStopBatch();
    expect(ui.runs[0]!.signal?.aborted).toBe(true);
    expect(ui.render().batchReport.incomplete).toEqual(['edge.example.com', '203.0.113.20:443']);
    ui.render().handleResumeBatch();
    expect(ui.runs[1]!.text).toBe('edge.example.com\n203.0.113.20:443');
    expect(ui.render().batchReport.items).toEqual([]);
    expect(createBatchSource).toHaveBeenCalledTimes(1);
    ui.progress(0, 1, '203.0.113.99:443');
    ui.runs[0]!.finish();
    await Promise.resolve();
    expect(ui.render().checkingBatch).toBe(true);
    ui.progress(1, 0, '203.0.113.11:443');
    ui.progress(1, 1, '203.0.113.20:443');
    ui.runs[1]!.finish();
    await Promise.resolve();
    expect(ui.render().batchReport.items.map((entry: PoolCheckItemResponse) => entry.address))
      .toEqual(['203.0.113.11:443', '203.0.113.20:443']);
  });

  it('discards the cached source and ignores old results when input is replaced', async () => {
    const ui = setup();
    ui.render().replaceIpText('203.0.113.10:443');
    ui.render().handleCheckBatch();
    ui.render().replaceIpText('203.0.113.20:443');
    ui.progress(0, 0, '203.0.113.10:443');
    ui.runs[0]!.finish();
    await Promise.resolve();
    expect(ui.render().batchReport).toBeNull();
    ui.render().handleCheckBatch();
    expect(createBatchSource).toHaveBeenCalledTimes(2);
    expect(ui.runs[1]!.text).toBe('203.0.113.20:443');
  });
});
