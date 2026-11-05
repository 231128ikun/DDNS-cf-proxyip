import { expect, it, vi } from 'vitest';
import { alive, dead } from '../../src/domain/probe-result';
import type { PoolCheckResponse } from '../../src/contracts/pool-check';
import type { ProbeAdapter } from '../../src/ports/probe';
import { cleaningClient } from '../helpers/cleaning-client';
import { MemoryPoolCatalog } from '../helpers/memory-pool-catalog';
import { ApiClient } from '../../web/src/api/client';

const pool = 'ip_pool_default';
const path = `/api/pools/${pool}/clean`;
const text = 'dead.example:443\nalive.example:443';

function fixture(probe: ProbeAdapter['probe'], content = text) {
  const catalog = new MemoryPoolCatalog({[pool]:content});
  const write = vi.spyOn(catalog, 'write');
  const trash = {load:async () => '', save:async () => {}, addToTrash:vi.fn(async () => {})};
  return {...cleaningClient(catalog, trash, {name:'fixture', probe}), catalog, write, trash};
}

it('keeps the configured batch concurrency and commits after all progress', async () => {
  let active = 0, peak = 0;
  const source = Array.from({length:16}, (_, i) => `node-${i}.example:443`).join('\n');
  const {client, requests, write} = fixture(async target => {
    peak = Math.max(peak, ++active);
    await new Promise(resolve => setTimeout(resolve, 2));
    active--; return alive(target);
  }, source);
  const ordinary = await client.checkBatch(source, undefined, undefined, 3);
  expect(ordinary.total).toBe(16); expect(peak).toBe(3);
  expect(write).not.toHaveBeenCalled();
  peak = 0;
  const progress: number[] = [];
  await expect(client.cleanPool(pool, undefined, event => {
    expect(requests.some(item => item.path === path)).toBe(false);
    expect(write).not.toHaveBeenCalled();
    progress.push(event.completed);
  }, 3)).resolves.toMatchObject({checked:16, kept:16, skipped:false});
  expect(peak).toBe(3);
  expect(progress).toEqual(Array.from({length:16}, (_, i) => i + 1));
  expect(requests.at(-1)).toEqual({path, method:'POST', probes:0});
});

it('does not submit a cleaning commit after stopping the shared batch', async () => {
  const {client, requests, write, trash} = fixture(async target => dead(target));
  const stop = new AbortController();
  await expect(client.cleanPool(pool, stop.signal, () => stop.abort(), 1)).rejects.toThrow();
  expect(requests.filter(item => item.path === '/api/check')).toHaveLength(1);
  expect(requests.some(item => item.path === path)).toBe(false);
  expect(write).not.toHaveBeenCalled(); expect(trash.addToTrash).not.toHaveBeenCalled();
});

it('rejects changed inventory before any cleanup write', async () => {
  const {client, catalog, write, trash} = fixture(async target => dead(target));
  await expect(client.cleanPool(pool, undefined, () => catalog.data.set(pool, 'new.example:443'))).rejects.toThrow('库存已变化');
  expect(catalog.data.get(pool)).toBe('new.example:443');
  expect(write).not.toHaveBeenCalled(); expect(trash.addToTrash).not.toHaveBeenCalled();
});

const invalidReports: [string, (report: PoolCheckResponse) => unknown][] = [
  ['missing', report => ({...report, items:report.items.slice(1)})],
  ['duplicate', report => ({...report, items:[report.items[0], report.items[0]]})],
  ['foreign address', report => ({...report, items:[report.items[0], {...report.items[1], address:'outside.example:443'}]})],
  ['bad status', report => ({...report, items:[report.items[0], {...report.items[1], status:'failed'}]})],
];

it.each(invalidReports)('rejects a %s report without touching either pool', async (_label, change) => {
  const {client, request, write, trash} = fixture(async target => dead(target));
  const report = await client.checkBatch(text);
  const response = await request(path, {method:'POST', body:JSON.stringify({content:text, report:change(report)})});
  expect(response.status).toBe(400);
  expect(write).not.toHaveBeenCalled(); expect(trash.addToTrash).not.toHaveBeenCalled();
});

it('derives unknown safety from actual report items, ignoring a false summary', async () => {
  const {client, request, write, trash} = fixture(async target => dead(target));
  const report = await client.checkBatch(text);
  const response = await request(path, {method:'POST', body:JSON.stringify({content:text, report:{...report,
    items:[report.items[0], {...report.items[1], status:'unknown', code:'PROBE_API_ERROR'}], unknown:0}})});
  expect(response.status).toBe(200);
  await expect(response.json()).resolves.toMatchObject({skipped:true, unknown:1, trashed:0});
  expect(write).not.toHaveBeenCalled(); expect(trash.addToTrash).not.toHaveBeenCalled();
});

it('does not report a successful cleanup without a complete receipt', async () => {
  const {request} = fixture(async target => alive(target));
  const client = new ApiClient({fetchImpl:async (url, init) => String(url) === path
    ? Response.json({ok:true, poolKey:pool}) : request(url, init)});
  await expect(client.cleanPool(pool)).rejects.toThrow('未取得有效洗库回执');
});
