import { expect, it, vi } from 'vitest';
import { alive, dead, unknown } from '../../src/domain/probe-result';
import type { PoolCheckResponse } from '../../src/contracts/pool-check';
import type { ProbeAdapter } from '../../src/ports/probe';
import type { TrashCandidate } from '../../src/ports/pool-repository';
import { cleaningClient } from '../helpers/cleaning-client';
import { MemoryPoolCatalog } from '../helpers/memory-pool-catalog';
import { ApiClient } from '../../web/src/api/client';

const pool = 'ip_pool_default';
const path = `/api/pools/${pool}/clean`;
const text = 'dead.example:443\nalive.example:443';

function fixture(probe: ProbeAdapter['probe'], content = text) {
  const catalog = new MemoryPoolCatalog({[pool]:content});
  const write = vi.spyOn(catalog, 'write');
  const trash = {load:async () => '', save:async () => {}, addToTrash:vi.fn(async (_entries: readonly TrashCandidate[]) => {})};
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
  await expect(response.json()).resolves.toMatchObject({skipped:false, kept:1, unknown:1, trashed:1});
  expect(write).toHaveBeenCalledTimes(1);
  expect(trash.addToTrash).toHaveBeenCalledTimes(1);
  expect(trash.addToTrash.mock.calls[0]?.[0]).toEqual([expect.objectContaining({entryLine:expect.stringContaining('dead.example:443')})]);
});

it('uses inventory metadata and comments for unknown results instead of submitted lines', async () => {
  const content = '# 标题\nalive.example:443,AS64500,JP,v4 # 有效\n[2001:db8::1]:8443,AS64510,DE,v6 # 异常保留\n[2001:db8::1]:443,AS64511,FR,v6 # 失效';
  const { client, request, catalog, trash } = fixture(async target => target.host === 'alive.example'
    ? alive(target, { exits: [{ family: 'ipv4', ip: '198.51.100.42', asn: '64520', country: 'US' }] })
    : target.port === 8443 ? unknown(target, 'CANCELLED', '检测已取消') : dead(target), content);
  const report = await client.checkBatch(content.split('\n').slice(1).join('\n'));
  const response = await request(path, { method: 'POST', body: JSON.stringify({ content, report: { ...report, unknown: 0,
    items: report.items.map(item => ({ ...item, line: 'outside.example:443', asn: 'AS99999', country: 'CN' })) } }) });
  expect(response.status).toBe(200);
  expect(await response.json()).toMatchObject({ kept: 2, trashed: 1, unknown: 1, skipped: false });
  const saved = catalog.data.get(pool)!;
  expect(saved).toContain('# 标题');
  expect(saved).toContain('alive.example:443,AS64520,US,v4 # 有效');
  expect(saved).toContain('[2001:db8::1]:8443,AS64510,DE,v6 # 异常保留');
  expect(saved).not.toContain('[2001:db8::1]:443,');
  expect(saved).not.toContain('outside');
  expect(trash.addToTrash.mock.calls[0]?.[0]).toEqual([expect.objectContaining({ entryLine: '[2001:db8::1]:443,AS64511,FR,v6 # 失效' })]);
});

it('does not rewrite legacy inventory when every result is unknown', async () => {
  const content = '# 标题\nflaky.example:443,AS64500\n[2001:db8::1]:8443,AS64510,DE # 原备注';
  const { client, catalog, write, trash } = fixture(async target => unknown(target, 'CANCELLED', '检测已取消'), content);
  expect(await client.cleanPool(pool)).toMatchObject({ kept: 2, trashed: 0, unknown: 2, skipped: false });
  expect(catalog.data.get(pool)).toBe(content);
  expect(write).not.toHaveBeenCalled(); expect(trash.addToTrash).not.toHaveBeenCalled();
});

it('does not apply a complete mixed report if cancelled on the last progress event', async () => {
  const { client, requests, write, trash } = fixture(async target => target.host.startsWith('dead') ? dead(target)
    : unknown(target, 'PROBE_API_ERROR', '检测接口异常'));
  const stop = new AbortController();
  await expect(client.cleanPool(pool, stop.signal, event => { if (event.completed === event.total) stop.abort(); }, 1)).rejects.toThrow();
  expect(requests.filter(item => item.path === '/api/check')).toHaveLength(2);
  expect(requests.some(item => item.path === path)).toBe(false);
  expect(write).not.toHaveBeenCalled(); expect(trash.addToTrash).not.toHaveBeenCalled();
});

it('requires a remaining count in successful trash cleaning receipts', async () => {
  const trashPool = 'ip_pool_trash';
  const catalog = new MemoryPoolCatalog({ [trashPool]: 'alive.example:443' });
  const { request } = cleaningClient(catalog, { load: async () => '', save: async () => {}, addToTrash: async () => {} },
    { name: 'fixture', probe: async target => alive(target) });
  const client = new ApiClient({ fetchImpl: async (url, init) => String(url).endsWith('/clean')
    ? Response.json({ ok: true, poolKey: trashPool, checked: 1, kept: 0, trashed: 0, unknown: 0, skipped: false }) : request(url, init) });
  await expect(client.cleanPool(trashPool)).rejects.toThrow('未取得有效洗库回执');
});

it('does not report a successful cleanup without a complete receipt', async () => {
  const {request} = fixture(async target => alive(target));
  const client = new ApiClient({fetchImpl:async (url, init) => String(url) === path
    ? Response.json({ok:true, poolKey:pool}) : request(url, init)});
  await expect(client.cleanPool(pool)).rejects.toThrow('未取得有效洗库回执');
});
