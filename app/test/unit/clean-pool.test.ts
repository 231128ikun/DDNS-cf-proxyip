import { failingNativeProbe } from '../helpers/native-probe';
import { ExternalApiProbeAdapter } from '../../src/adapters/probe/external-api';
import { describe, expect, it, vi } from 'vitest';

import { KvPoolRepository } from '../../src/adapters/storage/kv-pool-repository';
import { DEFAULT_POOL_KEY, TRASH_POOL_KEY } from '../../src/contracts/pool';
import { alive, dead, unknown, type ProbeResult } from '../../src/domain/probe-result';
import type { ProxyTarget } from '../../src/domain/proxy-target';
import type { PoolRepository, TrashCandidate } from '../../src/ports/pool-repository';
import type { ProbeAdapter } from '../../src/ports/probe';
import { MemoryPoolCatalog } from '../helpers/memory-pool-catalog';
import { cleaningClient } from '../helpers/cleaning-client';

/** 按地址前缀给出确定结论：`dead.` 判失效，`flaky.` 模拟探针异常，其余可用。 */
class AddressingProbeAdapter implements ProbeAdapter {
  readonly name = 'addressing';

  async probe(target: ProxyTarget): Promise<ProbeResult> {
    const authority = target.authority ?? '';
    if (authority.startsWith('flaky.')) return unknown(target, 'NETWORK_ERROR', 'network error');
    if (authority.startsWith('dead.')) return dead(target, { code: 'connect-refused' });
    return alive(target, { endpoint: 'fake', exitIp: '198.51.100.8', exitFamily: 'ipv4' });
  }
}

class RecordingTrashRepository implements PoolRepository {
  readonly batches: (readonly TrashCandidate[])[] = [];

  async load(): Promise<string> {
    return '';
  }

  async save(): Promise<void> {}

  async addToTrash(entries: readonly TrashCandidate[]): Promise<void> {
    this.batches.push([...entries]);
  }
}

function createCleaner(catalog: MemoryPoolCatalog) {
  const trash = new RecordingTrashRepository();
  const adapter = new AddressingProbeAdapter();
  return { ...cleaningClient(catalog, trash, adapter), trash, adapter };
}

const poolOf = (...addresses: readonly string[]): string => addresses.join('\n');

describe('一键洗库', () => {
  it('独立注释不误判为异常，清理后保留标题和有效条目备注', async () => {
    const catalog = new MemoryPoolCatalog({ [DEFAULT_POOL_KEY]: '# 池标题\nalive.example:443 # 保留备注\ndead.example:443' });
    const { client, trash } = createCleaner(catalog);
    expect(await client.cleanPool(DEFAULT_POOL_KEY)).toMatchObject({checked:2, kept:1, trashed:1, skipped:false});
    expect(catalog.data.get(DEFAULT_POOL_KEY)).toContain('# 池标题\nalive.example:443');
    expect(catalog.data.get(DEFAULT_POOL_KEY)).toContain('# 保留备注');
    expect(trash.batches).toHaveLength(1);
  });
  it('存在未确认项时不写回也不入桶', async () => {
    const catalog = new MemoryPoolCatalog({
      [DEFAULT_POOL_KEY]: poolOf('alive.example:443', 'dead.example:443', 'flaky.example:443'),
    });
    const { client, trash } = createCleaner(catalog);

    const report = await client.cleanPool(DEFAULT_POOL_KEY);

    expect(report).toMatchObject({ ok: true, checked: 3, skipped: true, unknown: 1, kept: 0, trashed: 0 });
    expect(catalog.data.get(DEFAULT_POOL_KEY)).toContain('dead.example:443');
    expect(trash.batches).toEqual([]);
  });

  it('失效项进垃圾桶，有效项写回原池', async () => {
    const catalog = new MemoryPoolCatalog({
      [DEFAULT_POOL_KEY]: poolOf('alive.example:443', 'dead.example:443'),
    });
    const { client, trash } = createCleaner(catalog);

    const report = await client.cleanPool(DEFAULT_POOL_KEY);

    expect(report).toMatchObject({ ok: true, checked: 2, kept: 1, trashed: 1, unknown: 0, skipped: false });
    const saved = catalog.data.get(DEFAULT_POOL_KEY) ?? '';
    expect(saved).toContain('alive.example:443');
    expect(saved).not.toContain('dead.example:443');

    const candidates = trash.batches.flat();
    expect(candidates).toHaveLength(1);
    expect(candidates[0]?.entryLine).toContain('dead.example:443');
    expect(candidates[0]?.reason).toBe('洗库失效');
    expect(candidates[0]?.poolKey).toBe(DEFAULT_POOL_KEY);
  });

  it('入桶失败时保留原池且不启动替换写入', async () => {
    const content = 'dead.example:443,AS64500,JP,v4 # 用户备注';
    const catalog = new MemoryPoolCatalog({ [DEFAULT_POOL_KEY]: content });
    const { client, trash } = createCleaner(catalog);
    const write = vi.spyOn(catalog, 'write');
    vi.spyOn(trash, 'addToTrash').mockRejectedValueOnce(new Error('trash write failed'));

    await expect(client.cleanPool(DEFAULT_POOL_KEY)).rejects.toThrow('internal error');

    expect(catalog.data.get(DEFAULT_POOL_KEY)).toBe(content);
    expect(write).not.toHaveBeenCalled();
    expect(trash.batches).toEqual([]);
  });

  it('原池替换失败时已留入桶副本，重试仍经过统一去重入口', async () => {
    const content = 'dead.example:443,AS64500,JP,v4 # 用户备注';
    const catalog = new MemoryPoolCatalog({ [DEFAULT_POOL_KEY]: content });
    const kv = {
      get: async (key: string) => catalog.data.get(key) ?? null,
      put: async (key: string, value: string) => { catalog.data.set(key, value); },
    } as unknown as KVNamespace;
    const trash = new KvPoolRepository(kv, { maxTrashSize: 1, now: () => new Date('2026-01-01T00:00:00Z') });
    const {client} = cleaningClient(catalog, trash, new AddressingProbeAdapter());
    const write = vi.spyOn(catalog, 'write').mockRejectedValueOnce(new Error('pool write failed'));

    await expect(client.cleanPool(DEFAULT_POOL_KEY)).rejects.toThrow('internal error');

    expect(catalog.data.get(DEFAULT_POOL_KEY)).toBe(content);
    const savedTrash = catalog.data.get(TRASH_POOL_KEY);
    expect(savedTrash).toContain('dead.example:443,AS64500,JP,v4 # 洗库失效');
    expect(savedTrash).toContain(`来自 ${DEFAULT_POOL_KEY}`);

    write.mockRestore();
    await expect(client.cleanPool(DEFAULT_POOL_KEY)).resolves.toMatchObject({ kept: 0, trashed: 1, skipped: false });
    expect(catalog.data.get(DEFAULT_POOL_KEY)).toBe('');
    expect(catalog.data.get(TRASH_POOL_KEY)).toBe(savedTrash);
  });

  it('垃圾桶全失效时成功返回零恢复，不写入任何池', async () => {
    const content = 'dead.example:443,AS64500,JP,v4 # 维护失效 来自 ip_pool_001';
    const catalog = new MemoryPoolCatalog({ [TRASH_POOL_KEY]: content });
    const { client, trash } = createCleaner(catalog);
    const write = vi.spyOn(catalog, 'write');

    await expect(client.cleanPool(TRASH_POOL_KEY)).resolves.toEqual({
      ok: true, poolKey: TRASH_POOL_KEY, checked: 1, kept: 0, trashed: 0, unknown: 0, skipped: false, remaining: 1,
    });
    expect(catalog.data.get(TRASH_POOL_KEY)).toBe(content);
    expect(write).not.toHaveBeenCalled();
    expect(trash.batches).toEqual([]);
  });

  it('空池直接报错，不触发检测', async () => {
    const { client } = createCleaner(new MemoryPoolCatalog({ [DEFAULT_POOL_KEY]: '' }));
    await expect(client.cleanPool(DEFAULT_POOL_KEY)).rejects.toThrow('没有有效地址');
  });

  it('洗垃圾桶只做恢复，不把失效项再写回桶里', async () => {
    const catalog = new MemoryPoolCatalog({
      [TRASH_POOL_KEY]: 'alive.example:443,null,null,v4 # 维护失效 2026-01-01 来自 ip_pool_001',
      ip_pool_001: '',
    });
    const { client, trash } = createCleaner(catalog);

    const report = await client.cleanPool(TRASH_POOL_KEY);

    expect(report).toMatchObject({ ok: true, kept: 1, trashed: 0, skipped: false });
    expect(catalog.data.get('ip_pool_001')).toContain('alive.example:443');
    expect(trash.batches).toEqual([]);
  });
});

describe('一键洗库完整性边界', () => {
  const entries = Array.from({ length: 200 }, (_, index) => `node-${index}.example:443,AS64500,JP,v4 # 用户备注${index}`);

  it.each([DEFAULT_POOL_KEY, TRASH_POOL_KEY])('超过 1000 个地址完整洗库或恢复 %s，不静默截断', async (poolKey) => {
    const content = Array.from({ length: 1205 }, (_, index) => `node-${index}.example:443,AS64500,JP,v4 # 来自 ip_pool_001`).join('\n');
    const catalog = new MemoryPoolCatalog({ [poolKey]: content, ip_pool_001: 'existing.example:443 # 原池' });
    const { client, trash, adapter, requests } = createCleaner(catalog);
    const write = vi.spyOn(catalog, 'write');
    const probe = vi.spyOn(adapter, 'probe');
    const exists = vi.spyOn(catalog, 'exists');

    await expect(client.cleanPool(poolKey)).resolves.toMatchObject({ checked: 1205, kept: 1205, skipped: false });
    expect(probe).toHaveBeenCalledTimes(1205);
    expect(requests.filter(request => request.path === '/api/check')).toHaveLength(1205);
    expect(requests.filter(request => request.path.startsWith('/api/pools'))).toEqual([
      {path:`/api/pools/${poolKey}`,method:'GET',probes:0}, {path:`/api/pools/${poolKey}/clean`,method:'POST',probes:0},
    ]);
    expect(write).toHaveBeenCalledTimes(poolKey === TRASH_POOL_KEY ? 2 : 0);
    expect(catalog.data.get(poolKey === TRASH_POOL_KEY ? 'ip_pool_001' : poolKey)).toContain('node-1204.example:443');
    if (poolKey === TRASH_POOL_KEY) expect(catalog.data.get(poolKey)).toBe('');
    expect(exists).toHaveBeenCalledTimes(poolKey === TRASH_POOL_KEY ? 1 : 0);
    expect(trash.batches).toEqual([]);
  });

  it('200 个有效地址正常洗库并保留全部元数据和备注', async () => {
    const catalog = new MemoryPoolCatalog({ [DEFAULT_POOL_KEY]: entries.join('\n') });
    const { client, trash } = createCleaner(catalog);
    expect(await client.cleanPool(DEFAULT_POOL_KEY)).toMatchObject({ checked: 200, kept: 200, skipped: false });
    expect(catalog.data.get(DEFAULT_POOL_KEY)).toBe(entries.join('\n'));
    expect(trash.batches).toEqual([]);
  });

  it('规范化重复地址不造成超限', async () => {
    const catalog = new MemoryPoolCatalog({ [DEFAULT_POOL_KEY]: [...entries, 'NODE-0.EXAMPLE', 'node-199.example:443'].join('\n') });
    const { client } = createCleaner(catalog);
    expect(await client.cleanPool(DEFAULT_POOL_KEY)).toMatchObject({ checked: 200, kept: 200, skipped: false });
  });

  it('第 200 个有效地址后的无效项阻止整池写回', async () => {
    const content = [...entries, '203.0.113.999:443'].join('\n');
    const catalog = new MemoryPoolCatalog({ [DEFAULT_POOL_KEY]: content });
    const { client, trash } = createCleaner(catalog);
    const write = vi.spyOn(catalog, 'write');
    expect(await client.cleanPool(DEFAULT_POOL_KEY)).toMatchObject({ checked: 200, unknown: 1, skipped: true });
    expect(write).not.toHaveBeenCalled();
    expect(catalog.data.get(DEFAULT_POOL_KEY)).toBe(content);
    expect(trash.batches).toEqual([]);
  });
});

it('洗库将复检后仍超时的节点通过统一 KV 入口入桶并移出原池', async () => {
  const timed = '203.0.113.10:443,AS64500,JP,v4 # 用户备注';
  const catalog = new MemoryPoolCatalog({ [DEFAULT_POOL_KEY]: [timed, '203.0.113.20:443 # 保留'].join('\n') });
  const kv = {
    get: async (key: string) => catalog.data.get(key) ?? null,
    put: async (key: string, value: string) => { catalog.data.set(key, value); },
  } as unknown as KVNamespace;
  const trash = new KvPoolRepository(kv, { maxTrashSize: 1, now: () => new Date('2026-11-03T00:00:00Z') });
  const probe = new ExternalApiProbeAdapter({ endpoints: [{ name: 'primary', urlTemplate: 'https://probe.example/?proxyip=' }], timeoutMs: 1000,
    fetchImpl: (async url => Response.json(String(url).includes('203.0.113.10')
      ? { success: false, message: 'tcp connect timeout' } : { success: true })) as typeof fetch });
  const {client} = cleaningClient(catalog, trash, probe);
  const addToTrash = vi.spyOn(trash, 'addToTrash');
  expect(await client.cleanPool(DEFAULT_POOL_KEY)).toMatchObject({ checked: 2, kept: 1, trashed: 1, unknown: 0, skipped: false });
  expect(addToTrash).toHaveBeenCalledTimes(1);
  expect(catalog.data.get(DEFAULT_POOL_KEY)).not.toContain('203.0.113.10');
  expect(catalog.data.get(DEFAULT_POOL_KEY)).toContain('203.0.113.20');
  expect(catalog.data.get(TRASH_POOL_KEY)).toContain('203.0.113.10:443,AS64500,JP,v4 # 洗库失效');
  expect(catalog.data.get(TRASH_POOL_KEY)).toContain('来自 ip_pool_default');
});

it.each([
  { success: false, message: 'TCP Loop detected, contact us if this doesn\'t seem right.' },
  { success: false, probes: { ipv4: { apiError: true, error: 'candidate timeout' } } },
])('洗库保留已知检测接口异常的原池且不入桶：%j', async payload => {
  const content = '203.0.113.10:443,AS64500,JP,v4 # 用户备注';
  const catalog = new MemoryPoolCatalog({ [DEFAULT_POOL_KEY]: content });
  const trash = new RecordingTrashRepository();
  const write = vi.spyOn(catalog, 'write');
  const fetchImpl = vi.fn(async () => Response.json(payload));
  const probe = new ExternalApiProbeAdapter({ endpoints: [{ name: 'primary', urlTemplate: 'https://probe.example/?proxyip=' }],
    timeoutMs: 1000, fetchImpl: fetchImpl as typeof fetch });
  const {client} = cleaningClient(catalog, trash, probe);

  expect(await client.cleanPool(DEFAULT_POOL_KEY)).toMatchObject({ checked: 1, kept: 0, trashed: 0, unknown: 1, skipped: true });
  expect(fetchImpl).toHaveBeenCalledTimes(2);
  expect(write).not.toHaveBeenCalled();
  expect(catalog.data.get(DEFAULT_POOL_KEY)).toBe(content);
  expect(trash.batches).toEqual([]);
});

describe('native probe cleaning boundary', () => {
  it.each([['loop', new Error('TCP Loop detected'), true], ['runtime', new TypeError('runtime unavailable'), true], ['candidate', new Error('connection refused'), false]] as const)('%s protects only detector failures', async (_label, error, skipped) => {
    const original = poolOf('203.0.113.10:443,AS64500,JP,v4 # note', '203.0.113.11:443');
    const catalog = new MemoryPoolCatalog({ [DEFAULT_POOL_KEY]: original });
    const trash = new RecordingTrashRepository();
    const {client} = cleaningClient(catalog, trash, failingNativeProbe(error));
    const report = await client.cleanPool(DEFAULT_POOL_KEY);
    expect(report.skipped).toBe(skipped);
    expect(catalog.data.get(DEFAULT_POOL_KEY)).toBe(skipped ? original : '');
    expect(trash.batches.flat().length).toBe(skipped ? 0 : 2);
  });
});
