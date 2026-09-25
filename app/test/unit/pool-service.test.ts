import { describe, expect, it } from 'vitest';
import { PoolInputError, PoolService } from '../../src/application/pool-service';
import { DEFAULT_POOL_KEY, TRASH_POOL_KEY } from '../../src/contracts/pool';
import { MemoryPoolCatalog } from '../helpers/memory-pool-catalog';

describe('PoolService', () => {
  it('replaces a pool with canonical entries and no forced trailing newline', async () => {
    const catalog = new MemoryPoolCatalog();
    const service = new PoolService(catalog);

    const result = await service.save(DEFAULT_POOL_KEY, '203.0.113.10:443\r\n203.0.113.11:443\n\n', 'replace');

    expect(result).toEqual({ ok: true, mode: 'replace', count: 2, added: 2, removed: 0, replaced: 0 });
    expect(catalog.data.get(DEFAULT_POOL_KEY)).toBe(
      '203.0.113.10:443,null,null,null\n203.0.113.11:443,null,null,null',
    );
  });

  it('appends entries while retaining known metadata and using the new comment', async () => {
    const catalog = new MemoryPoolCatalog({
      [DEFAULT_POOL_KEY]: '203.0.113.10:443,AS64500,US,v4 # old',
    });
    const service = new PoolService(catalog);

    const result = await service.save(DEFAULT_POOL_KEY, '203.0.113.10:443,null,null,null # new', 'append');

    expect(result).toMatchObject({ mode: 'append', count: 1, added: 0 });
    expect(catalog.data.get(DEFAULT_POOL_KEY)).toBe('203.0.113.10:443,AS64500,US,v4 # new');
  });

  it('removes selected entries without rewriting unrelated entries', async () => {
    const catalog = new MemoryPoolCatalog({
      [DEFAULT_POOL_KEY]: '203.0.113.10:443,AS64500,US,v4 # keep\n203.0.113.11:443 # drop',
    });

    const result = await new PoolService(catalog).save(DEFAULT_POOL_KEY, '203.0.113.11', 'remove');

    expect(result).toEqual({ ok: true, mode: 'remove', count: 1, added: 0, removed: 1, replaced: 0 });
    expect(catalog.data.get(DEFAULT_POOL_KEY)).toBe('203.0.113.10:443,AS64500,US,v4 # keep');
  });

  it('creates, renames and deletes numbered pools only', async () => {
    const catalog = new MemoryPoolCatalog();
    const service = new PoolService(catalog);

    const created = await service.create('香港池');
    expect(created).toEqual({ key: 'ip_pool_001', name: '香港池', count: 0 });

    await service.rename(created.key, 'HK');
    expect(catalog.names.get(created.key)).toBe('HK');

    await service.remove(created.key);
    expect(catalog.removed).toEqual([created.key]);
    await expect(service.remove(DEFAULT_POOL_KEY)).rejects.toThrow('只能删除编号 IP 池');
    await expect(service.remove(TRASH_POOL_KEY)).rejects.toThrow('只能删除编号 IP 池');
  });

  it('normalizes order with default first and trash last', async () => {
    const catalog = new MemoryPoolCatalog({
      'ip_pool_001': '',
      'ip_pool_002': '',
    });

    await new PoolService(catalog).saveOrder([
      TRASH_POOL_KEY,
      'ip_pool_002',
      DEFAULT_POOL_KEY,
      'ip_pool_001',
    ]);

    expect(catalog.order).toEqual([DEFAULT_POOL_KEY, 'ip_pool_002', 'ip_pool_001', TRASH_POOL_KEY]);
  });

  it('restores trash to its source pool and strips the trash comment', async () => {
    const catalog = new MemoryPoolCatalog({
      'ip_pool_001': '',
      [TRASH_POOL_KEY]: '203.0.113.10:443,AS64500,US,v4 # dead 2026-09-25 来自 ip_pool_001',
    });
    const service = new PoolService(catalog);

    const result = await service.restoreTrash(['203.0.113.10:443'], true);

    expect(result).toEqual({ ok: true, restored: 1, restoredByPool: { ip_pool_001: 1 } });
    expect(catalog.data.get('ip_pool_001')).toBe('203.0.113.10:443,AS64500,US,v4');
    expect(catalog.data.get(TRASH_POOL_KEY)).toBe('');
    await service.clearTrash();
    expect(catalog.data.get(TRASH_POOL_KEY)).toBe('');
  });

  it('falls back to the selected pool when the trash source no longer exists', async () => {
    const catalog = new MemoryPoolCatalog({
      [TRASH_POOL_KEY]: '203.0.113.11:443 # dead 来自 ip_pool_999',
    });

    await new PoolService(catalog).restoreTrash(['203.0.113.11:443'], true);

    expect(catalog.data.get(DEFAULT_POOL_KEY)).toBe('203.0.113.11:443,null,null,null');
  });

  it('rejects invalid keys, oversized content and empty appends', async () => {
    const service = new PoolService(new MemoryPoolCatalog());

    await expect(service.read('app_config')).rejects.toBeInstanceOf(PoolInputError);
    await expect(service.save('ip_pool_trash/../app_config', 'x')).rejects.toBeInstanceOf(PoolInputError);
    await expect(service.save(DEFAULT_POOL_KEY, 'x'.repeat(512_001))).rejects.toBeInstanceOf(PoolInputError);
    await expect(service.save(DEFAULT_POOL_KEY, 42)).rejects.toBeInstanceOf(PoolInputError);
    await expect(service.save(DEFAULT_POOL_KEY, '   ', 'append')).rejects.toThrow('没有有效 IP');
  });
});
