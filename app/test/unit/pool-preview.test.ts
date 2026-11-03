import { describe, expect, it, vi } from 'vitest';
import { PoolService } from '../../src/application/pool-service';
import { CheckProxy } from '../../src/application/check-proxy';
import { CheckTarget } from '../../src/application/check-target';
import { ResolveTarget } from '../../src/application/resolve-target';
import { DEFAULT_POOL_KEY, TRASH_POOL_KEY } from '../../src/contracts/pool';
import { createHttpApp } from '../../src/transport/http';
import { ApiClient } from '../../web/src/api/client';
import { MemoryPoolCatalog } from '../helpers/memory-pool-catalog';

const initial = '203.0.113.10:443,AS64500,JP,v4 # old\n203.0.113.11:443,null,null,null';
const input = '203.0.113.10:443,null,null,null # new\n203.0.113.12:443';

function setup(content = initial, authKey = '') {
  const catalog = new MemoryPoolCatalog({ [DEFAULT_POOL_KEY]: content });
  const write = vi.spyOn(catalog, 'write');
  const probe = vi.fn(async () => { throw new Error('Preview must not probe'); });
  const app = createHttpApp({ version: 'fixture', authKey, pools: new PoolService(catalog),
    checkTarget: new CheckTarget({ checkProxy: new CheckProxy({ name: 'unused', probe }),
      resolver: new ResolveTarget({ query: async () => ({ ok: true, values: [] }) }) }),
  });
  const client = new ApiClient({ fetchImpl: async (url, init) => app.request(String(url), init) });
  return { catalog, write, probe, client, app };
}

describe('read-only pool mutation preview through the real client and route', () => {
  it.each([
    ['append', { currentCount: 2, count: 3, added: 1, updated: 1, removed: 0 }],
    ['replace', { currentCount: 2, count: 2, added: 1, updated: 1, removed: 1 }],
    ['remove', { currentCount: 2, count: 1, added: 0, updated: 0, removed: 1 }],
  ] as const)('previews %s without writing or probing', async (mode, expected) => {
    const { client, catalog, write, probe } = setup();
    const before = new Map(catalog.data);
    const preview = await client.previewPool(DEFAULT_POOL_KEY, input, mode);
    expect(preview).toMatchObject({ ok: true, poolKey: DEFAULT_POOL_KEY, mode, changed: true, ...expected });
    expect(preview.changes.map(change => change.kind).sort()).toEqual(mode === 'append' ? ['add', 'update'] : mode === 'replace' ? ['add', 'remove', 'update'] : ['remove']);
    expect(catalog.data).toEqual(before);
    expect(write).not.toHaveBeenCalled();
    expect(probe).not.toHaveBeenCalled();
  });

  it('uses the same normalization and merge rules on preview and commit', async () => {
    const { client, catalog, write } = setup();
    const preview = await client.previewPool(DEFAULT_POOL_KEY, input);
    expect(preview.mode).toBe('append');
    expect(preview.changes.find(item => item.kind === 'update')?.after).toBe('203.0.113.10:443,AS64500,JP,v4 # new');
    expect(write).not.toHaveBeenCalled();
    await client.savePool(DEFAULT_POOL_KEY, input, preview.mode);
    expect(catalog.data.get(DEFAULT_POOL_KEY)?.split('\n')).toHaveLength(preview.count);
    for (const change of preview.changes) if (change.after) expect(catalog.data.get(DEFAULT_POOL_KEY)).toContain(change.after);
  });

  it('reports unchanged data and formatting-only changes accurately', async () => {
    const canonical = setup();
    expect(await canonical.client.previewPool(DEFAULT_POOL_KEY, initial, 'replace')).toMatchObject({ changed: false, added: 0, updated: 0, removed: 0, changes: [] });
    const legacy = setup('203.0.113.10:443');
    expect(await legacy.client.previewPool(DEFAULT_POOL_KEY, '203.0.113.10:443', 'append')).toMatchObject({ changed: true, added: 0, updated: 0, removed: 0, changes: [] });
  });

  it('makes removal of unrecognized stored rows visible before replacement', async () => {
    const { client, catalog, write } = setup(initial + '\n203.0.113.999:443');
    expect(await client.previewPool(DEFAULT_POOL_KEY, input, 'replace')).toMatchObject({ unrecognized: { before: 1, after: 0 } });
    expect(await client.previewPool(DEFAULT_POOL_KEY, input, 'append')).toMatchObject({ unrecognized: { before: 1, after: 1 } });
    expect(catalog.data.get(DEFAULT_POOL_KEY)).toContain('203.0.113.999:443');
    expect(write).not.toHaveBeenCalled();
  });

  it('shares the existing auth, malformed input and trash restrictions', async () => {
    const { client, app, write } = setup();
    await expect(client.previewPool(TRASH_POOL_KEY, input)).rejects.toMatchObject({ status: 400 });
    await expect(client.previewPool(DEFAULT_POOL_KEY, '203.0.113.999:443')).rejects.toMatchObject({ status: 400 });
    const badJson = await app.request('/api/pools/ip_pool_default/preview', { method: 'POST', body: '{bad', headers: { 'content-type': 'application/json' } });
    expect(badJson.status).toBe(400);
    const protectedApp = setup(initial, 'fixture-panel-key');
    await expect(protectedApp.client.previewPool(DEFAULT_POOL_KEY, input)).rejects.toMatchObject({ status: 401 });
    expect(write).not.toHaveBeenCalled();
    expect(protectedApp.write).not.toHaveBeenCalled();
  });
});

it('previews more than 200 addresses without applying the probe request limit or writing data', async () => {
  const { client, write, probe } = setup('');
  const text = Array.from({ length: 201 }, (_, index) => '203.0.113.' + (index + 1) + ':443').join('\n');
  expect(await client.previewPool(DEFAULT_POOL_KEY, text, 'append')).toMatchObject({ currentCount: 0, count: 201, added: 201 });
  expect(write).not.toHaveBeenCalled();
  expect(probe).not.toHaveBeenCalled();
});

it('reports standalone comment changes separately from address or malformed-row changes', async () => {
  const { client, write } = setup('# user heading\n' + initial);
  expect(await client.previewPool(DEFAULT_POOL_KEY, input, 'replace')).toMatchObject({ standaloneComments: { before: 1, after: 0 }, unrecognized: { before: 0, after: 0 } });
  expect(await client.previewPool(DEFAULT_POOL_KEY, input, 'append')).toMatchObject({ standaloneComments: { before: 1, after: 1 } });
  expect(write).not.toHaveBeenCalled();
});
