import { describe, expect, it, vi } from 'vitest';
import { PoolService } from '../../src/application/pool-service';
import { CheckProxy } from '../../src/application/check-proxy';
import { CheckTarget } from '../../src/application/check-target';
import { ResolveTarget } from '../../src/application/resolve-target';
import { createHttpApp } from '../../src/transport/http';
import { createWorker } from '../../src/worker';
import { ApiClient } from '../../web/src/api/client';
import { MemoryPoolCatalog } from '../helpers/memory-pool-catalog';
import { DEFAULT_POOL_KEY } from '../../src/contracts/pool';

const initial = '203.0.113.10:443,AS64500,JP,v4 # old';
const input = '203.0.113.11:443';

function setup() {
  const catalog = new MemoryPoolCatalog({ [DEFAULT_POOL_KEY]: initial });
  const writes = vi.spyOn(catalog, 'write');
  const requests: unknown[] = [];
  const app = createHttpApp({ version: 'fixture', pools: new PoolService(catalog),
    checkTarget: new CheckTarget({ checkProxy: new CheckProxy({ name: 'unused', probe: async () => { throw new Error('Must not probe'); } }),
      resolver: new ResolveTarget({ query: async () => ({ ok: true, values: [] }) }) }),
  });
  const client = new ApiClient({ fetchImpl: async (url, init) => {
    if (typeof init?.body === 'string') requests.push(JSON.parse(init.body));
    return app.request(String(url), init);
  } });
  return { catalog, writes, requests, app, client };
}

describe('optional pool write receipts', () => {
  it('keeps the legacy request and exact response when no receipt is requested', async () => {
    const { client, requests } = setup();
    expect(await client.savePool(DEFAULT_POOL_KEY, input, 'append')).toEqual({ ok: true, mode: 'append', count: 2, added: 1, removed: 0, replaced: 0 });
    expect(requests).toEqual([{ content: input, mode: 'append' }]);
  });

  it('returns the accepted normalized content only after the requested write succeeds', async () => {
    const { client, catalog, writes, requests } = setup();
    const saved = await client.savePool(DEFAULT_POOL_KEY, input, 'append', undefined, true);
    expect(saved.receipt).toEqual({ poolKey: DEFAULT_POOL_KEY, content: initial + '\n203.0.113.11:443,null,null,null', written: true });
    expect(saved.receipt?.content).toBe(catalog.data.get(DEFAULT_POOL_KEY));
    expect(writes).toHaveBeenCalledTimes(1);
    expect(requests).toEqual([{ content: input, mode: 'append', returnReceipt: true }]);
  });

  it('does not claim a new write for an unchanged read snapshot', async () => {
    const { client, writes } = setup();
    const saved = await client.savePool(DEFAULT_POOL_KEY, initial, 'append', undefined, true);
    expect(saved.receipt).toEqual({ poolKey: DEFAULT_POOL_KEY, content: initial, written: false });
    expect(writes).not.toHaveBeenCalled();
  });

  it('rejects a malformed receipt directive before storage writes', async () => {
    const { app, writes } = setup();
    const response = await app.request('/api/pools/ip_pool_default', { method: 'PUT', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ content: input, mode: 'append', returnReceipt: 'yes' }) });
    expect(response.status).toBe(400);
    expect(writes).not.toHaveBeenCalled();
  });

  it('does not return a successful receipt when a write throws', async () => {
    const { client, writes } = setup();
    const errorLog = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    writes.mockRejectedValueOnce(new Error('fixture KV write failed'));
    try { await expect(client.savePool(DEFAULT_POOL_KEY, input, 'append', undefined, true)).rejects.toMatchObject({ status: 500 }); }
    finally { errorLog.mockRestore(); }
  });

  it('returns its accepted value even when a following real Worker KV read remains stale', async () => {
    const accepted = new Map<string, string>();
    const put = vi.fn(async (key: string, content: string) => { accepted.set(key, content); });
    const kv = { get: async (key: string) => key === 'app_config' ? JSON.stringify({ checkApi: '', checkApiBackup: '' })
      : key === DEFAULT_POOL_KEY ? initial : null, put } as unknown as KVNamespace;
    const client = new ApiClient({ fetchImpl: async (url, init) => {
      const worker = createWorker();
      const request = new Request(new URL(String(url), 'https://worker.example'), init) as Parameters<NonNullable<typeof worker.fetch>>[0];
      return worker.fetch!(request, { IP_DATA: kv }, {} as ExecutionContext);
    } });
    const saved = await client.savePool(DEFAULT_POOL_KEY, input, 'append', undefined, true);
    expect(saved.receipt?.written).toBe(true);
    expect(saved.receipt?.content).toBe(accepted.get(DEFAULT_POOL_KEY));
    expect(saved.receipt?.content).toContain('203.0.113.11:443');
    expect((await client.readPool(DEFAULT_POOL_KEY)).content).toBe(initial);
    expect(put).toHaveBeenCalledTimes(1);
  });
});
