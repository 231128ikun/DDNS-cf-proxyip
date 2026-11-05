import { describe, expect, it, vi } from 'vitest';
import { PoolService } from '../../src/application/pool-service';
import { CheckProxy } from '../../src/application/check-proxy';
import { CheckTarget } from '../../src/application/check-target';
import { ResolveTarget } from '../../src/application/resolve-target';
import { createHttpApp } from '../../src/transport/http';
import { ApiClient } from '../../web/src/api/client';
import { MemoryPoolCatalog } from '../helpers/memory-pool-catalog';

function setup() {
  const catalog = new MemoryPoolCatalog({ ip_pool_default: '# keep\n203.0.113.10:443,AS64500,JP,v4 # first\n203.0.113.10:8443,AS64500,JP,v4 # other port\n[2001:db8::1]:443,AS64500,JP,v6' });
  const write = vi.spyOn(catalog, 'write');
  const app = createHttpApp({ version: 'fixture', executionColo: 'HKG', pools: new PoolService(catalog),
    checkTarget: new CheckTarget({ checkProxy: new CheckProxy({ name: 'fixture', probe: async target => ({ status: 'alive', target, exits: [], exitFamily: 'unknown' }) }),
      resolver: new ResolveTarget({ query: async () => ({ ok: true, values: [] }) }) }) });
  const client = new ApiClient({ fetchImpl: async (url, init) => app.request(String(url), init) });
  return { catalog, write, app, client };
}
describe('pool input commands', () => {
  it('removes only matching address and port while preserving comments and other entries', async () => {
    const { client, catalog, write } = setup();
    const result = await client.savePool('ip_pool_default', '203.0.113.10:443\n[2001:db8::1]:443', 'remove', undefined, true);
    expect(result).toMatchObject({ removed: 2, count: 1, receipt: { written: true } });
    const text = catalog.data.get('ip_pool_default')!;
    expect(text).toContain('# keep'); expect(text).toContain('203.0.113.10:8443,AS64500,JP,v4 # other port');
    expect(text).not.toContain('203.0.113.10:443'); expect(text).not.toContain('[2001:db8::1]'); expect(write).toHaveBeenCalledTimes(1);
    expect(catalog.data.has('ip_pool_trash')).toBe(false);
  });
  it('rejects empty or malformed removals before writing', async () => {
    const { client, write } = setup();
    await expect(client.savePool('ip_pool_default', '', 'remove')).rejects.toMatchObject({ status: 400 });
    await expect(client.savePool('ip_pool_default', '???', 'remove')).rejects.toMatchObject({ status: 400 });
    expect(write).not.toHaveBeenCalled();
  });
  it('removes inventory preview and rejects public whole-pool replacement', async () => {
    const { app, write } = setup();
    expect((await app.request('/api/pools/ip_pool_default/preview', { method: 'POST' })).status).toBe(404);
    expect((await app.request('/api/pools/ip_pool_default', { method: 'PUT', body: JSON.stringify({ content: '', mode: 'replace' }) })).status).toBe(400);
    expect(write).not.toHaveBeenCalled();
  });
  it('returns the executing Worker colo independently from the proxy exit colo', async () => {
    const { client } = setup();
    expect(await client.health()).toMatchObject({ executionColo: 'HKG' });
    expect((await client.checkTarget('203.0.113.10:443')).items[0]?.result.executionColo).toBe('HKG');
  });
});
