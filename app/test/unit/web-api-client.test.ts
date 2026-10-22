import { describe, expect, it, vi } from 'vitest';
import { ApiClient } from '../../web/src/api/client';

describe('web API client', () => {
  it('uses the shared check contract without adding a panel key header', async () => {
    const fetchMock = vi.fn(async function (this: unknown, _input: RequestInfo | URL, init?: RequestInit) {
      expect(this).toBeUndefined();
      expect(init?.method).toBe('POST');
      expect(init?.body).toBe(JSON.stringify({ proxyip: '203.0.113.10:443' }));
      expect(new Headers(init?.headers).get('Authorization')).toBeNull();
      return Response.json({
        ok: true,
        input: '203.0.113.10:443',
        source: { kind: 'direct' },
        items: [{ address: '203.0.113.10:443', result: { status: 'alive', exitFamily: 'ipv4', exits: [] } }],
        skipped: [],
      });
    });
    const client = new ApiClient({ fetchImpl: fetchMock as typeof fetch });

    await expect(client.checkTarget('203.0.113.10:443')).resolves.toMatchObject({ ok: true, source: { kind: 'direct' } });
  });

  it('maps API error responses to ApiError', async () => {
    const fetchMock = vi.fn(async () => Response.json({ error: 'unauthorized' }, { status: 401 }));
    const client = new ApiClient({ fetchImpl: fetchMock as typeof fetch });

    await expect(client.health()).rejects.toMatchObject({ status: 401, message: 'unauthorized' });
  });
});

describe('web API client pool endpoints', () => {
  it('checks one target per API request and keeps batch concurrency bounded', async () => {
    let active = 0;
    let peak = 0;
    const requests: string[] = [];
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const proxyip = JSON.parse(String(init?.body)).proxyip as string;
      requests.push(proxyip);
      active += 1;
      peak = Math.max(peak, active);
      await new Promise((resolve) => setTimeout(resolve, 5));
      active -= 1;
      return Response.json({
        ok: true,
        input: proxyip,
        source: { kind: 'direct' },
        items: [{ address: proxyip, result: { status: 'alive', exitFamily: 'ipv4', exits: [] } }],
        skipped: [],
      });
    });
    const client = new ApiClient({ fetchImpl: fetchMock as typeof fetch });
    const text = Array.from({ length: 136 }, (_, index) => `203.0.113.${index + 10}:443 # node${index}`).join('\n');
    const progress: number[] = [];

    const report = await client.checkBatch(text, undefined, (event) => progress.push(event.completed));

    expect(fetchMock).toHaveBeenCalledTimes(136);
    expect(new Set(requests).size).toBe(136);
    expect(peak).toBeLessThanOrEqual(32);
    expect(progress).toEqual(Array.from({ length: 136 }, (_, index) => index + 1));
    expect(report).toMatchObject({ total: 136, alive: 136, dead: 0, unknown: 0, invalid: [] });
    expect(report.items[0]?.line).toBe('203.0.113.10:443,null,null,v4 # node0');
  });

  it('turns an individual request failure into unknown and keeps checking later targets', async () => {
    const calls: string[] = [];
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const proxyip = JSON.parse(String(init?.body)).proxyip as string;
      calls.push(proxyip);
      if (proxyip === '203.0.113.10:443') throw new TypeError('Failed to fetch');
      return Response.json({
        ok: true,
        input: proxyip,
        source: { kind: 'direct' },
        items: [{ address: proxyip, result: { status: 'alive', exitFamily: 'ipv4', exits: [] } }],
        skipped: [],
      });
    });
    const client = new ApiClient({ fetchImpl: fetchMock as typeof fetch });
    const progress: string[] = [];

    const report = await client.checkBatch(
      '203.0.113.10:443\n203.0.113.11:443',
      undefined,
      (event) => progress.push(`${event.completed}:${event.item.address}:${event.item.status}`),
    );

    expect(calls).toEqual(['203.0.113.10:443', '203.0.113.11:443']);
    expect(progress).toEqual(['1:203.0.113.10:443:unknown', '2:203.0.113.11:443:alive']);
    expect(report).toMatchObject({ total: 2, alive: 1, dead: 0, unknown: 1 });
  });

  it('returns final items in source order when requests finish out of order', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const proxyip = JSON.parse(String(init?.body)).proxyip as string;
      const lastOctet = Number(proxyip.match(/\.(\d+):/)?.[1] ?? 0);
      await new Promise((resolve) => setTimeout(resolve, (12 - lastOctet) * 5));
      return Response.json({
        ok: true,
        input: proxyip,
        source: { kind: 'direct' },
        items: [{ address: proxyip, result: { status: 'alive', exitFamily: 'ipv4', exits: [] } }],
        skipped: [],
      });
    });
    const client = new ApiClient({ fetchImpl: fetchMock as typeof fetch });
    const addresses = ['203.0.113.10:443', '203.0.113.11:443', '203.0.113.12:443'];

    const report = await client.checkBatch(addresses.join('\n'));

    expect(report.items.map((item) => item.address)).toEqual(addresses);
  });

  it('treats an empty target response as unknown and keeps checking the batch', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const proxyip = JSON.parse(String(init?.body)).proxyip as string;
      return Response.json({
        ok: true,
        input: proxyip,
        source: { kind: 'direct' },
        items: proxyip === '203.0.113.10:443'
          ? []
          : [{ address: proxyip, result: { status: 'alive', exitFamily: 'ipv4', exits: [] } }],
        skipped: [],
      });
    });
    const client = new ApiClient({ fetchImpl: fetchMock as typeof fetch });

    const report = await client.checkBatch('203.0.113.10:443 # first\n203.0.113.11:443 # second');

    expect(report).toMatchObject({ total: 2, alive: 1, dead: 0, unknown: 1 });
    expect(report.items).toEqual([
      expect.objectContaining({
        address: '203.0.113.10:443',
        status: 'unknown',
        line: '203.0.113.10:443 # first',
      }),
      expect.objectContaining({ address: '203.0.113.11:443', status: 'alive' }),
    ]);
  });

  it('treats a malformed successful response as unknown instead of failing the batch', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const proxyip = JSON.parse(String(init?.body)).proxyip as string;
      if (proxyip === '203.0.113.10:443') return Response.json({ ok: true });
      return Response.json({
        ok: true,
        input: proxyip,
        source: { kind: 'direct' },
        items: [{ address: proxyip, result: { status: 'alive', exitFamily: 'ipv4', exits: [] } }],
        skipped: [],
      });
    });
    const client = new ApiClient({ fetchImpl: fetchMock as typeof fetch });

    const report = await client.checkBatch('203.0.113.10:443\n203.0.113.11:443');

    expect(report).toMatchObject({ total: 2, alive: 1, dead: 0, unknown: 1 });
    expect(report.items.map((item) => item.status)).toEqual(['unknown', 'alive']);
  });

  it('treats a malformed item inside a successful response as unknown', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const proxyip = JSON.parse(String(init?.body)).proxyip as string;
      if (proxyip === '203.0.113.10:443') {
        return Response.json({
          ok: true,
          input: proxyip,
          source: { kind: 'direct' },
          items: [null],
          skipped: [],
        });
      }
      return Response.json({
        ok: true,
        input: proxyip,
        source: { kind: 'direct' },
        items: [{ address: proxyip, result: { status: 'alive', exitFamily: 'ipv4', exits: [] } }],
        skipped: [],
      });
    });
    const client = new ApiClient({ fetchImpl: fetchMock as typeof fetch });

    const report = await client.checkBatch('203.0.113.10:443 # first\n203.0.113.11:443 # second');

    expect(report).toMatchObject({ total: 2, alive: 1, dead: 0, unknown: 1 });
    expect(report.items).toEqual([
      expect.objectContaining({
        address: '203.0.113.10:443',
        status: 'unknown',
        line: '203.0.113.10:443 # first',
      }),
      expect.objectContaining({ address: '203.0.113.11:443', status: 'alive' }),
    ]);
  });

  it('writes resolved addresses instead of duplicating the source domain line', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      expect(JSON.parse(String(init?.body)).proxyip).toBe('edge.example.com');
      return Response.json({
        ok: true,
        input: 'edge.example.com',
        source: { kind: 'dns', host: 'edge.example.com', addresses: ['203.0.113.10', '2001:db8::1'] },
        items: [
          { address: '203.0.113.10:443', result: { status: 'alive', exitFamily: 'ipv4', exits: [] } },
          { address: '[2001:db8::1]:443', result: { status: 'alive', exitFamily: 'ipv6', exits: [] } },
        ],
        skipped: [],
      });
    });
    const client = new ApiClient({ fetchImpl: fetchMock as typeof fetch });

    const report = await client.checkBatch('edge.example.com # source');

    expect(report.items.map((item) => item.line)).toEqual([
      '203.0.113.10:443,null,null,v4 # source',
      '[2001:db8::1]:443,null,null,v6 # source',
    ]);
  });

  it('does not call the removed server batch route', async () => {
    const urls: string[] = [];
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      urls.push(String(input));
      return Response.json({
        ok: true,
        input: '203.0.113.10:443',
        source: { kind: 'direct' },
        items: [{ address: '203.0.113.10:443', result: { status: 'alive', exitFamily: 'ipv4', exits: [] } }],
        skipped: [],
      });
    });
    const client = new ApiClient({ fetchImpl: fetchMock as typeof fetch });

    await client.checkBatch('203.0.113.10:443');

    expect(urls).toEqual(['/api/check']);
  });

  it('uses the shared pool and batch contracts', async () => {
    const calls: Array<{ readonly url: string; readonly init: RequestInit }> = [];
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(input), init: init ?? {} });
      if (String(input) === '/api/check') {
        return Response.json({
          ok: true,
          input: '203.0.113.9:443',
          source: { kind: 'direct' },
          items: [{ address: '203.0.113.9:443', result: { status: 'alive', exitFamily: 'ipv4', exits: [] } }],
          skipped: [],
        });
      }
      return Response.json({ ok: true });
    });
    const client = new ApiClient({ fetchImpl: fetchMock as typeof fetch });

    await client.savePool('ip_pool_001', '203.0.113.9:443\n');
    await client.checkBatch('203.0.113.9:443');
    await client.removePool('ip_pool_001');

    expect(calls[0]).toMatchObject({
      url: '/api/pools/ip_pool_001',
      init: { method: 'PUT', body: JSON.stringify({ content: '203.0.113.9:443\n', mode: 'replace' }) },
    });
    expect(calls[1]).toMatchObject({
      url: '/api/check',
      init: {
        method: 'POST',
        body: JSON.stringify({ proxyip: '203.0.113.9:443' }),
        headers: expect.any(Headers),
      },
    });
    expect(new Headers(calls[1]?.init.headers).get('Accept')).toBe('application/json');
    expect(calls[2]).toMatchObject({ url: '/api/pools/ip_pool_001', init: { method: 'DELETE' } });
  });

  it('exposes create, rename, ordering and trash operations', async () => {
    const calls: Array<{ readonly url: string; readonly init: RequestInit }> = [];
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(input), init: init ?? {} });
      if (String(input) === '/api/pools' && init?.method === 'POST') {
        return Response.json({ ok: true, key: 'ip_pool_001', displayName: '香港' });
      }
      if (String(input).endsWith('/trash/restore')) {
        return Response.json({ ok: true, restored: 1, restoredByPool: { ip_pool_001: 1 } });
      }
      return Response.json({ ok: true });
    });
    const client = new ApiClient({ fetchImpl: fetchMock as typeof fetch });

    await expect(client.createPool('香港')).resolves.toMatchObject({ key: 'ip_pool_001' });
    await client.renamePool('ip_pool_001', 'HK');
    await client.savePoolOrder(['ip_pool_001', 'ip_pool_default']);
    await client.restoreTrash(['203.0.113.9:443'], { restoreToSource: true, targetPool: 'ip_pool_001' });
    await client.clearTrash();

    expect(calls.map((call) => call.url)).toEqual([
      '/api/pools',
      '/api/pools/ip_pool_001',
      '/api/pools/order',
      '/api/pools/trash/restore',
      '/api/pools/trash/clear',
    ]);
    expect(calls[1]?.init).toMatchObject({
      method: 'PATCH',
      body: JSON.stringify({ displayName: 'HK' }),
    });
    expect(calls[2]?.init).toMatchObject({
      method: 'PUT',
      body: JSON.stringify({ order: ['ip_pool_001', 'ip_pool_default'] }),
    });
    expect(calls[3]?.init).toMatchObject({
      method: 'POST',
      body: JSON.stringify({ addresses: ['203.0.113.9:443'], restoreToSource: true, targetPool: 'ip_pool_001' }),
    });
    expect(calls[4]?.init).toMatchObject({ method: 'POST' });
  });

  it('reads pool content with an encoded key', async () => {
    const fetchMock = vi.fn(async () => Response.json({ key: 'ip_pool_hk', content: '203.0.113.9:443\n' }));
    const client = new ApiClient({ fetchImpl: fetchMock as typeof fetch });

    await expect(client.readPool('ip_pool_hk')).resolves.toEqual({ key: 'ip_pool_hk', content: '203.0.113.9:443\n' });
    expect(fetchMock).toHaveBeenCalledWith('/api/pools/ip_pool_hk', expect.objectContaining({ method: 'GET' }));
  });
});

describe('web API client config and remote load endpoints', () => {
  it('reads and writes the shared flat config contract', async () => {
    const calls: Array<{ readonly url: string; readonly init: RequestInit }> = [];
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(input), init: init ?? {} });
      return Response.json({ source: 'kv', config: {} });
    });
    const client = new ApiClient({ baseUrl: 'https://panel.example/', fetchImpl: fetchMock as typeof fetch });

    await client.config();

    const update = {
      checkApi: 'https://probe.example/?proxyip={proxyip}',
      settings: { CHECK_TIMEOUT: 5_000 },
    };
    await client.saveConfig(update);

    expect(calls[0]).toMatchObject({ url: 'https://panel.example/api/config', init: { method: 'GET' } });
    expect(calls[1]).toMatchObject({
      url: 'https://panel.example/api/config',
      init: { method: 'PUT', body: JSON.stringify(update) },
    });
    // 未提交的 Cloudflare / Telegram 密钥由服务端沿用旧值。
    expect(calls[1]?.init.body).not.toContain('apiKey');
  });

  it('posts the remote load request', async () => {
    const calls: Array<{ readonly url: string; readonly init: RequestInit }> = [];
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(input), init: init ?? {} });
      return Response.json({ ok: true });
    });
    const client = new ApiClient({ fetchImpl: fetchMock as typeof fetch });

    await client.remoteLoad('https://example.com/pool.txt');

    expect(calls[0]).toMatchObject({
      url: '/api/remote-load',
      init: { method: 'POST', body: JSON.stringify({ url: 'https://example.com/pool.txt' }) },
    });
  });

  it('does not add a panel key header to config writes', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      expect(new Headers(init?.headers).get('Authorization')).toBeNull();
      return Response.json({ source: 'kv', config: {} });
    });
    const client = new ApiClient({ fetchImpl: fetchMock as typeof fetch });

    await client.saveConfig({ checkApi: 'https://probe.example/?proxyip={proxyip}', settings: { CHECK_TIMEOUT: 5_000 } });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

describe('web API client domain binding and maintenance endpoints', () => {
  it('uses the binding and manual maintenance contracts', async () => {
    const calls: Array<{ readonly url: string; readonly init: RequestInit }> = [];
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(input), init: init ?? {} });
      if (String(input) === '/api/domain-bindings' && (!init?.method || init.method === 'GET')) {
        return Response.json({ items: [] });
      }
      return Response.json({ ok: true });
    });
    const client = new ApiClient({ fetchImpl: fetchMock as typeof fetch });

    await expect(client.domainBindings()).resolves.toEqual({ items: [] });
    await client.saveDomainBindings({ 'a.example.com|A': 'ip_pool_002' });
    await client.saveDomainBindingOrder(['b.example.com|A', 'a.example.com|A']);
    await client.runMaintenance();

    expect(calls.map((call) => call.url)).toEqual([
      '/api/domain-bindings',
      '/api/domain-bindings',
      '/api/domain-bindings/order',
      '/api/maintenance/run',
    ]);
    expect(calls[0]?.init).toMatchObject({ method: 'GET' });
    expect(calls[1]?.init).toMatchObject({
      method: 'PUT',
      body: JSON.stringify({ mapping: { 'a.example.com|A': 'ip_pool_002' } }),
    });
    expect(calls[2]?.init).toMatchObject({
      method: 'PUT',
      body: JSON.stringify({ order: ['b.example.com|A', 'a.example.com|A'] }),
    });
    expect(calls[3]?.init).toMatchObject({ method: 'POST' });
  });
});
