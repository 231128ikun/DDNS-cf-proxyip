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
  it('reads streamed batch progress and returns the completed report', async () => {
    const events = [
      { type: 'progress', completed: 1, total: 1, item: { address: '203.0.113.10:443', status: 'alive', exitFamily: 'ipv4', line: '203.0.113.10:443' } },
      {
        type: 'complete',
        report: {
          total: 1,
          alive: 1,
          dead: 0,
          unknown: 0,
          invalid: [],
          items: [{ address: '203.0.113.10:443', status: 'alive', exitFamily: 'ipv4', line: '203.0.113.10:443' }],
        },
      },
    ];
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      expect(new Headers(init?.headers).get('Accept')).toContain('application/x-ndjson');
      return new Response(`${events.map((event) => JSON.stringify(event)).join('\n')}\n`, {
        headers: { 'content-type': 'application/x-ndjson; charset=utf-8' },
      });
    });
    const client = new ApiClient({ fetchImpl: fetchMock as typeof fetch });
    const progress: Array<{ completed: number; total: number }> = [];

    const report = await client.checkBatch('203.0.113.10:443', undefined, (event) => {
      progress.push({ completed: event.completed, total: event.total });
    });

    expect(progress).toEqual([{ completed: 1, total: 1 }]);
    expect(report).toMatchObject({ total: 1, alive: 1 });
  });

  it('splits large batches into safe requests and keeps global progress', async () => {
    const calls: string[] = [];
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const text = JSON.parse(String(init?.body)).text as string;
      const addresses = text.split('\n');
      calls.push(text);
      const items = addresses.map((address, index) => ({
        address,
        status: 'alive' as const,
        exitFamily: 'ipv4' as const,
        line: address,
        ...(index === 0 ? { latencyMs: 120 } : {}),
      }));
      const events = [
        ...items.map((item, index) => ({
          type: 'progress',
          completed: index + 1,
          total: items.length,
          item,
        })),
        {
          type: 'complete',
          report: {
            total: items.length,
            alive: items.length,
            dead: 0,
            unknown: 0,
            invalid: [],
            items,
          },
        },
      ];
      return new Response(`${events.map((event) => JSON.stringify(event)).join('\n')}\n`, {
        headers: { 'content-type': 'application/x-ndjson; charset=utf-8' },
      });
    });
    const client = new ApiClient({ fetchImpl: fetchMock as typeof fetch });
    const text = Array.from({ length: 136 }, (_, index) => `203.0.113.${index + 10}:443`).join('\n');
    const progress: number[] = [];

    const report = await client.checkBatch(text, undefined, (event) => progress.push(event.completed));

    expect(calls.map((call) => call.split('\n').length)).toEqual(Array.from({ length: 34 }, () => 4));
    expect(progress).toEqual(Array.from({ length: 136 }, (_, index) => index + 1));
    expect(report).toMatchObject({ total: 136, alive: 136, dead: 0, unknown: 0, invalid: [] });
  });

  it('falls back to JSON when the streaming request cannot connect', async () => {
    let attempt = 0;
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      attempt += 1;
      if (attempt === 1) throw new TypeError('Failed to fetch');
      expect(new Headers(init?.headers).get('Accept')).toBe('application/json');
      return Response.json({
        total: 1,
        alive: 1,
        dead: 0,
        unknown: 0,
        invalid: [],
        items: [{ address: '203.0.113.10:443', status: 'alive', exitFamily: 'ipv4', line: '203.0.113.10:443' }],
      });
    });
    const client = new ApiClient({ fetchImpl: fetchMock as typeof fetch });
    const progress: number[] = [];

    const report = await client.checkBatch('203.0.113.10:443', undefined, (event) => progress.push(event.completed));

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(progress).toEqual([1]);
    expect(report).toMatchObject({ total: 1, alive: 1 });
  });

  it('falls back once and replays buffered progress when the stream ends without a final report', async () => {
    let attempt = 0;
    const item = {
      address: '203.0.113.10:443',
      status: 'alive' as const,
      exitFamily: 'ipv4' as const,
      line: '203.0.113.10:443',
    };
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      attempt += 1;
      if (attempt === 1) {
        expect(new Headers(init?.headers).get('Accept')).toContain('application/x-ndjson');
        return new Response(`${JSON.stringify({ type: 'progress', completed: 1, total: 1, item })}\n`, {
          headers: { 'content-type': 'application/x-ndjson; charset=utf-8' },
        });
      }
      expect(new Headers(init?.headers).get('Accept')).toBe('application/json');
      return Response.json({
        total: 1,
        alive: 1,
        dead: 0,
        unknown: 0,
        invalid: [],
        items: [item],
      });
    });
    const client = new ApiClient({ fetchImpl: fetchMock as typeof fetch });
    const progress: number[] = [];

    const report = await client.checkBatch('203.0.113.10:443', undefined, (event) => progress.push(event.completed));

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(progress).toEqual([1]);
    expect(report).toMatchObject({ total: 1, alive: 1 });
  });

  it('does not retry an explicit error event from the batch stream', async () => {
    const fetchMock = vi.fn(async () => new Response(
      `${JSON.stringify({ type: 'error', error: '批量检测未能完成' })}\n`,
      { headers: { 'content-type': 'application/x-ndjson; charset=utf-8' } },
    ));
    const client = new ApiClient({ fetchImpl: fetchMock as typeof fetch });

    await expect(client.checkBatch(
      '203.0.113.10:443',
      undefined,
      () => undefined,
    )).rejects.toMatchObject({ message: '批量检测未能完成', status: 200 });

    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('uses the shared pool and batch contracts', async () => {
    const calls: Array<{ readonly url: string; readonly init: RequestInit }> = [];
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(input), init: init ?? {} });
      if (String(input) === '/api/check/batch') {
        return Response.json({ total: 1, alive: 1, dead: 0, unknown: 0, invalid: [], items: [] });
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
      url: '/api/check/batch',
      init: {
        method: 'POST',
        body: JSON.stringify({ text: '203.0.113.9:443' }),
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
