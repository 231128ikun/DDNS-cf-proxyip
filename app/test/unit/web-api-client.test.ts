import { describe, expect, it, vi } from 'vitest';
import { ApiClient } from '../../web/src/api/client';

describe('web API client', () => {
  it('uses the shared check contract and sends the bearer token', async () => {
    const fetchMock = vi.fn(async function (this: unknown, _input: RequestInfo | URL, init?: RequestInit) {
      expect(this).toBeUndefined();
      expect(init?.method).toBe('POST');
      expect(init?.body).toBe(JSON.stringify({ proxyip: '203.0.113.10:443' }));
      expect(new Headers(init?.headers).get('Authorization')).toBe('Bearer secret');
      return Response.json({ status: 'alive', exitFamily: 'ipv4', exits: [] });
    });
    const client = new ApiClient({ authKey: ' secret ', fetchImpl: fetchMock as typeof fetch });

    await expect(client.check('203.0.113.10:443')).resolves.toMatchObject({ status: 'alive' });
  });

  it('maps API error responses to ApiError', async () => {
    const fetchMock = vi.fn(async () => Response.json({ error: 'unauthorized' }, { status: 401 }));
    const client = new ApiClient({ fetchImpl: fetchMock as typeof fetch });

    await expect(client.health()).rejects.toMatchObject({ status: 401, message: 'unauthorized' });
  });
});

describe('web API client pool endpoints', () => {
  it('uses the shared pool and batch contracts', async () => {
    const calls: Array<{ readonly url: string; readonly init: RequestInit }> = [];
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(input), init: init ?? {} });
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
      init: { method: 'POST', body: JSON.stringify({ text: '203.0.113.9:443' }) },
    });
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
    // 未提交的密钥由服务端沿用旧值，客户端不得凭空补空字符串。
    expect(calls[1]?.init.body).not.toContain('authKey');
  });

  it('posts the probe self-test and the remote load request', async () => {
    const calls: Array<{ readonly url: string; readonly init: RequestInit }> = [];
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(input), init: init ?? {} });
      return Response.json({ ok: true });
    });
    const client = new ApiClient({ fetchImpl: fetchMock as typeof fetch });

    await client.testProbe({ proxyip: '203.0.113.10:443', urlTemplate: 'https://api.example/?ip={ip}' });
    await client.remoteLoad('https://example.com/pool.txt');

    expect(calls[0]).toMatchObject({
      url: '/api/config/probe/test',
      init: {
        method: 'POST',
        body: JSON.stringify({ proxyip: '203.0.113.10:443', urlTemplate: 'https://api.example/?ip={ip}' }),
      },
    });
    expect(calls[1]).toMatchObject({
      url: '/api/remote-load',
      init: { method: 'POST', body: JSON.stringify({ url: 'https://example.com/pool.txt' }) },
    });
  });

  it('keeps the auth header on config writes', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      expect(new Headers(init?.headers).get('Authorization')).toBe('Bearer secret');
      return Response.json({ source: 'kv', config: {} });
    });
    const client = new ApiClient({ authKey: 'secret', fetchImpl: fetchMock as typeof fetch });

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
    await client.runMaintenance();

    expect(calls.map((call) => call.url)).toEqual([
      '/api/domain-bindings',
      '/api/domain-bindings',
      '/api/maintenance/run',
    ]);
    expect(calls[0]?.init).toMatchObject({ method: 'GET' });
    expect(calls[1]?.init).toMatchObject({
      method: 'PUT',
      body: JSON.stringify({ mapping: { 'a.example.com|A': 'ip_pool_002' } }),
    });
    expect(calls[2]?.init).toMatchObject({ method: 'POST' });
  });
});
