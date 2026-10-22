import { describe, expect, it } from 'vitest';
import { CheckProxy } from '../../src/application/check-proxy';
import { CheckTarget } from '../../src/application/check-target';
import { ResolveTarget } from '../../src/application/resolve-target';
import type { ProbeAdapter } from '../../src/ports/probe';
import type { ProxyTarget } from '../../src/domain/proxy-target';
import { alive, type ProbeResult } from '../../src/domain/probe-result';
import { createHttpApp } from '../../src/transport/http';
import { ApiClient } from '../../web/src/api/client';

interface ClientOperation {
  readonly name: string;
  readonly invoke: (client: ApiClient) => Promise<unknown>;
  readonly method: string;
  readonly path: string;
}

/**
 * 前端与 Worker 的唯一接口契约清单。
 * 新增 ApiClient 公共方法时必须在这里补对应请求，否则测试会失败。
 */
const CLIENT_OPERATIONS: readonly ClientOperation[] = [
  { name: 'health', invoke: (client) => client.health(), method: 'GET', path: '/api/health' },
  { name: 'checkTarget', invoke: (client) => client.checkTarget('203.0.113.10:443'), method: 'POST', path: '/api/check' },
  { name: 'checkBatch', invoke: (client) => client.checkBatch('203.0.113.10:443'), method: 'POST', path: '/api/check' },
  { name: 'pools', invoke: (client) => client.pools(), method: 'GET', path: '/api/pools' },
  { name: 'readPool', invoke: (client) => client.readPool('ip_pool_001'), method: 'GET', path: '/api/pools/ip_pool_001' },
  {
    name: 'savePool',
    invoke: (client) => client.savePool('ip_pool_001', '203.0.113.10:443\n'),
    method: 'PUT',
    path: '/api/pools/ip_pool_001',
  },
  { name: 'createPool', invoke: (client) => client.createPool('测试池'), method: 'POST', path: '/api/pools' },
  {
    name: 'renamePool',
    invoke: (client) => client.renamePool('ip_pool_001', '测试池'),
    method: 'PATCH',
    path: '/api/pools/ip_pool_001',
  },
  { name: 'cleanPool', invoke: (client) => client.cleanPool('ip_pool_001'), method: 'POST', path: '/api/pools/ip_pool_001/clean' },
  {
    name: 'savePoolOrder',
    invoke: (client) => client.savePoolOrder(['ip_pool_001', 'ip_pool_default']),
    method: 'PUT',
    path: '/api/pools/order',
  },
  { name: 'clearTrash', invoke: (client) => client.clearTrash(), method: 'POST', path: '/api/pools/trash/clear' },
  {
    name: 'restoreTrash',
    invoke: (client) => client.restoreTrash(['203.0.113.10:443']),
    method: 'POST',
    path: '/api/pools/trash/restore',
  },
  {
    name: 'removePool',
    invoke: (client) => client.removePool('ip_pool_001'),
    method: 'DELETE',
    path: '/api/pools/ip_pool_001',
  },
  { name: 'config', invoke: (client) => client.config(), method: 'GET', path: '/api/config' },
  {
    name: 'saveConfig',
    invoke: (client) => client.saveConfig({ checkApi: 'https://probe.example/?proxyip=' }),
    method: 'PUT',
    path: '/api/config',
  },
  {
    name: 'remoteLoad',
    invoke: (client) => client.remoteLoad('https://example.com/pool.txt'),
    method: 'POST',
    path: '/api/remote-load',
  },
  { name: 'domainBindings', invoke: (client) => client.domainBindings(), method: 'GET', path: '/api/domain-bindings' },
  {
    name: 'saveDomainBindings',
    invoke: (client) => client.saveDomainBindings({ 'a.example.com|A': 'ip_pool_001' }),
    method: 'PUT',
    path: '/api/domain-bindings',
  },
  {
    name: 'saveDomainBindingOrder',
    invoke: (client) => client.saveDomainBindingOrder(['a.example.com|A']),
    method: 'PUT',
    path: '/api/domain-bindings/order',
  },
  { name: 'runMaintenance', invoke: (client) => client.runMaintenance(), method: 'POST', path: '/api/maintenance/run' },
];

class FakeProbeAdapter implements ProbeAdapter {
  readonly name = 'fake';

  async probe(target: ProxyTarget): Promise<ProbeResult> {
    return alive(target, { endpoint: 'fake', exitFamily: 'ipv4' });
  }
}

describe('web and Worker API contract', () => {
  it('keeps every public ApiClient method mapped to a real Worker route', async () => {
    const publicMethods = Object.getOwnPropertyNames(ApiClient.prototype)
      .filter((name) => !['constructor', 'request', 'checkPoolTarget'].includes(name))
      .sort();
    expect(publicMethods).toEqual(CLIENT_OPERATIONS.map((operation) => operation.name).sort());

    const requests: Array<{ readonly url: string; readonly method: string; readonly body?: string }> = [];
    const client = new ApiClient({
      fetchImpl: async (input, init) => {
        const url = String(input);
        requests.push({
          url,
          method: init?.method ?? 'GET',
          ...(typeof init?.body === 'string' ? { body: init.body } : {}),
        });
        if (url === '/api/check') {
          return Response.json({
            ok: true,
            input: '203.0.113.10:443',
            source: { kind: 'direct' },
            items: [{
              address: '203.0.113.10:443',
              result: { status: 'alive', exitFamily: 'ipv4', exits: [] },
            }],
            skipped: [],
          });
        }
        return Response.json({ ok: true });
      },
    });

    for (const operation of CLIENT_OPERATIONS) await operation.invoke(client);

    expect(requests).toHaveLength(CLIENT_OPERATIONS.length);
    requests.forEach((request, index) => {
      expect(request).toMatchObject({
        url: CLIENT_OPERATIONS[index]!.path,
        method: CLIENT_OPERATIONS[index]!.method,
      });
    });

    const checkProxy = new CheckProxy(new FakeProbeAdapter());
    const app = createHttpApp({
      checkTarget: new CheckTarget({
        resolver: new ResolveTarget({ query: async () => ({ ok: true, values: [] }) }),
        checkProxy,
      }),
      version: 'contract-test',
    });

    for (const request of requests) {
      const response = await app.request(request.url, {
        method: request.method,
        ...(request.body
          ? { headers: { 'content-type': 'application/json' }, body: request.body }
          : {}),
      });
      expect(response.status, `${request.method} ${request.url} must be routed by the Worker`).not.toBe(404);
      expect(response.status, `${request.method} ${request.url} must accept the client method`).not.toBe(405);
    }
  });

  it('runs browser-scheduled targets through the real single-target Worker route', async () => {
    const checkProxy = new CheckProxy(new FakeProbeAdapter());
    const app = createHttpApp({
      checkTarget: new CheckTarget({
        resolver: new ResolveTarget({ query: async () => ({ ok: true, values: [] }) }),
        checkProxy,
      }),
      version: 'contract-test',
    });
    let requestCount = 0;
    const client = new ApiClient({
      fetchImpl: ((input: RequestInfo | URL, init?: RequestInit) => {
        requestCount += 1;
        return app.request(String(input), init);
      }) as typeof fetch,
    });
    const addresses = Array.from({ length: 5 }, (_, index) => `203.0.113.${index + 10}:443`);
    const progress: number[] = [];

    const report = await client.checkBatch(addresses.join('\n'), undefined, (event) => {
      progress.push(event.completed);
    });

    expect(requestCount).toBe(5);
    expect(progress).toEqual([1, 2, 3, 4, 5]);
    expect(report).toMatchObject({ total: 5, alive: 5, dead: 0, unknown: 0, invalid: [] });
    expect(report.items.map((item) => item.address)).toEqual(addresses);
  });
});
