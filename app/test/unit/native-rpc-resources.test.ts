import { once } from 'node:events';
import { createServer, type Socket } from 'node:net';
import { resolve } from 'node:path';
import { build } from 'esbuild';
import { Miniflare, convertV4MiniflareOptions, Response as TestResponse } from 'miniflare';
import { describe, expect, it, vi } from 'vitest';
import { ApiClient } from '../../web/src/api/client';

describe('native RPC resource isolation in workerd', () => {
  it.each([
    ['batch', 'reject'], ['batch', 'hang'], ['maintenance', 'reject'], ['maintenance', 'hang'],
  ] as const)('continues %s after real socket close %s and releases every connection', async (entry, failure) => {
    const peers = new Set<Socket>();
    let accepted = 0;
    let peak = 0;
    const body = JSON.stringify({ ip: '198.51.100.42', asn: 64500, country: 'US', colo: 'NRT' });
    const server = createServer({ allowHalfOpen: true }, socket => {
      peers.add(socket);
      accepted++;
      peak = Math.max(peak, peers.size);
      socket.on('close', () => peers.delete(socket));
      socket.on('error', () => {});
      socket.on('end', () => socket.end());
      let request = '';
      socket.on('data', data => {
        request += data.toString();
        if (request.includes('\r\n\r\n')) {
          socket.write('HTTP/1.1 200 OK\r\nContent-Length: ' + body.length + '\r\n\r\n' + body);
          request = '';
        }
      });
    });
    let runtime: Miniflare | undefined;
    try {
      server.listen(0, '127.0.0.1');
      await once(server, 'listening');
      const { port } = server.address() as { port: number };
      const root = resolve(import.meta.dirname, '../..');
      const bundled = await build({ bundle: true, write: false, format: 'esm', platform: 'neutral',
        external: ['cloudflare:sockets', 'cloudflare:workers'], alias: { crypto: resolve(root, 'src/adapters/probe/web-crypto.ts') },
        stdin: { resolveDir: root, sourcefile: 'native-resource-boundary.js', contents: `
          import { connect } from 'cloudflare:sockets';
          import { WorkerEntrypoint } from 'cloudflare:workers';
          import { createWorker, dispatchWorkerInvocation } from './src/worker.ts';
          import { NativeProbeAdapter } from './src/adapters/probe/native.ts';
          const app = createWorker((config, deps) => new NativeProbeAdapter({
            ...deps, urls: config.urls, timeoutMs: config.timeoutMs, secure: async socket => socket,
            connect(address) {
              const socket = connect({hostname:'127.0.0.1', port:${port}}, {allowHalfOpen:false});
              const broken = Number(address.hostname.split('.').at(-1)) <= 3;
              return {opened:socket.opened, closed:socket.closed, readable:socket.readable, writable:socket.writable,
                close: () => broken ? ${failure === 'hang' ? 'new Promise(() => {})' : "Promise.reject(new Error('close failed'))"} : socket.close(),
                startTls: options => socket.startTls(options)};
            },
          }));
          export default class TestWorker extends WorkerEntrypoint {
            fetch(request) {return app.fetch(request, this.env, this.ctx);}
            dispatch(url, init, props, cancelled) {return dispatchWorkerInvocation(app, this.env, this.ctx, url, init, props, cancelled);}
          }
        ` } });
      const targets = ['TXT', 'A', 'TXT'].map((mode, index) => ({ domain: 'target' + index + '.example.com', mode, zoneIndex: 0, minActive: 3 }));
      const mf = runtime = new Miniflare(convertV4MiniflareOptions({ modules: true, script: bundled.outputFiles![0]!.text,
        compatibilityDate: '2026-09-24', compatibilityFlags: ['nodejs_compat'], kvNamespaces: ['IP_DATA'],
        outboundService: async request => {
          const url = new URL(request.url);
          expect(request.method).toBe('GET');
          expect(url.hostname).toBe('api.cloudflare.com');
          const index = targets.findIndex(target => target.domain === url.searchParams.get('name'));
          expect(index).toBeGreaterThanOrEqual(0);
          const type = url.searchParams.get('type');
          const addresses = [1, 2, 3].map(item => '203.0.113.' + (index * 3 + item));
          const result = type === 'AAAA' ? [] : type === 'TXT'
            ? [{ id: 'txt' + index, type, name: targets[index]!.domain, content: '"' + addresses.map(address => address + ':443').join(',') + '"' }]
            : addresses.map((address, item) => ({ id: 'a' + index + '-' + item, type, name: targets[index]!.domain, content: address }));
          return TestResponse.json({ success: true, result });
        } }));
      const { IP_DATA } = await mf.getBindings<{ IP_DATA: KVNamespace }>();
      await IP_DATA.put('app_config', JSON.stringify({ tgEnabled: false, checkApiBackup: '', settings: { CHECK_TIMEOUT: 500 },
        zones: [{ baseDomain: 'example.com', zoneId: 'fixture-zone', apiKey: 'fixture-token' }], targets }));
      const addresses = Array.from({ length: 18 }, (_, index) => '203.0.113.' + (index + 1) + ':443');
      const pool = '# 真实连接回归\n' + addresses.map(address => address + ',AS64500,US,v4').join('\n');
      await IP_DATA.put('ip_pool_default', pool);
      await IP_DATA.put('ip_pool_trash', '# 原垃圾桶');
      const client = new ApiClient({ fetchImpl: async (input, init) => {
        const request = new Request(new URL(String(input), 'https://panel.example'), init);
        const headers: Record<string, string> = {};
        request.headers.forEach((value, key) => { headers[key] = value; });
        const response = await mf.dispatchFetch(request.url, { method: request.method,
          headers, body: await request.text() });
        return new Response(response.body as unknown as ReadableStream<Uint8Array>, {
          status: response.status, headers: Object.fromEntries(response.headers),
        });
      } });
      if (entry === 'batch') {
        const result = await client.checkBatch(addresses.join('\n'), undefined, undefined, 1);
        expect(result.items).toHaveLength(18);
        expect(result.items.every(item => item.status === 'alive')).toBe(true);
        expect(accepted).toBe(36);
      } else {
        const result = await client.runMaintenance();
        expect(result).toMatchObject({ completed: true, changed: false, probeErrors: 0 });
        expect(result.results.map(target => target.activeCount)).toEqual([3, 3, 3]);
        expect(accepted).toBe(18);
      }
      await vi.waitFor(() => expect(peers.size).toBe(0), { timeout: 2000 });
      expect(peak).toBeLessThanOrEqual(4);
      expect(await IP_DATA.get('ip_pool_default')).toBe(pool);
      expect(await IP_DATA.get('ip_pool_trash')).toBe('# 原垃圾桶');
    } finally {
      try { await runtime?.dispose(); }
      finally {
        for (const socket of peers) socket.destroy();
        await new Promise<void>(resolve => server.close(() => resolve()));
      }
    }
  }, 20_000);
});
