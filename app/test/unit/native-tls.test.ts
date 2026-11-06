import { readFileSync } from 'node:fs';
import { createServer } from 'node:tls';
import { connect } from 'node:net';
import { Readable, Writable } from 'node:stream';
import { describe, expect, it, vi } from 'vitest';
import { TrustedCert } from 'subtls';
import { NativeProbeAdapter, type ProbeSocket } from '../../src/adapters/probe/native';
import { secureProbeSocket } from '../../src/adapters/probe/tls';
import { parseProxyTarget } from '../../src/domain/proxy-target';

// 仅供回环服务器使用的自签名测试证书，绝不用于生产信任库。
const key = readFileSync(new URL('../fixtures/probe-test-key.pem', import.meta.url));
const cert = readFileSync(new URL('../fixtures/probe-test-cert.pem', import.meta.url));

describe('explicit SNI over a real TCP/TLS connection', () => {
  it('keeps CA-loading timeouts unknown instead of declaring a candidate dead', async () => {
    vi.useFakeTimers();
    vi.stubGlobal('fetch', (_url: string, init?: RequestInit) => new Promise((_, reject) => {
      init?.signal?.addEventListener('abort', () => reject(new Error('CA timeout')), { once: true });
    }));
    try {
      const connect = () => ({ opened: Promise.resolve({}), closed: Promise.resolve(),
        readable: new ReadableStream(), writable: new WritableStream(), async close() {},
        startTls() { throw new Error('unused'); } }) as ProbeSocket;
      const result = new NativeProbeAdapter({ urls: ['https://probe.test/'], timeoutMs: 500, connect })
        .probe(parseProxyTarget('203.0.113.10:443')!);
      await vi.advanceTimersByTimeAsync(1000);
      expect(await result).toMatchObject({ status: 'unknown', code: 'PROBE_API_ERROR' });
      await vi.advanceTimersByTimeAsync(5000);
    } finally { vi.unstubAllGlobals(); vi.useRealTimers(); }
  });
  it('verifies the certificate, sends SNI and reads the actual HTTP exit response', async () => {
    const names: string[] = [];
    const server = createServer({ key, cert, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' }, socket => {
      names.push(socket.servername || '');
      socket.once('data', () => socket.end('HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{"ip":"198.51.100.42","country":"JP"}'));
    });
    server.on('tlsClientError', () => {});
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as { port: number }).port;
    const roots = await TrustedCert.databaseFromPEM(cert.toString());
    const open = () => {
      const raw = connect(port, '127.0.0.1');
      return {
        opened: new Promise(resolve => { raw.once('connect', () => resolve({})); raw.once('error', () => {}); }),
        closed: Promise.resolve(), readable: Readable.toWeb(raw), writable: Writable.toWeb(raw),
        async close() { raw.destroy(); }, startTls() { throw new Error('platform startTls must not be used'); },
      } as ProbeSocket;
    };
    try {
      const probe = new NativeProbeAdapter({ urls: ['https://probe.test/'], timeoutMs: 3000,
        connect: open, secure: (socket, host) => secureProbeSocket(socket, host, roots) });
      const result = await probe.probe(parseProxyTarget('127.0.0.1:' + port)!);
      expect(result, JSON.stringify(result))
        .toMatchObject({ status: 'alive', exitIp: '198.51.100.42', exitFamily: 'ipv4' });
      expect(names).toEqual(['probe.test']);
      const repeated = await Promise.all(Array.from({ length: 18 }, () => probe.probe(parseProxyTarget('127.0.0.1:' + port)!)));
      expect(repeated.every(item => item.status === 'alive')).toBe(true);
      expect(names).toHaveLength(19);
      const raw = open();
      let releaseClose!: () => void;
      const delayedClose = vi.fn(() => new Promise<void>(resolve => {
        releaseClose = () => { void raw.close().then(resolve); };
      }));
      const secured = await secureProbeSocket({ ...raw, close: delayedClose }, 'probe.test', roots);
      const firstClose = secured.close();
      const secondClose = secured.close();
      let finished = false;
      void secondClose.then(() => { finished = true; });
      try {
        await Promise.resolve();
        expect(secondClose).toBe(firstClose);
        expect(finished).toBe(false);
        expect(delayedClose).toHaveBeenCalledTimes(1);
      } finally { releaseClose(); await Promise.all([firstClose, secondClose]); }
      const mismatch = new NativeProbeAdapter({ urls: ['https://wrong.test/'], timeoutMs: 3000,
        connect: open, secure: (socket, host) => secureProbeSocket(socket, host, roots) });
      expect(await mismatch.probe(parseProxyTarget('127.0.0.1:' + port)!))
        .toMatchObject({ status: 'dead', code: 'TARGET_TLS_ERROR' });
    } finally { await new Promise<void>(resolve => server.close(() => resolve())); }
  });
});
