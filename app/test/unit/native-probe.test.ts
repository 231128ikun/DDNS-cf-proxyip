import { describe, expect, it, vi } from 'vitest';
import { NativeProbeAdapter, type ProbeConnect, type ProbeSocket } from '../../src/adapters/probe/native';
import { parseProxyTarget } from '../../src/domain/proxy-target';
import { alive, dead, unknown } from '../../src/domain/probe-result';

vi.mock('../../src/adapters/probe/tls', () => ({
  secureProbeSocket: async (socket: ProbeSocket, hostname: string) => socket.startTls({ expectedServerHostname: hostname }),
}));

const target = parseProxyTarget('203.0.113.10:8443')!;
const urls = ['https://ipv4.example/exit?format=json', 'https://ipv6.example/'];
const encode = (value: string) => new TextEncoder().encode(value);
function http(body: string, headers = ''): Uint8Array {
  return encode('HTTP/1.1 200 OK\r\n' + headers + '\r\n' + body);
}
function connector(response: (host: string) => Uint8Array | Error = host => http(JSON.stringify({
  ip: host.includes('ipv6') ? '2001:db8::42' : '198.51.100.42', asn: 64500, country: 'jp', colo: ' icn ',
}))) {
  const writes: string[] = [], hosts: string[] = [], closes: ReturnType<typeof vi.fn>[] = [];
  const connect = vi.fn((_address: SocketAddress, _options: SocketOptions): ProbeSocket => {
    const close = vi.fn(async () => {}); closes.push(close);
    const socket: ProbeSocket = {
      opened: Promise.resolve({}), closed: Promise.resolve(), close,
      writable: new WritableStream({ write(chunk) { writes.push(new TextDecoder().decode(chunk)); } }),
      readable: new ReadableStream({ start(controller) { controller.close(); } }),
      startTls(options) {
        const host = options?.expectedServerHostname ?? ''; hosts.push(host);
        const value = response(host);
        return { ...socket, readable: new ReadableStream({ start(controller) {
          if (value instanceof Error) controller.error(value);
          else { controller.enqueue(value); controller.close(); }
        } }) } as Socket;
      },
    };
    return socket;
  });
  return { connect, writes, hosts, closes };
}

describe('native candidate probe', () => {
  it.each([
    [new Error('connection refused'), 'dead', 'TARGET_CONNECT_ERROR'],
    [new TypeError('socket API unavailable'), 'unknown', 'PROBE_API_ERROR'],
  ])('distinguishes an immediate connection failure from a runtime failure: %s', async (error, status, code) => {
    const probe = new NativeProbeAdapter({ urls, timeoutMs: 1000, connect: () => { throw error; } });
    expect(await probe.probe(target)).toMatchObject({ status, code });
  });
  it('connects to the candidate port with endpoint SNI and Host, retaining both exit families', async () => {
    const io = connector();
    const probe = new NativeProbeAdapter({ urls, timeoutMs: 1000, connect: io.connect });
    expect(await probe.probe(target)).toMatchObject({ status: 'alive', colo: 'ICN', exitFamily: 'dual', exits: [
      { ip: '198.51.100.42', family: 'ipv4', country: 'JP', asn: '64500' },
      { ip: '2001:db8::42', family: 'ipv6' },
    ] });
    expect(io.connect).toHaveBeenCalledTimes(2);
    expect(io.connect).toHaveBeenCalledWith({ hostname: target.host, port: 8443 }, { secureTransport: 'off', allowHalfOpen: false });
    expect(io.hosts).toEqual(['ipv4.example', 'ipv6.example']);
    expect(io.writes[0]).toContain('GET /exit?format=json HTTP/1.1\r\nHost: ipv4.example\r\n');
    expect(io.closes.every(close => close.mock.calls.length === 1)).toBe(true);
  });

  it('preserves region and city from the native exit payload', async () => {
    const io = connector(host => http(JSON.stringify({
      ip: host.includes('ipv6') ? '2001:db8::42' : '198.51.100.42', country: 'jp', region: 'Tokyo', city: 'Chiyoda',
    })));
    const result = await new NativeProbeAdapter({ urls, timeoutMs: 1000, connect: io.connect }).probe(target);
    expect(result.exits).toHaveLength(2);
    expect(result.exits).toEqual(expect.arrayContaining([
      expect.objectContaining({ family: 'ipv4', country: 'JP', region: 'Tokyo', city: 'Chiyoda' }),
      expect.objectContaining({ family: 'ipv6', country: 'JP', region: 'Tokyo', city: 'Chiyoda' }),
    ]));
  });

  it.each([
    'HTTP/1.1 503 Unavailable\r\n\r\nservice unavailable',
    'HTTP/1.1 200 OK\r\n\r\nnot json',
    'HTTP/1.1 200 OK\r\n\r\n{"ip":"invalid"}',
    'HTTP/1.1 200 OK\r\n\r\n{"ip":"198.51.100.1:443"}',
    'HTTP/1.1 200 OK\r\n\r\n{"ip":"[2001:db8::42]:443"}',
    'HTTP/1.1 200 OK\r\n\r\n{"ip":"https://[2001:db8::42]/"}',
    'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n20\r\nshort\r\n0\r\n\r\n',
    'HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{"ip":"198.51.100.1"}',
  ])('rechecks normal candidate failures without broad anomaly matching: %s', async text => {
    const io = connector(() => encode(text));
    expect(await new NativeProbeAdapter({ urls, timeoutMs: 1000, connect: io.connect }).probe(target))
      .toMatchObject({ status: 'dead', code: 'TARGET_HTTP_ERROR' });
    expect(io.connect).toHaveBeenCalledTimes(4);
  });

  it('decodes byte-sized chunks including non-ASCII metadata', async () => {
    const body = JSON.stringify({ ip: '198.51.100.42', asOrganization: '网络' });
    const io = connector(() => http(`${encode(body).length.toString(16)};name=value\r\n${body}\r\n0\r\n\r\n`, 'Transfer-Encoding: chunked\r\n'));
    expect(await new NativeProbeAdapter({ urls, timeoutMs: 1000, connect: io.connect }).probe(target))
      .toMatchObject({ status: 'alive', exitFamily: 'ipv4', exits: [{ organization: '网络' }] });
  });

  it('keeps the real exit family instead of assuming a URL name implies IPv6', async () => {
    const io = connector(() => http('{"ip":"198.51.100.42","ipType":"ipv6"}'));
    expect(await new NativeProbeAdapter({ urls, timeoutMs: 1000, connect: io.connect }).probe(target))
      .toMatchObject({ status: 'alive', exitFamily: 'ipv4' });
  });

  it('protects TCP Loop but keeps an independently healthy branch', async () => {
    const loop = new Error('TCP Loop detected, contact us if this does not seem right');
    const bad = connector(() => loop);
    expect(await new NativeProbeAdapter({ urls, timeoutMs: 1000, connect: bad.connect }).probe(target))
      .toMatchObject({ status: 'unknown', code: 'PROBE_API_ERROR' });
    const partial = connector(host => host.includes('ipv6') ? loop : http('{"ip":"198.51.100.42"}'));
    expect(await new NativeProbeAdapter({ urls, timeoutMs: 1000, connect: partial.connect }).probe(target))
      .toMatchObject({ status: 'alive', code: 'PARTIAL_EXIT', exitFamily: 'ipv4' });
  });

  it.each(['unknown', 'dead', 'alive'] as const)('uses backup %s after candidate failure, not another native pass', async status => {
    const io = connector(() => new Error('connection refused'));
    const result = status === 'unknown' ? unknown(target, 'HTTP_ERROR', 'backup unavailable')
      : status === 'alive' ? alive(target) : dead(target);
    const backup = { name: 'backup', probe: vi.fn(async () => result) };
    expect((await new NativeProbeAdapter({ urls, timeoutMs: 1000, connect: io.connect, backup }).probe(target)).status).toBe(status);
    expect(io.connect).toHaveBeenCalledTimes(2); expect(backup.probe).toHaveBeenCalledTimes(1);
  });

  it('cannot use a backup failure to overwrite a native runtime anomaly', async () => {
    const io = connector(() => new Error('TCP Loop detected'));
    const backup = { name: 'backup', probe: vi.fn(async () => dead(target)) };
    expect((await new NativeProbeAdapter({ urls, timeoutMs: 1000, connect: io.connect, backup }).probe(target)).status).toBe('unknown');
  });

  it('releases timed-out sockets and rechecks before marking dead', async () => {
    vi.useFakeTimers();
    try {
      const close = vi.fn(async () => {});
      const connect: ProbeConnect = () => ({ ...connector().connect({ hostname: '', port: 443 }, { allowHalfOpen: false }),
        opened: new Promise(() => {}), close });
      const pending = new NativeProbeAdapter({ urls, timeoutMs: 10, connect }).probe(target);
      await vi.advanceTimersByTimeAsync(25);
      expect(await pending).toMatchObject({ status: 'dead', code: 'TIMEOUT' });
      expect(close).toHaveBeenCalled(); expect(vi.getTimerCount()).toBe(0);
    } finally { vi.useRealTimers(); }
  });

  it('aborts queued and active work without a backup or additional sockets', async () => {
    const controller = new AbortController();
    const base = connector();
    const connect = vi.fn((...args: Parameters<ProbeConnect>) => ({ ...base.connect(...args), opened: new Promise<SocketInfo>(() => {}) }));
    const backup = { name: 'backup', probe: vi.fn(async () => dead(target)) };
    const adapter = new NativeProbeAdapter({ urls, timeoutMs: 1000, connect, backup });
    const results = Array.from({ length: 8 }, () => adapter.probe(target, { signal: controller.signal }));
    await Promise.resolve();
    expect(connect).toHaveBeenCalledTimes(4);
    controller.abort();
    expect((await Promise.all(results)).every(result => result.code === 'CANCELLED')).toBe(true);
    expect(connect).toHaveBeenCalledTimes(4); expect(backup.probe).not.toHaveBeenCalled();
  });

  it('does not connect when URLs are missing or invalid', async () => {
    const io = connector();
    for (const values of [[], ['http://plain.example/'], ['https://name:password@example/']]) {
      expect(await new NativeProbeAdapter({ urls: values, timeoutMs: 1000, connect: io.connect }).probe(target))
        .toMatchObject({ status: 'unknown', code: 'NOT_CONFIGURED' });
    }
    expect(io.connect).not.toHaveBeenCalled();
  });
});

it.each(['2001:DB8::42', '2001:0db8:0:0:0:0:0:42'])('accepts and normalizes bare IPv6 exit JSON: %s', async ip => {
  const io = connector(() => http(JSON.stringify({ ip, ipType: 'ipv6' })));
  expect(await new NativeProbeAdapter({ urls: [urls[1]!], timeoutMs: 1000, connect: io.connect }).probe(target))
    .toMatchObject({ status: 'alive', exitIp: '2001:db8::42', exits: [{ ip: '2001:db8::42', family: 'ipv6' }] });
});
