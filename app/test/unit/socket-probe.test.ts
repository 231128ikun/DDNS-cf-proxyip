import { describe, expect, it } from 'vitest';
import { SocketProbeAdapter, type ProbeSocket, type SocketConnect } from '../../src/adapters/probe/socket';
import { parseProxyTarget } from '../../src/domain/proxy-target';

/**
 * 假 socket：把参考实现的两段式流程（明文连接 → startTls）压成一个对象，
 * 让正常、拒绝、超时、坏响应等分支都能在不联网的情况下覆盖。
 */
const IPV4_URL = 'https://ipv4.probe.example/';
const IPV6_URL = 'https://ipv6.probe.example/';
const TIMEOUT_MS = 250;
const encoder = new TextEncoder();

const ipv4Target = requireTarget('203.0.113.10:8443');
const ipv6Target = requireTarget('[2001:db8::1]:443');

const ALIVE_BODY = '{"ip":"198.51.100.7","ipType":"ipv4","asn":"64500","country":"us","asOrganization":"Example"}';
const IPV6_BODY = '{"ip":"2001:db8::99","ipType":"ipv6"}';

interface ProbeScript {
  /** 明文 connect 直接抛错。 */
  readonly connectError?: Error;
  /** 明文 connect 的 opened 拒绝。 */
  readonly openedError?: Error;
  /** TLS 之后探针返回的原始 HTTP 响应；缺省表示不回包。 */
  readonly response?: string;
  /** TLS 读一直挂起，用于超时用例。 */
  readonly mute?: boolean;
}

interface Harness {
  readonly connect: SocketConnect;
  readonly connections: Array<{ readonly address: SocketAddress; readonly options: SocketOptions }>;
  readonly tlsOptions: TlsOptions[];
  readonly writes: Uint8Array[];
  readonly closes: number[];
}

describe('socket probe adapter', () => {
  it('returns alive with the exit metadata reported by the probe', async () => {
    const harness = createHarness([{ response: httpResponse(ALIVE_BODY) }, { mute: true }]);

    const result = await createAdapter({ connect: harness.connect }).probe(ipv4Target);

    expect(result).toMatchObject({
      status: 'alive',
      endpoint: 'socket',
      exitFamily: 'ipv4',
      exitIp: '198.51.100.7',
    });
    expect(result.exits[0]).toMatchObject({ asn: '64500', country: 'US', organization: 'Example' });
    expect(result.latencyMs).toBeTypeOf('number');

    // 明文连接用候选地址，TLS 用探针域名做 SNI，HTTP 请求的 Host 也必须是探针域名。
    expect(harness.connections[0]?.address).toEqual({ hostname: '203.0.113.10', port: 8443 });
    expect(harness.connections[0]?.options).toEqual({ secureTransport: 'starttls', allowHalfOpen: true });
    expect(harness.tlsOptions[0]).toEqual({ expectedServerHostname: 'ipv4.probe.example' });
    expect(decode(harness.writes[0])).toContain('GET / HTTP/1.1\r\nHost: ipv4.probe.example');
  });

  it('merges both probes into a dual stack result', async () => {
    const harness = createHarness([{ response: httpResponse(ALIVE_BODY) }, { response: httpResponse(IPV6_BODY) }]);

    const result = await createAdapter({ connect: harness.connect }).probe(ipv4Target);

    expect(result.status).toBe('alive');
    expect(result.exitFamily).toBe('dual');
    expect(result.exits).toHaveLength(2);
    expect(result.exitIp).toBe('198.51.100.7');
  });

  it('decodes a chunked probe response', async () => {
    const chunked = `${ALIVE_BODY.slice(0, 20)}${ALIVE_BODY.slice(20)}`;
    const response = [
      'HTTP/1.1 200 OK',
      'Content-Type: application/json',
      'Transfer-Encoding: chunked',
      'Connection: close',
      '',
      `${chunked.length.toString(16)}\r\n${chunked}\r\n0\r\n\r\n`,
    ].join('\r\n');
    const harness = createHarness([{ response }, { mute: true }]);

    await expect(createAdapter({ connect: harness.connect }).probe(ipv4Target)).resolves.toMatchObject({
      status: 'alive',
      exitIp: '198.51.100.7',
    });
  });

  it('brackets IPv6 candidates before connecting', async () => {
    const harness = createHarness([{ response: httpResponse(ALIVE_BODY) }, { mute: true }]);

    await createAdapter({ connect: harness.connect }).probe(ipv6Target);

    expect(harness.connections[0]?.address.hostname).toBe('[2001:db8::1]');
  });

  it('treats the candidate as dead only when both probes refuse the connection', async () => {
    const harness = createHarness([
      { connectError: new Error('connect ECONNREFUSED 203.0.113.10:8443') },
      { openedError: new Error('ECONNREFUSED') },
    ]);

    const result = await createAdapter({ connect: harness.connect }).probe(ipv4Target);

    expect(result).toMatchObject({ status: 'dead', endpoint: 'socket' });
    // 已经建立的连接（第二个探针的 opened 失败）也必须关闭，避免请求结束后仍占着 socket。
    expect(harness.closes[1]).toBeGreaterThan(0);
    expect(harness.closes[0]).toBe(0);
  });

  it('keeps mixed failures unknown instead of reporting a dead node', async () => {
    const harness = createHarness([
      { connectError: new Error('ECONNREFUSED') },
      { mute: true },
    ]);

    const result = await createAdapter({ connect: harness.connect }).probe(ipv4Target);

    expect(result).toMatchObject({ status: 'unknown', code: 'NETWORK_ERROR' });
  });

  it('reports a timeout when no probe answers in time', async () => {
    const harness = createHarness([{ mute: true }, { mute: true }]);

    const result = await createAdapter({ connect: harness.connect }).probe(ipv4Target);

    expect(result).toMatchObject({ status: 'unknown', code: 'TIMEOUT' });
    expect(harness.closes[0]).toBeGreaterThan(0);
  });

  it('keeps unparsable or incomplete responses unknown', async () => {
    const cases = [
      { response: httpResponse('<html>not json</html>'), expected: 'INVALID_RESPONSE' },
      { response: httpResponse('{"ok":true}'), expected: 'INVALID_RESPONSE' },
      { response: 'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n', expected: 'INVALID_RESPONSE' },
    ];

    for (const item of cases) {
      const harness = createHarness([{ response: item.response }]);
      const adapter = createAdapter({ connect: harness.connect });

      const result = await adapter.probe(ipv4Target);

      expect(result).toMatchObject({ status: 'unknown', code: item.expected });
    }
  });

  it('stops reading at the configured limit so a bad response cannot exhaust memory', async () => {
    const body = '{"ip":"198.51.100.7"}';
    // 只留一个探针，避免另一个探针的超时掩盖读取上限导致的结果。
    const harness = createHarness([{ response: httpResponseWithSize(body, 512) }]);

    const result = await createAdapter({ connect: harness.connect, readLimitBytes: 48, ipv6Url: '' }).probe(ipv4Target);

    // 响应头被截断，拿不到完整 JSON，只能给出 unknown 而不是误判。
    expect(result).toMatchObject({ status: 'unknown', code: 'INVALID_RESPONSE' });
  });

  it('does not connect when the caller already cancelled the check', async () => {
    const harness = createHarness([{ response: httpResponse(ALIVE_BODY) }]);
    const controller = new AbortController();
    controller.abort();

    const result = await createAdapter({ connect: harness.connect }).probe(ipv4Target, { signal: controller.signal });

    expect(result).toMatchObject({ status: 'unknown', code: 'CANCELLED' });
    expect(harness.connections).toEqual([]);
  });

  it('reports an unconfigured adapter when both probes are left empty', async () => {
    const harness = createHarness([{ response: httpResponse(ALIVE_BODY) }]);

    const result = await createAdapter({ connect: harness.connect, ipv4Url: '', ipv6Url: '' }).probe(ipv4Target);

    expect(result).toMatchObject({ status: 'unknown', code: 'NOT_CONFIGURED' });
    expect(harness.connections).toEqual([]);
  });
});

function createAdapter(options: {
  readonly connect: SocketConnect;
  readonly ipv4Url?: string;
  readonly ipv6Url?: string;
  readonly readLimitBytes?: number;
}): SocketProbeAdapter {
  return new SocketProbeAdapter({
    ipv4Url: options.ipv4Url ?? IPV4_URL,
    ipv6Url: options.ipv6Url ?? IPV6_URL,
    timeoutMs: TIMEOUT_MS,
    readLimitBytes: options.readLimitBytes ?? 65_536,
    connect: options.connect,
  });
}

function createHarness(scripts: readonly ProbeScript[]): Harness {
  const connections: Harness['connections'] = [];
  const tlsOptions: TlsOptions[] = [];
  const writes: Uint8Array[] = [];
  const closes: number[] = [];

  const connect: SocketConnect = (address, options) => {
    const index = connections.length;
    connections.push({ address, options });
    closes.push(0);
    const script = scripts[index] ?? {};
    if (script.connectError) throw script.connectError;
    return createFakeSocket('plain', script, { writes, tlsOptions, closes, index });
  };

  return { connect, connections, tlsOptions, writes, closes };
}

function createFakeSocket(
  phase: 'plain' | 'tls',
  script: ProbeScript,
  sink: { writes: Uint8Array[]; tlsOptions: TlsOptions[]; closes: number[]; index: number },
): ProbeSocket {
  const response = phase === 'tls' ? script.response : undefined;
  const mute = phase === 'tls' && script.mute === true;
  let controller: ReadableStreamDefaultController<Uint8Array> | null = null;
  let drained = false;

  const readable = new ReadableStream<Uint8Array>({
    start: (streamController) => {
      controller = streamController;
      if (response) streamController.enqueue(encoder.encode(response));
      if (!mute) {
        drained = true;
        streamController.close();
      }
    },
  });

  return {
    opened: phase === 'plain' && script.openedError ? Promise.reject(script.openedError) : Promise.resolve({}),
    readable,
    writable: new WritableStream<Uint8Array>({
      write: (chunk) => {
        sink.writes.push(chunk);
      },
    }),
    close: async () => {
      sink.closes[sink.index] = (sink.closes[sink.index] ?? 0) + 1;
      if (!drained && controller) {
        drained = true;
        try {
          controller.error(new Error('socket closed'));
        } catch {
          // 关闭已经出错的流不改变结论。
        }
      }
    },
    startTls: (options) => {
      if (options) sink.tlsOptions.push(options);
      return createFakeSocket('tls', script, sink);
    },
  };
}

function httpResponse(body: string): string {
  return `HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n${body}`;
}

/** 声明比实际响应更长的 Content-Length，用于验证读取上限被真正截断。 */
function httpResponseWithSize(body: string, declaredLength: number): string {
  return `HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${declaredLength}\r\nConnection: close\r\n\r\n${body}`;
}

function requireTarget(input: string) {
  const target = parseProxyTarget(input);
  if (!target) throw new Error(`测试目标无效：${input}`);
  return target;
}

function decode(bytes: Uint8Array | undefined): string {
  return bytes ? new TextDecoder().decode(bytes) : '';
}