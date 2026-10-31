import { describe, expect, it, vi } from 'vitest';
import { ExternalApiProbeAdapter, buildProbeUrl } from '../../src/adapters/probe/external-api';
import { parseProxyTarget } from '../../src/domain/proxy-target';

const target = parseProxyTarget('203.0.113.10:8443');
if (!target) throw new Error('test target is invalid');

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

describe('ExternalApiProbeAdapter', () => {
  it.each([
    ['tcp connect timeout after 9999ms', 'TIMEOUT', '探针连接超时（节点状态未知）'],
    ['probe request timed out', 'TIMEOUT', '探针连接超时（节点状态未知）'],
    ['unexpected status: 502 body: <html><h1>502 Bad Gateway</h1></html>', 'HTTP_ERROR', '探针上游 HTTP 502（节点状态未知）'],
    ['upstream returned 503 Service Unavailable', 'HTTP_ERROR', '探针上游 HTTP 503（节点状态未知）'],
  ])('classifies reported infrastructure errors without exposing response bodies: %s', async (message, code, expected) => {
    const adapter = new ExternalApiProbeAdapter({ endpoints: [{ name: 'primary', urlTemplate: 'https://probe.example/?proxyip=' }],
      timeoutMs: 15000, fetchImpl: (async () => jsonResponse({ success: false, message })) as typeof fetch });
    expect(await adapter.probe(target)).toMatchObject({ status: 'unknown', code, message: expected });
  });

  it('retries a reported timeout on the backup without marking the node dead', async () => {
    let attempts = 0;
    const adapter = new ExternalApiProbeAdapter({ endpoints: [
      { name: 'primary', urlTemplate: 'https://primary.example/?proxyip=' },
      { name: 'backup', urlTemplate: 'https://backup.example/?proxyip=' },
    ], timeoutMs: 15000, fetchImpl: (async () => ++attempts === 1
      ? jsonResponse({ success: false, probe_results: { ipv4: { ok: false, error: 'tcp connect timeout after 9999ms' } } })
      : jsonResponse({ success: true })) as typeof fetch });
    expect(await adapter.probe(target)).toMatchObject({ status: 'alive', endpoint: 'backup' });
  });
  it('builds URL templates without duplicating parsing logic', () => {
    expect(buildProbeUrl('https://check.example/check?proxyip={proxyip}', target)).toBe(
      'https://check.example/check?proxyip=203.0.113.10%3A8443',
    );
    expect(buildProbeUrl('https://check.example/check?proxyip=', target)).toBe(
      'https://check.example/check?proxyip=203.0.113.10%3A8443',
    );
  });

  it('accepts a cmliu-style successful probe result', async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse({
        success: true,
        proxyIP: '203.0.113.10',
        inferred_stack: 'dual_stack',
        probe_results: {
          ipv4: { ok: true, exit: { ip: '198.51.100.1', ipType: 'ipv4' } },
          ipv6: { ok: true, exit: { ip: '2001:db8::2', ipType: 'ipv6' } },
        },
      }),
    ) as unknown as typeof fetch;

    const adapter = new ExternalApiProbeAdapter({
      endpoints: [{ name: 'primary', urlTemplate: 'https://check.example/check?proxyip={proxyip}' }],
      timeoutMs: 1_000,
      fetchImpl,
    });

    const result = await adapter.probe(target);
    expect(result.status).toBe('alive');
    expect(result.exitFamily).toBe('dual');
    expect(result.exitIp).toBe('198.51.100.1');
    expect(result.exits).toEqual([
      { family: 'ipv4', ip: '198.51.100.1' },
      { family: 'ipv6', ip: '2001:db8::2' },
    ]);
  });

  it('preserves ASN, country and organization from cmliu-style exits', async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse({
        success: true,
        colo: ' sjc ',
        inferred_stack: 'ipv4_only',
        probe_results: {
          ipv4: {
            ok: true,
            exit: {
              ip: '198.51.100.8',
              ipType: 'ipv4',
              asn: 'AS64500',
              country: 'jp',
              asOrganization: 'Example Network',
            },
          },
        },
      }),
    ) as unknown as typeof fetch;

    const adapter = new ExternalApiProbeAdapter({
      endpoints: [{ name: 'primary', urlTemplate: 'https://check.example/check?proxyip={proxyip}' }],
      timeoutMs: 1_000,
      fetchImpl,
    });

    const result = await adapter.probe(target);
    expect(result).toMatchObject({
      status: 'alive',
      colo: 'SJC',
      exitFamily: 'ipv4',
      exitIp: '198.51.100.8',
      exits: [
        {
          family: 'ipv4',
          ip: '198.51.100.8',
          asn: '64500',
          country: 'JP',
          organization: 'Example Network',
        },
      ],
    });
  });

  it('keeps an explicit failure as dead', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse({ success: false, message: 'node failed' })) as unknown as typeof fetch;
    const adapter = new ExternalApiProbeAdapter({
      endpoints: [{ name: 'primary', urlTemplate: 'https://check.example/check?proxyip={proxyip}' }],
      timeoutMs: 1_000,
      fetchImpl,
    });

    const result = await adapter.probe(target);
    expect(result.status).toBe('dead');
    expect(result.message).toBe('node failed');
  });

  it('treats invalid JSON as unknown', async () => {
    const fetchImpl = vi.fn(async () => new Response('not json', { status: 200 })) as unknown as typeof fetch;
    const adapter = new ExternalApiProbeAdapter({
      endpoints: [{ name: 'primary', urlTemplate: 'https://check.example/check?proxyip={proxyip}' }],
      timeoutMs: 1_000,
      fetchImpl,
    });

    const result = await adapter.probe(target);
    expect(result.status).toBe('unknown');
    expect(result.code).toBe('INVALID_JSON');
  });

  it('treats HTTP errors as unknown', async () => {
    const fetchImpl = vi.fn(async () => new Response('server error', { status: 502 })) as unknown as typeof fetch;
    const adapter = new ExternalApiProbeAdapter({
      endpoints: [{ name: 'primary', urlTemplate: 'https://check.example/check?proxyip={proxyip}' }],
      timeoutMs: 1_000,
      fetchImpl,
    });

    const result = await adapter.probe(target);
    expect(result.status).toBe('unknown');
    expect(result.code).toBe('HTTP_ERROR');
  });

  it('falls back to the backup endpoint after an unknown result', async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(new Response('bad gateway', { status: 502 }))
      .mockResolvedValueOnce(jsonResponse({ ok: true, ip: '198.51.100.9' })) as unknown as typeof fetch;

    const adapter = new ExternalApiProbeAdapter({
      endpoints: [
        { name: 'primary', urlTemplate: 'https://primary.example/?proxyip=' },
        { name: 'backup', urlTemplate: 'https://backup.example/?proxyip=' },
      ],
      timeoutMs: 1_000,
      fetchImpl,
    });

    const result = await adapter.probe(target);
    expect(result.status).toBe('alive');
    expect(result.endpoint).toBe('backup');
    expect(result.exitIp).toBe('198.51.100.9');
  });

  it('treats a TCP loop reported by the probe as an infrastructure error', async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse({
        candidate: '203.0.113.10:8443',
        success: false,
        elapsed_ms: 0,
        message: 'TCP Loop detected, contact us if this doesn\'t seem right.',
        probe_results: {
          ipv4: { ok: false, error: 'TCP Loop detected, contact us if this doesn\'t seem right.', exit: null },
          ipv6: { ok: false, error: 'TCP Loop detected, contact us if this doesn\'t seem right.', exit: null },
        },
      }),
    ) as unknown as typeof fetch;
    const adapter = new ExternalApiProbeAdapter({
      endpoints: [{ name: 'primary', urlTemplate: 'https://check.example/check?proxyip={proxyip}' }],
      timeoutMs: 1_000,
      fetchImpl,
    });

    const result = await adapter.probe(target);
    expect(result.status).toBe('unknown');
    expect(result.code).toBe('PROBE_API_ERROR');
    expect(result.message).toContain('TCP Loop detected');
  });

  it('does not fall back after a trusted endpoint reports the node dead', async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ success: false, message: 'connection refused' }))
      .mockResolvedValueOnce(jsonResponse({ ok: true, ip: '198.51.100.9' })) as unknown as typeof fetch;

    const adapter = new ExternalApiProbeAdapter({
      endpoints: [
        { name: 'primary', urlTemplate: 'https://primary.example/?proxyip=' },
        { name: 'backup', urlTemplate: 'https://backup.example/?proxyip=' },
      ],
      timeoutMs: 1_000,
      fetchImpl,
    });

    const result = await adapter.probe(target);
    expect(result.status).toBe('dead');
    expect(result.endpoint).toBe('primary');
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it.each([
    'Network connection lost.',
    'Worker exceeded resource limits',
    'too many requests, rate limit exceeded',
    'fetch failed: internal error',
  ])('treats probe service failure %s as unknown', async (message) => {
    const fetchImpl = vi.fn(async () => jsonResponse({ success: false, message })) as unknown as typeof fetch;
    const adapter = new ExternalApiProbeAdapter({
      endpoints: [{ name: 'primary', urlTemplate: 'https://check.example/check?proxyip={proxyip}' }],
      timeoutMs: 1_000,
      fetchImpl,
    });

    const result = await adapter.probe(target);
    expect(result.status).toBe('unknown');
    expect(result.code).toBe('PROBE_API_ERROR');
  });
});

describe('external probe safety regressions', () => {
  const adapterFor = (payload: unknown) => new ExternalApiProbeAdapter({
    endpoints: [{ name: 'primary', urlTemplate: 'https://probe.example/?proxyip=' }],
    timeoutMs: 1_000,
    fetchImpl: (async () => jsonResponse(payload)) as typeof fetch,
  });

  it.each([true, false])('apiError:true overrides success:%s and exit evidence', async (success) => {
    const result = await adapterFor({ success, apiError: true, exits: [{ ip: '198.51.100.1', stack: 'ipv4' }] }).probe(target);
    expect(result).toMatchObject({ status: 'unknown', code: 'PROBE_API_ERROR' });
  });

  it('recognizes a standalone apiError:true response as an API error', async () => {
    expect(await adapterFor({ apiError: true }).probe(target)).toMatchObject({ status: 'unknown', code: 'PROBE_API_ERROR' });
  });

  it.each([true, false])('apiError:false does not override success:%s', async (success) => {
    expect((await adapterFor({ success, apiError: false }).probe(target)).status).toBe(success ? 'alive' : 'dead');
  });

  it.each([
    ['detail', { detail: 'Network connection lost.' }],
    ['reason', { reason: 'Network connection lost.' }],
    ['error alongside ordinary message', { message: 'node failed', error: 'Network connection lost.' }],
    ['error object alongside ordinary message', { message: 'node failed', error: { detail: 'Network connection lost.' } }],
    ['probe_results', { probe_results: { ipv4: { ok: false, error: 'Network connection lost.' } } }],
    ['probeResults', { probeResults: { ipv4: { ok: false, error: 'Network connection lost.' } } }],
    ['probes', { probes: { ipv4: { ok: false, error: 'Network connection lost.' } } }],
    ['simultaneous aliases', { probe_results: { ipv4: { ok: false, error: 'connection refused' } }, probeResults: { ipv6: { ok: false, error: 'Network connection lost.' } } }],
    ['nested probe error', { probes: { ipv4: { ok: false, error: { cause: { message: 'Network connection lost.' } } } } }],
    ['untruncated evidence', { message: 'ordinary details '.repeat(30) + 'Network connection lost.' }],
  ] as const)('detects infrastructure evidence in %s', async (_label, evidence) => {
    const result = await adapterFor({ success: false, ...evidence }).probe(target);
    expect(result).toMatchObject({ status: 'unknown', code: 'PROBE_API_ERROR' });
    expect(result.message!.length).toBeLessThanOrEqual(240);
  });

  it('keeps specific timeout classification even when apiError is set', async () => {
    expect(await adapterFor({ success: false, apiError: true, detail: 'tcp connect timeout after 9999ms' }).probe(target))
      .toMatchObject({ status: 'unknown', code: 'TIMEOUT' });
  });

  it.each([
    { success: false, apiError: true },
    { success: false, detail: 'Network connection lost.' },
  ])('uses the backup after a reported API/infrastructure error: %j', async (payload) => {
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(jsonResponse(payload))
      .mockResolvedValueOnce(jsonResponse({ success: true }));
    const adapter = new ExternalApiProbeAdapter({ endpoints: [
      { name: 'primary', urlTemplate: 'https://primary.example/?proxyip=' },
      { name: 'backup', urlTemplate: 'https://backup.example/?proxyip=' },
    ], timeoutMs: 1_000, fetchImpl: fetchImpl as typeof fetch });
    expect(await adapter.probe(target)).toMatchObject({ status: 'alive', endpoint: 'backup' });
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  const dualExits = [{ stack: 'ipv4', ip: '198.51.100.1', asn: 'AS64500', country: 'JP' },
    { stack: 'ipv6', ip: '2001:db8::1', asn: 'AS64501', country: 'US' }];

  it.each([false, true])('infers dual stack from all exits (reversed=%s)', async (reversed) => {
    const exits = reversed ? [...dualExits].reverse() : dualExits;
    const result = await adapterFor({ success: true, exits }).probe(target);
    expect(result).toMatchObject({ status: 'alive', exitFamily: 'dual', exitIp: exits[0]!.ip });
    expect(result.exits).toHaveLength(2);
    expect(result.exits.map(exit => exit.asn)).toEqual(exits.map(exit => exit.asn.replace('AS', '')));
  });

  it.each([
    [{ inferred_stack: 'v6' }, 'ipv6'],
    [{ supports_ipv4: true }, 'ipv4'],
  ] as const)('keeps explicit family hints ahead of exit inference: %j', async (hint, family) => {
    expect(await adapterFor({ success: true, exits: dualExits, ...hint }).probe(target)).toMatchObject({ exitFamily: family });
  });
});
