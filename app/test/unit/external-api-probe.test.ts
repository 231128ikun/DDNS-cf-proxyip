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
    ['tcp connect timeout after 9999ms', 'TIMEOUT', '节点连接超时'],
    ['probe request timed out', 'TIMEOUT', '节点连接超时'],
    ['unexpected status: 502 body: <html><h1>502 Bad Gateway</h1></html>', 'HTTP_ERROR', '探针上游 HTTP 502（节点状态未知）'],
    ['upstream returned 503 Service Unavailable', 'HTTP_ERROR', '探针上游 HTTP 503（节点状态未知）'],
    ['HTTP 500', 'HTTP_ERROR', '探针上游 HTTP 500（节点状态未知）'],
    ['HTTP status: 403', 'HTTP_ERROR', '探针上游 HTTP 403（节点状态未知）'],
    ['TLS handshake failed', 'PROBE_API_ERROR', 'TLS handshake failed'],
    ['certificate has expired', 'PROBE_API_ERROR', 'certificate has expired'],
    ['ERR_SSL_PROTOCOL_ERROR', 'PROBE_API_ERROR', 'ERR_SSL_PROTOCOL_ERROR'],
    ['unable to verify the first certificate', 'PROBE_API_ERROR', 'unable to verify the first certificate'],
  ])('classifies reported infrastructure errors without exposing response bodies: %s', async (message, code, expected) => {
    const adapter = new ExternalApiProbeAdapter({ endpoints: [{ name: 'primary', urlTemplate: 'https://probe.example/?proxyip=' }],
      timeoutMs: 15000, fetchImpl: (async () => jsonResponse({ success: false, message })) as typeof fetch });
    expect(await adapter.probe(target)).toMatchObject({ status: code === 'TIMEOUT' ? 'dead' : 'unknown', code, message: expected });
  });

  it('accepts backup recovery after a reported timeout', async () => {
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

  it('rechecks a failed node on the backup before adopting a dead result', async () => {
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
    expect(result.status).toBe('alive');
    expect(result.endpoint).toBe('backup');
    expect(fetchImpl).toHaveBeenCalledTimes(2);
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

describe('probe rechecks', () => {
  const cases = [
    { label: 'confirmed timeout', payloads: [{ success: false, message: 'tcp connect timeout' }], status: 'dead', attempts: 2 },
    { label: 'timeout followed by API error', payloads: [{ success: false, message: 'tcp connect timeout' }, { success: false, message: 'HTTP 500' }], status: 'unknown', attempts: 2 },
    { label: 'healthy', payloads: [{ success: true }], status: 'alive', attempts: 1 },
    { label: 'recovered', payloads: [{ success: false }, { success: true }], status: 'alive', attempts: 2 },
    { label: 'confirmed failure', payloads: [{ success: false }, { success: false }], status: 'dead', attempts: 2 },
    { label: 'failed recheck', payloads: [{ success: false }, { success: false, message: 'TLS handshake failed' }], status: 'unknown', attempts: 2 },
    { label: 'recovered API error', payloads: [{ success: false, message: 'HTTP 500' }, { success: true }], status: 'alive', attempts: 2 },
  ];

  it.each(cases)('reuses a single endpoint for $label', async ({ payloads, status, attempts }) => {
    let index = 0;
    const fetchImpl = vi.fn(async (_url: RequestInfo | URL) => jsonResponse(payloads[index++] ?? payloads.at(-1)));
    const adapter = new ExternalApiProbeAdapter({
      endpoints: [{ name: 'backup', urlTemplate: 'https://only.example/?proxyip=' }],
      timeoutMs: 1_000, fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(await adapter.probe(target)).toMatchObject({ status, endpoint: 'backup' });
    expect(fetchImpl).toHaveBeenCalledTimes(attempts);
    expect(fetchImpl.mock.calls.map(([url]) => String(url))).toEqual(Array(attempts).fill('https://only.example/?proxyip=203.0.113.10%3A8443'));
  });

  it.each(cases)('uses primary then backup for $label', async ({ payloads, status, attempts }) => {
    let index = 0;
    const fetchImpl = vi.fn(async (_url: RequestInfo | URL) => jsonResponse(payloads[index++] ?? payloads.at(-1)));
    const adapter = new ExternalApiProbeAdapter({ endpoints: [
      { name: 'primary', urlTemplate: 'https://primary.example/?proxyip=' },
      { name: 'backup', urlTemplate: 'https://backup.example/?proxyip=' },
    ], timeoutMs: 1_000, fetchImpl: fetchImpl as unknown as typeof fetch });
    expect(await adapter.probe(target)).toMatchObject({ status, endpoint: attempts === 1 ? 'primary' : 'backup' });
    expect(fetchImpl).toHaveBeenCalledTimes(attempts);
    expect(fetchImpl.mock.calls.map(([url]) => String(url))).toEqual([
      'https://primary.example/?proxyip=203.0.113.10%3A8443',
      ...(attempts === 2 ? ['https://backup.example/?proxyip=203.0.113.10%3A8443'] : []),
    ]);
  });

  it('does not recheck when fallback is explicitly disabled', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse({ success: false }));
    const adapter = new ExternalApiProbeAdapter({ endpoints: [{ name: 'primary', urlTemplate: 'https://primary.example/?proxyip=' }],
      timeoutMs: 1_000, fallbackToNext: false, fetchImpl: fetchImpl as typeof fetch });
    expect((await adapter.probe(target)).status).toBe('dead');
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('does not start a request when the caller has already cancelled', async () => {
    const controller = new AbortController();
    controller.abort();
    const fetchImpl = vi.fn(async () => jsonResponse({ success: false }));
    const adapter = new ExternalApiProbeAdapter({ endpoints: [{ name: 'primary', urlTemplate: 'https://primary.example/?proxyip=' }],
      timeoutMs: 1_000, fetchImpl: fetchImpl as typeof fetch });
    expect(await adapter.probe(target, { signal: controller.signal })).toMatchObject({ status: 'unknown', code: 'CANCELLED' });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('does not recheck or report dead after the caller cancels the first request', async () => {
    const controller = new AbortController();
    const fetchImpl = vi.fn(async () => { controller.abort(); return jsonResponse({ success: false }); });
    const adapter = new ExternalApiProbeAdapter({ endpoints: [{ name: 'primary', urlTemplate: 'https://primary.example/?proxyip=' }],
      timeoutMs: 1_000, fetchImpl: fetchImpl as typeof fetch });
    expect(await adapter.probe(target, { signal: controller.signal })).toMatchObject({ status: 'unknown', code: 'CANCELLED' });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });
});

describe('complete public probe payload regressions', () => {
  // Failure captured from the public probe on 2026-11-02. Successful IPv6 fields come from the user's live log; IPv4/country are simulated.
  const completePayload = (success: boolean) => ({
    candidate: success ? '188.166.171.1:443' : '1.1.1.1:443',
    success,
    proxyIP: success ? '188.166.171.1' : '1.1.1.1',
    portRemote: 443,
    inferred_stack: success ? 'dual_stack' : 'unknown',
    supports_ipv4: success,
    supports_ipv6: success,
    dual_stack: success,
    responseTime: success ? 1107 : null,
    elapsed_ms: success ? 1110 : 1,
    colo: success ? 'LHR' : 'ICN',
    timeStamp: '2026-11-02T06:52:27.657Z',
    message: success ? 'proxy request succeeded' : 'proxy request failed, cannot connect to the specified address. It looks like you might be trying to connect to a HTTP-based service — consider using fetch instead',
    probe_results: {
      ipv4: {
        candidate: success ? '188.166.171.1:443' : '1.1.1.1:443', connect_ms: success ? 12 : null, tls_ms: success ? 24 : null,
        http_ms: success ? 88 : null, status_code: success ? 200 : null, ok: success,
        error: success ? null : 'proxy request failed, cannot connect to the specified address. It looks like you might be trying to connect to a HTTP-based service — consider using fetch instead',
        exit: success ? { ip: '198.51.100.42', ipType: 'ipv4', asn: 'AS64500', country: 'jp', asOrganization: 'Example Network' } : null,
      },
      ipv6: {
        candidate: success ? '188.166.171.1:443' : '1.1.1.1:443', connect_ms: success ? 270 : null, tls_ms: success ? 278 : null,
        http_ms: success ? 559 : null, status_code: success ? 200 : null, ok: success,
        error: success ? null : 'proxy request failed, cannot connect to the specified address. It looks like you might be trying to connect to a HTTP-based service — consider using fetch instead',
        exit: success ? { ip: '2a03:b0c0:1:e0:0:1:38db:b001', ipType: 'ipv6', colo: 'LHR', asn: 14061, country: 'gb', asOrganization: 'DigitalOcean' } : null,
      },
    },
  });

  it.each([true, false])('does not mistake timing/error field names for TLS failures (success=%s)', async (success) => {
    const fetchImpl = vi.fn(async () => jsonResponse(completePayload(success)));
    const adapter = new ExternalApiProbeAdapter({
      endpoints: [{ name: 'primary', urlTemplate: 'https://probe.example/?candidate=' }],
      timeoutMs: 1_000, fetchImpl: fetchImpl as typeof fetch,
    });
    const result = await adapter.probe(target);
    expect(result).toMatchObject({ status: success ? 'alive' : 'dead' });
    expect(result.code).toBeUndefined();
    expect(fetchImpl).toHaveBeenCalledTimes(success ? 1 : 2);
    if (success) {
      expect(result).toMatchObject({ colo: 'LHR', exitFamily: 'dual', exitIp: '198.51.100.42', exits: [
        { family: 'ipv4', ip: '198.51.100.42', asn: '64500', country: 'JP', organization: 'Example Network' },
        { family: 'ipv6', ip: '2a03:b0c0:1:e0:0:1:38db:b001', asn: '14061', country: 'GB', organization: 'DigitalOcean' },
      ] });
    }
  });

  it.each([
    ['timeout_ms', 15000], ['error', null], ['tls', { error: null }], ['HTTP', 500],
    ['TLS handshake failed', null], ['timeout', false],
  ])('ignores non-string values and infrastructure-looking field names: %s', async (key, value) => {
    const payload = { ...completePayload(true), error: { [key]: value } };
    const adapter = new ExternalApiProbeAdapter({
      endpoints: [{ name: 'primary', urlTemplate: 'https://probe.example/?candidate=' }],
      timeoutMs: 1_000, fetchImpl: (async () => jsonResponse(payload)) as typeof fetch,
    });
    expect((await adapter.probe(target)).status).toBe('alive');
  });

  it.each(['probe_results', 'probeResults', 'probes'])('ignores normal metadata inside %s even when strings contain error-like words', async (alias) => {
    const { probe_results, ...record } = completePayload(true);
    probe_results.ipv6.candidate = 'timeout.example.com:443';
    probe_results.ipv6.exit!.asOrganization = 'TLS handshake failed';
    const payload = { ...record, [alias]: probe_results };
    const adapter = new ExternalApiProbeAdapter({
      endpoints: [{ name: 'primary', urlTemplate: 'https://probe.example/?candidate=' }],
      timeoutMs: 1_000, fetchImpl: (async () => jsonResponse(payload)) as typeof fetch,
    });
    expect((await adapter.probe(target)).status).toBe('alive');
  });

  it.each(['asn', 'as', 'asNumber'])('preserves numeric ASN from %s without inventing other metadata', async (key) => {
    const adapter = new ExternalApiProbeAdapter({
      endpoints: [{ name: 'primary', urlTemplate: 'https://probe.example/?candidate=' }],
      timeoutMs: 1_000, fetchImpl: (async () => jsonResponse({ success: true,
        probe_results: { ipv6: { ok: true, error: null, exit: {
          ip: '2a03:b0c0:1:e0:0:1:38db:b001', ipType: 'ipv6', [key]: 14061, country: 'gb', asOrganization: 'DigitalOcean',
        } } },
      })) as typeof fetch,
    });
    expect(await adapter.probe(target)).toMatchObject({ status: 'alive', exits: [
      { family: 'ipv6', ip: '2a03:b0c0:1:e0:0:1:38db:b001', asn: '14061', country: 'GB', organization: 'DigitalOcean' },
    ] });
  });

  it.each([null, false, 0, -1, 1.5, '', { number: 14061 }])('ignores invalid numeric/missing ASN without hiding a valid alias: %j', async (asn) => {
    const adapter = new ExternalApiProbeAdapter({
      endpoints: [{ name: 'primary', urlTemplate: 'https://probe.example/?candidate=' }],
      timeoutMs: 1_000, fetchImpl: (async () => jsonResponse({ success: true,
        exit: { ip: '198.51.100.42', asn, asNumber: 'AS64500' },
      })) as typeof fetch,
    });
    expect(await adapter.probe(target)).toMatchObject({ status: 'alive', exits: [{ asn: '64500' }] });
  });

  it.each([
    ['TLS handshake failed', 'PROBE_API_ERROR', true], ['TLS handshake failed', 'PROBE_API_ERROR', false],
    ['tcp connect timeout after 9999ms', 'TIMEOUT', true], ['tcp connect timeout after 9999ms', 'TIMEOUT', false],
    ['HTTP 502', 'HTTP_ERROR', true], ['HTTP 502', 'HTTP_ERROR', false],
  ] as const)('still classifies real nested errors in complete payloads: %s / %s (success=%s)', async (message, code, success) => {
    const payload = completePayload(success);
    payload.probe_results.ipv6.error = message;
    const adapter = new ExternalApiProbeAdapter({
      endpoints: [{ name: 'primary', urlTemplate: 'https://probe.example/?candidate=' }],
      timeoutMs: 1_000, fetchImpl: (async () => jsonResponse(payload)) as typeof fetch,
    });
    expect(await adapter.probe(target)).toMatchObject({ status: code === 'TIMEOUT' ? 'dead' : 'unknown', code });
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
    ['nested error array', { probes: { ipv4: { ok: false, error: { causes: [{ detail: 'Network connection lost.' }] } } } }],
    ['untruncated evidence', { message: 'ordinary details '.repeat(30) + 'Network connection lost.' }],
  ] as const)('detects infrastructure evidence in %s', async (_label, evidence) => {
    const result = await adapterFor({ success: false, ...evidence }).probe(target);
    expect(result).toMatchObject({ status: 'unknown', code: 'PROBE_API_ERROR' });
    expect(result.message!.length).toBeLessThanOrEqual(240);
  });

  it('keeps specific timeout classification even when apiError is set', async () => {
    expect(await adapterFor({ success: false, apiError: true, detail: 'tcp connect timeout after 9999ms' }).probe(target))
      .toMatchObject({ status: 'dead', code: 'TIMEOUT' });
  });

  it.each([
    { success: false, apiError: true },
    { success: false, detail: 'Network connection lost.' },
    { success: false, message: 'TLS handshake failed' },
    { success: false, message: 'certificate has expired' },
    { success: false, error: { message: 'HTTP 500' } },
    { success: false, probes: { ipv4: { error: { cause: 'ERR_SSL_PROTOCOL_ERROR' } } } },
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

describe('probe timeout decisions', () => {
  const endpoint = { name: 'primary', urlTemplate: 'https://probe.example/?proxyip=' };
  const stalledFetch = (_url: RequestInfo | URL, init?: RequestInit): Promise<Response> => new Promise((_, reject) => {
    init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')), { once: true });
  });

  it('marks an exhausted deadline dead after the existing single-endpoint recheck', async () => {
    vi.useFakeTimers();
    try {
      const fetchImpl = vi.fn(stalledFetch);
      const adapter = new ExternalApiProbeAdapter({ endpoints: [endpoint], timeoutMs: 10, fetchImpl: fetchImpl as typeof fetch });
      const pending = adapter.probe(target);
      await vi.advanceTimersByTimeAsync(20);
      expect(await pending).toMatchObject({ status: 'dead', code: 'TIMEOUT', endpoint: 'primary', message: '检测超时 (10ms)' });
      expect(fetchImpl).toHaveBeenCalledTimes(2);
    } finally { vi.useRealTimers(); }
  });

  it('returns alive when the backup recovers from a local request timeout', async () => {
    vi.useFakeTimers();
    try {
      let attempts = 0;
      const adapter = new ExternalApiProbeAdapter({ endpoints: [endpoint, { ...endpoint, name: 'backup' }], timeoutMs: 10,
        fetchImpl: (async (url, init) => ++attempts === 1 ? stalledFetch(url, init) : jsonResponse({ success: true })) as typeof fetch });
      const pending = adapter.probe(target);
      await vi.advanceTimersByTimeAsync(10);
      expect(await pending).toMatchObject({ status: 'alive', endpoint: 'backup' });
    } finally { vi.useRealTimers(); }
  });

  it('marks a response-body deadline dead and releases its timer', async () => {
    vi.useFakeTimers();
    try {
      const adapter = new ExternalApiProbeAdapter({ endpoints: [endpoint], timeoutMs: 10, fallbackToNext: false,
        fetchImpl: (async (_url, init) => new Response(new ReadableStream({ start(controller) {
          init?.signal?.addEventListener('abort', () => controller.error(new DOMException('aborted', 'AbortError')), { once: true });
        } }))) as typeof fetch });
      const pending = adapter.probe(target);
      await vi.advanceTimersByTimeAsync(10);
      expect(await pending).toMatchObject({ status: 'dead', code: 'TIMEOUT' });
      expect(vi.getTimerCount()).toBe(0);
    } finally { vi.useRealTimers(); }
  });

  it('keeps caller cancellation unknown and skips the backup', async () => {
    const controller = new AbortController();
    const fetchImpl = vi.fn(stalledFetch);
    const adapter = new ExternalApiProbeAdapter({ endpoints: [endpoint], timeoutMs: 1000, fetchImpl: fetchImpl as typeof fetch });
    const pending = adapter.probe(target, { signal: controller.signal });
    controller.abort();
    expect(await pending).toMatchObject({ status: 'unknown', code: 'CANCELLED' });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it.each([
    ['AbortError', 'unknown', 'NETWORK_ERROR'],
    ['TimeoutError', 'dead', 'TIMEOUT'],
  ])('distinguishes an unsolicited %s from caller cancellation', async (name, status, code) => {
    const adapter = new ExternalApiProbeAdapter({ endpoints: [endpoint], timeoutMs: 1000,
      fetchImpl: (async () => { throw new DOMException('fixture transport failure', name); }) as typeof fetch });
    expect(await adapter.probe(target)).toMatchObject({ status, code });
  });
});
