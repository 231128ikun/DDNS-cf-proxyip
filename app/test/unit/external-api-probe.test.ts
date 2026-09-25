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
});
