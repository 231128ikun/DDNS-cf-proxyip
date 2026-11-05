import { describe, expect, it, vi } from 'vitest';
import { ExternalApiProbeAdapter } from '../../src/adapters/probe/external-api';
import { parseProxyTarget } from '../../src/domain/proxy-target';

const target = parseProxyTarget('203.0.113.10:443')!;
const endpoint = { name: 'primary', urlTemplate: 'https://probe.example/?candidate=' };
const result = (ok: boolean, status: number | null, error: string | null, family: string | null = null) => ({
  probe_name: family === 'ipv4' ? 'dbip' : 'ipsb', candidate: target.authority, connect_ms: 12, tls_ms: 20, http_ms: 30,
  status_code: status, ok, error, exit_ip: ok ? (family === 'ipv6' ? '2001:db8::42' : '198.51.100.42') : null,
  exit_family: family, exit_country: ok ? 'JP' : null, exit_asn: ok ? 64500 : null, exit_org: ok ? 'Example Network' : null,
});

function adapter(payload: unknown, status = 200) {
  return new ExternalApiProbeAdapter({ endpoints: [endpoint], timeoutMs: 1000, fallbackToNext: false,
    fetchImpl: (async () => Response.json(payload, { status })) as typeof fetch });
}

describe('documented probe backend protocol', () => {
  it('classifies target HTTP 404 inside a successful detector response as a dead candidate', async () => {
    const payload = { candidate: target.authority, ok: false, inferred_stack: 'unknown', supports_ipv4: false, supports_ipv6: false,
      probe_results: [result(false, 404, 'unexpected status: 404'), result(false, 404, 'unexpected status: 404')] };
    expect(await adapter(payload).probe(target)).toMatchObject({ status: 'dead', code: 'TARGET_HTTP_ERROR', message: '候选链路 HTTP 404' });
  });

  it('keeps a successful flat ToiCF exit alive when the other target returns 404', async () => {
    const payload = { candidate: target.authority, ok: true, inferred_stack: 'ipv4_only', supports_ipv4: true, supports_ipv6: false,
      probe_results: [result(true, 200, null, 'ipv4'), result(false, 404, 'unexpected status: 404')] };
    expect(await adapter(payload).probe(target)).toMatchObject({ status: 'alive', code: 'PARTIAL_EXIT', exitFamily: 'ipv4',
      exitIp: '198.51.100.42', exits: [{ family: 'ipv4', ip: '198.51.100.42', country: 'JP', asn: '64500', organization: 'Example Network' }] });
  });

  it.each([
    ['tls handshake failed', 'TARGET_TLS_ERROR'],
    ['tcp connect failed', 'TARGET_CONNECT_ERROR'],
  ])('classifies %s in probe_results as candidate failure, not API failure', async (error, code) => {
    const payload = { candidate: target.authority, ok: false, probe_results: [result(false, null, error), result(false, null, error)] };
    expect(await adapter(payload).probe(target)).toMatchObject({ status: 'dead', code });
  });

  it('keeps an HTTP 404 from the detector endpoint as unknown API failure', async () => {
    expect(await adapter({ error: 'route not found' }, 404).probe(target)).toMatchObject({ status: 'unknown', code: 'HTTP_ERROR' });
  });

  it('keeps explicit apiError as unknown even when the payload also contains a candidate failure', async () => {
    const payload = { success: false, apiError: true, error: 'detector unavailable', probe_results: [result(false, 404, 'unexpected status: 404')] };
    expect(await adapter(payload).probe(target)).toMatchObject({ status: 'unknown', code: 'PROBE_API_ERROR' });
  });

  it('rechecks a target 404 on backup before returning dead', async () => {
    const payload = { ok: false, probe_results: [result(false, 404, 'unexpected status: 404')] };
    const fetchImpl = vi.fn(async () => Response.json(payload));
    const checked = new ExternalApiProbeAdapter({ endpoints: [endpoint, { ...endpoint, name: 'backup' }], timeoutMs: 1000, fetchImpl: fetchImpl as typeof fetch });
    expect(await checked.probe(target)).toMatchObject({ status: 'dead', code: 'TARGET_HTTP_ERROR', endpoint: 'backup' });
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });
});
