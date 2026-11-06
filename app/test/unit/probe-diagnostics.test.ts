import { describe, expect, it, vi } from 'vitest';
import { ExternalApiProbeAdapter } from '../../src/adapters/probe/external-api';
import { parseProxyTarget } from '../../src/domain/proxy-target';
import { createWorker } from '../../src/worker';
import { ApiClient } from '../../web/src/api/client';
import { localWorkerContext } from '../helpers/native-probe';

const target = parseProxyTarget('203.0.113.10:443')!;
const endpoint = { name: 'primary', urlTemplate: 'https://probe.example/check?proxyip=' };
const partial = (error: string) => ({ success: true, inferred_stack: 'dual_stack', supports_ipv4: true, supports_ipv6: true,
  probe_results: { ipv4: { ok: true, exit: { ip: '198.51.100.42', ipType: 'ipv4', asn: 'AS64500', country: 'JP' } },
    ipv6: { ok: false, error, exit: null } } });

describe('probe availability and diagnostic regressions', () => {
  it.each(['TLS handshake failed', 'tcp connect timeout', 'HTTP 502'])('keeps a working exit available when only the other family reports %s', async error => {
    const fetchImpl = vi.fn(async () => Response.json(partial(error)));
    const onDiagnostic = vi.fn();
    const adapter = new ExternalApiProbeAdapter({ endpoints: [endpoint], timeoutMs: 1000, fetchImpl: fetchImpl as typeof fetch, onDiagnostic });
    const result = await adapter.probe(target);
    expect(result).toMatchObject({ status: 'alive', code: 'PARTIAL_EXIT', exitFamily: 'ipv4', exits: [{ family: 'ipv4', ip: '198.51.100.42' }] });
    expect(result.exits).toHaveLength(1);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(result.diagnostics).toMatchObject([{ endpoint: 'primary', code: 'PARTIAL_EXIT', status: 'alive' }]);
    expect(onDiagnostic).toHaveBeenCalledWith(expect.objectContaining({ phase: 'payload', code: 'PARTIAL_EXIT' }));
  });

  it.each([{ apiError: true }, { apiError: true, message: 'TCP Loop detected' }])('does not hide a global service error behind one working family: %j', async flags => {
    const adapter = new ExternalApiProbeAdapter({ endpoints: [endpoint], timeoutMs: 1000,
      fetchImpl: (async () => Response.json({ ...partial('TLS handshake failed'), ...flags })) as typeof fetch });
    expect(await adapter.probe(target)).toMatchObject({ status: 'unknown', code: 'PROBE_API_ERROR' });
  });

  it('keeps the primary error in diagnostics when the backup recovers', async () => {
    const onDiagnostic = vi.fn();
    const fetchImpl = vi.fn().mockRejectedValueOnce(new Error('socket hang up')).mockResolvedValueOnce(Response.json({ success: true }));
    const adapter = new ExternalApiProbeAdapter({ endpoints: [endpoint, { ...endpoint, name: 'backup' }], timeoutMs: 1000, fetchImpl, onDiagnostic });
    const result = await adapter.probe(target);
    expect(result).toMatchObject({ status: 'alive', endpoint: 'backup', diagnostics: [{ endpoint: 'primary', code: 'NETWORK_ERROR', message: expect.stringContaining('socket hang up') }] });
    expect(onDiagnostic).toHaveBeenCalledTimes(1);
  });

  it('reports request causes without exposing URL credentials, query keys, or headers', async () => {
    const onDiagnostic = vi.fn();
    const cause = new Error('connection reset https://user:fixture-password@probe.example/?token=fixture-token');
    const adapter = new ExternalApiProbeAdapter({ endpoints: [{ ...endpoint,
      urlTemplate: 'https://user:fixture-password@probe.example/check?token=fixture-token&proxyip=',
      headers: { Authorization: 'Bearer fixture-header-token' } }], timeoutMs: 1000, onDiagnostic,
      fetchImpl: (async () => { throw new Error('fetch failed fixture-header-token', { cause }); }) as typeof fetch });
    const result = await adapter.probe(target);
    expect(result.message).toContain('connection reset');
    expect(result.diagnostics).toHaveLength(2);
    expect(onDiagnostic).toHaveBeenCalledTimes(2);
    const output = JSON.stringify({ result, logs: onDiagnostic.mock.calls });
    for (const secret of ['fixture-password', 'fixture-token', 'fixture-header-token', 'user:']) expect(output).not.toContain(secret);
  });

  it('logs HTTP status and content type without reading or leaking an error body', async () => {
    const onDiagnostic = vi.fn();
    const adapter = new ExternalApiProbeAdapter({ endpoints: [endpoint], timeoutMs: 1000, onDiagnostic,
      fetchImpl: (async () => new Response('<html>private-response-value</html>', { status: 503, headers: { 'content-type': 'text/html' } })) as typeof fetch });
    expect(await adapter.probe(target)).toMatchObject({ status: 'unknown', code: 'HTTP_ERROR' });
    expect(onDiagnostic).toHaveBeenCalledWith(expect.objectContaining({ httpStatus: 503, contentType: 'text/html', phase: 'request' }));
    expect(JSON.stringify(onDiagnostic.mock.calls)).not.toContain('private-response-value');
  });

  it('describes HTML or empty bad JSON structurally without returning raw response text', async () => {
    const onDiagnostic = vi.fn();
    const adapter = new ExternalApiProbeAdapter({ endpoints: [endpoint], timeoutMs: 1000, onDiagnostic,
      fetchImpl: (async () => new Response('<html>private-response-value</html>', { headers: { 'content-type': 'text/html' } })) as typeof fetch });
    const result = await adapter.probe(target);
    expect(result).toMatchObject({ status: 'unknown', code: 'INVALID_JSON', message: expect.stringContaining('HTML') });
    expect(onDiagnostic).toHaveBeenCalledWith(expect.objectContaining({ phase: 'payload', responseShape: expect.stringContaining('HTML') }));
    expect(JSON.stringify({ result, logs: onDiagnostic.mock.calls })).not.toContain('private-response-value');
  });

  it('retains a service error reason even when the JSON is not a recognized node verdict', async () => {
    const adapter = new ExternalApiProbeAdapter({ endpoints: [endpoint], timeoutMs: 1000,
      fetchImpl: (async () => Response.json({ error: { message: 'upstream capacity unavailable' } })) as typeof fetch });
    expect(await adapter.probe(target)).toMatchObject({ status: 'unknown', code: 'INVALID_RESPONSE', message: expect.stringContaining('upstream capacity unavailable') });
  });

  it('keeps cancellation unknown without printing a service failure', async () => {
    const onDiagnostic = vi.fn();
    const controller = new AbortController();
    controller.abort();
    const adapter = new ExternalApiProbeAdapter({ endpoints: [endpoint], timeoutMs: 1000, onDiagnostic, fetchImpl: vi.fn() as typeof fetch });
    expect(await adapter.probe(target, { signal: controller.signal })).toMatchObject({ status: 'unknown', code: 'CANCELLED' });
    expect(onDiagnostic).not.toHaveBeenCalled();
  });

  it('passes sanitized diagnostics through the real ApiClient and Worker route and prints runtime logs', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    vi.stubGlobal('fetch', vi.fn(async () => new Response('bad response', { status: 502 })));
    try {
      const worker = createWorker();
      const env = { CHECK_API_BACKUP: 'https://probe.example/check?key=fixture-token&proxyip=' };
      const client = new ApiClient({ fetchImpl: async (url, init) => worker.fetch!(new Request(new URL(String(url), 'https://worker.example'), init) as Parameters<NonNullable<typeof worker.fetch>>[0],
        env, localWorkerContext(worker, env)) });
      const result = await client.checkTarget(target.authority);
      expect(result.items[0]!.result).toMatchObject({ status: 'unknown', code: 'HTTP_ERROR', diagnostics: [
        { endpoint: 'backup', code: 'HTTP_ERROR' },
      ] });
      expect(warn).toHaveBeenCalledTimes(1);
      expect(JSON.stringify(warn.mock.calls)).not.toContain('fixture-token');
    } finally { vi.unstubAllGlobals(); warn.mockRestore(); }
  });
});

it('does not reuse a failed branch stale exit while diagnosing the working family', async () => {
  const base = partial('TLS handshake failed');
  const payload = { ...base, probe_results: { ...base.probe_results, ipv6: { ok: false, error: 'TLS handshake failed', exit: { ip: '2001:db8::10', ipType: 'ipv6' } } } };
  const adapter = new ExternalApiProbeAdapter({ endpoints: [endpoint], timeoutMs: 1000,
    fetchImpl: (async () => Response.json(payload)) as typeof fetch });
  const result = await adapter.probe(target);
  expect(result.exitFamily).toBe('ipv4');
  expect(result.exits.map(exit => exit.ip)).toEqual(['198.51.100.42']);
});

it.each([{ apiError: true }, { status: 'error' }])('does not treat a child service error as a working exit: %j', async flags => {
  const base = partial('TLS handshake failed');
  const payload = { ...base, probe_results: { ...base.probe_results, ipv4: { ...base.probe_results.ipv4, ...flags } } };
  const adapter = new ExternalApiProbeAdapter({ endpoints: [endpoint], timeoutMs: 1000,
    fetchImpl: (async () => Response.json(payload)) as typeof fetch });
  expect(await adapter.probe(target)).toMatchObject({ status: 'unknown', code: 'PROBE_API_ERROR', exits: [] });
});
