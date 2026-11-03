import { describe, expect, it, vi } from 'vitest';
import { ExternalApiProbeAdapter } from '../../src/adapters/probe/external-api';
import { CheckProxy } from '../../src/application/check-proxy';
import { CheckTarget } from '../../src/application/check-target';
import { ResolveTarget } from '../../src/application/resolve-target';
import { TargetStatus } from '../../src/application/target-status';
import { alive } from '../../src/domain/probe-result';
import type { DnsRecord } from '../../src/ports/dns-repository';
import type { ProbeAdapter } from '../../src/ports/probe';
import { createHttpApp } from '../../src/transport/http';
import { ApiClient } from '../../web/src/api/client';
import { probeStatusLabel } from '../../web/src/components/probe-status';
import { loadTargetStatus, loadTargetStatuses } from '../../web/src/state/target-status';

function setup(records: readonly DnsRecord[], mode: 'A' | 'TXT' = 'A', failAddress?: string, probeAdapter?: ProbeAdapter) {
  const writes = vi.fn();
  const requests: { path: string; method: string; address?: string }[] = [];
  let active = 0;
  let peak = 0;
  const checkProxy = new CheckProxy(probeAdapter ?? {
    name: 'fixture',
    probe: async (target) => alive(target, { colo: 'SJC', latencyMs: 12, exitFamily: 'dual', exits: [
      { family: 'ipv4', ip: '198.51.100.42', asn: '64500', country: 'US' },
      { family: 'ipv6', ip: '2001:db8::42', asn: '64501', country: 'JP' },
    ] }),
  });
  const app = createHttpApp({
    version: 'fixture',
    checkTarget: new CheckTarget({ resolver: new ResolveTarget({ query: async () => ({ ok: true, values: [] }) }), checkProxy }),
    targetStatus: new TargetStatus({
      source: { load: async () => ({ zones: [], poolNames: {}, poolMapping: {}, targets: [{
        zoneIndex: null, enabled: true,
        target: { mode, domain: 'edge.example.com', port: mode === 'A' ? 2053 : null, minActive: 1, exitFilter: 'any', countries: [], asns: [] },
      }] }) },
      fallbackZone: { zoneId: 'fixture-zone', apiToken: 'fixture-token' },
      dns: {
        listAddressRecords: async () => records, listTxtRecords: async () => records,
        addAddressRecord: writes, upsertTxtRecord: writes, deleteRecord: writes,
      },
    }),
  });
  const client = new ApiClient({ fetchImpl: async (input, init) => {
    const path = String(input);
    const address = typeof init?.body === 'string' ? (JSON.parse(init.body) as { proxyip: string }).proxyip : undefined;
    requests.push({ path, method: init?.method ?? 'GET', ...(address ? { address } : {}) });
    if (address === failAddress && failAddress) return Response.json({ error: 'fixture probe error' }, { status: 500 });
    if (address) { active += 1; peak = Math.max(peak, active); }
    const response = await app.request(path, init);
    if (address) active -= 1;
    return response;
  } });
  return { client, requests, writes, peak: () => peak };
}

describe('current DNS display through ApiClient and Worker routes', () => {
  it('preserves complete upstream decisions and metadata through the real status chain', async () => {
    const records: DnsRecord[] = ['188.166.171.1', '203.0.113.11', '203.0.113.12'].map((content, index) => ({
      id: String(index), type: 'A', name: 'edge.example.com', content,
    }));
    const probeFetch = vi.fn(async (input: RequestInfo | URL) => {
      const candidate = new URL(String(input)).searchParams.get('candidate')!;
      const success = candidate === '188.166.171.1:2053';
      const error = success ? null : candidate === '203.0.113.12:2053' ? 'TLS handshake failed' : 'connection refused';
      return Response.json({
        candidate, success, proxyIP: candidate.split(':')[0], portRemote: 2053,
        inferred_stack: success ? 'dual_stack' : 'unknown', supports_ipv4: success, supports_ipv6: success, dual_stack: success,
        responseTime: success ? 1107 : null, elapsed_ms: success ? 1110 : 1, colo: 'LHR',
        timeStamp: '2026-11-02T06:52:27.657Z', message: error,
        probe_results: {
          ipv4: { candidate, connect_ms: success ? 12 : null, tls_ms: success ? 24 : null,
            http_ms: success ? 88 : null, status_code: success ? 200 : null, ok: success, error,
            exit: success ? { ip: '198.51.100.42', ipType: 'ipv4', asn: 'AS64500', country: 'JP', asOrganization: 'Example Network' } : null },
          ipv6: { candidate, connect_ms: success ? 270 : null, tls_ms: success ? 278 : null,
            http_ms: success ? 559 : null, status_code: success ? 200 : null, ok: success, error,
            exit: success ? { ip: '2a03:b0c0:1:e0:0:1:38db:b001', ipType: 'ipv6', colo: 'LHR', asn: 14061, country: 'GB', asOrganization: 'DigitalOcean' } : null },
        },
      });
    });
    const adapter = new ExternalApiProbeAdapter({
      endpoints: [{ name: 'primary', urlTemplate: 'https://probe.example/?candidate=' }],
      timeoutMs: 1_000, fetchImpl: probeFetch as typeof fetch,
    });
    const { client, requests, writes } = setup(records, 'A', undefined, adapter);
    const progress = vi.fn();
    const view = await loadTargetStatus(client, 'edge.example.com|A', 2053, undefined, progress);
    expect(view.records).toEqual(records);
    expect(view.probes).toMatchObject([
      { address: '188.166.171.1:2053', status: 'alive', colo: 'LHR', exitFamily: 'dual', exitIp: '198.51.100.42', exits: [
        { family: 'ipv4', ip: '198.51.100.42', asn: '64500', country: 'JP', organization: 'Example Network' },
        { family: 'ipv6', ip: '2a03:b0c0:1:e0:0:1:38db:b001', asn: '14061', country: 'GB', organization: 'DigitalOcean' },
      ] },
      { address: '203.0.113.11:2053', status: 'dead', message: 'connection refused' },
      { address: '203.0.113.12:2053', status: 'unknown', code: 'PROBE_API_ERROR', message: 'TLS handshake failed' },
    ]);
    expect(view.probes[0]!.latencyMs).toEqual(expect.any(Number));
    expect(view.probes.map(item => probeStatusLabel(item.status, item.code))).toEqual(['可用', '失效', '未知']);
    expect(progress).toHaveBeenCalledTimes(4);
    expect(progress.mock.calls.at(-1)![0].probes).toHaveLength(3);
    expect(requests.filter(request => request.address).map(request => request.address)).toEqual(records.map(record => `${record.content}:2053`));
    expect(probeFetch).toHaveBeenCalledTimes(5);
    expect(writes).not.toHaveBeenCalled();
  });

  it('publishes DNS records while a slow probe is still pending', async () => {
    const records: DnsRecord[] = [{ id: 'a', type: 'A', name: 'edge.example.com', content: '203.0.113.10' }];
    const { client } = setup(records);
    let finish!: () => void;
    vi.spyOn(client, 'checkBatch').mockImplementation(async () => {
      await new Promise<void>(resolve => { finish = resolve; });
      return { total: 0, alive: 0, dead: 0, unknown: 0, invalid: [], items: [] };
    });
    const progress = vi.fn();
    const pending = loadTargetStatus(client, 'edge.example.com|A', 2053, undefined, progress);
    await vi.waitFor(() => expect(progress).toHaveBeenCalledWith(expect.objectContaining({ records, probes: [] })));
    finish();
    await pending;
  });
  it('publishes each probe result without waiting for the slowest address', async () => {
    const records: DnsRecord[] = ['203.0.113.10', '203.0.113.11'].map((content, index) => ({
      id: String(index), type: 'A', name: 'edge.example.com', content,
    }));
    const { client, writes } = setup(records);
    let finish!: () => void;
    const slow = new Promise<void>(resolve => { finish = resolve; });
    const check = client.checkTarget.bind(client);
    vi.spyOn(client, 'checkTarget').mockImplementation(async (address, signal) => {
      if (address === '203.0.113.11:2053') await slow;
      return check(address, signal);
    });
    const progress = vi.fn();
    const pending = loadTargetStatus(client, 'edge.example.com|A', 2053, undefined, progress);
    try {
      await vi.waitFor(() => expect(progress).toHaveBeenCalledWith(expect.objectContaining({
        records, probes: [expect.objectContaining({ address: '203.0.113.10:2053', status: 'alive' })],
      })));
    } finally {
      finish();
    }
    expect((await pending).probes.map(item => item.address)).toEqual(['203.0.113.10:2053', '203.0.113.11:2053']);
    expect(writes).not.toHaveBeenCalled();
  });

  it('starts every current-record probe concurrently', async () => {
    const records: DnsRecord[] = Array.from({ length: 6 }, (_, index) => ({
      id: String(index), type: 'A', name: 'edge.example.com', content: `203.0.113.${index + 1}`,
    }));
    const { client, peak } = setup(records);
    const view = await loadTargetStatus(client, 'edge.example.com|A', 2053, undefined);
    expect(peak()).toBe(6);
    expect(view.probes.map(item => item.address)).toEqual([
      '203.0.113.1:2053', '203.0.113.2:2053', '203.0.113.3:2053',
      '203.0.113.4:2053', '203.0.113.5:2053', '203.0.113.6:2053',
    ]);
  });

  it('probes A and AAAA records at the configured port and keeps both exits and Colo', async () => {
    const records: DnsRecord[] = [
      { id: 'a', type: 'A', name: 'edge.example.com', content: '203.0.113.10' },
      { id: 'aaaa', type: 'AAAA', name: 'edge.example.com', content: '2001:db8::10' },
    ];
    const { client, requests, writes } = setup(records);
    const view = await loadTargetStatus(client, 'edge.example.com|A', 2053);
    expect(view.records).toEqual(records);
    expect(requests.map(request => request.address).filter(Boolean)).toEqual(['203.0.113.10:2053', '[2001:db8::10]:2053']);
    expect(view.probes[0]).toMatchObject({ status: 'alive', colo: 'SJC', latencyMs: 12, exits: [
      { family: 'ipv4', ip: '198.51.100.42' }, { family: 'ipv6', ip: '2001:db8::42' },
    ] });
    expect(writes).not.toHaveBeenCalled();
  });

  it('keeps TXT address ports while probing each address', async () => {
    const records: DnsRecord[] = [{ id: 'txt', type: 'TXT', name: 'edge.example.com', content: '"203.0.113.10:443,[2001:db8::10]:8443"' }];
    const { client, requests, writes } = setup(records, 'TXT');
    const view = await loadTargetStatus(client, 'edge.example.com|TXT', 'any');
    expect(view.records).toEqual(records);
    expect(requests.map(request => request.address).filter(Boolean)).toEqual(['203.0.113.10:443', '[2001:db8::10]:8443']);
    expect(writes).not.toHaveBeenCalled();
  });

  it('keeps a failed probe unknown and preserves its DNS record', async () => {
    const records: DnsRecord[] = [{ id: 'a', type: 'A', name: 'edge.example.com', content: '203.0.113.10' }];
    const { client, writes } = setup(records, 'A', '203.0.113.10:2053');
    const view = await loadTargetStatus(client, 'edge.example.com|A', 2053);
    expect(view.records).toEqual(records);
    expect(view.probes).toMatchObject([{ status: 'unknown', code: 'HTTP_500' }]);
    expect(writes).not.toHaveBeenCalled();
  });

  it('probes all records without a 200-address cap or the batch concurrency ceiling', async () => {
    const records: DnsRecord[] = Array.from({ length: 201 }, (_, index) => ({
      id: String(index), type: 'A', name: 'edge.example.com', content: `203.0.113.${index + 1}`,
    }));
    const { client, requests, writes, peak } = setup(records);
    const view = await loadTargetStatus(client, 'edge.example.com|A', 2053);
    expect(peak()).toBe(201);
    expect(view.records).toHaveLength(201);
    expect(view.probes).toHaveLength(201);
    expect(requests).toHaveLength(202);
    expect(writes).not.toHaveBeenCalled();
  });

  it('does not send probe requests after cancellation or for an empty record set', async () => {
    const { client, requests } = setup([]);
    const view = await loadTargetStatus(client, 'edge.example.com|A', 2053);
    expect(view.probes).toEqual([]);
    expect(requests).toHaveLength(1);
    const records: DnsRecord[] = [{ id: 'a', type: 'A', name: 'edge.example.com', content: '203.0.113.10' }];
    const cancelled = setup(records);
    const controller = new AbortController();
    controller.abort();
    await expect(loadTargetStatus(cancelled.client, 'edge.example.com|A', 2053, controller.signal)).rejects.toMatchObject({ name: 'AbortError' });
    expect(cancelled.requests).toHaveLength(1);
  });
});


describe('concurrent domain status loading', () => {
  const targets = [
    { domain: 'slow.example.com', mode: 'A' as const, port: 2053 },
    { domain: 'fast.example.com', mode: 'TXT' as const, port: 'any' as const },
  ];

  it('starts all domains together and publishes fast results before a slow domain finishes', async () => {
    const { client } = setup([]);
    let finish!: () => void;
    const slow = new Promise<void>(resolve => { finish = resolve; });
    const reads = vi.spyOn(client, 'currentStatus').mockImplementation(async key => {
      if (key.startsWith('slow.')) await slow;
      const isTxt = key.endsWith('|TXT');
      return { ok: true, domain: key.split('|')[0]!, mode: isTxt ? 'TXT' : 'A', records: [
        { id: key, name: key.split('|')[0]!, type: isTxt ? 'TXT' : 'A',
          content: isTxt ? '"203.0.113.11:8443"' : '203.0.113.10' },
      ] };
    });
    const progress = vi.fn();
    const pending = loadTargetStatuses(client, targets, undefined, progress);
    try {
      expect(reads).toHaveBeenCalledTimes(2);
      await vi.waitFor(() => expect(progress).toHaveBeenCalledWith(expect.objectContaining({ byKey: expect.objectContaining({
        'fast.example.com|TXT': expect.objectContaining({ status: 'ready', data: expect.objectContaining({ probes: [
          expect.objectContaining({ address: '203.0.113.11:8443', status: 'alive' }),
        ] }) }),
        'slow.example.com|A': { status: 'loading' },
      }) })));
    } finally { finish(); }
    const completed = await pending;
    expect(completed.byKey['slow.example.com|A']).toMatchObject({ status: 'ready', data: { probes: [
      { address: '203.0.113.10:2053', status: 'alive' },
    ] } });
  });

  it('isolates a domain read failure without hiding another domain and ignores cancelled progress', async () => {
    const { client } = setup([]);
    vi.spyOn(client, 'currentStatus').mockImplementation(async key => {
      if (key.startsWith('slow.')) throw new Error('fixture DNS failure');
      return { ok: true, domain: 'fast.example.com', mode: 'TXT', records: [] };
    });
    const status = await loadTargetStatuses(client, targets);
    expect(status.byKey['slow.example.com|A']).toMatchObject({ status: 'error', message: 'fixture DNS failure' });
    expect(status.byKey['fast.example.com|TXT']).toMatchObject({ status: 'ready', data: { probes: [] } });
    const controller = new AbortController();
    controller.abort();
    const progress = vi.fn();
    await expect(loadTargetStatuses(client, targets, controller.signal, progress)).rejects.toMatchObject({ name: 'AbortError' });
    expect(progress).not.toHaveBeenCalled();
  });
});
