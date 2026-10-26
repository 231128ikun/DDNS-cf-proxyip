import { describe, expect, it, vi } from 'vitest';
import { CheckProxy } from '../../src/application/check-proxy';
import { CheckTarget } from '../../src/application/check-target';
import { ResolveTarget } from '../../src/application/resolve-target';
import { TargetStatus } from '../../src/application/target-status';
import { alive } from '../../src/domain/probe-result';
import type { DnsRecord } from '../../src/ports/dns-repository';
import { createHttpApp } from '../../src/transport/http';
import { ApiClient } from '../../web/src/api/client';
import { loadTargetStatus, MAX_CURRENT_STATUS_PROBES } from '../../web/src/state/target-status';

function setup(records: readonly DnsRecord[], mode: 'A' | 'TXT' = 'A', failAddress?: string) {
  const writes = vi.fn();
  const requests: { path: string; method: string; address?: string }[] = [];
  let active = 0;
  let peak = 0;
  const checkProxy = new CheckProxy({
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
  it('uses the configured browser concurrency for automatic current-record probing', async () => {
    const records: DnsRecord[] = Array.from({ length: 6 }, (_, index) => ({
      id: String(index), type: 'A', name: 'edge.example.com', content: `203.0.113.${index + 1}`,
    }));
    const { client, peak } = setup(records);
    const view = await loadTargetStatus(client, 'edge.example.com|A', 2053, undefined, 2);
    expect(peak()).toBe(2);
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

  it('bounds automatic probing without hiding remaining DNS records', async () => {
    const records: DnsRecord[] = Array.from({ length: MAX_CURRENT_STATUS_PROBES + 1 }, (_, index) => ({
      id: String(index), type: 'A', name: 'edge.example.com', content: `203.0.113.${index + 1}`,
    }));
    const { client, requests, writes } = setup(records);
    const view = await loadTargetStatus(client, 'edge.example.com|A', 2053);
    expect(view.records).toHaveLength(MAX_CURRENT_STATUS_PROBES + 1);
    expect(view.probes).toHaveLength(MAX_CURRENT_STATUS_PROBES);
    expect(requests).toHaveLength(MAX_CURRENT_STATUS_PROBES + 1);
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
