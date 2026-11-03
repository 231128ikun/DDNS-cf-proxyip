import { describe, expect, it, vi } from 'vitest';
import { MaintainManagedTarget } from '../../src/application/maintain-managed-target';
import { MaintainManagedTargets, type MaintenanceRunReport } from '../../src/application/maintain-managed-targets';
import { CheckTarget } from '../../src/application/check-target';
import { CheckProxy } from '../../src/application/check-proxy';
import { ResolveTarget } from '../../src/application/resolve-target';
import { normalizeManagedTarget } from '../../src/domain/managed-target';
import { alive } from '../../src/domain/probe-result';
import type { DnsRecord, DnsRepository } from '../../src/ports/dns-repository';
import type { PoolRepository } from '../../src/ports/pool-repository';
import type { ProbeAdapter } from '../../src/ports/probe';
import { buildTelegramMaintenanceMessage } from '../../src/jobs/maintenance-message';
import { runMaintenanceJob } from '../../src/jobs/maintenance-job';
import { createHttpApp } from '../../src/transport/http';
import { ApiClient } from '../../web/src/api/client';

async function fixture(failAdd = false) {
  const target = normalizeManagedTarget({ mode: 'A', domain: 'edge.example.com', port: 443, minActive: 3 })!;
  const records: DnsRecord[] = ['10', '11'].map(last => ({ id: last, type: 'A', name: target.domain, content: '203.0.113.' + last }));
  const add = vi.fn(async (_zone, domain, host, type) => {
    if (failAdd) throw new Error('fixture DNS failure');
    const record = { id: 'new', name: domain, content: host, type };
    records.push(record);
    return record;
  });
  const dns: DnsRepository = { listAddressRecords: async () => records, listTxtRecords: async () => [], addAddressRecord: add,
    deleteRecord: async () => undefined, upsertTxtRecord: async () => { throw new Error('Unused'); } };
  const pools: PoolRepository = { load: async () => '203.0.113.12:443', save: async () => undefined, addToTrash: async () => undefined };
  const probe: ProbeAdapter = { name: 'fixture', probe: async address => alive(address, { exitFamily: 'ipv4', latencyMs: 12,
    exits: [{ family: 'ipv4', ip: '198.51.100.42', country: 'JP', asn: '64500' }] }) };
  const data = { zones: [], targets: [{ target, zoneIndex: null, enabled: true }], poolMapping: {}, poolNames: { ip_pool_default: '默认池' } };
  const zone = { zoneId: 'fixture-zone', apiToken: 'fixture-private-token' };
  const runner = new MaintainManagedTargets({ maintainer: new MaintainManagedTarget({ probe, pools, dns }) });
  const summary = await runner.execute(data, zone);
  const run: MaintenanceRunReport = { ...summary, poolStats: { before: { ip_pool_default: 1 }, after: { ip_pool_default: 1 },
    pools: [{ key: 'ip_pool_default', name: '默认池', count: 1 }], changed: false } };
  return { run, runner, data, zone, probe };
}

describe('complete and concise maintenance output', () => {
  it('includes every final DNS address, actual active count and successful additions', async () => {
    const { run } = await fixture();
    const message = buildTelegramMaintenanceMessage(run, { isManual: true, now: new Date('2026-11-03T00:00:00Z') });
    for (const last of ['10', '11', '12']) expect(message).toContain('解析 203.0.113.' + last);
    expect(message).toContain('活跃 3/3');
    expect(message).toContain('[新增]');
    expect(message).toContain('JP');
    expect(message).not.toContain('IP 池数量无变化');
    expect(message).not.toContain('fixture-private-token');
  });

  it('does not announce planned additions as active when DNS writing fails', async () => {
    const { run } = await fixture(true);
    expect(run.insufficient).toBe(true);
    const message = buildTelegramMaintenanceMessage(run, { isManual: true });
    expect(message).toContain('活跃 2/3');
    expect(message).toContain('未达到最小活跃数');
    expect(message).not.toContain('解析 203.0.113.12');
    expect(message).not.toContain('活跃 3/3');
  });

  it('returns prepared public lines and partial delivery status through the real client and route', async () => {
    const { run, probe } = await fixture();
    const app = createHttpApp({ version: 'fixture', maintenance: { run: async () => ({ run,
      notification: { sent: false, reason: 'failed', code: 'HTTP_429', delivered: 1, total: 2 } }) },
      checkTarget: new CheckTarget({ checkProxy: new CheckProxy(probe), resolver: new ResolveTarget({ query: async () => ({ ok: true, values: [] }) }) }) });
    const client = new ApiClient({ fetchImpl: async (url, init) => app.request(String(url), init) });
    const response = await client.runMaintenance();
    expect(response.results[0]!.dns?.after).toEqual(['203.0.113.10', '203.0.113.11', '203.0.113.12']);
    expect(response.results[0]!.lines?.join('\n')).toContain('活跃 3/3');
    expect(response.notificationMessage).toContain('通知发送失败');
    expect(response.notificationMessage).toContain('1/2');
    expect(response.completed).toBe(false);
    expect(response.message).toContain('通知发送失败');
    expect(JSON.stringify(response)).not.toContain('fixture-private-token');
    expect(JSON.stringify(response)).not.toContain('fixture-zone');
  });

  it('does not advance the notification baseline after partial delivery', async () => {
    const { runner, data, zone } = await fixture();
    const saveBaseline = vi.fn(async () => undefined);
    const result = await runMaintenanceJob({ source: { load: async () => data }, maintainer: runner, fallbackZone: zone, isManual: true,
      stats: { current: async () => [{ key: 'ip_pool_default', name: '默认池', count: 1 }], loadBaseline: async () => null, saveBaseline },
      notifier: { send: async () => ({ sent: false, reason: 'failed', delivered: 1, total: 2, code: 'HTTP_503' }) } });
    expect(result.notification?.sent).toBe(false);
    expect(saveBaseline).not.toHaveBeenCalled();
  });
});
