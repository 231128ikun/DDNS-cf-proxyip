import { describe, expect, it, vi } from 'vitest';
import { MaintainManagedTarget } from '../../src/application/maintain-managed-target';
import { MaintainManagedTargets, type MaintenanceRunReport } from '../../src/application/maintain-managed-targets';
import { CheckTarget } from '../../src/application/check-target';
import { CheckProxy } from '../../src/application/check-proxy';
import { ResolveTarget } from '../../src/application/resolve-target';
import { normalizeManagedTarget } from '../../src/domain/managed-target';
import { parseProxyTarget } from '../../src/domain/proxy-target';
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
  const probe: ProbeAdapter = { name: 'fixture', probe: async address => alive(address, { exitFamily: 'ipv4', latencyMs: 12, colo: 'ICN',
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
  it('uses compact domain groups and keeps address metadata in the legacy order', async () => {
    const { run } = await fixture();
    const message = buildTelegramMaintenanceMessage(run, { isManual: true, now: new Date('2026-11-04T04:00:00Z') });
    expect(message).toContain('━━ <code>edge.example.com</code> ━━\nA/AAAA');
    expect(message).toContain('端口 443');
    expect(message).toContain('最小活跃数 3');
    expect(message).toContain('✅ 完成: 3/3');
    for (const last of ['10', '11']) {
      expect(message).toContain('✅ <code>203.0.113.' + last + ':443</code>\n   ICN · 12ms · JP · AS64500');
    }
    expect(message).toContain('📈 新增 1 个 IP\n   ✅ <code>203.0.113.12:443</code>\n      ICN · 12ms · JP · AS64500');
  });

  it('escapes domain-group labels and keeps pool inventories readable', async () => {
    const { run } = await fixture();
    const result = run.results[0]!;
    const named = { ...run, results: [{ ...result, poolName: 'A&B <pool>' }], poolStats: { ...run.poolStats,
      pools: [{ key: result.poolKey, name: 'A&B <pool>', count: 1 }] } };
    const message = buildTelegramMaintenanceMessage(named, { isManual: true });
    expect(message).toContain('A&amp;B &lt;pool&gt;');
    expect(message).not.toContain('A&B <pool>');
    expect(message).toContain('IP 池库存');
    expect(message).toContain('维护前: 1 个\n   维护后: 1 个');
  });

  it('labels actual start counts separately from the previous notification baseline', async () => {
    const { run } = await fixture();
    const message = buildTelegramMaintenanceMessage({ ...run, poolStats: { ...run.poolStats,
      before: { ip_pool_default: 9 }, start: { ip_pool_default: 2 }, after: { ip_pool_default: 1 } } }, { isManual: true });
    expect(message).toContain('维护前: 2 个\n   维护后: 1 个\n   📉 变化: -1');
    expect(message).toContain('较上次通知: -8');
    expect(message).not.toContain('维护前: 9 个');
  });

  it('preserves TXT ports, IPv6 and unknown diagnostics in domain groups', async () => {
    const { run } = await fixture();
    const original = run.results[0]!;
    const report = original.report!;
    const target = normalizeManagedTarget({ mode: 'TXT', domain: 'proxy.example.com', port: 'any', minActive: 2 })!;
    const values = ['203.0.113.10:443', '[2001:db8::10]:8443'];
    const template = report.plan.current[0]!;
    const current = values.map((value, index) => ({ ...template, item: { ...template.item, value, address: value,
      result: index === 0 ? alive(parseProxyTarget(value)!, { exitFamily: 'ipv4', latencyMs: 12, colo: 'ICN',
        exits: [{ family: 'ipv4', country: 'JP', asn: '64500' }] }) : {
        status: 'unknown' as const, target: parseProxyTarget(value)!, exitFamily: 'unknown' as const,
        exits: [], code: 'INVALID_RESPONSE', message: '检测接口返回坏 JSON',
      } } }));
    const changed = { ...run, insufficient: true, probeErrors: 1, results: [{ ...original, target, report: {
      ...report, target, added: 0, deleted: 0, activeCount: 1, probeErrors: 1, dnsUpdated: false,
      dns: { before: values, after: values, added: [], removed: [] }, candidateResults: [],
      plan: { ...report.plan, current, activeCount: 1, dnsValues: values, additions: [], trash: [] },
    } }] };
    const message = buildTelegramMaintenanceMessage(changed, { isManual: true });
    expect(message).toContain('━━ <code>proxy.example.com</code> ━━\nTXT · 最小活跃数 2');
    expect(message).toContain('✅ <code>203.0.113.10:443</code>');
    expect(message).toContain('⚠️ <code>[2001:db8::10]:8443</code>');
    expect(message).toContain('未确认 · [INVALID_RESPONSE] 检测接口返回坏 JSON');
    expect(message).toContain('⚠️ 未完成: 1/2');
    expect(message).toContain('未达到最小活跃数');
    expect(message).not.toContain('端口 443');
    expect(message).toContain('检测异常 1 次（未计为失效）');
    expect(message).not.toContain('❌ <code>[2001:db8::10]:8443</code>');
  });

  it('includes every final DNS address, actual active count and successful additions', async () => {
    const { run } = await fixture();
    const message = buildTelegramMaintenanceMessage(run, { isManual: true, now: new Date('2026-11-03T00:00:00Z') });
    for (const last of ['10', '11', '12']) expect(message).toContain('<code>203.0.113.' + last + ':443</code>');
    expect(message).toContain('✅ 完成: 3/3');
    expect(message).toContain('📈 新增 1 个 IP');
    expect(message).toContain('JP');
    expect(message).not.toContain('✨ 所有 IP 正常，无变化');
    expect(message).not.toContain('fixture-private-token');
  });

  it('does not announce planned additions as active when DNS writing fails', async () => {
    const { run } = await fixture(true);
    expect(run.insufficient).toBe(true);
    const message = buildTelegramMaintenanceMessage(run, { isManual: true });
    expect(message).toContain('⚠️ 未完成: 2/3');
    expect(message).toContain('未达到最小活跃数');
    expect(message).not.toContain('<code>203.0.113.12</code>');
    expect(message).not.toContain('✅ 完成: 3/3');
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

it('reports an archived failed pool candidate with its address and reason', async () => {
  const { run } = await fixture();
  const result = run.results[0]!;
  const report = result.report!;
  const target = report.target;
  const failedAddress = '203.0.113.99:443';
  const failed = { entry: { address: failedAddress, asn: null, country: null, stack: null, comment: '' }, address: failedAddress,
    value: '203.0.113.99', result: { status: 'dead' as const, target: parseProxyTarget(failedAddress)!, exitFamily: 'unknown' as const,
      exits: [], code: 'TARGET_HTTP_ERROR', message: '候选链路 HTTP 404' } };
  const changed = { ...run, results: [{ ...result, report: { ...report, candidateResults: [failed], archived: 1,
    plan: { ...report.plan, trash: [{ entryLine: failedAddress, reason: '维护失效' }] } } }] };
  const message = buildTelegramMaintenanceMessage(changed, { isManual: true });
  expect(message).toContain('<code>203.0.113.99:443</code>');
  expect(message).toContain('候选链路 HTTP 404');
  expect(message).toContain('归档 1 个地址');
  expect(target.domain).toBe('edge.example.com');
});
