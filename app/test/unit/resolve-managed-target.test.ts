import { describe, expect, it, vi } from 'vitest';
import { resolveManagedTarget, TargetStatusInputError } from '../../src/application/resolve-managed-target';
import type { MaintenanceSource, MaintenanceSourceData } from '../../src/ports/maintenance-source';

const fallback = { zoneId: 'fallback-zone', apiToken: 'fallback-token' };
const config: MaintenanceSourceData = { zones: [{ zoneId: 'zone', apiToken: '' }], targets: [{
  target: { mode: 'A', domain: 'edge.example.com', port: 443, minActive: 1, exitFilter: 'any', countries: [], asns: [] },
  zoneIndex: 0, enabled: false,
}], poolMapping: {}, poolNames: {} };

describe('shared managed target resolution', () => {
  it('normalizes keys, keeps disabled targets addressable and falls back by credential field', async () => {
    const load = vi.fn(async () => config);
    await expect(resolveManagedTarget({ load }, ' EDGE.EXAMPLE.COM|a ', fallback)).resolves.toEqual({
      config: config.targets[0], zone: { zoneId: 'zone', apiToken: 'fallback-token' },
    });
    expect(load).toHaveBeenCalledTimes(1);
  });
  it('does not load invalid keys and does not cache deleted targets', async () => {
    let data = config;
    const source: MaintenanceSource = { load: vi.fn(async () => data) };
    await expect(resolveManagedTarget(source, '', fallback)).rejects.toBeInstanceOf(TargetStatusInputError);
    expect(source.load).not.toHaveBeenCalled();
    await resolveManagedTarget(source, 'edge.example.com|A', fallback);
    data = { ...config, targets: [] };
    await expect(resolveManagedTarget(source, 'edge.example.com|A', fallback)).rejects.toThrow('管理域名不存在或已被删除，请刷新后重试');
  });
  it('passes through source errors instead of turning them into missing targets', async () => {
    await expect(resolveManagedTarget({ load: async () => { throw new Error('storage failed'); } }, 'edge.example.com|A', fallback))
      .rejects.toThrow('storage failed');
  });
});
