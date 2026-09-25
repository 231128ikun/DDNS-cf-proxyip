import { describe, expect, it } from 'vitest';
import type {
  MaintainManagedTargetCommand,
  MaintenanceReport,
} from '../../src/application/maintain-managed-target';
import {
  MaintainManagedTargets,
  shouldNotifyMaintenance,
  type TargetMaintainer,
} from '../../src/application/maintain-managed-targets';
import type { ManagedTarget } from '../../src/domain/managed-target';
import type { DnsZone } from '../../src/ports/dns-repository';
import type {
  MaintenanceSource,
  MaintenanceSourceData,
  MaintenanceTargetConfig,
} from '../../src/ports/maintenance-source';
import type { Notifier, NotifyResult } from '../../src/ports/notifier';
import { runMaintenanceJob } from '../../src/jobs/maintenance-job';

const fallbackZone: DnsZone = { zoneId: 'zone-fallback', apiToken: 'token-fallback' };

function target(domain: string, overrides: Partial<ManagedTarget> = {}): ManagedTarget {
  return { mode: 'A', domain, port: 443, minActive: 1, exitFilter: 'any', countries: [], asns: [], ...overrides };
}

function config(domain: string, overrides: Partial<MaintenanceTargetConfig> = {}): MaintenanceTargetConfig {
  return { target: target(domain), zoneIndex: null, enabled: true, ...overrides };
}

function createReport(report: Partial<MaintenanceReport> & Pick<MaintenanceReport, 'target'>): MaintenanceReport {
  return {
    poolKey: 'ip_pool_default',
    plan: {
      target: report.target,
      current: [],
      additions: [],
      retainedValues: [],
      dnsValues: [],
      nextPoolText: '',
      poolChanged: false,
      trash: [],
      activeCount: 1,
      exhausted: false,
    },
    deleted: 0,
    added: 0,
    dnsUpdated: false,
    probeErrors: 0,
    errors: [],
    ...report,
  };
}

class StubMaintainer implements TargetMaintainer {
  readonly calls: MaintainManagedTargetCommand[] = [];

  constructor(private readonly handler: (command: MaintainManagedTargetCommand) => Promise<MaintenanceReport>) {}

  async execute(command: MaintainManagedTargetCommand): Promise<MaintenanceReport> {
    this.calls.push(command);
    return await this.handler(command);
  }
}

class StubSource implements MaintenanceSource {
  loads = 0;

  constructor(private readonly data: MaintenanceSourceData) {}

  async load(): Promise<MaintenanceSourceData> {
    this.loads += 1;
    return this.data;
  }
}

class StubNotifier implements Notifier {
  readonly messages: string[] = [];

  constructor(private readonly result: NotifyResult = { sent: true, reason: 'sent' }) {}

  async send(text: string): Promise<NotifyResult> {
    this.messages.push(text);
    return this.result;
  }
}

function emptyData(overrides: Partial<MaintenanceSourceData> = {}): MaintenanceSourceData {
  return { zones: [], targets: [], poolMapping: {}, poolNames: {}, ...overrides };
}

describe('MaintainManagedTargets', () => {
  it('resolves pools by domain|mode, then domain, and skips disabled targets', async () => {
    const maintainer = new StubMaintainer(async (command) => createReport({ target: command.target }));
    const runner = new MaintainManagedTargets({ maintainer });

    const summary = await runner.execute(emptyData({
      targets: [
        config('a.example.com'),
        config('b.example.com'),
        config('c.example.com'),
        config('d.example.com', { enabled: false }),
      ],
      poolMapping: {
        'a.example.com|A': 'ip_pool_001',
        'b.example.com': 'ip_pool_002',
        'c.example.com': 'not-a-pool-key',
        'd.example.com': 'ip_pool_003',
      },
      poolNames: { ip_pool_001: '香港池' },
    }), fallbackZone);

    expect(maintainer.calls.map((call) => call.poolKey)).toEqual([
      'ip_pool_001',
      'ip_pool_002',
      'ip_pool_default',
    ]);
    expect(summary.results.map((result) => result.poolName)).toEqual(['香港池', '池 002', '默认池']);
    expect(summary.results.map((result) => result.zone)).toEqual([fallbackZone, fallbackZone, fallbackZone]);
    expect(summary.changed).toBe(false);
    expect(summary.errors).toEqual([]);
  });

  it('falls back to the default zone per field when zoneIndex is missing or out of range', async () => {
    const maintainer = new StubMaintainer(async (command) => createReport({ target: command.target }));
    const runner = new MaintainManagedTargets({ maintainer });

    const summary = await runner.execute(emptyData({
      zones: [
        { zoneId: 'zone-1', apiToken: '' },
        { zoneId: '', apiToken: 'token-2' },
      ],
      targets: [
        config('a.example.com', { zoneIndex: 0 }),
        config('b.example.com', { zoneIndex: 1 }),
        config('c.example.com', { zoneIndex: 9 }),
        config('d.example.com'),
      ],
    }), fallbackZone);

    expect(summary.results.map((result) => result.zone)).toEqual([
      { zoneId: 'zone-1', apiToken: 'token-fallback' },
      { zoneId: 'zone-fallback', apiToken: 'token-2' },
      fallbackZone,
      fallbackZone,
    ]);
  });

  it('keeps going after one target throws and aggregates changed, probe errors and messages', async () => {
    const maintainer = new StubMaintainer(async (command) => {
      if (command.target.domain === 'bad.example.com') throw new Error('boom');
      return createReport({
        target: command.target,
        dnsUpdated: true,
        added: 1,
        probeErrors: 2,
        errors: ['写入垃圾桶失败'],
      });
    });
    const runner = new MaintainManagedTargets({ maintainer });

    const summary = await runner.execute(emptyData({
      targets: [config('bad.example.com'), config('ok.example.com')],
    }), fallbackZone);

    expect(summary.results).toHaveLength(2);
    expect(summary.results[0]).toMatchObject({ report: null, error: 'boom' });
    expect(summary.results[1]).toMatchObject({ error: null });
    expect(summary.errors).toEqual(['bad.example.com: boom', 'ok.example.com: 写入垃圾桶失败']);
    expect(summary.changed).toBe(true);
    expect(summary.probeErrors).toBe(2);
  });

  it('marks the run as insufficient when any target fails to reach minActive', async () => {
    const maintainer = new StubMaintainer(async (command) => createReport({
      target: command.target,
      plan: {
        target: command.target,
        current: [],
        additions: [],
        retainedValues: [],
        dnsValues: [],
        nextPoolText: '',
        poolChanged: false,
        trash: [],
        activeCount: 0,
        exhausted: true,
      },
    }));
    const runner = new MaintainManagedTargets({ maintainer });

    const summary = await runner.execute(emptyData({ targets: [config('a.example.com')] }), fallbackZone);

    expect(summary.insufficient).toBe(true);
    expect(summary.changed).toBe(false);
  });
});

describe('shouldNotifyMaintenance', () => {
  const quiet = { results: [], changed: false, insufficient: false, errors: [], probeErrors: 0 };

  it('always notifies for manual maintenance', () => {
    expect(shouldNotifyMaintenance(quiet, true)).toBe(true);
  });

  it('stays quiet for an unchanged scheduled run', () => {
    expect(shouldNotifyMaintenance(quiet, false)).toBe(false);
  });

  it.each([
    ['changed', { changed: true }],
    ['insufficient', { insufficient: true }],
    ['execution errors', { errors: ['x'] }],
    ['probe errors', { probeErrors: 1 }],
  ])('notifies scheduled maintenance when there are %s', (_label, patch) => {
    expect(shouldNotifyMaintenance({ ...quiet, ...patch }, false)).toBe(true);
  });
});

describe('runMaintenanceJob', () => {
  function createJob(options: {
    readonly data?: MaintenanceSourceData;
    readonly isManual: boolean;
    readonly report?: (command: MaintainManagedTargetCommand) => MaintenanceReport;
    readonly fail?: boolean;
  }) {
    const source = new StubSource(options.data ?? emptyData({ targets: [config('edge.example.com')] }));
    const maintainer = new StubMaintainer(async (command) => {
      if (options.fail) throw new Error('boom');
      return options.report?.(command) ?? createReport({ target: command.target });
    });
    const runner = new MaintainManagedTargets({ maintainer });
    const notifier = new StubNotifier();
    return { source, runner, notifier, isManual: options.isManual };
  }

  it('notifies on a manual run even when nothing changed', async () => {
    const job = createJob({ isManual: true });

    const result = await runMaintenanceJob({
      source: job.source,
      maintainer: job.runner,
      notifier: job.notifier,
      fallbackZone,
      isManual: job.isManual,
    });

    expect(job.source.loads).toBe(1);
    expect(result.notification).toEqual({ sent: true, reason: 'sent' });
    expect(job.notifier.messages).toHaveLength(1);
    expect(job.notifier.messages[0]).toContain('DDNS 手动维护报告');
  });

  it('stays silent on an unchanged scheduled run', async () => {
    const job = createJob({ isManual: false });

    const result = await runMaintenanceJob({
      source: job.source,
      maintainer: job.runner,
      notifier: job.notifier,
      fallbackZone,
      isManual: false,
    });

    expect(result.notification).toBeNull();
    expect(job.notifier.messages).toEqual([]);
  });

  it('notifies the scheduled run once DNS actually changes', async () => {
    const job = createJob({
      isManual: false,
      report: (command) => createReport({ target: command.target, dnsUpdated: true, added: 1 }),
    });

    const result = await runMaintenanceJob({
      source: job.source,
      maintainer: job.runner,
      notifier: job.notifier,
      fallbackZone,
      isManual: false,
    });

    expect(result.notification).toEqual({ sent: true, reason: 'sent' });
    expect(job.notifier.messages[0]).toContain('DDNS 自动维护报告');
    expect(job.notifier.messages[0]).toContain('<code>edge.example.com</code>');
  });

  it('notifies and reports the failure reason when every target throws', async () => {
    const job = createJob({ isManual: false, fail: true });

    const result = await runMaintenanceJob({
      source: job.source,
      maintainer: job.runner,
      notifier: job.notifier,
      fallbackZone,
      isManual: false,
    });

    expect(result.run.errors).toEqual(['edge.example.com: boom']);
    expect(job.notifier.messages[0]).toContain('执行错误 1 项');
  });
});