import { describe, expect, it } from 'vitest';
import { buildTelegramMaintenanceMessage } from '../../src/jobs/maintenance-message';
import type { MaintenanceRunReport } from '../../src/application/maintain-managed-targets';

const run: MaintenanceRunReport = {
  results: [],
  changed: false,
  insufficient: false,
  errors: [],
  probeErrors: 0,
  poolStats: { before: {}, after: {}, pools: [], changed: false },
};

describe('Telegram maintenance message', () => {
  it('links a manual report back to the configured panel', () => {
    const message = buildTelegramMaintenanceMessage(run, {
      isManual: true,
      projectUrl: 'https://panel.example',
      now: new Date('2026-10-27T00:00:00.000Z'),
    });

    expect(message).toContain('<a href="https://panel.example">打开管理面板</a>');
  });

  it('keeps the link out of scheduled reports', () => {
    const message = buildTelegramMaintenanceMessage(run, {
      isManual: false,
      projectUrl: 'https://panel.example',
      now: new Date('2026-10-27T00:00:00.000Z'),
    });

    expect(message).not.toContain('打开管理面板');
  });
});
