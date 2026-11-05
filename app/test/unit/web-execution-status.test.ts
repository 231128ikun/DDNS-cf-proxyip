import { expect, it } from 'vitest';
import { executionStatus } from '../../web/src/state/execution-status';

it('keeps a healthy detector green when the candidate IP is dead', () => {
  expect(executionStatus('ready', [{ status: 'dead', code: 'TARGET_TLS_ERROR' }], 'ready')).toBe('ready');
});
it('distinguishes API errors, loading and user cancellation', () => {
  expect(executionStatus('ready', [{ status: 'unknown', code: 'PROBE_API_ERROR' }], 'ready')).toBe('error');
  expect(executionStatus('error', [], 'ready')).toBe('error');
  expect(executionStatus('loading', [], 'ready')).toBe('busy');
  expect(executionStatus('ready', [{ status: 'unknown', code: 'CANCELLED' }], 'ready')).toBe('ready');
  expect(executionStatus('idle', [], 'error')).toBe('error');
});
