import { expect, it } from 'vitest';
import { probeStatusLabel } from '../../web/src/components/probe-status';

it('shows the cause of unknown without changing the node decision', () => {
  expect(probeStatusLabel('unknown', 'TIMEOUT')).toBe('未知（超时）');
  expect(probeStatusLabel('unknown', 'HTTP_ERROR')).toBe('未知（HTTP 异常）');
  expect(probeStatusLabel('unknown', 'INVALID_RESPONSE')).toBe('未知');
  expect(probeStatusLabel('alive', 'TIMEOUT')).toBe('可用');
  expect(probeStatusLabel('dead')).toBe('失效');
});
