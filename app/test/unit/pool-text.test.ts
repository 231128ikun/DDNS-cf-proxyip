import { describe, expect, it } from 'vitest';
import { planPoolCheckChunks } from '../../src/domain/pool-text';

describe('pool check text planning', () => {
  it('chunks unique targets while preserving comments and invalid input', () => {
    const text = [
      '203.0.113.10:443,AS64500,US,v4 # first',
      '203.0.113.11:443 | 203.0.113.12:443',
      '-bad-',
      '203.0.113.10:443,AS64501,JP,v4 # duplicate',
      '203.0.113.13:443',
    ].join('\n');

    const plan = planPoolCheckChunks(text, 2);

    expect(plan.total).toBe(4);
    expect(plan.chunks).toHaveLength(2);
    expect(plan.chunks[0]).toContain('203.0.113.10:443,AS64500,US,v4 # first');
    expect(plan.chunks[0]).toContain('203.0.113.11:443');
    expect(plan.chunks.join('\n')).toContain('-bad-');
    expect(plan.chunks.join('\n')).not.toContain('AS64501');
    expect(plan.chunks[1]).toContain('203.0.113.12:443');
    expect(plan.chunks[1]).toContain('203.0.113.13:443');
  });
});
