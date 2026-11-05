import { describe, expect, it } from 'vitest';
import { describeBatch, remainingBatch } from '../../web/src/state/batch-resume';

describe('batch interruption progress', () => {
  it('separates immutable source, multi-result groups, invalid and incomplete lines', () => {
    const source = 'example.com\n???\n2.2.2.2\n# note';
    const report = describeBatch(source, new Map([[0, [
      { address: '1.1.1.1:443', status: 'alive' as const, exitFamily: 'ipv4' as const, line: '1.1.1.1:443,AS1,US,v4' },
      { address: '1.1.1.2:443', status: 'unknown' as const, exitFamily: 'unknown' as const, line: '1.1.1.2:443' },
    ]]]), new Set([0]));
    expect(report.source).toBe(source);
    expect(report.items.map(item => item.status)).toEqual(['alive', 'unknown']);
    expect(report.invalid).toEqual(['???']);
    expect(report.incomplete).toEqual(['2.2.2.2']);
  });
  const input = '203.0.113.10:443 # first\ninvalid input\n203.0.113.12:443 # third';

  it('keeps only unfinished valid and invalid source lines for a resume', () => {
    expect(remainingBatch(input, new Set([0])).text).toBe(
      'invalid input\n203.0.113.12:443 # third',
    );
  });

  it('maps resumed client indexes back to the original input positions', () => {
    expect(remainingBatch(input, new Set([0]))).toEqual({
      text: 'invalid input\n203.0.113.12:443 # third',
      sourceIndices: [1, 2],
    });
  });

  it('only derives fields consumed by the results workspace', () => {
    const report = describeBatch(input, new Map(), new Set());
    expect(Object.keys(report).sort()).toEqual(['incomplete', 'invalid', 'items', 'source']);
  });

  it('merges duplicate metadata and comments while preserving the first source index', () => {
    const duplicated = '203.0.113.10:443\ninvalid input\n203.0.113.10:443,AS64500,JP,v4 # keep\n203.0.113.11:443';
    expect(remainingBatch(duplicated, new Set())).toEqual({
      text: '203.0.113.10:443,AS64500,JP,v4 # keep\ninvalid input\n203.0.113.11:443',
      sourceIndices: [0, 1, 3],
    });
    expect(remainingBatch(duplicated, new Set([0])).text).toBe('invalid input\n203.0.113.11:443');
    expect(describeBatch(duplicated, new Map(), new Set()).incomplete)
      .toEqual(['203.0.113.10:443,AS64500,JP,v4 # keep', '203.0.113.11:443']);
  });
});
