import { describe, expect, it } from 'vitest';
import { createBatchSource, describeBatch, remainingBatch } from '../../web/src/state/batch-resume';

describe('batch interruption progress', () => {
  it('separates immutable source, multi-result groups, invalid and incomplete lines', () => {
    const source = 'example.com\n???\n2.2.2.2\n# note';
    const report = describeBatch(createBatchSource(source), new Map([[0, [
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
    expect(remainingBatch(createBatchSource(input), new Set([0])).text).toBe(
      'invalid input\n203.0.113.12:443 # third',
    );
  });

  it('maps resumed client indexes back to the original input positions', () => {
    expect(remainingBatch(createBatchSource(input), new Set([0]))).toEqual({
      text: 'invalid input\n203.0.113.12:443 # third',
      sourceIndices: [1, 2],
    });
  });

  it('only derives fields consumed by the results workspace', () => {
    const report = describeBatch(createBatchSource(input), new Map(), new Set());
    expect(Object.keys(report).sort()).toEqual(['incomplete', 'invalid', 'items', 'source']);
  });

  it('keeps the same source view through repeated progress and partial domain results', () => {
    const source = createBatchSource('# header\nedge.example.com\n???\n[2001:db8::1]:8443\n[2001:0db8::1]:8443 # keep');
    const groups = new Map([[1, [{ address: '203.0.113.10:443', status: 'alive' as const,
      exitFamily: 'ipv4' as const, line: '203.0.113.10:443' }]]]);
    const before = JSON.stringify(source);
    for (let index = 0; index < 20; index++) {
      expect(describeBatch(source, groups, new Set()).incomplete).toEqual(['edge.example.com', '[2001:db8::1]:8443,null,null,null # keep']);
    }
    expect(remainingBatch(source, new Set([3]))).toEqual({ text: '# header\nedge.example.com\n???', sourceIndices: [0, 1, 2] });
    expect(JSON.stringify(source)).toBe(before);
  });

  it('merges duplicate metadata and comments while preserving the first source index', () => {
    const duplicated = '203.0.113.10:443\ninvalid input\n203.0.113.10:443,AS64500,JP,v4 # keep\n203.0.113.11:443';
    expect(remainingBatch(createBatchSource(duplicated), new Set())).toEqual({
      text: '203.0.113.10:443,AS64500,JP,v4 # keep\ninvalid input\n203.0.113.11:443',
      sourceIndices: [0, 1, 3],
    });
    expect(remainingBatch(createBatchSource(duplicated), new Set([0])).text).toBe('invalid input\n203.0.113.11:443');
    expect(describeBatch(createBatchSource(duplicated), new Map(), new Set()).incomplete)
      .toEqual(['203.0.113.10:443,AS64500,JP,v4 # keep', '203.0.113.11:443']);
  });
});
