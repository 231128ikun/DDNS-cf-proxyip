import { describe, expect, it } from 'vitest';
import { describeBatch, mergeBatchProgress, remainingBatch, remainingBatchText } from '../../web/src/state/batch-resume';

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
    expect(remainingBatchText(input, new Set([0]))).toBe(
      'invalid input\n203.0.113.12:443 # third',
    );
  });

  it('maps resumed client indexes back to the original input positions', () => {
    expect(remainingBatch(input, new Set([0]))).toEqual({
      text: 'invalid input\n203.0.113.12:443 # third',
      sourceIndices: [1, 2],
    });
  });

  it('applies completed results while preserving unfinished and invalid lines in source order', () => {
    const text = mergeBatchProgress(input, new Map([
      [0, [{ address: '203.0.113.10:443', status: 'alive', exitFamily: 'ipv4',
        line: '203.0.113.10:443,AS64500,JP,v4 # first' }]],
      [2, [{ address: '203.0.113.12:443', status: 'dead', exitFamily: 'ipv4',
        line: '203.0.113.12:443' }]],
    ]));

    expect(text).toBe('203.0.113.10:443,AS64500,JP,v4 # first\ninvalid input');
  });

  it('does not schedule or preserve duplicate targets when resuming', () => {
    const duplicated = '203.0.113.10:443 # first\n203.0.113.10:443 # duplicate';

    expect(remainingBatchText(duplicated, new Set())).toBe('203.0.113.10:443 # first');
    expect(mergeBatchProgress(duplicated, new Map([
      [0, [{ address: '203.0.113.10:443', status: 'alive', exitFamily: 'ipv4',
        line: '203.0.113.10:443,AS64500,JP,v4 # first' }]],
    ]))).toBe('203.0.113.10:443,AS64500,JP,v4 # first');
  });
});
