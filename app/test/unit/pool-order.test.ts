import { describe, expect, it } from 'vitest';
import { normalizePoolOrder } from '../../src/domain/pool-order';

const keys = ['ip_pool_default', 'ip_pool_002', 'ip_pool_010', 'ip_pool_trash'];

describe('shared pool order', () => {
  it('keeps submitted user order and pins the default and trash ends', () => {
    expect(normalizePoolOrder(['ip_pool_trash', 'ip_pool_010', 'ip_pool_default', 'ip_pool_002'], keys))
      .toEqual(['ip_pool_default', 'ip_pool_010', 'ip_pool_002', 'ip_pool_trash']);
  });
  it('recovers old, duplicate and incomplete saved order without adding absent pools', () => {
    expect(normalizePoolOrder(['ip_pool_099', 'ip_pool_010', 'ip_pool_010'], keys))
      .toEqual(['ip_pool_default', 'ip_pool_010', 'ip_pool_002', 'ip_pool_trash']);
    expect(normalizePoolOrder(null, ['ip_pool_010', 'ip_pool_002', 'invalid', 'ip_pool_002']))
      .toEqual(['ip_pool_002', 'ip_pool_010']);
  });
  it('is stable when normalization is repeated', () => {
    const order = normalizePoolOrder(['ip_pool_010'], keys);
    expect(normalizePoolOrder(order, keys)).toEqual(order);
  });
});
