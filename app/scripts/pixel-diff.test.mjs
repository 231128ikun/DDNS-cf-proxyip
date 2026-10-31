import { test } from 'node:test';
import assert from 'node:assert/strict';
import { comparePixels } from './pixel-diff.mjs';

test('identical pixels pass', () => {
  assert.equal(comparePixels([255, 255, 255, 255], [255, 255, 255, 255]).changed, 0);
});
test('one channel changing by one is a difference', () => {
  const result = comparePixels([255, 255, 255, 255, 0, 0, 0, 255], [254, 255, 255, 255, 0, 0, 0, 255]);
  assert.equal(result.changed, 1);
  assert.equal(result.total, 2);
  assert.equal(result.maxChannelDelta, 1);
  assert.deepEqual([...result.diff.slice(0, 4)], [255, 0, 80, 255]);
});
test('alpha changes and invalid image lengths cannot silently pass', () => {
  assert.equal(comparePixels([0, 0, 0, 0], [0, 0, 0, 1]).changed, 1);
  assert.throws(() => comparePixels([0], [0]), /RGBA sizes/);
  assert.throws(() => comparePixels([], [0, 0, 0, 0]), /RGBA sizes/);
});
