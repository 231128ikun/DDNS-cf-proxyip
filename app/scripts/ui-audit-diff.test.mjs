import { test } from 'node:test';
import assert from 'node:assert/strict';
import { compareAudit } from './ui-audit-diff.mjs';

const contrast = (key, ratio) => ({ key, ratio, required: 4.5 });
const target = (key, w, h) => ({ key, w, h });
const page = (contrastFailures = [], smallTargets = []) => ({ contrastFailures, smallTargets });

test('existing issues remain reported while improvements are allowed', () => {
  const result = compareAudit(page([contrast('检测', 4.02)], [target('帮助', 26, 26)]),
    page([contrast('检测', 4.1)], [target('帮助', 27, 26)]));
  assert.equal(result.inheritedContrast.length, 1);
  assert.equal(result.inheritedTargets.length, 1);
  assert.deepEqual(result.regressions, []);
});

test('a lower ratio or stricter text requirement is a regression', () => {
  assert.equal(compareAudit(page([contrast('检测', 4.02)]), page([contrast('检测', 4.01)])).regressions.length, 1);
  assert.equal(compareAudit(page([{ key: '检测', ratio: 2.9, required: 3 }]),
    page([contrast('检测', 2.9)])).regressions.length, 1);
});

test('shrinking either target dimension is a regression without rounding away fractions', () => {
  const reference = page([], [target('帮助', 26, 26)]);
  assert.equal(compareAudit(reference, page([], [target('帮助', 26, 25.99)])).regressions.length, 1);
  assert.equal(compareAudit(reference, page([], [target('帮助', 25.99, 26)])).regressions.length, 1);
});

test('a fixed issue cannot excuse a different new issue', () => {
  const reference = page([contrast('检测', 4.02)], [target('帮助', 26, 26)]);
  const replaced = compareAudit(reference, page([contrast('保存', 4.02)], [target('入库', 26, 26)]));
  assert.equal(replaced.regressions.length, 2);
});

test('ambiguous identities fail closed instead of masking or inventing a regression', () => {
  const baseline = page([contrast('刷新', 2), contrast('刷新', 4)]);
  const reversed = page([contrast('刷新', 4), contrast('刷新', 2)]);
  assert.throws(() => compareAudit(baseline, reversed), /audit data/i);
  assert.throws(() => compareAudit(page(), page([], [target('帮助', 26, 26), target('帮助', 26, 26)])), /audit data/i);
});

test('separate functional identities cannot offset a regression when traversal order changes', () => {
  const result = compareAudit(page([contrast('DNS:刷新', 2), contrast('绑定:刷新', 4)]),
    page([contrast('绑定:刷新', 2), contrast('DNS:刷新', 4)]));
  assert.equal(result.regressions.length, 1);
  assert.match(result.regressions[0], /绑定:刷新/);
});

test('missing comparison data fails closed', () => {
  assert.throws(() => compareAudit(null, page()), /audit data/i);
  assert.throws(() => compareAudit(page(), { contrastFailures: [] }), /audit data/i);
  assert.throws(() => compareAudit(page(), page([{ ratio: 4, required: 4.5 }])), /audit data/i);
});
