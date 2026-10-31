export function compareAudit(reference, current) {
  for (const data of [reference, current]) {
    if (!Array.isArray(data?.contrastFailures) || !Array.isArray(data?.smallTargets)
      || data.contrastFailures.some(item => !item.key || !Number.isFinite(item.ratio) || !Number.isFinite(item.required))
      || data.smallTargets.some(item => !item.key || !Number.isFinite(item.w) || !Number.isFinite(item.h))) {
      throw new Error('Invalid audit data; a live main comparison is required');
    }
    for (const kind of ['contrastFailures', 'smallTargets']) {
      const keys = data[kind].map(item => item.key);
      if (new Set(keys).size !== keys.length) throw new Error(`Invalid audit data: ambiguous ${kind} identities; add a stable functional anchor`);
    }
  }
  const result = { inheritedContrast: [], inheritedTargets: [], regressions: [] };
  const compare = (kind, inherited, qualifies) => {
    const baselineByKey = new Map(reference[kind].map(item => [item.key, item]));
    for (const item of current[kind]) {
      const baseline = baselineByKey.get(item.key);
      if (!baseline || !qualifies(baseline, item)) result.regressions.push(`${kind}: ${item.key} ${JSON.stringify(item)}`);
      else result[inherited].push(item);
    }
  };
  compare('contrastFailures', 'inheritedContrast', (baseline, item) => item.ratio >= baseline.ratio && item.required <= baseline.required);
  compare('smallTargets', 'inheritedTargets', (baseline, item) => item.w >= baseline.w && item.h >= baseline.h);
  return result;
}
