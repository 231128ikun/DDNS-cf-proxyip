import { parsePoolEntry, parsePoolAddress, normalizePoolStack, type PoolEntry } from './pool-entry';

export interface PortFilterRange {
  readonly start: number;
  readonly end: number;
}

export interface PoolFilterCriterion {
  readonly ports: readonly (number | PortFilterRange)[];
  readonly countries: readonly string[];
  readonly asns: readonly string[];
  readonly stacks: readonly string[];
  readonly text: readonly string[];
}

export type PoolFilter = readonly PoolFilterCriterion[];

/** 解析面板筛选表达式；无效端口条件让整次筛选失败，避免产生误导结果。 */
export function parsePoolFilter(query: string): PoolFilter | null {
  const groups: PoolFilterCriterion[] = [];
  for (const rawGroup of query.split('|')) {
    const criterion = parseFilterGroup(rawGroup);
    if (!criterion) return null;
    groups.push(criterion);
  }
  return groups;
}

export function matchesPoolFilter(line: string, filter: PoolFilter): boolean {
  const entry = parsePoolEntry(line);
  return filter.some(criterion => matchesCriterion(line, entry, criterion));
}

function parseFilterGroup(group: string): PoolFilterCriterion | null {
  const textGroup = group.trim();
  if (!textGroup) return null;

  const ports: (number | PortFilterRange)[] = [];
  const countries: string[] = [];
  const asns: string[] = [];
  const stacks: string[] = [];
  const text: string[] = [];

  for (const token of textGroup.split(/\s+/)) {
    const match = /^([a-zA-Z]+):(.*)$/.exec(token);
    if (!match) {
      text.push(token.toLowerCase());
      continue;
    }
    const key = match[1]!.toLowerCase();
    const values = match[2]!.split(',').filter(Boolean);
    if (!values.length) return null;

    if (key === 'port') {
      const parsed = parsePortValues(values);
      if (!parsed) return null;
      ports.push(...parsed);
    } else if (key === 'country') {
      countries.push(...values.map((value) => value.toUpperCase()));
    } else if (key === 'asn' || key === 'as') {
      asns.push(...values.map((value) => value.replace(/^AS/i, '').toUpperCase()));
    } else if (key === 'stack' || key === 'exit') {
      stacks.push(...values.map((value) => normalizePoolStack(value) ?? value.toLowerCase().replace(/-/g, '_')));
    } else {
      text.push(token.toLowerCase());
    }
  }

  return { ports, countries, asns, stacks, text };
}

function parsePortValues(values: readonly string[]): readonly (number | PortFilterRange)[] | null {
  const parsed: (number | PortFilterRange)[] = [];
  for (const value of values) {
    if (value.includes('-')) {
      const [startText, endText, extra] = value.split('-');
      if (extra !== undefined) return null;
      const start = Number(startText);
      const end = Number(endText);
      if (!Number.isInteger(start) || !Number.isInteger(end) || start < 1 || end > 65_535 || start > end) return null;
      parsed.push({ start, end });
      continue;
    }
    if (!/^\d+$/.test(value)) return null;
    const port = Number(value);
    if (!Number.isInteger(port) || port < 1 || port > 65_535) return null;
    parsed.push(port);
  }
  return parsed;
}

function matchesCriterion(line: string, entry: PoolEntry | null, criterion: PoolFilterCriterion): boolean {
  if (criterion.ports.length) {
    const port = entry && parsePoolAddress(entry)?.port;
    if (!port || !criterion.ports.some(item => typeof item === 'number' ? item === port : port >= item.start && port <= item.end)) return false;
  }
  if (criterion.countries.length && !matchesMetadata(entry?.country, criterion.countries)) return false;
  if (criterion.asns.length && !matchesMetadata(entry?.asn, criterion.asns, /^AS/)) return false;
  if (criterion.stacks.length && (!entry?.stack || !criterion.stacks.includes(entry.stack))) return false;
  return !criterion.text.length || criterion.text.some(value => line.toLowerCase().includes(value));
}

function matchesMetadata(value: string | null | undefined, expected: readonly string[], prefix?: RegExp): boolean {
  return !!value && value.toUpperCase().split(/[\/,，\s]+/).some(item => expected.includes(prefix ? item.replace(prefix, '') : item));
}
