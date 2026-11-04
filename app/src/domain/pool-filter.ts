import { parsePoolEntry, normalizePoolStack, type PoolStack } from './pool-entry';
import { parseProxyTarget } from './proxy-target';

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
  for (const rawGroup of String(query ?? '').split('|')) {
    const criterion = parseFilterGroup(rawGroup);
    if (!criterion) return null;
    groups.push(criterion);
  }
  return groups.length ? groups : null;
}

export function matchesPoolFilter(line: string, filter: PoolFilter): boolean {
  return filter.some((criterion) => matchesCriterion(line, criterion));
}

function parseFilterGroup(group: string): PoolFilterCriterion | null {
  const tokens = group.trim().split(/\s+/).filter(Boolean);
  if (!tokens.length) return null;

  const ports: (number | PortFilterRange)[] = [];
  const countries: string[] = [];
  const asns: string[] = [];
  const stacks: string[] = [];
  const text: string[] = [];

  for (const token of tokens) {
    const match = /^([a-zA-Z]+):(.*)$/.exec(token);
    if (!match) {
      text.push(token.toLowerCase());
      continue;
    }
    const key = match[1]!.toLowerCase();
    const values = match[2]!.split(',').map((value) => value.trim()).filter(Boolean);
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
      const [startText, endText, extra] = value.split('-').map((part) => part.trim());
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
  return parsed.length ? parsed : null;
}

function matchesCriterion(line: string, criterion: PoolFilterCriterion): boolean {
  const entry = parsePoolEntry(line);
  const target = entry ? parseProxyTarget(entry.address, 443) : null;

  if (criterion.ports.length) {
    const port = target?.port;
    if (!port || !criterion.ports.some((item) => typeof item === 'number' ? item === port : port >= item.start && port <= item.end)) return false;
  }

  const countries = splitMetadata(entry?.country ?? '').map((value) => value.toUpperCase());
  if (criterion.countries.length && !criterion.countries.some((value) => countries.includes(value))) return false;

  const asns = splitMetadata(entry?.asn ?? '').map((value) => value.replace(/^AS/i, '').toUpperCase());
  if (criterion.asns.length && !criterion.asns.some((value) => asns.includes(value))) return false;

  if (criterion.stacks.length) {
    const stack: PoolStack | null = entry?.stack ?? null;
    if (!stack || !criterion.stacks.includes(stack)) return false;
  }

  if (criterion.text.length) {
    const searchable = [line, entry?.asn, entry?.country, entry?.comment].filter(Boolean).join(' ').toLowerCase();
    if (!criterion.text.some((value) => searchable.includes(value))) return false;
  }
  return true;
}

function splitMetadata(value: string): string[] {
  return value.split(/[\/,，\s]+/).map((item) => item.trim()).filter(Boolean);
}
