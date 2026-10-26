import { describe, expect, it } from 'vitest';
import { createDefaultConfig, parseAppConfig, type AppConfig, type ZoneConfig } from '../../src/contracts/config';

const first: ZoneConfig = { name: '主域名', label: '主域名', baseDomain: 'example.com', zoneId: 'zone-first', apiKey: 'first-fixture-token' };
const second: ZoneConfig = { name: '备用域名', label: '备用域名', baseDomain: 'example.net', zoneId: 'zone-second', apiKey: 'second-fixture-token' };
const previous: AppConfig = { ...createDefaultConfig(), zones: [first, second], apiKey: first.apiKey, zoneId: first.zoneId };
const masked = (zone: ZoneConfig) => ({ ...zone, apiKey: '' });

describe('masked zone credentials', () => {
  it('uses the base domain to distinguish tokens when multiple zones share an ID', () => {
    const child = { ...second, baseDomain: 'child.example.com', zoneId: first.zoneId };
    const result = parseAppConfig({ zones: [{ ...masked(child), baseDomain: '.CHILD.EXAMPLE.COM.' }, masked(first)] },
      { ...previous, zones: [first, child] });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.zones.map(zone => zone.apiKey)).toEqual([child.apiKey, first.apiKey]);
  });

  it('rejects ambiguous masked credentials instead of clearing saved tokens', () => {
    const child = { ...second, baseDomain: 'child.example.com', zoneId: first.zoneId };
    const result = parseAppConfig({ zones: [{ ...masked(first), baseDomain: 'renamed.example.com' }] },
      { ...previous, zones: [first, child] });
    expect(result.ok).toBe(false);
  });

  it('allows an explicit replacement token even when old zone identities are ambiguous', () => {
    const child = { ...second, baseDomain: 'child.example.com', zoneId: first.zoneId };
    const result = parseAppConfig({ zones: [{ ...first, baseDomain: 'renamed.example.com', apiKey: 'replacement-fixture-token' }] },
      { ...previous, zones: [first, child] });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.zones[0]?.apiKey).toBe('replacement-fixture-token');
  });

  it('rejects ambiguous credential-only legacy rows', () => {
    const left = { ...first, baseDomain: '', zoneId: '', label: '旧权限' };
    const right = { ...second, baseDomain: '', zoneId: '', label: '旧权限' };
    expect(parseAppConfig({ zones: [masked(left)] }, { ...previous, zones: [left, right] }).ok).toBe(false);
  });

  it('retains the remaining zone token after deleting the first zone', () => {
    const result = parseAppConfig({ zones: [masked(second)] }, previous);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.zones[0]?.apiKey).toBe(second.apiKey);
    expect(result.value.apiKey).toBe(second.apiKey);
    expect(result.value.zoneId).toBe(second.zoneId);
  });

  it('retains each token when zones are reordered', () => {
    const result = parseAppConfig({ zones: [masked(second), masked(first)] }, previous);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.zones.map(zone => zone.apiKey)).toEqual([second.apiKey, first.apiKey]);
  });

  it('does not give a newly added zone the removed zone token', () => {
    const result = parseAppConfig({ zones: [{ ...masked(first), baseDomain: 'new.example', zoneId: 'zone-new' }] }, previous);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.zones[0]?.apiKey).toBe('');
  });

  it('keeps a token when only the label or domain spelling changes', () => {
    const result = parseAppConfig({ zones: [{ ...masked(second), label: '改名', baseDomain: 'EXAMPLE.NET' }] }, previous);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.zones[0]?.apiKey).toBe(second.apiKey);
  });

  it('matches a legacy domain-only zone independently of its position', () => {
    const legacy = { ...second, zoneId: '' };
    const result = parseAppConfig({ zones: [{ ...masked(legacy), baseDomain: 'EXAMPLE.NET' }] }, { ...previous, zones: [first, legacy] });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.zones[0]?.apiKey).toBe(legacy.apiKey);
  });

  it('keeps an unchanged credential-only legacy row without borrowing another token', () => {
    const legacy = { ...second, baseDomain: '', zoneId: '' };
    const result = parseAppConfig({ zones: [masked(legacy)] }, { ...previous, zones: [first, legacy] });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.zones[0]?.apiKey).toBe(legacy.apiKey);
  });
});
