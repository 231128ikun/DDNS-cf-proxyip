import { describe, expect, it } from 'vitest';
import { createDefaultConfig, parseAppConfig, type AppConfig, type ZoneConfig } from '../../src/contracts/config';

const first: ZoneConfig = { name: '主域名', label: '主域名', baseDomain: 'example.com', zoneId: 'zone-first', apiKey: 'first-fixture-token' };
const second: ZoneConfig = { name: '备用域名', label: '备用域名', baseDomain: 'example.net', zoneId: 'zone-second', apiKey: 'second-fixture-token' };
const previous: AppConfig = { ...createDefaultConfig(), zones: [first, second], apiKey: first.apiKey, zoneId: first.zoneId };
const masked = (zone: ZoneConfig) => ({ ...zone, apiKey: '' });

describe('masked zone credentials', () => {
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
