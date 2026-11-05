import { describe, expect, it } from 'vitest';
import { createDefaultConfig, parseAppConfig, parseConfigUpdate, type AppConfig, type ZoneConfig } from '../../src/contracts/config';

const first: ZoneConfig = { name: '主域名', label: '主域名', baseDomain: 'example.com', zoneId: 'zone-first', apiKey: 'first-fixture-token' };
const second: ZoneConfig = { name: '备用域名', label: '备用域名', baseDomain: 'example.net', zoneId: 'zone-second', apiKey: 'second-fixture-token' };
const previous: AppConfig = { ...createDefaultConfig(), zones: [first, second], apiKey: first.apiKey, zoneId: first.zoneId };
const masked = (zone: ZoneConfig) => ({ ...zone, apiKey: '' });

describe('masked zone credentials', () => {
  it('keeps the panel key private while preserving it across an unrelated config update', () => {
    const base = { ...createDefaultConfig(), authKey: 'fixture-panel-key' };
    const result = parseAppConfig({ checkApi: 'https://probe.example/?proxyip=' }, base);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.authKey).toBe('fixture-panel-key');
  });

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

  it.each(['新的备注', ''])('rejects an unidentifiable masked credential-only row with label %j', (label) => {
    const legacy = { ...first, baseDomain: '', zoneId: '' };
    const result = parseAppConfig({ zones: [{ ...masked(legacy), name: label, label }, masked(second)] },
      { ...previous, zones: [legacy, second] });
    expect(result.ok).toBe(false);
  });

  it('allows renaming a credential-only row with an explicit token', () => {
    const legacy = { ...first, baseDomain: '', zoneId: '' };
    const result = parseAppConfig({ zones: [{ ...legacy, name: '新的备注', label: '新的备注', apiKey: 'replacement-fixture-token' }, masked(second)] },
      { ...previous, zones: [legacy, second] });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.zones.map(zone => zone.apiKey)).toEqual(['replacement-fixture-token', second.apiKey]);
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

describe('configuration write validation', () => {
  it.each([
    { targets: null },
    { targets: 'edge.example.com' },
    { targets: [null] },
    { targets: [{}] },
    { targets: [{ domain: 'a'.repeat(254) }] },
    { targets: [{ domain: 'a'.repeat(254), baseDomain: 'example.com', prefix: 'edge' }] },
    { targets: [{ domain: 'edge.example.com', prefix: 'a'.repeat(64) }] },
    { targets: [{ domain: 123, baseDomain: 'example.com', prefix: 'edge' }] },
    { targets: [{ baseDomain: 'a'.repeat(200), prefix: 'b'.repeat(63) }] },
    { targets: Array.from({ length: 101 }, (_, index) => ({ domain: `edge${index}.example.com` })) },
  ])('rejects an invalid target update without silently dropping or replacing it: %j', input => {
    expect(parseConfigUpdate(input).ok).toBe(false);
  });

  it('keeps legacy reads tolerant while validating explicit target writes', () => {
    const input = { targets: [{ domain: 'edge.example.com' }, { domain: 'a'.repeat(254) }] };
    const read = parseAppConfig(input);
    expect(read.ok && read.value.targets.map(target => target.domain)).toEqual(['edge.example.com']);
    expect(parseConfigUpdate(input).ok).toBe(false);
    if (!read.ok) return;
    const partial = parseConfigUpdate({ tgEnabled: false }, read.value);
    expect(partial.ok && partial.value.targets).toEqual(read.value.targets);
  });

  it('allows complete valid lists, explicit removal and normalized trailing dots', () => {
    const parsed = parseConfigUpdate({ targets: [{ domain: 'EDGE.EXAMPLE.COM.' }, { baseDomain: 'example.net', prefix: 'proxy', mode: 'TXT' }] });
    expect(parsed.ok && parsed.value.targets.map(target => target.domain)).toEqual(['edge.example.com', 'proxy.example.net']);
    if (!parsed.ok) return;
    expect(parseConfigUpdate({ targets: [] }, parsed.value)).toMatchObject({ ok: true, value: { targets: [] } });
  });
});

describe('native probe configuration', () => {
  it('migrates legacy primary into one backup field and keeps exit URL changes in the same config', () => {
    const parsed = parseAppConfig({ checkApi: 'https://legacy.example/check?proxyip=', checkApiBackup: '', probeIpv4Url: 'https://custom.example/info' });
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.value).not.toHaveProperty('checkApi');
    expect(parsed.value.checkApiBackup).toBe('https://legacy.example/check?proxyip=');
    expect(parsed.value.probeIpv4Url).toBe('https://custom.example/info');
    expect(parseAppConfig(parsed.value)).toEqual(parsed);
  });
  it.each(['http://example.test/', 'https://user:secret@example.test/', 'https://example.test/#fragment', 'not-a-url'])('rejects invalid native endpoint %s', value => {
    expect(parseAppConfig({ probeIpv4Url: value }).ok).toBe(false);
  });
  it('allows disabling branches and the optional backup explicitly', () => {
    const parsed = parseAppConfig({ probeIpv4Url: '', probeIpv6Url: '', checkApiBackup: '' });
    expect(parsed.ok && parsed.value.probeIpv4Url === '' && parsed.value.checkApiBackup === '').toBe(true);
  });
});
