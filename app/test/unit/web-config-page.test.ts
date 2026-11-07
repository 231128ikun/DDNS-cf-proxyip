import { afterEach, describe, expect, it, vi } from 'vitest';
import { createDefaultConfig, type ConfigResponse, type ConfigUpdateRequest } from '../../src/contracts/config';
import type { DomainBindingsResponse } from '../../src/contracts/maintenance';
import type { RequestState } from '../../web/src/state/request-state';
import { createWorker } from '../../src/worker';
import { ApiClient } from '../../web/src/api/client';

// 用真实组件回调验证草稿和回执；不依赖浏览器或新增 DOM 测试依赖。
const hooks = vi.hoisted(() => {
  let slots: unknown[] = [];
  let cursor = 0;
  let changed = false;
  let effects: (() => unknown)[] = [];
  return {
    reset: () => { slots = []; },
    begin: () => { cursor = 0; changed = false; effects = []; },
    flush: () => { effects.forEach(effect => effect()); return changed; },
    useState: (initial: unknown) => {
      const index = cursor++;
      if (!(index in slots)) slots[index] = typeof initial === 'function' ? initial() : initial;
      return [slots[index], (next: unknown) => {
        const value = typeof next === 'function' ? next(slots[index]) : next;
        if (!Object.is(value, slots[index])) { slots[index] = value; changed = true; }
      }];
    },
    useRef: (initial: unknown) => {
      const index = cursor++;
      if (!(index in slots)) slots[index] = { current: initial };
      return slots[index];
    },
    useEffect: (effect: () => unknown, dependencies: unknown[]) => {
      const index = cursor++;
      const previous = slots[index] as unknown[] | undefined;
      if (!previous || dependencies.some((value, position) => !Object.is(value, previous[position]))) {
        slots[index] = dependencies;
        effects.push(effect);
      }
    },
  };
});
vi.mock('preact/hooks', () => ({
  useState: hooks.useState, useRef: hooks.useRef, useEffect: hooks.useEffect, useLayoutEffect: hooks.useEffect,
  useCallback: (callback: unknown) => callback, useMemo: (factory: () => unknown) => factory(),
}));
// 动态路径避免服务端测试 tsconfig 将 JSX 组件作为服务端源码编译。
const componentPath = '../../web/src/components/config-page.tsx';
const { ConfigPage } = await import(componentPath);

interface Element {
  readonly type: unknown;
  readonly props: Record<string, unknown>;
}
function elements(tree: unknown): Element[] {
  if (Array.isArray(tree)) return tree.flatMap(elements);
  if (!tree || typeof tree !== 'object' || !('props' in tree)) return [];
  const node = tree as Element;
  if (typeof node.type === 'function') return elements(node.type(node.props));
  return [node, ...elements(node.props.children)];
}
function text(tree: unknown): string {
  if (typeof tree === 'string' || typeof tree === 'number') return String(tree);
  if (Array.isArray(tree)) return tree.map(text).join('');
  if (!tree || typeof tree !== 'object' || !('props' in tree)) return '';
  const node = tree as Element;
  return text(typeof node.type === 'function' ? node.type(node.props) : node.props.children);
}
function find(tree: unknown, predicate: (node: Element) => boolean): Element {
  const found = elements(tree).find(predicate);
  if (!found) throw new Error('未找到测试控件');
  return found;
}
function field(tree: unknown, id: string): Element { return find(tree, node => node.props.id === id); }
function button(tree: unknown, label: string): Element {
  return find(tree, node => node.type === 'button' && text(node).trim() === label);
}
function invoke(node: Element, event: string, value?: string): unknown {
  return (node.props[event] as (event: unknown) => unknown)({ currentTarget: { value } });
}
function poolSelect(tree: unknown): Element {
  return find(tree, node => node.type === 'select' && String(node.props['aria-label']).endsWith('绑定的 IP 池'));
}

async function setup(existing = false) {
  hooks.reset();
  vi.stubGlobal('window', { addEventListener: vi.fn(), removeEventListener: vi.fn() });
  const stored = { ...createDefaultConfig(), zones: [{ name: '测试', label: '测试', baseDomain: 'example.com',
    zoneId: 'test-zone', apiKey: 'test-key' }], targets: existing
    ? [{ domain: 'old.example.com', prefix: 'old', baseDomain: 'example.com', mode: 'A', zoneIndex: 0, enabled: true }]
    : [] };
  const store = new Map([['app_config', JSON.stringify(stored)],
    ['domain_pool_mapping', JSON.stringify({ 'historical.example.com|A': 'ip_pool_009',
      ...(existing ? { 'old.example.com|A': 'ip_pool_001' } : {}) })]]);
  const writes: string[] = [];
  let failKey = '';
  const kv = { get: async (key: string, options?: { type?: string }) => {
    const raw = store.get(key) ?? null;
    return raw !== null && options?.type === 'json' ? JSON.parse(raw) : raw;
  },
    put: async (key: string, value: string) => {
      writes.push(key);
      if (key === failKey) throw new Error('storage unavailable');
      store.set(key, value);
    } } as unknown as KVNamespace;
  const worker = createWorker();
  const context = { waitUntil: () => undefined, passThroughOnException: () => undefined } as unknown as ExecutionContext;
  const client = new ApiClient({ fetchImpl: async (input, init) => worker.fetch!(
    new Request(`https://panel.example${input}`, init) as Parameters<NonNullable<typeof worker.fetch>>[0],
    { IP_DATA: kv }, context) });
  const notify = vi.fn();
  const onBindPool = vi.fn();
  const onSaveConfig = vi.fn((update: ConfigUpdateRequest) => client.saveConfig(update));
  const onSaveBindings = vi.fn(async (mapping: Readonly<Record<string, string>>) => { await client.saveDomainBindings(mapping); });
  const onSaved = vi.fn((response: ConfigResponse) => { props.config = { status: 'ready', data: response }; });
  const props = { config: { status: 'ready', data: await client.config() },
    bindings: { status: 'ready', data: await client.domainBindings() } as RequestState<DomainBindingsResponse>,
    pools: { status: 'ready', data: { pools: [
      { key: 'ip_pool_default', name: '默认池', count: 0 }, { key: 'ip_pool_001', name: '自定义池', count: 0 },
      { key: 'ip_pool_002', name: '第二池', count: 0 }, { key: 'ip_pool_trash', name: '垃圾桶', count: 0 },
    ] } }, saving: false, bindingBusy: false, onToggleSetting: vi.fn(), notify,
    onSaveConfig, onSaveBindings, onSaved, onBindPool, onReload: vi.fn(), onReloadBindings: vi.fn(), onOpenBindingOrder: vi.fn() };
  const render = (): unknown => {
    let tree: unknown;
    for (let attempt = 0; attempt < 8; attempt++) {
      hooks.begin(); tree = ConfigPage(props);
      if (!hooks.flush()) return tree;
    }
    throw new Error('组件状态未收敛');
  };
  const draft = (mode = 'A'): unknown => {
    invoke(button(render(), '添加维护域名'), 'onClick');
    invoke(field(render(), 'target-prefix-0'), 'onInput', 'Edge');
    invoke(field(render(), 'target-mode-0'), 'onChange', mode);
    const tree = render();
    expect(poolSelect(tree).props.disabled).toBe(false);
    expect(elements(poolSelect(tree)).some(node => node.props.value === 'ip_pool_trash')).toBe(false);
    invoke(poolSelect(tree), 'onChange', 'ip_pool_001');
    return render();
  };
  return { client, store, writes, props, render, draft, notify, onSaved, onSaveConfig, onSaveBindings, onBindPool,
    fail: (key: string) => { failKey = key; } };
}
afterEach(() => { vi.unstubAllGlobals(); });

describe('维护域名草稿 IP 池选择', () => {
  it.each(['A', 'TXT'])('先保存 %s 配置，再通过真实路由保存预选绑定，保留历史映射', async mode => {
    const ui = await setup();
    const editing = ui.draft(mode);
    expect(ui.writes).toEqual([]);
    await expect(ui.client.saveDomainBindings({ [`edge.example.com|${mode}`]: 'ip_pool_001' })).rejects.toThrow('管理域名列表已变化');
    invoke(button(editing, '确认修改'), 'onClick');
    invoke(poolSelect(ui.render()), 'onChange', 'ip_pool_002');
    expect(ui.writes).toEqual([]);
    expect(ui.onBindPool).not.toHaveBeenCalled();
    const saving = invoke(field(ui.render(), 'btn-save-config'), 'onClick');
    expect(field(ui.render(), 'page-config').props.disabled).toBe(true);
    expect(ui.onSaved).not.toHaveBeenCalled();
    await saving;
    expect(ui.writes).toEqual(['app_config', 'domain_pool_mapping']);
    expect(JSON.parse(ui.store.get('domain_pool_mapping')!)).toEqual({
      'historical.example.com|A': 'ip_pool_009', [`edge.example.com|${mode}`]: 'ip_pool_002',
    });
    expect(JSON.parse(ui.store.get('app_config')!).targets[0]).not.toHaveProperty('pendingPoolKey');
    expect(JSON.parse(ui.store.get('app_config')!).targets[0]).not.toHaveProperty('sourceKey');
    expect(ui.onSaved).toHaveBeenCalledTimes(1);
    expect(ui.notify).toHaveBeenCalledTimes(1);
    expect(find(ui.render(), node => node.props.class === 'config-toolbar card').props.hidden).toBe(true);
  });

  it('绑定失败同步已保存配置，保留池草稿和警告，显式重试不重写配置', async () => {
    const ui = await setup();
    invoke(button(ui.draft(), '确认修改'), 'onClick');
    ui.fail('domain_pool_mapping');
    const save = field(ui.render(), 'btn-save-config');
    const saving = invoke(save, 'onClick');
    await invoke(save, 'onClick');
    await saving;
    expect(ui.onSaveConfig).toHaveBeenCalledTimes(1);
    expect(ui.onSaveBindings).toHaveBeenCalledTimes(1);
    expect(ui.onSaved).toHaveBeenCalledTimes(1);
    expect(ui.props.config.data.config.targets[0]?.domain).toBe('edge.example.com');
    expect(ui.notify).not.toHaveBeenCalled();
    const failed = ui.render();
    expect(text(failed)).toContain('配置有未保存改动');
    expect(text(failed)).toContain('配置已保存，IP 池绑定未确认保存；维护可能仍使用默认池或原绑定');
    expect(poolSelect(failed).props.value).toBe('ip_pool_001');
    expect(field(failed, 'page-config').props.disabled).toBe(false);
    ui.fail('');
    await invoke(field(failed, 'btn-save-config'), 'onClick');
    expect(ui.onSaveConfig).toHaveBeenCalledTimes(1);
    expect(ui.writes).toEqual(['app_config', 'domain_pool_mapping', 'domain_pool_mapping']);
    expect(ui.onSaveBindings).toHaveBeenLastCalledWith({ 'edge.example.com|A': 'ip_pool_001' });
    expect(find(ui.render(), node => node.props.class === 'config-toolbar card').props.hidden).toBe(true);
    expect(ui.notify).toHaveBeenCalledTimes(1);
  });

  it('配置写入失败时不写绑定、不同步成功回执，保留全部草稿', async () => {
    const ui = await setup();
    invoke(button(ui.draft(), '确认修改'), 'onClick');
    ui.fail('app_config');
    await invoke(field(ui.render(), 'btn-save-config'), 'onClick');
    expect(ui.writes).toEqual(['app_config']);
    expect(ui.onSaveBindings).not.toHaveBeenCalled();
    expect(ui.onSaved).not.toHaveBeenCalled();
    expect(ui.notify).not.toHaveBeenCalled();
    expect(poolSelect(ui.render()).props.value).toBe('ip_pool_001');
    expect(text(ui.render())).toContain('配置有未保存改动');
    expect(text(ui.render())).not.toContain('配置已保存，IP 池绑定未确认保存');
    expect(JSON.parse(ui.store.get('app_config')!).targets).toEqual([]);
  });

  it('取消编辑和删除未保存目标不遗留绑定草稿', async () => {
    const ui = await setup();
    invoke(button(ui.draft(), '取消'), 'onClick');
    expect(find(ui.render(), node => node.props.class === 'config-toolbar card').props.hidden).toBe(true);
    invoke(button(ui.draft(), '确认修改'), 'onClick');
    const cards = field(ui.render(), 'maintained-domains');
    invoke(button(cards, '删除'), 'onClick');
    expect(find(ui.render(), node => node.props.class === 'config-toolbar card').props.hidden).toBe(true);
    expect(ui.writes).toEqual([]);
  });

  it('绑定读取失败时不默认迁移池，明确选择后才能保存改名', async () => {
    const ui = await setup(true);
    ui.props.bindings = { status: 'error', message: '读取失败', unavailable: false };
    expect(poolSelect(ui.render()).props.value).toBe('');
    expect(text(ui.render())).toContain('绑定未读取');
    invoke(button(field(ui.render(), 'maintained-domains'), '编辑'), 'onClick');
    invoke(field(ui.render(), 'target-prefix-0'), 'onInput', 'renamed');
    invoke(button(field(ui.render(), 'target-edit-panel'), '确认修改'), 'onClick');
    await invoke(field(ui.render(), 'btn-save-config'), 'onClick');
    expect(ui.writes).toEqual([]);
    expect(text(ui.render())).toContain('原 IP 池绑定未读取');
    expect(ui.onSaved).not.toHaveBeenCalled();
    invoke(poolSelect(ui.render()), 'onChange', 'ip_pool_002');
    await invoke(field(ui.render(), 'btn-save-config'), 'onClick');
    expect(ui.writes).toEqual(['app_config', 'domain_pool_mapping']);
    expect(ui.onSaved).toHaveBeenLastCalledWith(expect.anything(), { 'old.example.com|A': 'renamed.example.com|A' },
      { 'renamed.example.com|A': 'ip_pool_002' });
  });

  it('成功回执包含已确认池绑定；绑定失败回执不能声称该池已保存', async () => {
    const ui = await setup();
    invoke(button(ui.draft(), '确认修改'), 'onClick');
    ui.fail('domain_pool_mapping');
    await invoke(field(ui.render(), 'btn-save-config'), 'onClick');
    expect(ui.onSaved).toHaveBeenLastCalledWith(expect.anything(), {}, {});
    ui.fail('');
    await invoke(field(ui.render(), 'btn-save-config'), 'onClick');
    expect(ui.onSaved).toHaveBeenLastCalledWith(expect.anything(), { 'edge.example.com|A': 'edge.example.com|A' },
      { 'edge.example.com|A': 'ip_pool_001' });
  });

  it('改名未重新选池时保留界面显示的既有池选择', async () => {
    const ui = await setup(true);
    invoke(button(field(ui.render(), 'maintained-domains'), '编辑'), 'onClick');
    invoke(field(ui.render(), 'target-prefix-0'), 'onInput', 'renamed');
    invoke(button(field(ui.render(), 'target-edit-panel'), '确认修改'), 'onClick');
    expect(poolSelect(ui.render()).props.value).toBe('ip_pool_001');
    await invoke(field(ui.render(), 'btn-save-config'), 'onClick');
    expect(ui.onSaveBindings).toHaveBeenLastCalledWith({ 'renamed.example.com|A': 'ip_pool_001' });
  });

  it('保留已保存卡片的即时绑定，改名/类型后的草稿按新 key 保存', async () => {
    const ui = await setup(true);
    expect(poolSelect(ui.render()).props.value).toBe('ip_pool_001');
    invoke(poolSelect(ui.render()), 'onChange', 'ip_pool_002');
    expect(ui.onBindPool).toHaveBeenCalledWith('old.example.com|A', 'ip_pool_002');
    invoke(button(field(ui.render(), 'maintained-domains'), '编辑'), 'onClick');
    invoke(field(ui.render(), 'target-prefix-0'), 'onInput', 'renamed');
    invoke(field(ui.render(), 'target-mode-0'), 'onChange', 'TXT');
    const editor = field(ui.render(), 'target-edit-panel');
    invoke(poolSelect(editor), 'onChange', 'ip_pool_002');
    invoke(button(field(ui.render(), 'target-edit-panel'), '确认修改'), 'onClick');
    await invoke(field(ui.render(), 'btn-save-config'), 'onClick');
    expect(ui.onSaved).toHaveBeenLastCalledWith(expect.anything(), { 'old.example.com|A': 'renamed.example.com|TXT' },
      { 'renamed.example.com|TXT': 'ip_pool_002' });
    expect(ui.onSaveBindings).toHaveBeenLastCalledWith({ 'renamed.example.com|TXT': 'ip_pool_002' });
    expect(JSON.parse(ui.store.get('domain_pool_mapping')!)).toMatchObject({ 'renamed.example.com|TXT': 'ip_pool_002' });
  });
});
