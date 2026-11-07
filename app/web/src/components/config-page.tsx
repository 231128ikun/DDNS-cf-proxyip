import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'preact/hooks';
import {
  MAX_TARGETS,
  MAX_ZONES,
  SETTINGS_LIMITS,
  createDefaultConfig,
  parseConfigUpdate,
  type ConfigResponse,
  type ConfigUpdateRequest,
  type PublicAppConfig,
  type RuntimeSettings,
  type TargetConfig,
  type ZoneConfig,
} from '../../../src/contracts/config';
import type { ExitFilter, TargetMode } from '../../../src/domain/managed-target';
import type { DomainBindingsResponse } from '../../../src/contracts/maintenance';
import { DEFAULT_POOL_KEY, isUserPoolKey, type PoolsResponse } from '../../../src/contracts/pool';
import { sortByKeyOrder } from '../../../src/util/key-order';
import { bindingKey } from '../../../src/domain/domain-binding';
import { errorMessage } from '../api/errors';
import type { RequestState } from '../state/request-state';
import { Icon } from './icon';
import { ResourceFeedback } from './resource-feedback';
import { poolOptions } from '../state/pool-options';

export type GlobalSettingKey = 'scheduledEnabled' | 'tgEnabled';

interface ConfigPageProps {
  readonly onToggleSetting: (key: GlobalSettingKey, enabled: boolean) => void;
  readonly onSaveConfig: (update: ConfigUpdateRequest) => Promise<ConfigResponse>;
  readonly saving: boolean;
  readonly notify: (message: string, type?: 'success' | 'error') => void;
  readonly config: RequestState<ConfigResponse>;
  readonly onReload: (signal?: AbortSignal) => Promise<boolean>;
  readonly onSaved: (response: ConfigResponse, targetKeys: Readonly<Record<string, string>>, mapping: Readonly<Record<string, string>>) => void;
  readonly pools: RequestState<PoolsResponse>;
  readonly bindings: RequestState<DomainBindingsResponse>;
  readonly bindingBusy: boolean;
  readonly onBindPool: (key: string, poolKey: string) => void;
  readonly onSaveBindings: (mapping: Readonly<Record<string, string>>) => Promise<void>;
  readonly onReloadBindings: () => void;
  readonly onOpenBindingOrder: () => void;
}

interface ZoneDraft extends ZoneConfig {
  readonly hasApiKey?: boolean;
}

interface ZoneEditor {
  readonly index: number;
  readonly draft: ZoneDraft;
}

interface TargetEditor {
  readonly index: number;
  readonly draft: TargetDraft;
  readonly aPort: number;
}

/** 原 key 稳定关联池选择；本地字段不进入配置请求。 */
interface TargetDraft extends TargetConfig {
  readonly sourceKey: string | null;
  readonly pendingPoolKey: string | null;
}

interface ConfigForm {
  readonly zones: readonly ZoneDraft[];
  readonly targets: readonly TargetDraft[];
  readonly probeIpv4Url: string;
  readonly probeIpv6Url: string;
  readonly checkApiBackup: string;
  readonly dohApi: string;
  readonly projectUrl: string;
  readonly zoneId: string;
  readonly tgId: string;
  readonly settings: Readonly<Record<keyof RuntimeSettings, string>>;
}

type SecretKey = 'authKey' | 'tgToken';
type SecretDrafts = Readonly<Record<SecretKey, string>>;

class FieldError extends Error {
  constructor(readonly field: string, message: string) { super(message); }
}

const EMPTY_DRAFTS: SecretDrafts = { authKey: '', tgToken: '' };
const SECRET_LABELS: Readonly<Record<SecretKey, string>> = {
  authKey: '面板密钥',
  tgToken: 'TG Bot Token',
};
const SETTINGS_FIELDS: readonly (readonly [keyof RuntimeSettings, string, string, string])[] = [
  ['CONCURRENT_CHECKS', '检测并发', '同时检测的地址数；默认 8，建议 4–16。批检、解析实况与维护共用，增大不能突破单次调用资源限制。', 'cfg-concurrent-checks'],
  ['CHECK_TIMEOUT', '检测超时(ms)', '原生候选连接超时；复检仍失败才清理。备用 API 请求超时不清理。', 'cfg-check-timeout'],
  ['REMOTE_LOAD_TIMEOUT', '远程加载超时(ms)', '远程 TXT URL 加载。', 'cfg-remote-timeout'],
  ['DOH_TIMEOUT', 'DoH超时(ms)', 'DNS over HTTPS 查询。', 'cfg-doh-timeout'],
  ['DEFAULT_MIN_ACTIVE', '默认活跃数', '新增维护域名默认值。', 'cfg-default-min-active'],
  ['MAX_TRASH_SIZE', '垃圾桶上限', '超过后保留最新条目。', 'cfg-max-trash-size'],
];

export function ConfigPage({ onSaveConfig, onToggleSetting, saving, notify, config: load, onReload, onSaved, pools, bindings, bindingBusy,
  onBindPool, onSaveBindings, onReloadBindings, onOpenBindingOrder }: ConfigPageProps) {
  const applied = useRef<ConfigResponse | null>(null);
  const savePending = useRef(false);
  const [submitting, setSubmitting] = useState(false);
  const saveBusy = saving || submitting;
  // 已落库基线用于提示是否有未保存改动，并控制保存/还原按钮状态。
  const [baseline, setBaseline] = useState('');
  const [form, setForm] = useState<ConfigForm | null>(null);
  const [secrets, setSecrets] = useState<PublicAppConfig['secrets']>({ apiKey: false, authKey: false, tgToken: false });
  const [drafts, setDrafts] = useState<SecretDrafts>(EMPTY_DRAFTS);
  const [editingZone, setEditingZone] = useState<ZoneEditor | null>(null);
  const [editingTarget, setEditingTarget] = useState<TargetEditor | null>(null);
  const [saveError, setSaveError] = useState<Error | null>(null);
  const [zoneError, setZoneError] = useState('');
  const [targetError, setTargetError] = useState('');

  const applyResponse = useCallback((response: ConfigResponse, pendingPools: Readonly<Record<string, string>> = {}): void => {
    const nextForm = formFromConfig(response.config);
    applied.current = response;
    setForm({ ...nextForm, targets: nextForm.targets.map(target => ({ ...target,
      pendingPoolKey: pendingPools[target.sourceKey!] ?? null })) });
    // 配置回执是落库基线；未确认的池选择仍保留为草稿。
    setBaseline(snapshot(nextForm, EMPTY_DRAFTS));
    setSecrets(response.config.secrets);
    setDrafts(EMPTY_DRAFTS);
    setEditingZone(null);
    setEditingTarget(null);
    setSaveError(null);
    setZoneError('');
    setTargetError('');
  }, []);

  /** 配置只由 App 读取；重试也更新共享状态，同一保存响应只应用一次。 */
  const retried = useRef(false);
  useEffect(() => {
    if (load.status === 'ready') {
      if (savePending.current) return undefined;
      if (applied.current !== load.data) {
        // 顶部开关只更新全局标志，远端表单基线未变时保留本地表单和编辑区草稿。
        if (applied.current && snapshot(formFromConfig(load.data.config), EMPTY_DRAFTS) === baseline) {
          applied.current = load.data;
          setSecrets(load.data.config.secrets);
        } else applyResponse(load.data);
      }
      return undefined;
    }
    if (load.status !== 'error' || retried.current) return undefined;
    retried.current = true;
    void onReload();
    return undefined;
  }, [applyResponse, baseline, load, onReload]);

  const patch = (partial: Partial<ConfigForm>): void => {
    setSaveError(null);
    setForm((current) => (current ? { ...current, ...partial } : current));
  };

  const editZone = (index: number): void => {
    if (!form) return;
    const zone = form.zones[index];
    if (!zone) return;
    setZoneError('');
    setEditingZone((current) => current?.index === index ? null : { index, draft: { ...zone } });
  };

  const patchZone = (partial: Partial<ZoneDraft>): void => {
    setZoneError('');
    setEditingZone((current) => current ? { ...current, draft: { ...current.draft, ...partial } } : current);
  };

  const addZone = (): void => {
    if (!form || form.zones.length >= MAX_ZONES) return;
    setZoneError('');
    setEditingZone({ index: form.zones.length,
      draft: { name: '', label: '', baseDomain: '', zoneId: '', apiKey: '', hasApiKey: false } });
  };

  const commitZone = (): void => {
    if (!form || !editingZone) return;
    const { draft, index } = editingZone;
    if (!draft.baseDomain.trim() && !draft.zoneId.trim() && !draft.apiKey.trim() && !draft.hasApiKey) {
      setZoneError('请至少填写目标维护域名、Zone ID 或 CF Key');
      return;
    }
    const zones = [...form.zones];
    zones[index] = { ...draft, baseDomain: draft.baseDomain.trim(), zoneId: draft.zoneId.trim(),
      label: draft.label.trim() || draft.baseDomain.trim(), name: draft.label.trim() || draft.baseDomain.trim() };
    const validated = parseConfigUpdate({ zones, targets: form.targets });
    if (!validated.ok) { setZoneError(validated.message); return; }
    patch({ zones });
    setEditingZone(null);
  };

  const removeZone = (index: number): void => {
    setForm((current) => current ? {
      ...current,
      zones: current.zones.filter((_, position) => position !== index),
      targets: current.targets.map((target) => withoutZone(target, index, current.zones.length - 1)),
    } : current);
    setEditingZone(null);
    setEditingTarget((current) => current && form ? { ...current,
      draft: withoutZone(current.draft, index, form.zones.length - 1) } : current);
  };

  const patchTarget = (index: number, partial: Partial<TargetDraft>): void => {
    setForm((current) => current ? { ...current, targets: current.targets.map((target, position) => position === index ? mergeTarget(target, partial) : target) } : current);
    setEditingTarget((current) => current?.index === index
      ? { ...current, draft: mergeTarget(current.draft, partial) } : current);
  };

  const editTarget = (index: number): void => {
    if (!form) return;
    const target = form.targets[index];
    if (!target) return;
    setTargetError('');
    setEditingTarget((current) => current?.index === index ? null : { index, draft: { ...target },
      aPort: typeof target.port === 'number' ? target.port : 443 });
  };

  const patchTargetDraft = (partial: Partial<TargetDraft>): void => {
    setTargetError('');
    setEditingTarget((current) => {
      if (!current) return null;
      const aPort = typeof partial.port === 'number' ? partial.port : current.aPort;
      return { ...current, aPort, draft: mergeTarget(current.draft,
        { ...partial, ...(partial.mode === 'A' ? { port: aPort } : {}) }) };
    });
  };

  const addTarget = (): void => {
    if (!form) return;
    if (form.zones.length === 0) {
      notify('请先添加权限配置，再创建维护域名', 'error');
      return;
    }
    if (form.targets.length >= MAX_TARGETS) return;
    setTargetError('');
    const target = { ...createEmptyTarget(form.settings.DEFAULT_MIN_ACTIVE), zoneIndex: 0 };
    setEditingTarget({ index: form.targets.length, draft: target, aPort: 443 });
  };

  const commitTarget = (): void => {
    if (!form || !editingTarget) return;
    const target = { ...normalizeTargetDraft(editingTarget.draft, form.zones),
      sourceKey: editingTarget.draft.sourceKey, pendingPoolKey: editingTarget.draft.pendingPoolKey };
    if (!target.domain) { setTargetError('请先填写权限配置和域名前缀'); return; }
    try {
      if (target.mode === 'A') readInteger(String(target.port), '端口', 1, 65535);
      readInteger(String(target.minActive), '最少可用数', 0, 100);
    } catch (error) { setTargetError(errorMessage(error)); return; }
    const targets = [...form.targets];
    targets[editingTarget.index] = target;
    const validated = parseConfigUpdate({ zones: form.zones, targets });
    if (!validated.ok) { setTargetError(validated.message); return; }
    patch({ targets });
    setEditingTarget(null);
  };

  const removeTarget = (index: number): void => {
    setForm((current) => current ? { ...current, targets: current.targets.filter((_, position) => position !== index) } : current);
    setEditingTarget(null);
  };

  const dirty = useMemo(() => form !== null && snapshot(form, drafts) !== baseline, [baseline, drafts, form]);
  const editing = Boolean(
    (editingZone && JSON.stringify(editingZone.draft) !== JSON.stringify(form?.zones[editingZone.index]))
    || (editingTarget && JSON.stringify(editingTarget.draft) !== JSON.stringify(form?.targets[editingTarget.index])),
  );
  useEffect(() => {
    if (!dirty && !editing) return;
    const confirmLeave = (event: BeforeUnloadEvent): void => { event.preventDefault(); event.returnValue = true; };
    window.addEventListener('beforeunload', confirmLeave);
    return () => window.removeEventListener('beforeunload', confirmLeave);
  }, [dirty, editing]);

  useLayoutEffect(() => {
    if (!(saveError instanceof FieldError)) return;
    const field = document.getElementById(saveError.field);
    const details = field?.closest('details');
    if (details) details.open = true;
    field?.focus({ preventScroll: true });
    field?.scrollIntoView({ block: 'center' });
  }, [saveError]);

  const handleSave = async (): Promise<void> => {
    if (!form || saveBusy || bindingBusy || savePending.current || editing) return;
    setSaveError(null);
    let update: ConfigUpdateRequest;
    let pendingPools: Readonly<Record<string, string>>;
    try {
      update = buildUpdate(form, drafts);
      const validated = parseConfigUpdate(update);
      if (!validated.ok) throw new Error(validated.message);
      pendingPools = Object.fromEntries(form.targets.flatMap((target, index) => {
        const key = bindingKey(update.targets![index]!);
        if (target.pendingPoolKey !== null) return [[key, target.pendingPoolKey]];
        if (target.sourceKey === key) return [];
        const item = bindings.status === 'ready' ? bindings.data.items.find(item => item.key === target.sourceKey) : undefined;
        if (!item) throw new Error('原 IP 池绑定未读取，请刷新绑定或明确选择 IP 池后再保存');
        return [[key, item.poolKey]];
      }));
    } catch (error) {
      setSaveError(error instanceof Error ? error : new Error(errorMessage(error)));
      return;
    }

    savePending.current = true;
    setSubmitting(true);
    let response: ConfigResponse | null = null;
    let targetKeys: Readonly<Record<string, string>> = {};
    let confirmedPools: Readonly<Record<string, string>> = {};
    try {
      // 只有池草稿时只重试绑定，不重复写入已确认的配置。
      const configSnapshot = snapshot({ ...form, targets: form.targets.map(target => ({ ...target, pendingPoolKey: null })) }, drafts);
      response = configSnapshot !== baseline ? await onSaveConfig(update) : applied.current;
      if (!response) throw new Error('配置尚未读取，请刷新后重试');
      const savedTargets = response.config.targets;
      targetKeys = Object.fromEntries(form.targets.flatMap((target, index) => target.sourceKey && savedTargets[index]
        ? [[target.sourceKey, bindingKey(savedTargets[index]!)]] : []));
      const hasPendingPools = Object.keys(pendingPools).length > 0;
      if (hasPendingPools) {
        applyResponse(response, pendingPools);
        await onSaveBindings(pendingPools);
      }
      confirmedPools = pendingPools;
      applyResponse(response);
      notify(hasPendingPools ? '配置及 IP 池绑定已保存到 KV' : '配置已保存到 KV');
    } catch (error) {
      setSaveError(new Error(response
        ? `配置已保存，IP 池绑定未确认保存；维护可能仍使用默认池或原绑定。${errorMessage(error)}`
        : errorMessage(error)));
    } finally {
      if (response) onSaved(response, targetKeys, confirmedPools);
      savePending.current = false;
      setSubmitting(false);
    }
  };

  const orderedTargets = useMemo(() => form ? sortByKeyOrder(form.targets.map((target, index) => ({
    target: { ...target, ...normalizeTargetDraft(target, form.zones) }, index, key: target.sourceKey ?? bindingKey(target),
  })), bindings.status === 'ready' ? bindings.data.items.map(item => item.key) : []) : [],
  [form?.targets, form?.zones, bindings]);

  if (load.status === 'loading' || load.status === 'idle' || (load.status === 'ready' && !form)) {
    return <div id="page-config" role="tabpanel" aria-labelledby="tab-config" class="card p-4" tabIndex={0}>
      <p class="text-secondary mb-0">正在读取配置…</p>
    </div>;
  }
  if (load.status === 'error') {
    return (
      <div id="page-config" role="tabpanel" aria-labelledby="tab-config" class="card p-4">
        <p class="text-danger mb-2">{load.message}</p>
        <button class="btn btn-sm btn-outline-primary" type="button" onClick={() => void onReload()}>重试</button>
      </div>
    );
  }
  if (load.status !== 'ready' || !form) return null;

  const activeZone = editingZone?.draft ?? null;
  const activeTarget = editingTarget?.draft ?? null;
  const targetZone = activeTarget?.zoneIndex === null || activeTarget?.zoneIndex === undefined
    ? null
    : form.zones[activeTarget.zoneIndex] ?? null;

  return (
    <fieldset id="page-config" role="tabpanel" aria-labelledby="tab-config" disabled={saveBusy} aria-busy={saveBusy}>
      <ResourceFeedback state={load} id="retry-config" onRetry={() => void onReload()} />
      <div class="config-toolbar card" hidden={!dirty && !editing}>
        <span role="status">{editing ? '请先确认或取消编辑' : '配置有未保存改动'}</span>
        <div class="config-edit-actions">
          <button id="btn-cancel-config" class="btn btn-sm btn-outline-secondary" type="button"
            disabled={saveBusy || bindingBusy || editing} onClick={() => applyResponse(load.data)}>还原改动</button>
          <button id="btn-save-config" class="btn btn-sm btn-success" type="button"
            disabled={saveBusy || bindingBusy || editing} onClick={handleSave}>
            <Icon name="save" /> {saveBusy ? '保存中…' : '保存到 KV'}
          </button>
        </div>
        {saveError && !(saveError instanceof FieldError) && <small class="text-danger" role="alert">{saveError.message}</small>}
      </div>
      <details class="card p-4 mb-3 config-details">
        <summary class="config-details-summary">
          <h2 class="card-title m-0 fw-bold"><Icon name="settings" /> 基础配置</h2>
        </summary>
        <div class="config-details-body">
          <fieldset class="config-task-settings" aria-label="自动化设置" disabled={saveBusy}>
            {([['scheduledEnabled', '自动维护', 'cfg-scheduled-enabled'], ['tgEnabled', 'Telegram 通知', 'cfg-tg-enabled']] as const).map(([key, label, id]) => (
              <label class="setting-switch" key={key}>
                <input id={id} type="checkbox" role="switch" checked={load.data.config[key]} onChange={(event) => onToggleSetting(key, event.currentTarget.checked)} />
                <span class="setting-switch-track" aria-hidden="true" /><span>{label}</span>
              </label>
            ))}
          </fieldset>
          {load.data.notice && <p class="text-warning small">{load.data.notice}</p>}
          <div class="config-grid config-group">
            <TextField id="cfg-check-api-backup" label="备用检测 API" help="原生失败时复检；留空则原生重试。支持 {proxyip} 占位符。" value={form.checkApiBackup} placeholder="CHECK_API_BACKUP" onValue={(value) => patch({ checkApiBackup: value })} />
            <TextField id="cfg-doh" label="DoH API" help="域名解析查询接口。" value={form.dohApi} placeholder="DOH_API" onValue={(value) => patch({ dohApi: value })} />
            <SecretField id="cfg-auth-key" label={SECRET_LABELS.authKey} help="用于访问面板的身份验证。" placeholder="AUTH_KEY" configured={secrets.authKey} value={drafts.authKey} onValue={(value) => setDrafts((current) => ({ ...current, authKey: value }))} />
            <SecretField id="cfg-tg-token" label={SECRET_LABELS.tgToken} help="开启 Telegram 通知时必填。" placeholder="TG_TOKEN" configured={secrets.tgToken} value={drafts.tgToken} onValue={(value) => setDrafts((current) => ({ ...current, tgToken: value }))} />
            <TextField id="cfg-tg-id" label="TG Chat ID" help="通知接收账号或群组 ID。" value={form.tgId} placeholder="TG_ID" onValue={(value) => patch({ tgId: value })} />
          </div>
          <details class="config-group">
            <summary>高级：覆盖内置出口探针</summary>
            <p class="small text-secondary">默认使用内置探针，无需配置。仅在需要自定义时填写 HTTPS JSON 接口，留空恢复内置。</p>
            <div class="config-grid">
              <TextField id="cfg-probe-ipv4" label="IPv4 自定义探针" help="可选，返回包含 ip 的 JSON。" value={form.probeIpv4Url === createDefaultConfig().probeIpv4Url ? '' : form.probeIpv4Url} placeholder="留空使用内置 IPv4 探针" onValue={value => patch({ probeIpv4Url: value || createDefaultConfig().probeIpv4Url })} />
              <TextField id="cfg-probe-ipv6" label="IPv6 自定义探针" help="可选，返回包含 ip 的 JSON。" value={form.probeIpv6Url === createDefaultConfig().probeIpv6Url ? '' : form.probeIpv6Url} placeholder="留空使用内置 IPv6 探针" onValue={value => patch({ probeIpv6Url: value || createDefaultConfig().probeIpv6Url })} />
            </div>
          </details>
          <section class="config-group" aria-labelledby="config-runtime-title">
            <h3 id="config-runtime-title">运行参数</h3>
            <div class="config-grid config-runtime-grid">
              {SETTINGS_FIELDS.map(([key, label, help, id]) => (
                <NumberField key={key} id={id} label={label} help={help} value={form.settings[key]} min={SETTINGS_LIMITS[key].min} max={SETTINGS_LIMITS[key].max}
                  error={saveError instanceof FieldError && saveError.field === id ? saveError.message : undefined}
                  onChange={(value) => patch({ settings: { ...form.settings, [key]: value } })} />
              ))}
            </div>
          </section>
        </div>
      </details>

      <section class="card p-4 mb-3" aria-labelledby="zone-config-title">
        <div class="config-section-heading">
          <h2 id="zone-config-title" class="card-title m-0 fw-bold"><Icon name="globe" /> 域名权限配置</h2>
          <button class="btn btn-sm btn-outline-primary" type="button" disabled={form.zones.length >= MAX_ZONES} onClick={addZone}>
            <Icon name="plus" /> 添加权限配置
          </button>
        </div>
        <div class="config-card-grid">
          {form.zones.length === 0 && <div class="config-empty-state">暂无权限配置，点击“添加权限配置”创建。</div>}
          {form.zones.map((zone, index) => (
            <article
              class="config-mini-card"
              key={index}
            >
              <button class="config-card-open" type="button" aria-expanded={editingZone?.index === index} aria-controls="zone-edit-panel" onClick={() => editZone(index)}>
                <h3>{zone.label || zone.name || zone.baseDomain || '未命名权限配置'}</h3>
                {(zone.label || zone.name) !== zone.baseDomain && <div class="meta"><span>{zone.baseDomain || '未设置维护域名'}</span></div>}
                <div class="meta">
                  <span>Zone: {zone.zoneId ? '已填写' : '未填写'}</span>
                  <span>CF Key: {zone.hasApiKey || zone.apiKey ? '已填写' : '未填写'}</span>
                </div>
              </button>
              <div class="actions">
                <button class="btn btn-sm btn-outline-primary" type="button" onClick={() => editZone(index)}>编辑</button>
                <button class="btn btn-sm btn-outline-danger" type="button" onClick={() => removeZone(index)}>删除</button>
              </div>
            </article>
          ))}
        </div>
        <div id="zone-edit-panel" class={`config-edit-panel${activeZone ? ' active' : ''}`}>
          {activeZone && editingZone !== null && (
            <>
              <div class="config-edit-heading">
                <h3>{editingZone.index >= form.zones.length ? '添加' : '编辑'}权限配置</h3>
              </div>
              <div class="config-grid">
                <TextField id={`zone-name-${editingZone.index}`} label="备注" help="可选；不填时使用维护域名。" value={activeZone.label} placeholder="可选" onValue={(value) => patchZone({ label: value, name: value })} />
                <TextField id={`zone-domain-${editingZone.index}`} label="目标维护域名" help="目前只支持托管在cf的域名" value={activeZone.baseDomain} placeholder="example.com" onValue={(value) => patchZone({ baseDomain: value })} />
                <TextField id={`zone-id-${editingZone.index}`} label="Zone ID" help="Cloudflare 区域 ID。" value={activeZone.zoneId} placeholder="Zone ID" onValue={(value) => patchZone({ zoneId: value })} />
                <TextField id={`zone-token-${editingZone.index}`} label="CF Key" help="留空保持原值；需要 DNS 编辑权限。" type="password" autoComplete="new-password" value={activeZone.apiKey} placeholder={activeZone.hasApiKey ? '已配置，留空保持不变' : 'CF API Token'} onValue={(value) => patchZone({ apiKey: value })} />
              </div>
              <ConfigEditorActions error={zoneError} disabled={saveBusy} onCancel={() => setEditingZone(null)} onSave={commitZone} />
            </>
          )}
        </div>
      </section>

      <section id="maintained-domains" class="card p-4 mb-3 domain-binding-card" aria-labelledby="target-config-title">
        <div class="config-section-heading">
          <h2 id="target-config-title" class="card-title m-0 fw-bold"><Icon name="compass" /> 维护域名管理</h2>
          <div class="domain-binding-actions">
            <button class="btn btn-sm btn-outline-primary" type="button" disabled={form.targets.length >= MAX_TARGETS} onClick={addTarget}>
              <Icon name="plus" /> 添加维护域名
            </button>
            <button class="btn btn-sm btn-outline-secondary domain-binding-refresh" type="button" aria-label="刷新域名池绑定" title="刷新 IP 池绑定" disabled={bindingBusy} onClick={onReloadBindings}><Icon name="refresh" /></button>
            <button id="domain-order-trigger" class="btn btn-sm btn-outline-secondary" type="button" aria-label="调整维护域名顺序" aria-haspopup="dialog" title={dirty ? '保存域名改动后可调整顺序' : '调整维护域名顺序'} disabled={dirty || bindingBusy || bindings.status !== 'ready'} onClick={onOpenBindingOrder}><Icon name="sort" /></button>
          </div>
        </div>
        <ResourceFeedback state={bindings} id="retry-bindings" onRetry={onReloadBindings} />
        <ResourceFeedback state={pools} id="retry-config-pools" onRetry={onReloadBindings} />
        <div class="config-card-grid">
          {form.targets.length === 0 && <div class="config-empty-state">暂无维护域名，点击“添加维护域名”创建。</div>}
          {orderedTargets.map(({ target, index }) => (
            <article
              class="config-mini-card"
              data-target-index={index}
              key={index}
            >
              <button class="config-card-open" type="button" aria-expanded={editingTarget?.index === index} aria-controls="target-edit-panel" onClick={() => editTarget(index)}>
                <h3 class="domain-binding-name">{targetDisplayDomain(target)}</h3>
                <div class="meta">
                  <span>{target.mode === 'TXT' ? 'TXT' : `A/AAAA · ${target.port}`}</span>
                  <span>{exitFilterLabel(target.exitFilter)}</span>
                  <span>{zoneDisplayName(form.zones, target.zoneIndex)}</span>
                </div>
                <div class="meta">
                  <span>活跃数 {target.minActive}</span>
                  {target.country && <span>国家 {target.country}</span>}
                  {target.asn && <span>ASN {target.asn}</span>}
                </div>
              </button>
              <TargetPoolField target={target} bindings={bindings} pools={pools} busy={bindingBusy} onBind={onBindPool}
                onDraft={(pendingPoolKey) => patchTarget(index, { pendingPoolKey })} />
              <div class="actions">
                <label class="switch" title="单独控制这个域名是否参与维护">
                  <input type="checkbox" aria-label={`维护开关：${targetDisplayDomain(target)}`} checked={target.enabled} onChange={(event) => patchTarget(index, { enabled: event.currentTarget.checked })} />
                  <span>维护</span>
                </label>
                <button class="btn btn-sm btn-outline-primary" type="button" onClick={() => editTarget(index)}>编辑</button>
                <button class="btn btn-sm btn-outline-danger" type="button" onClick={() => removeTarget(index)}>删除</button>
              </div>
            </article>
          ))}
        </div>
        <div id="target-edit-panel" class={`config-edit-panel${activeTarget ? ' active' : ''}`}>
          {activeTarget && editingTarget !== null && (
            <>
              <div class="config-edit-heading">
                <h3>{editingTarget.index >= form.targets.length ? '添加' : '编辑'}维护域名</h3>
              </div>
              <div class="config-grid">
                <label class="field">
                  <span>权限配置</span>
                  <small>选择配置1/2/3。</small>
                  <select class="form-select form-select-sm" value={activeTarget.zoneIndex === null ? '' : String(activeTarget.zoneIndex)} onChange={(event) => {
                    const zoneIndex = event.currentTarget.value === '' ? null : Number(event.currentTarget.value);
                    const baseDomain = zoneIndex === null ? '' : form.zones[zoneIndex]?.baseDomain.trim() ?? '';
                    const currentBase = activeTarget.zoneIndex === null ? activeTarget.baseDomain : form.zones[activeTarget.zoneIndex]?.baseDomain ?? activeTarget.baseDomain;
                    const prefix = targetPrefix(activeTarget, currentBase);
                    patchTargetDraft({
                      zoneIndex,
                      baseDomain,
                      prefix,
                      ...(zoneIndex === null ? {} : { domain: composeDomain(prefix, baseDomain) }),
                    });
                  }}>
                    {activeTarget.zoneIndex === null && <option value="">使用顶层凭据</option>}
                    {form.zones.map((_, zoneIndex) => <option value={zoneIndex} key={zoneIndex}>{zoneDisplayName(form.zones, zoneIndex)}</option>)}
                  </select>
                </label>
                <label class="field">
                  <span>维护类型</span>
                  <small>A/AAAA 或 TXT。</small>
                  <select id={`target-mode-${editingTarget.index}`} class="form-select form-select-sm" value={activeTarget.mode} onChange={(event) => patchTargetDraft({ mode: readTargetMode(event.currentTarget.value) })}>
                    <option value="A">A/AAAA</option><option value="TXT">TXT</option>
                  </select>
                </label>
                <label class="field">
                  <span>出口类型</span>
                  <small>由检测 API 实时判断。</small>
                  <select class="form-select form-select-sm" value={activeTarget.exitFilter} onChange={(event) => patchTargetDraft({ exitFilter: readExitFilter(event.currentTarget.value) })}>
                    <option value="any">任意</option><option value="v4">仅 IPv4</option><option value="v6">仅 IPv6</option><option value="dual">双栈</option>
                  </select>
                </label>
                {targetZone?.baseDomain ? (
                  <>
                    <TextField
                      id={`target-prefix-${editingTarget.index}`}
                      label="域名前缀"
                      help="留空表示根域。"
                      value={targetPrefix(activeTarget, targetZone.baseDomain)}
                      placeholder="留空使用根域名"
                      onValue={(value) => {
                        const baseDomain = targetZone.baseDomain.trim();
                        const prefix = value.trim().replace(/^\.+|\.+$/g, '');
                        patchTargetDraft({ prefix, baseDomain, domain: composeDomain(prefix, baseDomain) });
                      }}
                    />
                  </>
                ) : (
                  <TextField id={`target-domain-${editingTarget.index}`} label="维护域名" help="填写需要维护的完整域名。" value={activeTarget.domain} placeholder="proxy.example.com" onValue={(value) => patchTargetDraft({ domain: value, baseDomain: '', prefix: '' })} />
                )}
                <NumberField id={`target-min-${editingTarget.index}`} label="活跃数" help="最小可用数量。" value={String(activeTarget.minActive)} min={0} max={100} onChange={(value) => patchTargetDraft({ minActive: Number(value) })} />
                <TextField id={`target-country-${editingTarget.index}`} label="国家" help="可填多个，逗号分隔；任一命中即可。" value={activeTarget.country} placeholder="JP,US,SG" onValue={(value) => patchTargetDraft({ country: value })} />
                <TextField id={`target-asn-${editingTarget.index}`} label="ASN" help="可填多个，逗号分隔；任一命中即可。" value={activeTarget.asn} placeholder="13335,209242" onValue={(value) => patchTargetDraft({ asn: value })} />
                <NumberField id={`target-port-${editingTarget.index}`} label="端口" help="A/AAAA 模式使用。" value={activeTarget.mode === 'TXT' ? '任意' : String(activeTarget.port)} min={1} max={65535} disabled={activeTarget.mode === 'TXT'} onChange={(value) => patchTargetDraft({ port: Number(value) })} />
                <TargetPoolField target={activeTarget} bindings={bindings} pools={pools} busy={bindingBusy} draftOnly
                  onBind={onBindPool} onDraft={(pendingPoolKey) => patchTargetDraft({ pendingPoolKey })} />
              </div>
              <ConfigEditorActions error={targetError} disabled={saveBusy} onCancel={() => setEditingTarget(null)} onSave={commitTarget} />
            </>
          )}
        </div>
      </section>
    </fieldset>
  );
}

function targetDisplayDomain(target: TargetConfig): string {
  const explicit = target.domain.trim();
  if (explicit) return explicit;
  if (target.prefix.trim() && target.baseDomain.trim()) return `${target.prefix.trim()}.${target.baseDomain.trim()}`;
  return target.baseDomain.trim() || '等待生成';
}

function zoneDisplayName(zones: readonly ZoneDraft[], zoneIndex: number | null): string {
  if (zoneIndex === null) return '顶层凭据';
  const zone = zones[zoneIndex];
  if (!zone) return '权限配置未找到';
  const label = zone.label || zone.name || zone.baseDomain || `权限配置 ${zoneIndex + 1}`;
  return zone.baseDomain && label !== zone.baseDomain ? `${label} · ${zone.baseDomain}` : label;
}

function exitFilterLabel(value: TargetConfig['exitFilter']): string {
  if (value === 'v4') return 'IPv4 出口';
  if (value === 'v6') return 'IPv6 出口';
  if (value === 'dual') return '双栈出口';
  return '任意出口';
}

function TargetPoolField({ target, bindings, pools, busy, draftOnly = false, onBind, onDraft }: {
  readonly target: TargetDraft;
  readonly bindings: RequestState<DomainBindingsResponse>;
  readonly pools: RequestState<PoolsResponse>;
  readonly busy: boolean;
  readonly draftOnly?: boolean;
  readonly onBind: (key: string, poolKey: string) => void;
  readonly onDraft: (poolKey: string) => void;
}) {
  const item = bindings.status === 'ready' ? bindings.data.items.find(binding => binding.key === target.sourceKey) : undefined;
  const persisted = target.sourceKey !== null && target.sourceKey === bindingKey(target);
  const staged = draftOnly || !persisted || target.pendingPoolKey !== null;
  const poolKey = target.pendingPoolKey ?? item?.poolKey ?? (target.sourceKey === null ? DEFAULT_POOL_KEY : '');
  return (
    <label class="field target-pool-field">
      <span>IP 池</span>
      <select class="form-select form-select-sm domain-binding-select" value={poolKey}
        aria-label={`${targetDisplayDomain(target)} 绑定的 IP 池`} aria-busy={busy}
        disabled={busy || pools.status !== 'ready' || (!staged && (!item?.enabled || !target.enabled))}
        onChange={(event) => {
          if (staged) onDraft(event.currentTarget.value);
          else if (target.sourceKey) onBind(target.sourceKey, event.currentTarget.value);
        }}>
        {!poolKey && <option value="">绑定未读取</option>}
        {poolOptions(pools, poolKey).filter(pool => isUserPoolKey(pool.key)).map(pool => <option key={pool.key} value={pool.key}>{pool.name}</option>)}
      </select>
      <small>{!poolKey ? '刷新绑定或明确选择 IP 池' : staged ? '随配置一起保存到 KV' : '更改后立即保存'}</small>
    </label>
  );
}

function ConfigEditorActions({ error, disabled, onCancel, onSave }: {
  readonly error: string;
  readonly disabled: boolean;
  readonly onCancel: () => void;
  readonly onSave: () => void;
}) {
  return (
    <div class="config-edit-actions">
      {error && <small class="text-danger" role="alert">{error}</small>}
      <button class="btn btn-sm btn-outline-secondary" type="button" disabled={disabled} onClick={onCancel}>
        取消
      </button>
      <button class="btn btn-sm btn-primary" type="button" disabled={disabled} onClick={onSave}>
        确认修改
      </button>
    </div>
  );
}

function TextField({
  id,
  label,
  help,
  value,
  placeholder,
  type = 'text',
  autoComplete,
  onValue,
}: {
  readonly id: string;
  readonly label: string;
  readonly help?: string;
  readonly value: string;
  readonly placeholder?: string;
  readonly type?: string;
  readonly autoComplete?: string;
  readonly onValue: (value: string) => void;
}) {
  return (
    <div class="field">
      <label class="field-label" for={id}>{label}</label>
      {help && <small id={`${id}-help`}>{help}</small>}
      <input
        id={id}
        type={type}
        class="form-control form-control-sm"
        value={value}
        placeholder={placeholder}
        autocomplete={autoComplete}
        aria-describedby={help ? `${id}-help` : undefined}
        onInput={(event) => onValue(event.currentTarget.value)}
      />
    </div>
  );
}

function NumberField({
  id,
  label,
  help,
  error,
  value,
  min,
  max,
  disabled = false,
  onChange,
}: {
  readonly id: string;
  readonly label: string;
  readonly help: string;
  readonly error?: string | undefined;
  readonly value: string;
  readonly min: number;
  readonly max: number;
  readonly disabled?: boolean;
  readonly onChange: (value: string) => void;
}) {
  return (
    <div class="field">
      <label class="field-label" for={id}>{label}</label>
      <small id={`${id}-help`}>{help}</small>
      <input
        id={id}
        type={disabled ? 'text' : 'number'}
        disabled={disabled}
        class="form-control form-control-sm"
        min={min}
        max={max}
        aria-invalid={error ? true : undefined}
        aria-describedby={error ? `${id}-help ${id}-error` : `${id}-help`}
        value={value}
        onInput={(event) => onChange(event.currentTarget.value)}
      />
      {error && <small id={`${id}-error`} class="text-danger" role="alert">{error}</small>}
    </div>
  );
}

function SecretField({
  id,
  label,
  help,
  placeholder,
  configured,
  value,
  onValue,
}: {
  readonly id: string;
  readonly label: string;
  readonly help: string;
  readonly placeholder: string;
  readonly configured: boolean;
  readonly value: string;
  readonly onValue: (value: string) => void;
}) {
  return (
    <div class="field">
      <label class="field-label" for={id}>{label}</label>
      <small id={`${id}-help`}>{help}</small>
      <input
        id={id}
        type="password"
        class="form-control form-control-sm"
        value={value}
        autocomplete="new-password"
        aria-describedby={`${id}-help`}
        placeholder={configured ? '已配置，留空保持不变' : placeholder}
        onInput={(event) => onValue(event.currentTarget.value)}
      />
    </div>
  );
}

function formFromConfig(config: PublicAppConfig): ConfigForm {
  return {
    zones: config.zones.map((zone) => ({ ...zone, apiKey: '', hasApiKey: zone.hasApiKey })),
    targets: config.targets.map((target) => ({ ...target, sourceKey: bindingKey(target), pendingPoolKey: null })),
    probeIpv4Url: config.probeIpv4Url,
    probeIpv6Url: config.probeIpv6Url,
    checkApiBackup: config.checkApiBackup,
    dohApi: config.dohApi,
    projectUrl: config.projectUrl,
    zoneId: config.zoneId,
    tgId: config.tgId,
    settings: Object.fromEntries(SETTINGS_FIELDS.map(([key]) => [key, String(config.settings[key])])) as ConfigForm['settings'],
  };
}

/** 密钥留空时沿用旧值；新值非空时才提交替换。 */
function buildUpdate(form: ConfigForm, drafts: SecretDrafts): ConfigUpdateRequest {
  const settings = Object.fromEntries(
    SETTINGS_FIELDS.map(([key, label, , id]) => {
      try { return [key, readInteger(form.settings[key], label, SETTINGS_LIMITS[key].min, SETTINGS_LIMITS[key].max)]; }
      catch (error) { throw new FieldError(id, errorMessage(error)); }
    }),
  ) as unknown as RuntimeSettings;

  const authKey = secretValue(drafts, 'authKey');
  const tgToken = secretValue(drafts, 'tgToken');

  return {
    zoneId: form.zoneId.trim(),
    zones: form.zones.map((zone) => ({
      name: zone.label.trim() || zone.name.trim(),
      baseDomain: zone.baseDomain.trim(),
      zoneId: zone.zoneId.trim(),
      apiKey: zone.apiKey.trim(),
      label: zone.label.trim() || zone.name.trim(),
    })),
    targets: form.targets.map(({ sourceKey: _sourceKey, pendingPoolKey: _pendingPoolKey, ...target }) => normalizeTargetDraft(target, form.zones)),
    ...(authKey === undefined ? {} : { authKey }),
    probeIpv4Url: form.probeIpv4Url.trim(),
    probeIpv6Url: form.probeIpv6Url.trim(),
    checkApiBackup: form.checkApiBackup.trim(),
    dohApi: form.dohApi.trim(),
    ...(tgToken === undefined ? {} : { tgToken }),
    tgId: form.tgId.trim(),
    settings,
    projectUrl: form.projectUrl.trim(),
  };
}

function normalizeTargetDraft(target: TargetConfig, zones: readonly ZoneDraft[]): TargetConfig {
  const countries = splitList(target.country);
  const asns = splitList(target.asn);
  const zone = target.zoneIndex === null ? undefined : zones[target.zoneIndex];
  const baseDomain = zone?.baseDomain.trim() || target.baseDomain.trim();
  const prefix = targetPrefix(target, target.baseDomain.trim() || baseDomain);
  return {
    ...target,
    domain: (zone?.baseDomain ? composeDomain(prefix, baseDomain) : target.domain.trim()).toLowerCase(),
    baseDomain,
    prefix,
    port: target.mode === 'TXT' ? 'any' : target.port,
    countries,
    asns,
    country: countries.join(','),
    asn: asns.join(','),
  };
}

function createEmptyTarget(defaultMinActive: string): TargetDraft {
  const minActive = Number.parseInt(defaultMinActive, 10);
  return {
    sourceKey: null,
    pendingPoolKey: DEFAULT_POOL_KEY,
    mode: 'A',
    domain: '',
    baseDomain: '',
    prefix: '',
    zoneIndex: null,
    port: 443,
    minActive: Number.isInteger(minActive) ? minActive : 0,
    exitFilter: 'any',
    country: '',
    asn: '',
    countries: [],
    asns: [],
    enabled: true,
  };
}

function mergeTarget<T extends TargetConfig>(target: T, partial: Partial<T>): T {
  const merged = { ...target, ...partial };
  const countries = partial.country === undefined ? merged.countries : splitList(merged.country);
  const asns = partial.asn === undefined ? merged.asns : splitList(merged.asn);
  return {
    ...merged,
    port: merged.mode === 'TXT' ? 'any' : merged.port === 'any' ? 443 : merged.port,
    countries,
    asns,
    country: countries.join(','),
    asn: asns.join(','),
  };
}

function withoutZone<T extends TargetConfig>(target: T, index: number, remaining: number): T {
  return { ...target, zoneIndex: target.zoneIndex === index ? (remaining > 0 ? 0 : null)
    : target.zoneIndex !== null && target.zoneIndex > index ? target.zoneIndex - 1 : target.zoneIndex };
}

function targetPrefix(target: TargetConfig, baseDomain: string): string {
  const domain = target.domain.trim().replace(/\.$/, '').toLowerCase();
  const base = baseDomain.trim().replace(/^\.+|\.+$/g, '').toLowerCase();
  if (!base) return target.prefix.trim();
  if (domain === base) return '';
  if (domain.endsWith(`.${base}`)) return domain.slice(0, -(base.length + 1));
  return target.prefix.trim();
}

function composeDomain(prefix: string, baseDomain: string): string {
  const cleanPrefix = prefix.trim().replace(/^\.+|\.+$/g, '');
  const cleanBase = baseDomain.trim().replace(/^\.+|\.+$/g, '');
  return cleanPrefix ? `${cleanPrefix}.${cleanBase}` : cleanBase;
}

function splitList(value: string): readonly string[] {
  return [...new Set(value.split(/[,;，；\s]+/).map((item) => item.trim().toUpperCase()).filter(Boolean))];
}

function secretValue(
  drafts: SecretDrafts,
  key: SecretKey,
): string | undefined {
  const value = drafts[key].trim();
  return value || undefined;
}

function readInteger(value: string, label: string, min: number, max: number): number {
  const text = value.trim();
  if (!/^\d+$/.test(text)) throw new Error(`${label}必须是整数`);
  const parsed = Number(text);
  if (parsed < min || parsed > max) throw new Error(`${label}必须在 ${min}-${max} 之间`);
  return parsed;
}

function readTargetMode(value: string): TargetMode {
  return value === 'TXT' ? 'TXT' : 'A';
}

function readExitFilter(value: string): ExitFilter {
  return value === 'v4' || value === 'v6' || value === 'dual' ? value : 'any';
}

function snapshot(form: ConfigForm, drafts: SecretDrafts): string {
  return JSON.stringify([form, drafts]);
}
