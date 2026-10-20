import { useCallback, useEffect, useMemo, useRef, useState } from 'preact/hooks';
import {
  MAX_TARGETS,
  MAX_ZONES,
  SETTINGS_LIMITS,
  type ConfigResponse,
  type ConfigUpdateRequest,
  type PublicAppConfig,
  type RuntimeSettings,
  type TargetConfig,
  type ZoneConfig,
} from '../../../src/contracts/config';
import type { ExitFilter, TargetMode } from '../../../src/domain/managed-target';
import { ApiClient } from '../api/client';
import { errorMessage, isAbort } from '../api/errors';
import type { RequestState } from '../state/request-state';
import { Icon } from './icon';
import { RecordBadge } from './record-badge';

interface ConfigPageProps {
  readonly client: ApiClient;
  readonly notify: (message: string, type?: 'success' | 'error') => void;
  /** 首屏预取的配置：就绪时直接渲染，避免切页再等一轮请求。 */
  readonly initialConfig: RequestState<ConfigResponse>;
  readonly onReload: (signal?: AbortSignal) => Promise<void>;
}

interface ZoneDraft extends ZoneConfig {
  readonly hasApiKey?: boolean;
}

interface ConfigForm {
  readonly zones: readonly ZoneDraft[];
  readonly targets: readonly TargetConfig[];
  readonly checkApi: string;
  readonly checkApiBackup: string;
  readonly dohApi: string;
  readonly projectUrl: string;
  readonly zoneId: string;
  readonly tgId: string;
  readonly settings: Readonly<Record<keyof RuntimeSettings, string>>;
  readonly scheduledEnabled: boolean;
  readonly tgEnabled: boolean;
}

type SecretKey = 'apiKey' | 'tgToken';
type SecretDrafts = Readonly<Record<SecretKey, string>>;
type SecretClearing = Readonly<Record<SecretKey, boolean>>;

const EMPTY_DRAFTS: SecretDrafts = { apiKey: '', tgToken: '' };
const NO_CLEARING: SecretClearing = { apiKey: false, tgToken: false };
const SECRET_LABELS: Readonly<Record<SecretKey, string>> = {
  apiKey: 'Cloudflare API Token',
  tgToken: 'Telegram Bot Token',
};
const SETTINGS_FIELDS: readonly (readonly [keyof RuntimeSettings, string, string])[] = [
  ['BACKEND_CONCURRENT_CHECKS', '后端检测并发', '维护和补货预检使用。'],
  ['CHECK_TIMEOUT', '检测超时(ms)', '单次探针请求超时。'],
  ['REMOTE_LOAD_TIMEOUT', '远程加载超时(ms)', '远程 TXT 列表加载超时。'],
  ['DEFAULT_MIN_ACTIVE', '默认最少可用数', '新建域名时使用的默认值。'],
  ['MAX_TRASH_SIZE', '垃圾桶上限', '垃圾桶最多保留的条目数。'],
];

export function ConfigPage({ client, notify, initialConfig, onReload }: ConfigPageProps) {
  const [load, setLoad] = useState<RequestState<ConfigResponse>>(initialConfig);
  // 已落库基线用于提示是否有未保存改动，并控制保存/还原按钮状态。
  const [baseline, setBaseline] = useState('');
  const [form, setForm] = useState<ConfigForm | null>(null);
  const [secrets, setSecrets] = useState<PublicAppConfig['secrets']>({ apiKey: false, tgToken: false });
  const [drafts, setDrafts] = useState<SecretDrafts>(EMPTY_DRAFTS);
  const [clearing, setClearing] = useState<SecretClearing>(NO_CLEARING);
  const [saving, setSaving] = useState(false);
  const [editingZone, setEditingZone] = useState<number | null>(null);
  const [editingTarget, setEditingTarget] = useState<number | null>(null);
  const basicSettingsRef = useRef<HTMLDetailsElement>(null);

  const applyResponse = useCallback((response: ConfigResponse): void => {
    const nextForm = formFromConfig(response.config);
    setLoad({ status: 'ready', data: response });
    setForm(nextForm);
    // 基线跟着刚落库的响应走：保存或重载之后"未保存改动"必须重新归零。
    setBaseline(snapshot(nextForm, EMPTY_DRAFTS, NO_CLEARING));
    setSecrets(response.config.secrets);
    setDrafts(EMPTY_DRAFTS);
    setClearing(NO_CLEARING);
    setEditingZone(null);
    setEditingTarget(null);
  }, []);

  const reload = useCallback(
    (signal?: AbortSignal): void => {
      setLoad({ status: 'loading' });
      client.config(signal)
        .then(applyResponse)
        .catch((error: unknown) => {
          if (isAbort(error)) return;
          setLoad({ status: 'error', message: errorMessage(error) });
        });
    },
    [applyResponse, client],
  );

  /**
   * 首屏已经在预取配置，所以本页默认不发请求：
   * 预取就绪时直接渲染，预取失败时才由本页兜底并允许重试。
   */
  const retried = useRef(false);
  useEffect(() => {
    if (initialConfig.status === 'ready') {
      applyResponse(initialConfig.data);
      return undefined;
    }
    if (initialConfig.status !== 'error' || retried.current) return undefined;
    retried.current = true;
    reload();
    return undefined;
  }, [applyResponse, initialConfig, reload]);

  const patch = (partial: Partial<ConfigForm>): void => {
    setForm((current) => (current ? { ...current, ...partial } : current));
  };

  const patchZone = (index: number, partial: Partial<ZoneDraft>): void => {
    setForm((current) => current ? { ...current, zones: current.zones.map((zone, position) => position === index ? { ...zone, ...partial } : zone) } : current);
  };

  const addZone = (): void => {
    if (!form || form.zones.length >= MAX_ZONES) return;
    const index = form.zones.length;
    setForm({
      ...form,
      zones: [...form.zones, { name: '', label: '', baseDomain: '', zoneId: '', apiKey: '', hasApiKey: false }],
    });
    setEditingZone(index);
  };

  const removeZone = (index: number): void => {
    setForm((current) => current ? {
      ...current,
      zones: current.zones.filter((_, position) => position !== index),
      targets: current.targets.map((target) => ({
        ...target,
        zoneIndex: target.zoneIndex === index
          ? (current.zones.length > 1 ? 0 : null)
          : target.zoneIndex !== null && target.zoneIndex > index
            ? target.zoneIndex - 1
            : target.zoneIndex,
      })),
    } : current);
    setEditingZone((current) => current === null ? null : current === index ? null : current > index ? current - 1 : current);
    setEditingTarget((current) => current === null ? null : current === index ? null : current > index ? current - 1 : current);
  };

  const patchTarget = (index: number, partial: Partial<TargetConfig>): void => {
    setForm((current) => current ? { ...current, targets: current.targets.map((target, position) => position === index ? mergeTarget(target, partial) : target) } : current);
  };

  const addTarget = (): void => {
    if (!form) return;
    if (form.zones.length === 0) {
      notify('请先添加权限配置，再创建管理域名', 'error');
      return;
    }
    if (form.targets.length >= MAX_TARGETS) return;
    const index = form.targets.length;
    const target = { ...createEmptyTarget(form.settings.DEFAULT_MIN_ACTIVE), zoneIndex: 0 };
    setForm({ ...form, targets: [...form.targets, target] });
    setEditingTarget(index);
  };

  const removeTarget = (index: number): void => {
    setForm((current) => current ? { ...current, targets: current.targets.filter((_, position) => position !== index) } : current);
    setEditingTarget((current) => current === null ? null : current === index ? null : current > index ? current - 1 : current);
  };

  const dirty = useMemo(() => {
    if (!form) return false;
    try {
      return snapshot(form, drafts, clearing) !== baseline;
    } catch {
      // 数字框正在输入半截时无法构成合法请求，此时一律按"有改动"处理。
      return true;
    }
  }, [baseline, clearing, drafts, form]);

  const handleSave = (close: 'basic' | 'editor' = 'basic'): void => {
    if (!form) return;
    let update: ConfigUpdateRequest;
    try {
      update = buildUpdate(form, drafts, clearing);
    } catch (error) {
      notify(errorMessage(error), 'error');
      return;
    }

    setSaving(true);
    client.saveConfig(update)
      .then((response) => {
        applyResponse(response);
        if (close === 'basic') basicSettingsRef.current?.removeAttribute('open');
        // 回写首屏共享缓存，返回仪表盘再进来时不会看到旧数据。
        void onReload();
        notify('配置已保存');
      })
      .catch((error: unknown) => notify(errorMessage(error), 'error'))
      .finally(() => setSaving(false));
  };

  if (load.status === 'loading') return <div class="card p-4"><p class="text-secondary mb-0">正在读取配置…</p></div>;
  if (load.status === 'error') {
    return (
      <div class="card p-4">
        <p class="text-danger mb-2">{load.message}</p>
        <button class="btn btn-sm btn-outline-primary" type="button" onClick={() => reload()}>重试</button>
      </div>
    );
  }
  if (load.status !== 'ready' || !form) return null;

  const activeZone = editingZone === null ? null : form.zones[editingZone] ?? null;
  const activeTarget = editingTarget === null ? null : form.targets[editingTarget] ?? null;
  const targetZone = activeTarget?.zoneIndex === null || activeTarget?.zoneIndex === undefined
    ? null
    : form.zones[activeTarget.zoneIndex] ?? null;

  return (
    <div id="page-config" class="page-panel active" role="tabpanel" aria-labelledby="tab-config">
      <details ref={basicSettingsRef} class="card p-4 mb-3 config-details" open>
        <summary class="config-details-summary">
          <h2 class="card-title m-0 fw-bold"><Icon name="settings" /> 基础配置</h2>
          {dirty && <span class="config-dirty-hint">有未保存的改动</span>}
        </summary>
        <div class="config-details-body">
          {load.data.notice && <p class="text-warning small">{load.data.notice}</p>}
          <div class="switch-row mb-3">
            <label class="switch">
              <input type="checkbox" checked={form.tgEnabled} onChange={(event) => patch({ tgEnabled: event.currentTarget.checked })} />
              <span class="switch-slider" /><span>TG通知</span>
            </label>
            <label class="switch">
              <input type="checkbox" checked={form.scheduledEnabled} onChange={(event) => patch({ scheduledEnabled: event.currentTarget.checked })} />
              <span class="switch-slider" /><span>自动维护（cron 开关）</span>
            </label>
          </div>

          <section class="probe-config-block" aria-label="外部复检">
            <h3 class="probe-config-title">外部复检<span class="probe-config-tag">可配置复检接口</span></h3>
            <p class="probe-config-help">主链路无结论时复检；{'{proxyip}'} 为被检测地址占位符。</p>
            <div class="config-grid">
              <TextField id="cfg-check-api" label="主复检接口"  value={form.checkApi} placeholder="https://example.com/check?proxyip={proxyip}" onValue={(value) => patch({ checkApi: value })} />
              <TextField id="cfg-check-api-backup" label="备用复检接口" help="留空则不复检。" value={form.checkApiBackup} placeholder="https://checkapi.dvb.kdns.fr/?candidate=" onValue={(value) => patch({ checkApiBackup: value })} />
            </div>
            {!form.checkApi.trim() && !form.checkApiBackup.trim() && (
              <p class="kv-alert compact">至少保存一个复检接口，否则检测结果只会显示为探针异常。</p>
            )}
          </section>

          <div class="config-grid mb-3">
            <TextField id="cfg-doh" label="DoH API" help="`txt@域名` 与域名解析探测使用的公共 DNS 接口。" value={form.dohApi} onValue={(value) => patch({ dohApi: value })} />
            <TextField id="cfg-project-url" label="项目地址" help="页脚和通知中展示，可留空。" value={form.projectUrl} onValue={(value) => patch({ projectUrl: value })} />
            {SETTINGS_FIELDS.map(([key, label, help]) => (
              <NumberField key={key} id={`cfg-${key}`} label={label} help={`${help} ${SETTINGS_LIMITS[key].min}-${SETTINGS_LIMITS[key].max}。`} value={form.settings[key]} min={SETTINGS_LIMITS[key].min} max={SETTINGS_LIMITS[key].max} onChange={(value) => patch({ settings: { ...form.settings, [key]: value } })} />
            ))}
            <SecretField id="cfg-api-token" label={SECRET_LABELS.apiKey} help="旧配置兼容项，优先用权限配置里的 Token。" configured={secrets.apiKey} value={drafts.apiKey} clearing={clearing.apiKey} onValue={(value) => setDrafts((current) => ({ ...current, apiKey: value }))} onToggleClear={() => setClearing((current) => ({ ...current, apiKey: !current.apiKey }))} />
            <SecretField id="cfg-tg-token" label={SECRET_LABELS.tgToken} help="开启通知时必填。" configured={secrets.tgToken} value={drafts.tgToken} clearing={clearing.tgToken} onValue={(value) => setDrafts((current) => ({ ...current, tgToken: value }))} onToggleClear={() => setClearing((current) => ({ ...current, tgToken: !current.tgToken }))} />
            <TextField id="cfg-tg-id" label="TG Chat ID" help="通知接收账号或群组 ID。" value={form.tgId} placeholder="TG_ID" onValue={(value) => patch({ tgId: value })} />
          </div>
          <ConfigFormActions
            dirty={dirty}
            saving={saving}
            saveLabel="保存并收起"
            secondaryLabel="还原改动"
            secondaryDisabled={!dirty}
            onSecondary={() => applyResponse(load.data)}
            onSave={() => handleSave('basic')}
          />
        </div>
      </details>

      <section class="card p-4 mb-3" aria-labelledby="zone-config-title">
        <div class="config-section-heading">
          <div>
            <h2 id="zone-config-title" class="card-title m-0 fw-bold"><Icon name="globe" /> Cloudflare 权限配置</h2>
            <p class="config-section-help">每个 Zone 配置一次基础域名和凭据，下属管理域名会自动复用。</p>
          </div>
          <button class="btn btn-sm btn-outline-primary" type="button" disabled={form.zones.length >= MAX_ZONES} onClick={addZone}>
            <Icon name="plus" /> 添加 Zone
          </button>
        </div>
        <div class="config-card-grid">
          {form.zones.length === 0 && <div class="config-empty-state">暂无 Zone，点击“添加 Zone”创建。</div>}
          {form.zones.map((zone, index) => (
            <article
              class={`config-mini-card${editingZone === index ? ' selected' : ''}`}
              key={index}
            >
              <button class="config-card-open" type="button" aria-expanded={editingZone === index} aria-controls="zone-edit-panel" onClick={() => setEditingZone((current) => current === index ? null : index)}>
                <h5>{zone.label || zone.name || zone.baseDomain || '未命名权限配置'}</h5>
                <div class="meta"><span>{zone.baseDomain || '未设置维护域名'}</span></div>
                <div class="meta">
                  <span>Zone: {zone.zoneId ? '已填写' : '未填写'}</span>
                  <span>CF Key: {zone.hasApiKey || zone.apiKey ? '已配置' : '未配置'}</span>
                </div>
              </button>
              <div class="actions">
                <button class="btn btn-sm btn-outline-primary" type="button" onClick={() => setEditingZone(index)}>编辑</button>
                <button class="btn btn-sm btn-outline-danger" type="button" onClick={() => removeZone(index)}>删除</button>
              </div>
            </article>
          ))}
        </div>
        <div id="zone-edit-panel" class={`config-edit-panel${activeZone ? ' active' : ''}`}>
          {activeZone && editingZone !== null && (
            <>
              <div class="config-edit-heading">
                <h3>编辑权限配置</h3>
                <small>基础域名会用于生成下属管理域名。</small>
              </div>
              <div class="config-grid">
                <TextField id={`zone-name-${editingZone}`} label="显示名称" value={activeZone.label} onValue={(value) => patchZone(editingZone, { label: value, name: value })} />
                <TextField id={`zone-domain-${editingZone}`} label="维护域名" value={activeZone.baseDomain} placeholder="example.com" onValue={(value) => patchZone(editingZone, { baseDomain: value })} />
                <TextField id={`zone-id-${editingZone}`} label="Cloudflare Zone ID" value={activeZone.zoneId} onValue={(value) => patchZone(editingZone, { zoneId: value })} />
                <TextField id={`zone-token-${editingZone}`} label="Cloudflare API Token" help="留空保持原值。" type="password" autoComplete="new-password" value={activeZone.apiKey} placeholder={activeZone.hasApiKey ? '已配置，留空保持不变' : '未配置'} onValue={(value) => patchZone(editingZone, { apiKey: value })} />
              </div>
              <ConfigFormActions
                dirty={dirty}
                saving={saving}
                saveLabel="保存并收起"
                secondaryLabel="收起"
                onSecondary={() => setEditingZone(null)}
                onSave={() => handleSave('editor')}
              />
            </>
          )}
        </div>
      </section>

      <section class="card p-4 mb-3" aria-labelledby="target-config-title">
        <div class="config-section-heading">
          <div>
            <h2 id="target-config-title" class="card-title m-0 fw-bold"><Icon name="activity" /> 管理域名</h2>
            <p class="config-section-help">选择 Zone 后只填写子域名前缀；留空表示维护基础域名本身。</p>
          </div>
          <button class="btn btn-sm btn-outline-primary" type="button" disabled={form.targets.length >= MAX_TARGETS} onClick={addTarget}>
            <Icon name="plus" /> 添加管理域名
          </button>
        </div>
        <div class="config-card-grid">
          {form.targets.length === 0 && <div class="config-empty-state">暂无管理域名，点击“添加管理域名”创建。</div>}
          {form.targets.map((target, index) => (
            <article
              class={`config-mini-card${editingTarget === index ? ' selected' : ''}`}
              key={index}
            >
              <button class="config-card-open" type="button" aria-expanded={editingTarget === index} aria-controls="target-edit-panel" onClick={() => setEditingTarget((current) => current === index ? null : index)}>
                <h5>{targetDisplayDomain(target)}</h5>
                <div class="meta">
                  <RecordBadge mode={target.mode} />
                  <span>{target.mode === 'TXT' ? 'TXT 列表' : `端口 ${target.port}`}</span>
                  <span>{exitFilterLabel(target.exitFilter)}</span>
                  <span>{zoneDisplayName(form.zones, target.zoneIndex)}</span>
                  <span>{target.enabled ? '维护开启' : '维护关闭'}</span>
                </div>
                <div class="meta">
                  <span>活跃数 {target.minActive}</span>
                  {target.country && <span>国家 {target.country}</span>}
                  {target.asn && <span>ASN {target.asn}</span>}
                </div>
              </button>
              <div class="actions">
                <label class="switch" title="单独控制这个域名是否参与维护">
                  <input type="checkbox" aria-label={`维护开关：${targetDisplayDomain(target)}`} checked={target.enabled} onChange={(event) => patchTarget(index, { enabled: event.currentTarget.checked })} />
                  <span class="switch-slider" />
                </label>
                <button class="btn btn-sm btn-outline-primary" type="button" onClick={() => setEditingTarget(index)}>编辑</button>
                <button class="btn btn-sm btn-outline-danger" type="button" onClick={() => removeTarget(index)}>删除</button>
              </div>
            </article>
          ))}
        </div>
        <div id="target-edit-panel" class={`config-edit-panel${activeTarget ? ' active' : ''}`}>
          {activeTarget && editingTarget !== null && (
            <>
              <div class="config-edit-heading">
                <h3>编辑管理域名</h3>
                <small>基础域名来自权限配置，只需填写子域名前缀。</small>
              </div>
              <div class="config-grid">
                <label class="field">
                  <span>记录模式</span>
                  <select class="form-select form-select-sm" value={activeTarget.mode} onChange={(event) => patchTarget(editingTarget, { mode: readTargetMode(event.currentTarget.value) })}>
                    <option value="A">A / AAAA</option><option value="TXT">TXT</option>
                  </select>
                </label>
                <label class="field">
                  <span>权限配置</span>
                  <select class="form-select form-select-sm" value={activeTarget.zoneIndex === null ? '' : String(activeTarget.zoneIndex)} onChange={(event) => {
                    const zoneIndex = event.currentTarget.value === '' ? null : Number(event.currentTarget.value);
                    const baseDomain = zoneIndex === null ? '' : form.zones[zoneIndex]?.baseDomain.trim() ?? '';
                    const currentBase = activeTarget.zoneIndex === null ? activeTarget.baseDomain : form.zones[activeTarget.zoneIndex]?.baseDomain ?? activeTarget.baseDomain;
                    const prefix = targetPrefix(activeTarget, currentBase);
                    patchTarget(editingTarget, {
                      zoneIndex,
                      baseDomain,
                      prefix,
                      ...(zoneIndex === null ? {} : { domain: composeDomain(prefix, baseDomain) }),
                    });
                  }}>
                  <option value="">使用顶层凭据</option>
                    {form.zones.map((zone, zoneIndex) => <option value={zoneIndex} key={zoneIndex}>{zone.label || zone.baseDomain || `权限配置 ${zoneIndex + 1}`}</option>)}
                  </select>
                </label>
                {targetZone?.baseDomain ? (
                  <>
                    <TextField
                      id={`target-prefix-${editingTarget}`}
                      label="子域名前缀"
                      help={`完整域名：${composeDomain(targetPrefix(activeTarget, targetZone.baseDomain), targetZone.baseDomain)}`}
                      value={targetPrefix(activeTarget, targetZone.baseDomain)}
                      placeholder="留空使用根域名"
                      onValue={(value) => {
                        const baseDomain = targetZone.baseDomain.trim();
                        const prefix = value.trim().replace(/^\.+|\.+$/g, '');
                        patchTarget(editingTarget, { prefix, baseDomain, domain: composeDomain(prefix, baseDomain) });
                      }}
                    />
                    <div class="field domain-base-summary">
                      <span>基础域名（来自权限配置）</span>
                      <output>{targetZone.baseDomain}</output>
                    </div>
                  </>
                ) : (
                  <TextField id={`target-domain-${editingTarget}`} label="管理域名" help="填写需要维护的完整域名。" value={activeTarget.domain} placeholder="proxy.example.com" onValue={(value) => patchTarget(editingTarget, { domain: value, baseDomain: '', prefix: '' })} />
                )}
                <NumberField id={`target-port-${editingTarget}`} label={activeTarget.mode === 'TXT' ? '端口（TXT 固定任意）' : '端口'} help={activeTarget.mode === 'TXT' ? 'TXT 模式不限制端口。' : 'A/AAAA 使用；1-65535。'} value={activeTarget.mode === 'TXT' ? 'any' : String(activeTarget.port)} min={1} max={65535} onChange={(value) => patchTarget(editingTarget, { port: Number(value) })} />
                <NumberField id={`target-min-${editingTarget}`} label="最少可用数" help="低于此数量提示补货不足。" value={String(activeTarget.minActive)} min={0} max={100} onChange={(value) => patchTarget(editingTarget, { minActive: Number(value) })} />
                <label class="field">
                  <span>出口栈筛选</span>
                  <select class="form-select form-select-sm" value={activeTarget.exitFilter} onChange={(event) => patchTarget(editingTarget, { exitFilter: readExitFilter(event.currentTarget.value) })}>
                    <option value="any">不限</option><option value="v4">仅 IPv4</option><option value="v6">仅 IPv6</option><option value="dual">双栈</option>
                  </select>
                </label>
                <TextField id={`target-country-${editingTarget}`} label="国家筛选" value={activeTarget.country} placeholder="US,HK 或留空" onValue={(value) => patchTarget(editingTarget, { country: value })} />
                <TextField id={`target-asn-${editingTarget}`} label="ASN 筛选" value={activeTarget.asn} placeholder="AS13335 或留空" onValue={(value) => patchTarget(editingTarget, { asn: value })} />
                <label class="field checkbox-field"><span>维护开关</span><label class="switch"><input type="checkbox" checked={activeTarget.enabled} onChange={(event) => patchTarget(editingTarget, { enabled: event.currentTarget.checked })} /><span class="switch-slider" /><span>{activeTarget.enabled ? '启用' : '停用'}</span></label></label>
              </div>
              <ConfigFormActions
                dirty={dirty}
                saving={saving}
                saveLabel="保存并收起"
                secondaryLabel="收起"
                onSecondary={() => setEditingTarget(null)}
                onSave={() => handleSave('editor')}
              />
            </>
          )}
        </div>
      </section>
    </div>
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
  return zone ? zone.label || zone.name || zone.baseDomain || `权限配置 ${zoneIndex + 1}` : '权限配置未找到';
}

function exitFilterLabel(value: TargetConfig['exitFilter']): string {
  if (value === 'v4') return 'IPv4 出口';
  if (value === 'v6') return 'IPv6 出口';
  if (value === 'dual') return '双栈出口';
  return '任意出口';
}

/** 基础配置和各卡片编辑区共用同一套主次操作，避免保存按钮散落在不同位置。 */
function ConfigFormActions({
  dirty,
  saving,
  saveLabel,
  secondaryLabel,
  secondaryDisabled = false,
  onSecondary,
  onSave,
}: {
  readonly dirty: boolean;
  readonly saving: boolean;
  readonly saveLabel: string;
  readonly secondaryLabel: string;
  readonly secondaryDisabled?: boolean;
  readonly onSecondary: () => void;
  readonly onSave: () => void;
}) {
  return (
    <div class="config-edit-actions">
      <button class="btn btn-sm btn-outline-secondary" type="button" disabled={secondaryDisabled} onClick={onSecondary}>
        {secondaryLabel}
      </button>
      <button class="btn btn-sm btn-primary config-action-btn" type="button" disabled={saving || !dirty} onClick={onSave}>
        <Icon name="save" /> {saving ? '保存中…' : saveLabel}
      </button>
    </div>
  );
}

/**
 * 普通文本框：配置中心几十个输入框形状完全一样，
 * 标签、说明、输入框与事件绑定只实现一次，页面只描述差异部分。
 */
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
    <label class="field" for={id}>
      <span>{label}</span>
      {help && <small>{help}</small>}
      <input
        id={id}
        type={type}
        class="form-control form-control-sm"
        value={value}
        placeholder={placeholder}
        autocomplete={autoComplete}
        onInput={(event) => onValue(event.currentTarget.value)}
      />
    </label>
  );
}

function NumberField({
  id,
  label,
  help,
  value,
  min,
  max,
  onChange,
}: {
  readonly id: string;
  readonly label: string;
  readonly help: string;
  readonly value: string;
  readonly min: number;
  readonly max: number;
  readonly onChange: (value: string) => void;
}) {
  return (
    <label class="field">
      <span>{label}</span>
      <small>{help}</small>
      <input
        id={id}
        type="number"
        class="form-control form-control-sm"
        min={min}
        max={max}
        value={value}
        onInput={(event) => onChange(event.currentTarget.value)}
      />
    </label>
  );
}

function SecretField({
  id,
  label,
  help,
  configured,
  value,
  clearing,
  onValue,
  onToggleClear,
}: {
  readonly id: string;
  readonly label: string;
  readonly help: string;
  readonly configured: boolean;
  readonly value: string;
  readonly clearing: boolean;
  readonly onValue: (value: string) => void;
  readonly onToggleClear: () => void;
}) {
  return (
    <label class="field">
      <span>{label} {configured && <span class="record-badge">已配置</span>}</span>
      <small>{help}</small>
      <div class="d-flex gap-2">
        <input
          id={id}
          type="password"
          class="form-control form-control-sm"
          value={value}
          disabled={clearing}
          autocomplete="new-password"
          placeholder={configured ? '留空保持不变' : '未配置'}
          onInput={(event) => onValue(event.currentTarget.value)}
        />
        {configured && (
          <button class="btn btn-sm btn-outline-danger" type="button" onClick={onToggleClear}>
            {clearing ? '取消清除' : '清除'}
          </button>
        )}
      </div>
    </label>
  );
}

function formFromConfig(config: PublicAppConfig): ConfigForm {
  return {
    zones: config.zones.map((zone) => ({ ...zone, apiKey: '', hasApiKey: zone.hasApiKey })),
    targets: config.targets.map((target) => ({ ...target })),
    checkApi: config.checkApi,
    checkApiBackup: config.checkApiBackup,
    dohApi: config.dohApi,
    projectUrl: config.projectUrl,
    zoneId: config.zoneId,
    tgId: config.tgId,
    // 字段清单只有 SETTINGS_FIELDS 一份，这里按它派生，避免再维护第二份键名表。
    settings: Object.fromEntries(SETTINGS_FIELDS.map(([key]) => [key, String(config.settings[key])])) as ConfigForm['settings'],
    scheduledEnabled: config.scheduledEnabled,
    tgEnabled: config.tgEnabled,
  };
}

/** 密钥留空时沿用旧值；只有用户明确点击“清除”才提交空字符串。 */
function buildUpdate(form: ConfigForm, drafts: SecretDrafts, clearing: SecretClearing): ConfigUpdateRequest {
  const settings = Object.fromEntries(
    SETTINGS_FIELDS.map(([key, label]) => [
      key,
      readInteger(form.settings[key], label, SETTINGS_LIMITS[key].min, SETTINGS_LIMITS[key].max),
    ]),
  ) as unknown as RuntimeSettings;

  const apiKey = secretValue(drafts, clearing, 'apiKey');
  const tgToken = secretValue(drafts, clearing, 'tgToken');

  return {
    ...(apiKey === undefined ? {} : { apiKey }),
    zoneId: form.zoneId.trim(),
    zones: form.zones.map((zone) => ({
      name: zone.label.trim() || zone.name.trim(),
      baseDomain: zone.baseDomain.trim(),
      zoneId: zone.zoneId.trim(),
      apiKey: zone.apiKey.trim(),
      label: zone.label.trim() || zone.name.trim(),
    })),
    targets: form.targets.map((target) => normalizeTargetDraft(target, form.zones)),
    checkApi: form.checkApi.trim(),
    checkApiBackup: form.checkApiBackup.trim(),
    dohApi: form.dohApi.trim(),
    ...(tgToken === undefined ? {} : { tgToken }),
    tgId: form.tgId.trim(),
    scheduledEnabled: form.scheduledEnabled,
    tgEnabled: form.tgEnabled,
    settings,
    projectUrl: form.projectUrl.trim(),
  };
}

function normalizeTargetDraft(target: TargetConfig, zones: readonly ZoneDraft[]): TargetConfig {
  const countries = splitList(target.country);
  const asns = splitList(target.asn);
  const zone = target.zoneIndex === null ? undefined : zones[target.zoneIndex];
  const baseDomain = zone?.baseDomain.trim() || target.baseDomain.trim();
  const prefix = target.prefix.trim();
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

function createEmptyTarget(defaultMinActive: string): TargetConfig {
  const minActive = Number.parseInt(defaultMinActive, 10);
  return {
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

function mergeTarget(target: TargetConfig, partial: Partial<TargetConfig>): TargetConfig {
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
  clearing: SecretClearing,
  key: SecretKey,
): string | undefined {
  if (clearing[key]) return '';
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

/** 保存入口始终可见；只有表单与已落库基线不同时才允许提交。 */
function snapshot(form: ConfigForm, drafts: SecretDrafts, clearing: SecretClearing): string {
  return JSON.stringify([form, drafts, clearing]);
}
