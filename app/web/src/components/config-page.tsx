import { useCallback, useEffect, useMemo, useRef, useState } from 'preact/hooks';
import {
  MAX_SOCKET_READ_LIMIT_BYTES,
  MAX_TARGETS,
  MAX_ZONES,
  MIN_SOCKET_READ_LIMIT_BYTES,
  SETTINGS_LIMITS,
  type ConfigResponse,
  type ConfigUpdateRequest,
  type ProbeMode,
  type PublicAppConfig,
  type RuntimeSettings,
  type TargetConfig,
  type ZoneConfig,
} from '../../../src/contracts/config';
import type { ExitFilter, TargetMode } from '../../../src/domain/managed-target';
import type { ProbeTestDraft, ProbeTestItemResponse, ProbeTestResponse } from '../../../src/contracts/probe';
import { ApiClient } from '../api/client';
import { errorMessage, isAbort } from '../api/errors';
import type { RequestState } from '../state/request-state';
import { Icon } from './icon';
import { probeStatusLabel } from './probe-status';

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
  readonly probeMode: ProbeMode;
  readonly socketProbeIpv4Url: string;
  readonly socketProbeIpv6Url: string;
  readonly socketReadLimitBytes: string;
  readonly settings: Readonly<Record<keyof RuntimeSettings, string>>;
  readonly scheduledEnabled: boolean;
  readonly tgEnabled: boolean;
}

type SecretKey = 'authKey' | 'apiKey' | 'tgToken';
type SecretDrafts = Readonly<Record<SecretKey, string>>;
type SecretClearing = Readonly<Record<SecretKey, boolean>>;

const EMPTY_DRAFTS: SecretDrafts = { authKey: '', apiKey: '', tgToken: '' };
const NO_CLEARING: SecretClearing = { authKey: false, apiKey: false, tgToken: false };
const SECRET_LABELS: Readonly<Record<SecretKey, string>> = {
  authKey: '面板访问密钥',
  apiKey: 'Cloudflare API Token',
  tgToken: 'Telegram Bot Token',
};
/**
 * 主检测链路。cmliu-check 是旧配置遗留的只读形态：仍可读可保存，
 * 但界面上并入"外部复检"，不再把原始枚举值直接抛给用户。
 */
const PROBE_MODE_OPTIONS: readonly { readonly value: ProbeMode; readonly label: string; readonly help: string }[] = [
  { value: 'socket', label: '内部检测优先', help: '先用自建 socket 探针给结论，不通时再交给外部复检。' },
  { value: 'external-api', label: '外部复检优先', help: '先用外部接口给结论，异常时再回落到内部检测。' },
];
const SETTINGS_FIELDS: readonly (readonly [keyof RuntimeSettings, string, string])[] = [
  ['CONCURRENT_CHECKS', '前端批量检测并发', '单次批量检测的并发上限。'],
  ['BACKEND_CONCURRENT_CHECKS', '后端检测并发', '维护和补货预检使用。'],
  ['CHECK_TIMEOUT', '检测超时(ms)', '单次探针请求超时。'],
  ['REMOTE_LOAD_TIMEOUT', '远程加载超时(ms)', '远程 TXT 列表加载超时。'],
  ['DOH_TIMEOUT', 'DoH 超时(ms)', 'DNS over HTTPS 请求超时。'],
  ['DEFAULT_MIN_ACTIVE', '默认最少可用数', '新建域名时使用的默认值。'],
  ['MAX_TRASH_SIZE', '垃圾桶上限', '垃圾桶最多保留的条目数。'],
];

export function ConfigPage({ client, notify, initialConfig, onReload }: ConfigPageProps) {
  const [load, setLoad] = useState<RequestState<ConfigResponse>>(initialConfig);
  // 已落库基线：只有当前表单与基线不一致时，"保存到 KV / 还原改动"才值得占位置。
  const [baseline, setBaseline] = useState('');
  const [form, setForm] = useState<ConfigForm | null>(null);
  const [secrets, setSecrets] = useState<PublicAppConfig['secrets']>({ apiKey: false, authKey: false, tgToken: false });
  const [drafts, setDrafts] = useState<SecretDrafts>(EMPTY_DRAFTS);
  const [clearing, setClearing] = useState<SecretClearing>(NO_CLEARING);
  const [saving, setSaving] = useState(false);
  const [probeTarget, setProbeTarget] = useState('');
  const [probeTest, setProbeTest] = useState<RequestState<ProbeTestResponse>>({ status: 'idle' });
  const [editingZone, setEditingZone] = useState<number | null>(null);
  const [editingTarget, setEditingTarget] = useState<number | null>(null);

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

  const handleSave = (): void => {
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
        // 回写首屏共享缓存，返回仪表盘再进来时不会看到旧数据。
        void onReload();
        notify('配置已保存到 KV');
      })
      .catch((error: unknown) => notify(errorMessage(error), 'error'))
      .finally(() => setSaving(false));
  };

  /**
   * 接口自检把当前表单里的未保存草稿一起发过去，
   * 所以"刚填完还没保存"也能立刻试一次，而不必先回写 KV。
   */
  const handleTestProbe = (): void => {
    const target = probeTarget.trim();
    if (!target) {
      notify('请输入要测试的域名或 IP:端口', 'error');
      return;
    }
    const draft: ProbeTestDraft = {
      probeMode: form?.probeMode ?? 'external-api',
      checkApi: form?.checkApi.trim() ?? '',
      checkApiBackup: form?.checkApiBackup.trim() ?? '',
      socketProbeIpv4Url: form?.socketProbeIpv4Url.trim() ?? '',
      socketProbeIpv6Url: form?.socketProbeIpv6Url.trim() ?? '',
      ...(form && /^\d+$/.test(form.socketReadLimitBytes.trim()) ? { socketReadLimitBytes: Number(form.socketReadLimitBytes.trim()) } : {}),
    };
    setProbeTest({ status: 'loading' });
    client.testProbe({ proxyip: target, draft })
      .then((data) => setProbeTest({ status: 'ready', data }))
      .catch((error: unknown) => setProbeTest({ status: 'error', message: errorMessage(error) }));
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

  return (
    <div id="page-config" class="page-panel active" role="tabpanel" aria-labelledby="tab-config">
      <details class="card p-4 mb-3 config-details">
        <summary class="config-details-summary">
          <h2 class="card-title m-0 fw-bold"><Icon name="settings" /> 基础配置</h2>
          <div class="config-toolbar">
            <span class={`status-badge ${load.data.source === 'kv' ? 'ok' : 'warn'}`}>{sourceLabel(load.data.source)}</span>
            {dirty && <span class="config-dirty-hint">有未保存的改动</span>}
            {/* 保存与还原只在真有改动时出现：常驻按钮会让"已经存好了"看起来也像待办。 */}
            {dirty && (
              <>
                <button class="btn btn-sm btn-outline-secondary" type="button" disabled={saving} onClick={(event) => { event.preventDefault(); applyResponse(load.data); }}>还原改动</button>
                <button class="btn btn-sm btn-success config-save-btn" type="button" disabled={saving} onClick={(event) => { event.preventDefault(); handleSave(); }}>
                  <Icon name="save" /> {saving ? '保存中…' : '保存到 KV'}
                </button>
              </>
            )}
          </div>
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

          <fieldset class="probe-config-block">
            <legend class="probe-config-legend">主检测链路</legend>
            <div class="segmented" role="radiogroup" aria-label="主检测链路">
              {PROBE_MODE_OPTIONS.map((option) => (
                <button
                  key={option.value}
                  type="button"
                  role="radio"
                  aria-checked={form.probeMode === option.value}
                  class={`segmented-option${form.probeMode === option.value ? ' active' : ''}`}
                  onClick={() => patch({ probeMode: option.value })}
                >
                  {option.label}
                </button>
              ))}
            </div>
            <p class="probe-config-help mb-0">{PROBE_MODE_OPTIONS.find((option) => option.value === form.probeMode)?.help}</p>
          </fieldset>

          <section class="probe-config-block" aria-label="内部检测">
            <h3 class="probe-config-title">内部检测<span class="probe-config-tag">两个 socket 探针</span></h3>
            <p class="probe-config-help">任一族连通即判定可用。</p>
            <div class="config-grid">
              <TextField id="cfg-probe-v4" label="IPv4 探针地址" value={form.socketProbeIpv4Url} placeholder="https://ipv4.example.com/" onValue={(value) => patch({ socketProbeIpv4Url: value })} />
              <TextField id="cfg-probe-v6" label="IPv6 探针地址" value={form.socketProbeIpv6Url} placeholder="https://ipv6.example.com/" onValue={(value) => patch({ socketProbeIpv6Url: value })} />
              <NumberField id="cfg-probe-read-limit" label="探针读取上限(字节)" help={`${MIN_SOCKET_READ_LIMIT_BYTES}-${MAX_SOCKET_READ_LIMIT_BYTES}。`} value={form.socketReadLimitBytes} min={MIN_SOCKET_READ_LIMIT_BYTES} max={MAX_SOCKET_READ_LIMIT_BYTES} onChange={(value) => patch({ socketReadLimitBytes: value })} />
            </div>
          </section>

          <section class="probe-config-block" aria-label="外部复检">
            <h3 class="probe-config-title">外部复检<span class="probe-config-tag">可配置复检接口</span></h3>
            <p class="probe-config-help">主链路无结论时复检；{'{proxyip}'} 为被检测地址占位符。</p>
            <div class="config-grid">
              <TextField id="cfg-check-api" label="主复检接口"  value={form.checkApi} placeholder="https://example.com/check?proxyip={proxyip}" onValue={(value) => patch({ checkApi: value })} />
              <TextField id="cfg-check-api-backup" label="备用复检接口" help="留空则不复检。" value={form.checkApiBackup} placeholder="https://checkapi.dvb.kdns.fr/?candidate=" onValue={(value) => patch({ checkApiBackup: value })} />
            </div>
          </section>

          <div class="config-grid mb-3">
            <TextField id="cfg-doh" label="DoH API" help="用于解析 Cloudflare DNS 结果。" value={form.dohApi} onValue={(value) => patch({ dohApi: value })} />
            <TextField id="cfg-project-url" label="项目地址" help="页脚和通知中展示，可留空。" value={form.projectUrl} onValue={(value) => patch({ projectUrl: value })} />
            {SETTINGS_FIELDS.map(([key, label, help]) => (
              <NumberField key={key} id={`cfg-${key}`} label={label} help={`${help} ${SETTINGS_LIMITS[key].min}-${SETTINGS_LIMITS[key].max}。`} value={form.settings[key]} min={SETTINGS_LIMITS[key].min} max={SETTINGS_LIMITS[key].max} onChange={(value) => patch({ settings: { ...form.settings, [key]: value } })} />
            ))}
            <SecretField id="cfg-auth-key" label={SECRET_LABELS.authKey} help="留空则回退到环境变量 AUTH_KEY。" configured={secrets.authKey} value={drafts.authKey} clearing={clearing.authKey} onValue={(value) => setDrafts((current) => ({ ...current, authKey: value }))} onToggleClear={() => setClearing((current) => ({ ...current, authKey: !current.authKey }))} />
            <SecretField id="cfg-api-token" label={SECRET_LABELS.apiKey} help="旧配置兼容项，优先用权限配置里的 Token。" configured={secrets.apiKey} value={drafts.apiKey} clearing={clearing.apiKey} onValue={(value) => setDrafts((current) => ({ ...current, apiKey: value }))} onToggleClear={() => setClearing((current) => ({ ...current, apiKey: !current.apiKey }))} />
            <SecretField id="cfg-tg-token" label={SECRET_LABELS.tgToken} help="开启通知时必填。" configured={secrets.tgToken} value={drafts.tgToken} clearing={clearing.tgToken} onValue={(value) => setDrafts((current) => ({ ...current, tgToken: value }))} onToggleClear={() => setClearing((current) => ({ ...current, tgToken: !current.tgToken }))} />
            <TextField id="cfg-tg-id" label="TG Chat ID" help="通知接收账号或群组 ID。" value={form.tgId} placeholder="TG_ID" onValue={(value) => patch({ tgId: value })} />
            <div class="field span-2">
              <span>接口自检</span>
              <small>逐条试内部两个探针与外部两个复检接口，可用未保存的草稿。</small>
              <div class="probe-test-row">
                <input type="text" class="form-control form-control-sm" placeholder="要测试的域名 / IP:端口" aria-label="探测测试目标" value={probeTarget} onInput={(event) => setProbeTarget(event.currentTarget.value)} />
                <button class="btn btn-sm btn-outline-primary" type="button" disabled={probeTest.status === 'loading'} onClick={handleTestProbe}>
                  <Icon name="search" /> {probeTest.status === 'loading' ? '自检中…' : '开始自检'}
                </button>
              </div>
              {probeTest.status === 'idle' && <p class="probe-test-result mb-0"><span class="text-secondary">尚未自检。</span></p>}
              {probeTest.status === 'loading' && <p class="probe-test-result mb-0"><span class="text-secondary">正在逐条检测四个接口…</span></p>}
              {probeTest.status === 'error' && <p class="probe-test-result mb-0"><span class="text-danger">{probeTest.message}</span></p>}
              {probeTest.status === 'ready' && (
                <ul class="probe-test-list" aria-label="接口自检结果">
                  {probeTest.data.items.map((item) => (
                    <ProbeTestRow key={item.id} item={item} />
                  ))}
                </ul>
              )}
            </div>
          </div>
        </div>
      </details>

      <div class="card p-4 mb-3">
        <div class="d-flex justify-content-between align-items-center mb-3 flex-wrap gap-2">
          <h2 class="card-title m-0 fw-bold"><Icon name="globe" /> 维护的域名配置</h2>
          <button class="btn btn-sm btn-outline-primary" type="button" disabled={form.zones.length >= MAX_ZONES} onClick={addZone}>
            <Icon name="plus" /> 添加权限配置
          </button>
        </div>
        <div class="config-card-grid">
          {form.zones.length === 0 && <div class="config-empty-state">暂无权限配置，点击“添加权限配置”创建。</div>}
          {form.zones.map((zone, index) => (
            <div
              class={`config-mini-card${editingZone === index ? ' selected' : ''}`}
              key={index}
              title="点击编辑权限配置"
              onClick={() => setEditingZone((current) => current === index ? null : index)}
            >
              <h5>{zone.label || zone.name || zone.baseDomain || '未命名权限配置'}</h5>
              <div class="meta"><span>{zone.baseDomain || '未设置维护域名'}</span></div>
              <div class="meta">
                <span>Zone: {zone.zoneId ? '已填写' : '未填写'}</span>
                <span>CF Key: {zone.hasApiKey || zone.apiKey ? '已配置' : '未配置'}</span>
              </div>
              <div class="actions" onClick={(event) => event.stopPropagation()}>
                <button class="btn btn-sm btn-outline-primary" type="button" onClick={() => setEditingZone(index)}>编辑</button>
                <button class="btn btn-sm btn-outline-danger" type="button" onClick={() => removeZone(index)}>删除</button>
              </div>
            </div>
          ))}
        </div>
        <div id="zone-edit-panel" class={`config-edit-panel${activeZone ? ' active' : ''}`}>
          {activeZone && editingZone !== null && (
            <>
              <div class="config-edit-heading">
                <h3>编辑权限配置</h3>
                <small>修改后点击页首“保存到 KV”生效。</small>
              </div>
              <div class="config-grid">
                <TextField id={`zone-name-${editingZone}`} label="显示名称" value={activeZone.label} onValue={(value) => patchZone(editingZone, { label: value, name: value })} />
                <TextField id={`zone-domain-${editingZone}`} label="维护域名" value={activeZone.baseDomain} placeholder="example.com" onValue={(value) => patchZone(editingZone, { baseDomain: value })} />
                <TextField id={`zone-id-${editingZone}`} label="Cloudflare Zone ID" value={activeZone.zoneId} onValue={(value) => patchZone(editingZone, { zoneId: value })} />
                <TextField id={`zone-token-${editingZone}`} label="Cloudflare API Token" help="留空保持原值。" type="password" autoComplete="new-password" value={activeZone.apiKey} placeholder={activeZone.hasApiKey ? '已配置，留空保持不变' : '未配置'} onValue={(value) => patchZone(editingZone, { apiKey: value })} />
              </div>
              <div class="config-edit-actions"><button class="btn btn-sm btn-outline-secondary" type="button" onClick={() => setEditingZone(null)}>收起</button></div>
            </>
          )}
        </div>
      </div>

      <div class="card p-4 mb-3">
        <div class="d-flex justify-content-between align-items-center mb-3 flex-wrap gap-2">
          <h2 class="card-title m-0 fw-bold"><Icon name="activity" /> 管理域名</h2>
          <button class="btn btn-sm btn-outline-primary" type="button" disabled={form.targets.length >= MAX_TARGETS} onClick={addTarget}>
            <Icon name="plus" /> 添加管理域名
          </button>
        </div>
        <div class="config-card-grid">
          {form.targets.length === 0 && <div class="config-empty-state">暂无管理域名，点击“添加管理域名”创建。</div>}
          {form.targets.map((target, index) => (
            <div
              class={`config-mini-card${editingTarget === index ? ' selected' : ''}`}
              key={index}
              title="点击编辑管理域名"
              onClick={() => setEditingTarget((current) => current === index ? null : index)}
            >
              <h5>{targetDisplayDomain(target)}</h5>
              <div class="meta">
                <span class={`record-badge ${target.mode === 'TXT' ? 'record-badge-txt' : 'record-badge-a'}`}>{target.mode}</span>
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
              <div class="actions" onClick={(event) => event.stopPropagation()}>
                <label class="switch" title="单独控制这个域名是否参与维护">
                  <input type="checkbox" aria-label={`维护开关：${targetDisplayDomain(target)}`} checked={target.enabled} onChange={(event) => patchTarget(index, { enabled: event.currentTarget.checked })} />
                  <span class="switch-slider" />
                </label>
                <button class="btn btn-sm btn-outline-primary" type="button" onClick={() => setEditingTarget(index)}>编辑</button>
                <button class="btn btn-sm btn-outline-danger" type="button" onClick={() => removeTarget(index)}>删除</button>
              </div>
            </div>
          ))}
        </div>
        <div id="target-edit-panel" class={`config-edit-panel${activeTarget ? ' active' : ''}`}>
          {activeTarget && editingTarget !== null && (
            <>
              <div class="config-edit-heading">
                <h3>编辑管理域名</h3>
                <small>修改后点击页首“保存到 KV”生效。</small>
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
                  <select class="form-select form-select-sm" value={activeTarget.zoneIndex === null ? '' : String(activeTarget.zoneIndex)} onChange={(event) => patchTarget(editingTarget, { zoneIndex: event.currentTarget.value === '' ? null : Number(event.currentTarget.value) })}>
                  <option value="">使用顶层凭据</option>
                    {form.zones.map((zone, zoneIndex) => <option value={zoneIndex} key={zoneIndex}>{zone.label || zone.baseDomain || `权限配置 ${zoneIndex + 1}`}</option>)}
                  </select>
                </label>
                <TextField id={`target-prefix-${editingTarget}`} label="域名前缀" value={activeTarget.prefix} placeholder="proxy" onValue={(value) => patchTarget(editingTarget, { prefix: value })} />
                <TextField id={`target-base-${editingTarget}`} label="基础域名" value={activeTarget.baseDomain} placeholder="example.com" onValue={(value) => patchTarget(editingTarget, { baseDomain: value })} />
                <TextField id={`target-domain-${editingTarget}`} label="完整域名" help="留空则自动拼接。" value={activeTarget.domain} onValue={(value) => patchTarget(editingTarget, { domain: value })} />
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
              <div class="config-edit-actions"><button class="btn btn-sm btn-outline-secondary" type="button" onClick={() => setEditingTarget(null)}>收起</button></div>
            </>
          )}
        </div>
      </div>
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
    probeMode: config.probeMode,
    socketProbeIpv4Url: config.socketProbeIpv4Url,
    socketProbeIpv6Url: config.socketProbeIpv6Url,
    socketReadLimitBytes: String(config.socketReadLimitBytes),
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
  const authKey = secretValue(drafts, clearing, 'authKey');
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
    targets: form.targets.map(normalizeTargetDraft),
    checkApi: form.checkApi.trim(),
    checkApiBackup: form.checkApiBackup.trim(),
    dohApi: form.dohApi.trim(),
    ...(authKey === undefined ? {} : { authKey }),
    ...(tgToken === undefined ? {} : { tgToken }),
    tgId: form.tgId.trim(),
    scheduledEnabled: form.scheduledEnabled,
    tgEnabled: form.tgEnabled,
    settings,
    projectUrl: form.projectUrl.trim(),
    probeMode: form.probeMode,
    socketProbeIpv4Url: form.socketProbeIpv4Url.trim(),
    socketProbeIpv6Url: form.socketProbeIpv6Url.trim(),
    socketReadLimitBytes: readInteger(
      form.socketReadLimitBytes,
      '探针读取上限',
      MIN_SOCKET_READ_LIMIT_BYTES,
      MAX_SOCKET_READ_LIMIT_BYTES,
    ),
  };
}

function normalizeTargetDraft(target: TargetConfig): TargetConfig {
  const countries = splitList(target.country);
  const asns = splitList(target.asn);
  return {
    ...target,
    domain: target.domain.trim().toLowerCase(),
    baseDomain: target.baseDomain.trim(),
    prefix: target.prefix.trim(),
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

/** 保存按钮出现与否只取决于"表单与已落库基线是否一致"，因此这里只需要一个稳定的比较值。 */
function snapshot(form: ConfigForm, drafts: SecretDrafts, clearing: SecretClearing): string {
  return JSON.stringify([form, drafts, clearing]);
}

function probeTestStateLabel(item: ProbeTestItemResponse): { readonly label: string; readonly tone: string } {
  if (item.error) return { label: item.error, tone: 'text-danger' };
  if (!item.configured) return { label: '未配置', tone: 'text-secondary' };
  if (!item.result) return { label: '无结论', tone: 'text-warning' };
  const tone = item.result.status === 'alive' ? 'text-success' : item.result.status === 'dead' ? 'text-danger' : 'text-warning';
  return { label: probeStatusLabel(item.result.status), tone };
}

/** 一行一条链路：能用的信息尽量在这一行说清，失败原因直接跟在状态后面。 */
function ProbeTestRow({ item }: { readonly item: ProbeTestItemResponse }) {
  const state = probeTestStateLabel(item);
  const detail = item.result?.message;
  return (
    <li class="probe-test-item">
      <span class="probe-test-name">{item.label}</span>
      <span class={`probe-test-state ${state.tone}`}>
        {state.label}
        {item.result?.exitIp && <span class="probe-test-exit">出口 {item.result.exitIp}</span>}
        {item.result?.latencyMs !== undefined && <span class="probe-test-exit">{item.result.latencyMs} ms</span>}
      </span>
      {detail && state.tone !== 'text-danger' && <span class="probe-test-detail">{detail}</span>}
    </li>
  );
}

function sourceLabel(source: ConfigResponse['source']): string {
  return source === 'kv' ? 'KV 配置生效' : '环境变量回退';
}
