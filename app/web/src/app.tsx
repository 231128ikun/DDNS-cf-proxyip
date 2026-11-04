import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'preact/hooks';
import { DEFAULT_POOL_KEY, TRASH_POOL_KEY, NUMBERED_POOL_KEY_RE, isUserPoolKey } from '../../src/contracts/pool';
import type { CheckTargetResponse } from '../../src/contracts/probe';
import type { ConfigResponse, ConfigUpdateRequest } from '../../src/contracts/config';
import { bindingKey } from '../../src/domain/domain-binding';
import { sortByKeyOrder } from '../../src/util/key-order';
import { ApiClient, loadBatchCheckModule } from './api/client';
import { DEFAULT_RUNTIME_SETTINGS } from '../../src/contracts/runtime-settings';
import { errorMessage, isAbort } from './api/errors';
import {
  DashboardPage,
  type ConsoleLogEntry,
  type ConsoleTone,
  type DashboardActions,
  type PoolActionKey,
} from './components/dashboard-page';
import { PoolPanel } from './components/pool-panel';
import { Hero } from './components/hero';
import type { GlobalSettingKey } from './components/config-page';
import { TopNav, type AppPage } from './components/top-nav';
import { Modal } from './components/modal';
import type { OrderRequest } from './components/order-dialog';
import type { RequestState } from './state/request-state';
import { useResource } from './state/use-resource';
import { loadTargetStatuses, type TargetStatusesView, type TargetStatusView } from './state/target-status';
import { useBatchCheck } from './state/use-batch-check';
import { formatProbeLog, formatDnsSnapshot, shouldLogProbe } from './components/probe-log';

type ConfigPageComponent = typeof import('./components/config-page').ConfigPage;
type OrderDialogModule = typeof import('./components/order-dialog');

interface Toast {
  readonly message: string;
  readonly type: 'success' | 'error';
}

export function App({ client, initialConfig }: { readonly client: ApiClient; readonly initialConfig?: ConfigResponse }) {
  const [page, setPage] = useState<AppPage>('dashboard');
  const [ConfigPage, setConfigPage] = useState<ConfigPageComponent | null>(null);
  const [orderRequest, setOrderRequest] = useState<OrderRequest | null>(null);
  const [usageOpen, setUsageOpen] = useState(false);
  const [lookup, setLookup] = useState('');
  const [check, setCheck] = useState<RequestState<CheckTargetResponse>>({ status: 'idle' });
  const [maintenanceBusy, setMaintenanceBusy] = useState(false);
  const [selectedTargetKey, setSelectedTargetKey] = useState<string | null>(() => {
    const first = initialConfig?.config.targets[0];
    return first ? bindingKey(first) : null;
  });
  const initialOrderPending = useRef(true);
  const poolLeaveGuard = useRef<() => boolean>(() => true);
  const poolContainerChanged = useRef<(key: string) => void>(() => {});
  const [poolKey, setPoolKey] = useState(DEFAULT_POOL_KEY);
  const [poolBusy, setPoolBusy] = useState<PoolActionKey | null>(null);
  const [bindingBusy, setBindingBusy] = useState(false);
  const [configBusy, setConfigBusy] = useState(false);
  const configWritePending = useRef(false);
  const bindingWritePending = useRef(false);
  const [consoleLogs, setConsoleLogs] = useState<readonly ConsoleLogEntry[]>([]);
  const [toast, setToast] = useState<Toast | null>(null);
  const logSequence = useRef(0);
  const activeLookup = useRef<AbortController | null>(null);
  const currentTargetKey = useRef(selectedTargetKey);
  currentTargetKey.current = selectedTargetKey;
  const currentPage = useRef(page);
  currentPage.current = page;
  const openingOrder = useRef(false);
  const orderGeneration = useRef(0);
  const orderModule = useRef<OrderDialogModule | null>(null);
  const OrderDialog = orderModule.current?.OrderDialog;
  const startupLogged = useRef(false);
  const loggedProbeDiagnostics = useRef(new Map<string, string>());

  const notify = useCallback((message: string, type: Toast['type'] = 'success'): void => {
    setToast({ message, type });
  }, []);

  const appendConsoleLog = useCallback((message: string, tone: ConsoleTone = 'info'): void => {
    const entry: ConsoleLogEntry = {
      id: ++logSequence.current,
      time: new Date().toLocaleTimeString('zh-CN', { hour12: false }),
      tone,
      message,
    };
    setConsoleLogs((current) => [...current.slice(-199), entry]);
  }, []);

  const resetLookup = useCallback((): void => {
    activeLookup.current?.abort();
    activeLookup.current = null;
    setCheck({ status: 'idle' });
  }, []);

  useEffect(() => () => {
    activeLookup.current?.abort();
  }, []);

  const [health, refreshHealth] = useResource((signal) => client.health(signal));
  const [pools, refreshPools, patchPools] = useResource((signal) => client.pools(signal), true);
  const [config, refreshConfig, acceptConfig] = useResource((signal) => client.config(signal), true, initialConfig);
  const [bindings, refreshBindings, patchBindings] = useResource((signal) => client.domainBindings(signal), true);
  const confirmedBindings = bindings.status === 'ready' ? bindings.data : null;
  const configuredTargets = config.status === 'ready' ? config.data.config.targets : null;
  // 已保存配置决定目标集合；绑定回读只提供显示顺序，旧列表不能恢复已删除的目标。
  const targetChoices = useMemo(() => configuredTargets ? sortByKeyOrder(configuredTargets.map(target => ({
    key: bindingKey(target), domain: target.domain, mode: target.mode,
  })), confirmedBindings?.items.map(item => item.key) ?? []) : confirmedBindings?.items ?? [], [configuredTargets, confirmedBindings]);
  const targetKeys = useMemo(() => targetChoices.map(item => item.key), [targetChoices]);
  const webCheckConcurrency = config.status === 'ready'
    ? config.data.config.settings.CONCURRENT_CHECKS ?? DEFAULT_RUNTIME_SETTINGS.CONCURRENT_CHECKS
    : DEFAULT_RUNTIME_SETTINGS.CONCURRENT_CHECKS;
  const batchState = useBatchCheck({
    client, config, webCheckConcurrency, notify, appendConsoleLog,
    onInterrupt: () => { orderGeneration.current++; setOrderRequest(null); },
  });
  const { ipText, batch, batchProgressState, batchInterrupt, replaceIpText, handleResumeBatch, handleAbandonBatch } = batchState;
  const configuredTarget = configuredTargets?.find(target => bindingKey(target) === selectedTargetKey);
  const targetPort = configuredTarget?.port ?? 443;
  const [targetStatuses, refreshTargetStatuses] = useResource<TargetStatusesView>((signal, progress) =>
    loadTargetStatuses(client, configuredTargets ?? [], signal, progress), true);
  const targetStatus: RequestState<TargetStatusView> = targetStatuses.status === 'ready'
    ? targetStatuses.data.byKey[selectedTargetKey ?? ''] ?? { status: 'idle' }
    : targetStatuses;

  // 当前池被删掉时回落到默认池，避免下拉框停在一个已经不存在的 key 上。
  useEffect(() => {
    if (pools.status !== 'ready') return;
    setPoolKey((current) => (pools.data.pools.some((pool) => pool.key === current) ? current : DEFAULT_POOL_KEY));
  }, [pools]);

  /** 配置先决定首个目标，不等绑定回读；首次绑定就绪后应用保存顺序，但不覆盖用户选择。 */
  useEffect(() => {
    if (!configuredTargets && !confirmedBindings) return;
    const applySavedOrder = initialOrderPending.current && Boolean(confirmedBindings);
    if (confirmedBindings) initialOrderPending.current = false;
    setSelectedTargetKey((current) => {
      if (!applySavedOrder && current && targetKeys.includes(current)) return current;
      return targetKeys[0] ?? null;
    });
  }, [configuredTargets, confirmedBindings, targetKeys]);

  /** 配置就绪即并发预取全部域名；切换目标不取消其他域名或重复请求。 */
  useLayoutEffect(() => {
    if (!configuredTargets) return;
    resetLookup();
    const controller = new AbortController();
    loggedProbeDiagnostics.current.clear();
    void refreshTargetStatuses(controller.signal);
    void loadBatchCheckModule().catch(() => { /* 实际检测仍按原路径加载并报告失败。 */ });
    return () => controller.abort();
  }, [configuredTargets, refreshTargetStatuses, resetLookup]);

  /** 解析实况也是检测入口；异常逐项进工作台，同一加载过程不重复打印。 */
  useEffect(() => {
    if (targetStatuses.status !== 'ready') return;
    for (const [key, state] of Object.entries(targetStatuses.data.byKey)) {
      if (state.status === 'error') {
        if (loggedProbeDiagnostics.current.get(key) !== state.message) {
          loggedProbeDiagnostics.current.set(key, state.message);
          appendConsoleLog('[解析 ' + key + '] ' + state.message, 'error');
        }
      } else if (state.status === 'ready') {
        const snapshot = formatDnsSnapshot(state.data);
        if (loggedProbeDiagnostics.current.get(key + ':dns') !== snapshot) {
          loggedProbeDiagnostics.current.set(key + ':dns', snapshot);
          appendConsoleLog('[解析] ' + snapshot);
        }
        for (const item of state.data.probes) {
          if (!shouldLogProbe(item)) continue;
          const identity = key + ':' + item.address;
          const message = formatProbeLog(item);
          if (loggedProbeDiagnostics.current.get(identity) === message) continue;
          loggedProbeDiagnostics.current.set(identity, message);
          appendConsoleLog('[解析 ' + key + '] ' + item.address + ' · ' + message, item.status === 'dead' ? 'error' : 'warning');
        }
      }
    }
  }, [targetStatuses, appendConsoleLog]);

  /** 首次配置已由登录入口读取；其余只读资源立即并行拉取。 */
  useLayoutEffect(() => {
    const controller = new AbortController();
    void refreshHealth(controller.signal);
    void refreshPools(controller.signal);
    void refreshBindings(controller.signal);
    if (!initialConfig) void refreshConfig(controller.signal);
    return () => controller.abort();
  }, [initialConfig, refreshBindings, refreshConfig, refreshHealth, refreshPools]);

  /** 配置中心预取不阻塞首屏请求；重试和草稿状态由页面管理。 */
  useEffect(() => {
    let cancelled = false;
    void import('./components/config-page')
      .then((module) => {
        if (!cancelled) setConfigPage(() => module.ConfigPage);
      })
      .catch(() => {
        if (!cancelled) notify('配置中心加载失败，请刷新页面重试', 'error');
      });
    return () => { cancelled = true; };
  }, [notify]);

  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(null), 3200);
    return () => window.clearTimeout(timer);
  }, [toast]);

  useEffect(() => {
    if (startupLogged.current || health.status !== 'ready' || config.status !== 'ready' || pools.status !== 'ready' || !confirmedBindings) return;
    if (targetChoices.length && !selectedTargetKey) return;
    startupLogged.current = true;
    appendConsoleLog(targetChoices.length ? '[系统] 就绪' : '未设置维护域名，请在配置中心添加', targetChoices.length ? 'success' : 'warning');
  }, [appendConsoleLog, config, health, pools, confirmedBindings, selectedTargetKey, targetChoices]);

  const runPoolAction = useCallback(async (key: PoolActionKey, task: () => Promise<string>): Promise<void> => {
    setPoolBusy(key);
    try {
      const message = await task();
      await refreshPools();
      notify(message);
    } catch (error) {
      notify(errorMessage(error), 'error');
    } finally {
      setPoolBusy((current) => (current === key ? null : current));
    }
  }, [notify, refreshPools]);

  const handleLookupSubmit = (event: Event): void => {
    event.preventDefault();
    const value = lookup.trim();
    if (!value) {
      notify('请输入 ProxyIP 或目标地址', 'error');
      return;
    }
    setCheck({ status: 'loading' });
    activeLookup.current?.abort();
    const controller = new AbortController();
    activeLookup.current = controller;
    appendConsoleLog(`[探测] 开始检测 ${value}`);
    client.checkTarget(value, controller.signal)
      .then((data) => {
        if (controller.signal.aborted || activeLookup.current !== controller) return;
        setCheck({ status: 'ready', data });
        for (const item of data.items) {
          appendConsoleLog('[探测] ' + item.address + ' · ' + formatProbeLog(item.result),
            item.result.status === 'dead' ? 'error' : item.result.status === 'unknown' || item.result.diagnostics?.length ? 'warning' : 'success');
        }
        const statuses = data.items.reduce((counts, item) => {
          counts[item.result.status] += 1;
          return counts;
        }, { alive: 0, dead: 0, unknown: 0 });
        appendConsoleLog(
          `[探测] 完成 · 可用 ${statuses.alive} / 失效 ${statuses.dead} / 未知 ${statuses.unknown}`,
          statuses.alive ? 'success' : statuses.unknown ? 'warning' : 'error',
        );
      })
      .catch((error: unknown) => {
        if (isAbort(error) || controller.signal.aborted || activeLookup.current !== controller) return;
        const message = errorMessage(error);
        setCheck({ status: 'error', message });
        appendConsoleLog(`[探测] ${message}`, 'error');
      })
      .finally(() => { if (activeLookup.current === controller) activeLookup.current = null; });
  };

  const handleRefresh = (): void => {
    resetLookup();
    loggedProbeDiagnostics.current.clear();
    appendConsoleLog('[系统] 正在并发刷新全部域名解析');
    void refreshTargetStatuses();
  };

  const handleSelectTarget = (key: string | null): void => {
    initialOrderPending.current = false;
    resetLookup();
    setSelectedTargetKey(key);
    const target = targetChoices.find(item => item.key === key);
    if (target) appendConsoleLog(`切换到: ${target.domain} (${target.mode})`);
  };

  const handleSelectPool = (key: string): void => {
    setPoolKey(key);
    const name = pools.status === 'ready' ? pools.data.pools.find(pool => pool.key === key)?.name ?? key : key;
    appendConsoleLog(`[IP池] 已选择 ${name}`);
  };

  /** 只读地把当前记录复制到池工作台，不在 DNS 层做任何写入。 */
  const handleCopyToInput = (address: string): void => {
    const lines = ipText.split('\n').map((line) => line.trim()).filter(Boolean);
    if (lines.includes(address)) {
      notify('该地址已在输入框中', 'error');
      return;
    }
    replaceIpText([...lines, address].join('\n'));
    appendConsoleLog(`[记录] 已复制到输入框 ${address}`, 'success');
  };

  const handleCopyAddress = (address: string): void => {
    navigator.clipboard.writeText(address)
      .then(() => notify('维护地址已复制'))
      .catch(() => notify('复制失败，请手动复制地址', 'error'));
  };

  const handleAddRecord = (value: string): Promise<boolean> => {
    if (!selectedTargetKey) {
      notify('请先选择维护域名', 'error');
      return Promise.resolve(false);
    }
    const input = value.trim();
    if (!input) {
      notify('请输入要添加的 IP', 'error');
      return Promise.resolve(false);
    }
    return client.addRecord(selectedTargetKey, input)
      .then(async () => {
        if (currentTargetKey.current === selectedTargetKey) resetLookup();
        appendConsoleLog(`[记录] 已添加 ${input}`, 'success');
        notify('已添加 DNS 记录');
        await refreshTargetStatuses();
        return true;
      })
      .catch((error: unknown) => {
        const message = errorMessage(error);
        appendConsoleLog(`[记录] ${message}`, 'error');
        notify(message, 'error');
        return false;
      });
  };

  const handleDeleteRecord = (recordId: string, address?: string): void => {
    if (!selectedTargetKey) return;
    if (!window.confirm(address ? `确认删除 ${address}？` : '确认删除该记录？')) return;
    client.deleteRecord(selectedTargetKey, recordId, address)
      .then(async () => {
        if (currentTargetKey.current === selectedTargetKey) resetLookup();
        appendConsoleLog(`[记录] 已删除 ${address ?? recordId}`, 'success');
        notify('已删除 DNS 记录');
        await refreshTargetStatuses();
      })
      .catch((error: unknown) => {
        const message = errorMessage(error);
        appendConsoleLog(`[记录] ${message}`, 'error');
        notify(message, 'error');
      });
  };

  const handleCreatePool = (): void => {
    if (!poolLeaveGuard.current()) return;
    const name = window.prompt('新建 IP 池名称', '新池')?.trim();
    if (!name) return;
    void runPoolAction('pool-edit', async () => {
      const created = await client.createPool(name);
      poolContainerChanged.current(created.key);
      patchPools(current => ({ pools: [
        ...current.pools.filter(pool => pool.key !== TRASH_POOL_KEY && pool.key !== created.key),
        { key: created.key, name: created.displayName, count: 0 },
        ...current.pools.filter(pool => pool.key === TRASH_POOL_KEY),
      ] }));
      setPoolKey(created.key);
      return `已新建 ${created.displayName}`;
    });
  };

  const handleRenamePool = (): void => {
    if (!isUserPoolKey(poolKey)) {
      notify('默认池与编号池之外不支持重命名', 'error');
      return;
    }
    const current = pools.status === 'ready' ? pools.data.pools.find((pool) => pool.key === poolKey) : undefined;
    const name = window.prompt('重命名当前池', current?.name ?? poolKey)?.trim();
    if (!name || name === current?.name) return;
    void runPoolAction('pool-edit', async () => {
      await client.renamePool(poolKey, name);
      return `已重命名为 ${name}`;
    });
  };

  const openOrderDialog = async (kind: OrderRequest['kind']): Promise<void> => {
    if (openingOrder.current || orderRequest || batchInterrupt) return;
    openingOrder.current = true;
    const generation = orderGeneration.current;
    try {
      const module = orderModule.current ?? await import('./components/order-dialog');
      if (currentPage.current !== (kind === 'pools' ? 'dashboard' : 'config') || generation !== orderGeneration.current) return;
      orderModule.current = module;
      setOrderRequest(module.createOrderRequest(kind, pools.status === 'ready' ? pools.data : null,
        bindings.status === 'ready' ? bindings.data : null));
    } catch (error) {
      notify(errorMessage(error), 'error');
    } finally {
      openingOrder.current = false;
    }
  };

  const handleDeletePool = (): void => {
    if (!poolLeaveGuard.current()) return;
    if (!NUMBERED_POOL_KEY_RE.test(poolKey)) {
      notify('只能删除编号 IP 池', 'error');
      return;
    }
    if (!window.confirm(`确认删除 ${poolKey}？池内 IP 将一并删除，已绑定的域名会回退到默认池。`)) return;
    void runPoolAction('pool-edit', async () => {
      await client.removePool(poolKey);
      poolContainerChanged.current(poolKey);
      setPoolKey(DEFAULT_POOL_KEY);
      return `已删除 ${poolKey}`;
    });
  };

  /** 单行绑定写入串行执行，只有 PUT 确认后更新缓存；失败回读保留最后确认值。 */
  const handleBindPool = async (key: string, nextPoolKey: string): Promise<void> => {
    if (config.status !== 'ready' || bindings.status !== 'ready' || !targetKeys.includes(key) || bindingWritePending.current) return;
    bindingWritePending.current = true;
    setBindingBusy(true);
    try {
      await client.saveDomainBindings({ [key]: nextPoolKey });
      const poolName = pools.status === 'ready' ? pools.data.pools.find(pool => pool.key === nextPoolKey)?.name : undefined;
      patchBindings(current => ({ items: current.items.map(item => item.key === key
        ? { ...item, poolKey: nextPoolKey, poolName: poolName ?? nextPoolKey } : item) }));
      notify('已更新域名池绑定');
    } catch (error) {
      notify(errorMessage(error), 'error');
      await refreshBindings();
    } finally {
      bindingWritePending.current = false;
      setBindingBusy(false);
    }
  };

  const saveConfig = async (update: ConfigUpdateRequest): Promise<ConfigResponse> => {
    if (configWritePending.current) throw new Error('配置正在保存，请稍后重试');
    configWritePending.current = true;
    setConfigBusy(true);
    try {
      return await client.saveConfig(update);
    } finally {
      configWritePending.current = false;
      setConfigBusy(false);
    }
  };

  const handleToggleSetting = async (key: GlobalSettingKey, enabled: boolean): Promise<void> => {
    if (config.status !== 'ready' || configWritePending.current) return;
    try {
      const response = await saveConfig({ [key]: enabled });
      // 只确认全局开关，保留目标/参数引用和配置中心尚未提交的草稿。
      acceptConfig(current => ({ ...response, config: { ...current.config,
        scheduledEnabled: response.config.scheduledEnabled, tgEnabled: response.config.tgEnabled } }));
      notify(`${key === 'scheduledEnabled' ? '自动维护' : 'Telegram 通知'}已${enabled ? '开启' : '关闭'}`);
    } catch (error) {
      notify(errorMessage(error), 'error');
    }
  };

  const handleConfigSaved = (response: ConfigResponse, targetKeys: Readonly<Record<string, string>>): void => {
    initialOrderPending.current = false;
    const nextKeys = response.config.targets.map(bindingKey);
    setSelectedTargetKey(current => {
      const next = current ? targetKeys[current] ?? current : null;
      return next && nextKeys.includes(next) ? next : nextKeys[0] ?? null;
    });
    acceptConfig(response);
    void refreshBindings();
  };
  const handleRunMaintenance = (): void => {
    if (maintenanceBusy) return;
    setMaintenanceBusy(true);
    appendConsoleLog('[维护] 开始执行全部目标');
    client.runMaintenance()
      .then(async (data) => {
        for (const item of data.results) {
          for (const line of item.lines ?? [item.domain + '：' + (item.error ?? '维护明细未提供')]) appendConsoleLog('[维护] ' + line, item.error ? 'error' : item.probeErrors ? 'warning' : 'success');
        }
        const notification = data.notificationMessage;
        if (notification) appendConsoleLog('[通知] ' + notification, data.notification?.reason === 'failed' ? 'error' : 'info');
        appendConsoleLog('[维护] 结束', data.insufficient || data.errors.length || data.probeErrors ? 'warning' : 'success');
        await refreshBindings();
        await refreshPools();
        notify(data.message ?? '维护结束', data.completed === false ? 'error' : 'success');
      })
      .catch((error: unknown) => {
        const message = errorMessage(error);
        appendConsoleLog(`[维护] ${message}`, 'error');
        notify(message, 'error');
      })
      .finally(() => setMaintenanceBusy(false));
  };

  const actions: DashboardActions = {
    lookupSubmit: handleLookupSubmit,
    refresh: handleRefresh,
    addRecord: handleAddRecord,
    deleteRecord: handleDeleteRecord,
    runMaintenance: handleRunMaintenance,
  };

  return (
    <>
      <a
        href="https://github.com/231128ikun/DDNS-cf-proxyip"
        class="github-corner"
        aria-label="在 GitHub 查看源码"
        target="_blank"
        rel="noopener noreferrer"
      >
        <svg viewBox="0 0 250 250" aria-hidden="true" focusable="false">
          <use href="/github-corner.svg#corner" />
          <use class="octo-arm" href="/github-corner.svg#arm" fill="currentColor" />
          <use class="octo-body" href="/github-corner.svg#body" fill="currentColor" />
        </svg>
      </a>
      <Hero
        health={health}
        usageOpen={usageOpen}
        onToggleUsage={() => setUsageOpen((current) => !current)}
      />

      <div class="container">
        <TopNav page={page} onPageChange={next => { if (next === page || poolLeaveGuard.current()) setPage(next); }} />
        <div hidden={page !== 'dashboard'}>
          <DashboardPage
            poolPanel={<PoolPanel client={client} pools={pools} poolKey={poolKey} onPoolChange={handleSelectPool}
              actions={{ createPool: handleCreatePool, renamePool: handleRenamePool, openPoolOrder: () => void openOrderDialog('pools'), deletePool: handleDeletePool }}
              containerBusy={poolBusy !== null} refreshPools={() => void refreshPools()} batch={batchState}
              configReady={config.status === 'ready'} probeConfigured={config.status !== 'ready' || Boolean(config.data.config.probeIpv4Url || config.data.config.probeIpv6Url || config.data.config.checkApiBackup)}
              leaveGuard={poolLeaveGuard} containerChanged={poolContainerChanged} log={appendConsoleLog} />}
            check={check}
            batch={batch}
            lookup={lookup}
            consoleLogs={consoleLogs}
            batchProgressState={batchProgressState}
            targetStatus={targetStatus}
            bindings={bindings}
            targetChoices={targetChoices}
            onSelectTarget={handleSelectTarget}
            selectedTargetKey={selectedTargetKey}
            targetPort={targetPort}
            maintenanceBusy={maintenanceBusy}
            actions={actions}
            onCopyToInput={handleCopyToInput}
            onCopyAddress={handleCopyAddress}
            onLookupChange={setLookup}
          />
        </div>
        <div hidden={page !== 'config'}>
          {ConfigPage ? (
            <ConfigPage onSaveConfig={saveConfig} onToggleSetting={handleToggleSetting} saving={configBusy} notify={notify} config={config} onReload={refreshConfig} onSaved={handleConfigSaved}
              pools={pools} bindings={bindings} bindingBusy={bindingBusy} onBindPool={handleBindPool}
              onReloadBindings={() => { void refreshBindings(); void refreshPools(); }} onOpenBindingOrder={() => void openOrderDialog('bindings')} />
          ) : (
            <p class="text-secondary text-center py-4">正在加载配置中心…</p>
          )}
        </div>
      </div>

      <footer class="container text-center text-secondary small">
        DDNS Pro · {health.status === 'ready' ? health.data.version : 'unknown'}
      </footer>
      {orderRequest && OrderDialog && !batchInterrupt && <OrderDialog {...orderRequest}
        onSave={order => orderModule.current!.saveOrder(orderRequest.kind, order,
          { client, patchPools, patchBindings, refreshPools, refreshBindings, notify })}
        onClose={() => setOrderRequest(null)} />}
      {batchInterrupt && (
        <Modal id="batch-interrupt-title" title="检测已中断">
          <div class="custom-modal-stats">
            <div><span class="label">已完成来源</span><span class="value">{batchInterrupt.checked} / {batchInterrupt.total}</span></div>
            <div><span class="label">可用地址结果</span><span class="value">{batchInterrupt.valid} 个</span></div>
            <div><span class="label">已检测地址有效率</span><span class="value">{batchInterrupt.rate}%（{batchInterrupt.valid}/{batchInterrupt.results}）</span></div>
            <div><span class="label">待检测来源</span><span class="value">{batchInterrupt.unchecked} 个</span></div>
          </div>
          <div class="custom-modal-buttons">
            <button class="btn-abandon" type="button" onClick={handleAbandonBatch}>放弃检测</button>
            <button class="btn-continue" type="button" onClick={handleResumeBatch}>继续</button>
          </div>
        </Modal>
      )}
      <div class={`toast${toast ? ` ${toast.type} show` : ''}`} role="status" aria-live="polite">
        {toast?.message}
      </div>
    </>
  );
}
