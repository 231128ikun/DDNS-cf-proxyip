import { useCallback, useEffect, useMemo, useRef, useState } from 'preact/hooks';
import type { MaintenanceRunResponse } from '../../src/contracts/maintenance';
import { DEFAULT_POOL_KEY, TRASH_POOL_KEY, NUMBERED_POOL_KEY_RE, isUserPoolKey } from '../../src/contracts/pool';
import type { PoolCheckProgressEvent, PoolCheckResponse } from '../../src/contracts/pool-check';
import type { CheckTargetResponse } from '../../src/contracts/probe';
import type { ConfigResponse } from '../../src/contracts/config';
import { bindingKey } from '../../src/domain/domain-binding';
import { extractPoolAddressKey } from '../../src/domain/pool-entry';
import { dedupePoolText, filterPoolText, parsePoolFilter, type PoolFilterMode } from '../../src/domain/pool-filter';
import { cleanPoolText, countPoolTextLines } from '../../src/domain/pool-text';
import { sortByKeyOrder } from '../../src/util/key-order';
import { ApiClient } from './api/client';
import { DEFAULT_RUNTIME_SETTINGS } from '../../src/contracts/runtime-settings';
import { errorMessage, isAbort } from './api/errors';
import {
  DashboardPage,
  type ConsoleLogEntry,
  type ConsoleTone,
  type DashboardActions,
  type PoolCheckProgressState,
  type PoolActionKey,
} from './components/dashboard-page';
import { Hero } from './components/hero';
import { TopNav, type AppPage } from './components/top-nav';
import { Modal } from './components/modal';
import type { OrderRequest } from './components/order-dialog';
import type { RequestState } from './state/request-state';
import { useResource } from './state/use-resource';
import { loadTargetStatus, type TargetStatusView } from './state/target-status';

type ConfigPageComponent = typeof import('./components/config-page').ConfigPage;
type OrderDialogModule = typeof import('./components/order-dialog');

interface Toast {
  readonly message: string;
  readonly type: 'success' | 'error';
}

/** 批量检测中途停止时展示的确认信息，与 main 的“检测已中断”弹窗对齐。 */
interface BatchInterrupt {
  readonly checked: number;
  readonly total: number;
  readonly valid: number;
  readonly unchecked: number;
}

export function App() {
  const [page, setPage] = useState<AppPage>('dashboard');
  const [ConfigPage, setConfigPage] = useState<ConfigPageComponent | null>(null);
  const [orderRequest, setOrderRequest] = useState<OrderRequest | null>(null);
  const [usageOpen, setUsageOpen] = useState(false);
  const [lookup, setLookup] = useState('');
  const [check, setCheck] = useState<RequestState<CheckTargetResponse>>({ status: 'idle' });
  const [ipText, setIpText] = useState('');
  const [filterText, setFilterText] = useState('');
  const [remoteUrl, setRemoteUrl] = useState('');
  const [maintenance, setMaintenance] = useState<RequestState<MaintenanceRunResponse>>({ status: 'idle' });
  const [maintenanceBusy, setMaintenanceBusy] = useState(false);
  const [selectedTargetKey, setSelectedTargetKey] = useState<string | null>(null);
  const [poolKey, setPoolKey] = useState(DEFAULT_POOL_KEY);
  const [batch, setBatch] = useState<RequestState<PoolCheckResponse>>({ status: 'idle' });
  const [loadingPool, setLoadingPool] = useState(false);
  const [checkingBatch, setCheckingBatch] = useState(false);
  const [savingPool, setSavingPool] = useState(false);
  const [poolBusy, setPoolBusy] = useState<PoolActionKey | null>(null);
  const [bindingBusy, setBindingBusy] = useState(false);
  const bindingWritePending = useRef(false);
  const [consoleLogs, setConsoleLogs] = useState<readonly ConsoleLogEntry[]>([]);
  const [batchProgressState, setBatchProgressState] = useState<PoolCheckProgressState | null>(null);
  const [batchInterrupt, setBatchInterrupt] = useState<BatchInterrupt | null>(null);
  const [toast, setToast] = useState<Toast | null>(null);
  const client = useMemo(() => new ApiClient(), []);
  const logSequence = useRef(0);
  const activeBatch = useRef<AbortController | null>(null);
  const activeLookup = useRef<AbortController | null>(null);
  const currentTargetKey = useRef(selectedTargetKey);
  currentTargetKey.current = selectedTargetKey;
  const currentPage = useRef(page);
  currentPage.current = page;
  const openingOrder = useRef(false);
  const orderGeneration = useRef(0);
  const orderModule = useRef<OrderDialogModule | null>(null);
  const OrderDialog = orderModule.current?.OrderDialog;
  const aliveSoFar = useRef(0);
  const startupLogged = useRef(false);

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

  /** 所有输入替换都走这里：旧检测必须中止，旧结果也必须立即失效。 */
  const replaceIpText = useCallback((value: string): void => {
    activeBatch.current?.abort();
    activeBatch.current = null;
    setCheckingBatch(false);
    setIpText(value);
    setBatch({ status: 'idle' });
    setBatchProgressState(null);
    setBatchInterrupt(null);
  }, []);

  const resetLookup = useCallback((): void => {
    activeLookup.current?.abort();
    activeLookup.current = null;
    setCheck({ status: 'idle' });
  }, []);

  useEffect(() => () => {
    activeBatch.current?.abort();
    activeLookup.current?.abort();
  }, []);

  // 四个首屏只读资源形状完全一致，用同一个 hook 收口，页面只留下各自的刷新入口。
  const [health, refreshHealth] = useResource((signal) => client.health(signal));
  const [pools, refreshPools, patchPools] = useResource((signal) => client.pools(signal), true);
  const [config, refreshConfig, acceptConfig] = useResource((signal) => client.config(signal), true);
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
  const configuredTarget = configuredTargets?.find(target => bindingKey(target) === selectedTargetKey);
  const targetPort = configuredTarget?.port ?? 443;
  const [targetStatus, refreshTargetStatus] = useResource<TargetStatusView>((signal) => {
    if (!selectedTargetKey) return Promise.reject(new Error('尚未选择维护域名'));
    if (config.status !== 'ready') return Promise.reject(new Error(config.status === 'error' ? config.message : '正在读取维护配置，请稍后刷新'));
    if (!configuredTarget) return Promise.reject(new Error('当前目标已变更，请刷新域名绑定'));
    return loadTargetStatus(client, selectedTargetKey, targetPort, signal, webCheckConcurrency);
  });

  // 当前池被删掉时回落到默认池，避免下拉框停在一个已经不存在的 key 上。
  useEffect(() => {
    if (pools.status !== 'ready') return;
    setPoolKey((current) => (pools.data.pools.some((pool) => pool.key === current) ? current : DEFAULT_POOL_KEY));
  }, [pools]);

  /** 绑定就绪后默认选中第一个维护目标，并在目标被删后回退到首个仍存在的 key。 */
  useEffect(() => {
    if (!confirmedBindings) return;
    setSelectedTargetKey((current) => {
      if (current && targetKeys.includes(current)) return current;
      return targetKeys[0] ?? null;
    });
  }, [confirmedBindings, targetKeys]);

  /** 配置就绪后读取当前记录；目标或端口变化时中止旧请求并重新检测。 */
  useEffect(() => {
    if (!selectedTargetKey || config.status === 'loading' || config.status === 'idle') return;
    resetLookup();
    const controller = new AbortController();
    void refreshTargetStatus(controller.signal);
    return () => controller.abort();
  }, [config.status, refreshTargetStatus, resetLookup, selectedTargetKey, targetPort, webCheckConcurrency]);

  /**
   * 首屏把配置、维护域名、IP 池和健康度并行拉完，同时预取配置中心分块，
   * 所以点过去时数据和代码都已就绪，不会再等一轮网络往返。
   */
  useEffect(() => {
    const controller = new AbortController();
    void refreshHealth(controller.signal);
    void refreshPools(controller.signal);
    void refreshBindings(controller.signal);
    void refreshConfig(controller.signal);
    let cancelled = false;
    void import('./components/config-page')
      .then((module) => {
        if (!cancelled) setConfigPage(() => module.ConfigPage);
      })
      .catch(() => {
        if (!cancelled) notify('配置中心加载失败，请刷新页面重试', 'error');
      });
    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [notify, refreshBindings, refreshConfig, refreshHealth, refreshPools]);

  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(null), 3200);
    return () => window.clearTimeout(timer);
  }, [toast]);

  useEffect(() => {
    if (startupLogged.current || health.status !== 'ready' || config.status !== 'ready') return;
    startupLogged.current = true;
    appendConsoleLog('系统就绪', 'success');
    appendConsoleLog(`配置：并发 ${webCheckConcurrency} | 超时 ${config.data.config.settings.CHECK_TIMEOUT}ms`);
  }, [appendConsoleLog, config, health, webCheckConcurrency]);

  /** 池级写操作的统一收口：忙碌标记 + 提示 + 刷新列表只实现一次。 */
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
    appendConsoleLog('[系统] 正在刷新当前域名解析');
    void refreshTargetStatus();
  };

  const handleSelectTarget = (key: string | null): void => {
    resetLookup();
    setSelectedTargetKey(key);
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
    appendConsoleLog(`[记录] 正在添加 ${input}`);
    return client.addRecord(selectedTargetKey, input)
      .then(async () => {
        if (currentTargetKey.current === selectedTargetKey) resetLookup();
        appendConsoleLog(`[记录] 已添加 ${input}`, 'success');
        notify('已添加 DNS 记录');
        await refreshTargetStatus();
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
        await refreshTargetStatus();
      })
      .catch((error: unknown) => {
        const message = errorMessage(error);
        appendConsoleLog(`[记录] ${message}`, 'error');
        notify(message, 'error');
      });
  };

  const handleLoadPool = (): void => {
    setLoadingPool(true);
    appendConsoleLog(`[IP池] 正在读取 ${poolKey}`);
    client.readPool(poolKey)
      .then(({ content }) => {
        replaceIpText(content.replace(/\n$/, ''));
        appendConsoleLog(`[IP池] 已读取 ${countPoolTextLines(content)} 条地址`, 'success');
        notify(content.trim() ? '已从库中加载' : '该池当前为空', content.trim() ? 'success' : 'error');
      })
      .catch((error: unknown) => {
        const message = errorMessage(error);
        appendConsoleLog(`[IP池] ${message}`, 'error');
        notify(message, 'error');
      })
      .finally(() => setLoadingPool(false));
  };

  const handleCheckBatch = (): void => {
    if (config.status !== 'ready') {
      notify(config.status === 'error' ? config.message : '正在读取配置，请稍后检测', 'error');
      return;
    }
    const text = ipText.trim();
    if (!text) {
      notify('请先输入或从库加载 IP', 'error');
      return;
    }
    activeBatch.current?.abort();
    const controller = new AbortController();
    activeBatch.current = controller;
    aliveSoFar.current = 0;
    setCheckingBatch(true);
    setBatch({ status: 'loading' });
    const total = countPoolTextLines(text);
    setBatchProgressState({ completed: 0, total });
    appendConsoleLog(`[批量] 开始检测清洗 · ${total} 个地址`);
    appendConsoleLog(`[批量] 浏览器并发 ${webCheckConcurrency}，每个地址独立请求`);
    client.checkBatch(text, controller.signal, (event: PoolCheckProgressEvent) => {
      if (activeBatch.current !== controller) return;
      setBatchProgressState({ completed: event.completed, total: event.total });
      if (event.item.status === 'alive') aliveSoFar.current += 1;
      const statusLabel = event.item.status === 'alive' ? '可用' : event.item.status === 'dead' ? '失效' : '未知';
      const tone: ConsoleTone = event.item.status === 'alive' ? 'success' : event.item.status === 'dead' ? 'error' : 'warning';
      const detail = event.item.status === 'unknown' && event.item.message ? ` · ${event.item.message}` : '';
      appendConsoleLog(`[批量 ${event.completed}/${event.total}] ${event.item.address} · ${statusLabel}${detail}`, tone);
    }, webCheckConcurrency)
      .then((report) => {
        if (activeBatch.current !== controller) return;
        activeBatch.current = null;
        setCheckingBatch(false);
        setBatchProgressState({ completed: report.items.length, total: report.items.length });
        setBatch({ status: 'ready', data: report });
        // 与 main 的“检测清洗”一致：可用项写成标准格式，未知/无效保留原文，失效项移除。
        setIpText(cleanedBatchText(report));
        appendConsoleLog(
          `[批量] 完成 · 可用 ${report.alive} / 失效 ${report.dead} / 未知 ${report.unknown}${report.invalid.length ? ` / 无效 ${report.invalid.length}` : ''}`,
          report.unknown ? 'warning' : report.alive ? 'success' : 'error',
        );
        notify(
          `检测完成：可用 ${report.alive}，失效 ${report.dead}，未知 ${report.unknown}${report.invalid.length ? `，无效 ${report.invalid.length}` : ''}`,
          report.alive > 0 ? 'success' : 'error',
        );
      })
      .catch((error: unknown) => {
        if (isAbort(error) || activeBatch.current !== controller) return;
        activeBatch.current = null;
        setCheckingBatch(false);
        const message = errorMessage(error);
        setBatch({ status: 'error', message });
        appendConsoleLog(`[批量] ${message}`, 'error');
        notify(message, 'error');
      });
  };

  const handleStopBatch = (): void => {
    const controller = activeBatch.current;
    if (!controller) return;
    orderGeneration.current++;
    setOrderRequest(null);
    controller.abort();
    activeBatch.current = null;
    setCheckingBatch(false);
    const total = batchProgressState?.total ?? 0;
    const completed = batchProgressState?.completed ?? 0;
    setBatchInterrupt({
      checked: completed,
      total,
      valid: aliveSoFar.current,
      unchecked: Math.max(0, total - completed),
    });
  };

  const handleResumeBatch = (): void => {
    setBatchInterrupt(null);
    void handleCheckBatch();
  };

  const handleAbandonBatch = (): void => {
    setBatchInterrupt(null);
    setBatch({ status: 'idle' });
    setBatchProgressState(null);
    aliveSoFar.current = 0;
    appendConsoleLog('[批量] 已放弃，输入框保持原样', 'warning');
  };

  const handleSavePool = (): void => {
    if (!ipText.trim()) {
      notify('输入框为空，未写入池', 'error');
      return;
    }
    const normalized = cleanPoolText(ipText);
    if (!normalized) {
      notify('输入框里没有可识别的 IP 或域名', 'error');
      return;
    }
    setSavingPool(true);
    appendConsoleLog(`[IP池] 正在保存 ${poolKey}`);
    client.savePool(poolKey, normalized)
      .then(async () => {
        const { content } = await client.readPool(poolKey);
        replaceIpText(content);
        await refreshPools();
        appendConsoleLog(`[IP池] 已保存 ${countPoolTextLines(normalized)} 条地址`, 'success');
        notify('已保存并规范化到 IP 池');
      })
      .catch((error: unknown) => {
        const message = errorMessage(error);
        appendConsoleLog(`[IP池] ${message}`, 'error');
        notify(message, 'error');
      })
      .finally(() => setSavingPool(false));
  };

  const handleRemoveLines = (): void => {
    void runPoolAction('remove-lines', async () => {
      const result = await client.savePool(poolKey, ipText, 'remove');
      return result.removed ? `已从 ${poolKey} 移除 ${result.removed} 条` : '这些地址不在当前池中';
    });
  };

  const handleLoadRemote = (): void => {
    const url = remoteUrl.trim();
    if (!url) {
      notify('请输入远程 TXT URL', 'error');
      return;
    }
    void runPoolAction('remote-load', async () => {
      const result = await client.remoteLoad(url);
      replaceIpText(result.content.replace(/\n$/, ''));
      return `已加载 ${result.count} 条`;
    });
  };

  const handleApplyFilter = (mode: PoolFilterMode): void => {
    const filter = parsePoolFilter(filterText);
    if (!filter) {
      notify('筛选条件无效：端口需为 1-65535 的数字或范围', 'error');
      return;
    }
    const next = filterPoolText(ipText, filter, mode);
    replaceIpText(next);
    notify(mode === 'keep' ? `已保留 ${countPoolTextLines(next)} 条` : `已排除，剩余 ${countPoolTextLines(next)} 条`);
  };

  const handleDedupe = (): void => {
    const next = dedupePoolText(ipText);
    if (next === ipText.trim()) {
      notify('没有发现重复条目', 'error');
      return;
    }
    replaceIpText(next);
    notify(`去重后保留 ${countPoolTextLines(next)} 条`);
  };

  const handleCreatePool = (): void => {
    const name = window.prompt('新建 IP 池名称', '新池')?.trim();
    if (!name) return;
    void runPoolAction('pool-edit', async () => {
      const created = await client.createPool(name);
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
      if (currentPage.current !== 'dashboard' || generation !== orderGeneration.current) return;
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
    if (!NUMBERED_POOL_KEY_RE.test(poolKey)) {
      notify('只能删除编号 IP 池', 'error');
      return;
    }
    if (!window.confirm(`确认删除 ${poolKey}？池内 IP 将一并删除，已绑定的域名会回退到默认池。`)) return;
    void runPoolAction('pool-edit', async () => {
      await client.removePool(poolKey);
      setPoolKey(DEFAULT_POOL_KEY);
      return `已删除 ${poolKey}`;
    });
  };

  /**
   * 一键洗库：检测与淘汰都在服务端完成，垃圾桶只经过统一入口，
   * 面板不再自己拼「读池 → 检测 → 写回 → 入桶」这几步。
   */
  const handleCleanPool = (): void => {
    void runPoolAction('clean-pool', async () => {
      const report = await client.cleanPool(poolKey);
      // 服务端已经重写过池内容，回读一次让输入框和库保持一致。
      const { content } = await client.readPool(poolKey);
      replaceIpText(content);
      if (report.skipped) return `${report.unknown} 条未确认，本次未写回也未入桶`;
      const trashed = report.trashed > 0 ? `，移入垃圾桶 ${report.trashed} 条` : '';
      return `洗库完成：保留 ${report.kept} 条${trashed}`;
    });
  };

  const handleRestoreTrash = (): void => {
    const addresses = ipText.split('\n').map((line) => extractPoolAddressKey(line)).filter(Boolean);
    if (!addresses.length) {
      notify('请先在输入框填入要恢复的地址', 'error');
      return;
    }
    void runPoolAction('trash', async () => {
      const result = await client.restoreTrash(addresses, { restoreToSource: true });
      return result.restored ? `已恢复 ${result.restored} 条到原池` : '输入框中的地址不在垃圾桶中';
    });
  };

  const handleClearTrash = (): void => {
    if (!window.confirm('确认清空垃圾桶？该操作不可撤销。')) return;
    void runPoolAction('trash', async () => {
      await client.clearTrash();
      return '垃圾桶已清空';
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

  const handleConfigSaved = (response: ConfigResponse, targetKeys: Readonly<Record<string, string>>): void => {
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
    setMaintenance({ status: 'loading' });
    appendConsoleLog('[维护] 开始执行全部目标');
    client.runMaintenance()
      .then(async (data) => {
        setMaintenance({ status: 'ready', data });
        appendConsoleLog(
          `[维护] 完成 · 更新 ${data.results.filter((item) => item.dnsUpdated).length} 个目标 / 探针异常 ${data.probeErrors} 次 / 错误 ${data.errors.length} 项`,
          data.errors.length || data.probeErrors ? 'warning' : 'success',
        );
        await refreshBindings();
        await refreshPools();
        notify(
          data.changed ? '维护完成：DNS 已更新' : '维护完成：无需变更',
          data.errors.length || data.probeErrors ? 'error' : 'success',
        );
      })
      .catch((error: unknown) => {
        const message = errorMessage(error);
        setMaintenance({ status: 'error', message });
        appendConsoleLog(`[维护] ${message}`, 'error');
        notify(message, 'error');
      })
      .finally(() => setMaintenanceBusy(false));
  };

  const actions: DashboardActions = {
    lookupSubmit: handleLookupSubmit,
    refresh: handleRefresh,
    loadPool: handleLoadPool,
    checkBatch: handleCheckBatch,
    stopBatch: handleStopBatch,
    resumeBatch: handleResumeBatch,
    abandonBatch: handleAbandonBatch,
    savePool: handleSavePool,
    loadRemote: handleLoadRemote,
    applyFilter: handleApplyFilter,
    dedupe: handleDedupe,
    removeLines: handleRemoveLines,
    createPool: handleCreatePool,
    renamePool: handleRenamePool,
    openPoolOrder: () => void openOrderDialog('pools'),
    deletePool: handleDeletePool,
    cleanPool: handleCleanPool,
    restoreTrash: handleRestoreTrash,
    clearTrash: handleClearTrash,
    bindPool: handleBindPool,
    openBindingOrder: () => void openOrderDialog('bindings'),
    refreshPools: () => void refreshPools(),
    refreshBindings: () => void refreshBindings(),
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
        bindings={bindings}
        selectedTargetKey={selectedTargetKey}
        targetPort={targetPort}
        targetChoices={targetChoices}
        usageOpen={usageOpen}
        onToggleUsage={() => setUsageOpen((current) => !current)}
        onSelectTarget={handleSelectTarget}
        onOpenConfig={() => setPage('config')}
      />

      <div class="container">
        <TopNav page={page} onPageChange={setPage} />
        <div hidden={page !== 'dashboard'}>
          <DashboardPage
            check={check}
            pools={pools}
            batch={batch}
            lookup={lookup}
            ipText={ipText}
            probeConfigured={config.status !== 'ready' || Boolean(config.data.config.checkApi || config.data.config.checkApiBackup)}
            configReady={config.status === 'ready'}
            filterText={filterText}
            remoteUrl={remoteUrl}
            poolKey={poolKey}
            loadingPool={loadingPool}
            checkingBatch={checkingBatch}
            savingPool={savingPool}
            poolBusy={poolBusy}
            consoleLogs={consoleLogs}
            batchProgressState={batchProgressState}
            bindings={bindings}
            bindingBusy={bindingBusy}
            targetKeys={config.status === 'ready' ? targetKeys : []}
            targetStatus={targetStatus}
            selectedTargetKey={selectedTargetKey}
            targetPort={targetPort}
            maintenance={maintenance}
            maintenanceBusy={maintenanceBusy}
            actions={actions}
            onCopyToInput={handleCopyToInput}
            onCopyAddress={handleCopyAddress}
            onLookupChange={setLookup}
            onIpTextChange={replaceIpText}
            onFilterChange={setFilterText}
            onRemoteUrlChange={setRemoteUrl}
            onPoolChange={setPoolKey}
          />
        </div>
        <div hidden={page !== 'config'}>
          {ConfigPage ? (
            <ConfigPage client={client} notify={notify} config={config} onReload={refreshConfig} onSaved={handleConfigSaved} />
          ) : (
            <p class="text-secondary text-center py-4">正在加载配置中心…</p>
          )}
        </div>
      </div>

      <footer class="container text-center text-secondary small py-3">
        DDNS Pro · {health.status === 'ready' ? health.data.version : 'unknown'}
      </footer>
      {orderRequest && OrderDialog && !batchInterrupt && <OrderDialog {...orderRequest}
        onSave={order => orderModule.current!.saveOrder(orderRequest.kind, order,
          { client, patchPools, patchBindings, refreshPools, refreshBindings, notify })}
        onClose={() => setOrderRequest(null)} />}
      {batchInterrupt && (
        <Modal id="batch-interrupt-title" title="检测已中断">
          <div class="custom-modal-stats">
            <div><span class="label">已检测</span><span class="value">{batchInterrupt.checked} / {batchInterrupt.total}</span></div>
            <div><span class="label">有效 IP</span><span class="value">{batchInterrupt.valid} 个</span></div>
            <div><span class="label">未检测</span><span class="value">{batchInterrupt.unchecked} 个</span></div>
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

/** 批量清洗后的输入：保留可用（标准格式）与未知（原文），丢弃失效项，并追加无法识别的原文。 */
function cleanedBatchText(report: PoolCheckResponse): string {
  const kept = report.items
    .filter((item) => item.status === 'alive' || item.status === 'unknown')
    .map((item) => item.line);
  return [...kept, ...report.invalid].join('\n');
}
