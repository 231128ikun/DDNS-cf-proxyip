import { useCallback, useEffect, useMemo, useState } from 'preact/hooks';
import type { DomainBindingsResponse, MaintenanceRunResponse } from '../../src/contracts/maintenance';
import {
  DEFAULT_POOL_KEY,
  NUMBERED_POOL_KEY_RE,
  isUserPoolKey,
  type PoolsResponse,
} from '../../src/contracts/pool';
import type { PoolCheckResponse } from '../../src/contracts/pool-check';
import type { HealthResponse, ProbeResponse } from '../../src/contracts/probe';
import { extractPoolAddressKey } from '../../src/domain/pool-entry';
import { dedupePoolText, filterPoolText, parsePoolFilter, type PoolFilterMode } from '../../src/domain/pool-filter';
import { cleanPoolText, countPoolTextLines } from '../../src/domain/pool-text';
import { ApiClient } from './api/client';
import { errorMessage, isAbort } from './api/errors';
import { DashboardPage, type DashboardActions, type PoolActionKey } from './components/dashboard-page';
import { Hero } from './components/hero';
import { TopNav, type AppPage } from './components/top-nav';
import type { RequestState } from './state/request-state';

type ConfigPageComponent = typeof import('./components/config-page').ConfigPage;

const TOKEN_KEY = 'ddns-proxyip-token';

interface Toast {
  readonly message: string;
  readonly type: 'success' | 'error';
}

export function App() {
  const [page, setPage] = useState<AppPage>('dashboard');
  const [ConfigPage, setConfigPage] = useState<ConfigPageComponent | null>(null);
  const [usageOpen, setUsageOpen] = useState(false);
  const [health, setHealth] = useState<RequestState<HealthResponse>>({ status: 'loading' });
  const [lookup, setLookup] = useState('');
  const [check, setCheck] = useState<RequestState<ProbeResponse>>({ status: 'idle' });
  const [ipText, setIpText] = useState('');
  const [filterText, setFilterText] = useState('');
  const [remoteUrl, setRemoteUrl] = useState('');
  const [pools, setPools] = useState<RequestState<PoolsResponse>>({ status: 'loading' });
  const [bindings, setBindings] = useState<RequestState<DomainBindingsResponse>>({ status: 'loading' });
  const [maintenance, setMaintenance] = useState<RequestState<MaintenanceRunResponse>>({ status: 'idle' });
  const [maintenanceBusy, setMaintenanceBusy] = useState(false);
  const [poolKey, setPoolKey] = useState(DEFAULT_POOL_KEY);
  const [batch, setBatch] = useState<RequestState<PoolCheckResponse>>({ status: 'idle' });
  const [loadingPool, setLoadingPool] = useState(false);
  const [checkingBatch, setCheckingBatch] = useState(false);
  const [savingPool, setSavingPool] = useState(false);
  const [poolBusy, setPoolBusy] = useState<PoolActionKey | null>(null);
  const [toast, setToast] = useState<Toast | null>(null);
  const authKey = useMemo(readStoredToken, []);
  const client = useMemo(() => new ApiClient({ authKey }), [authKey]);

  const notify = useCallback((message: string, type: Toast['type'] = 'success'): void => {
    setToast({ message, type });
  }, []);

  const refreshHealth = useCallback(async (signal?: AbortSignal): Promise<void> => {
    setHealth({ status: 'loading' });
    try {
      const data = await client.health(signal);
      setHealth({ status: 'ready', data });
    } catch (error) {
      if (isAbort(error)) return;
      setHealth({ status: 'error', message: errorMessage(error) });
    }
  }, [client]);

  const refreshPools = useCallback(async (signal?: AbortSignal): Promise<void> => {
    setPools({ status: 'loading' });
    try {
      const data = await client.pools(signal);
      setPools({ status: 'ready', data });
      setPoolKey((current) => (data.pools.some((pool) => pool.key === current) ? current : DEFAULT_POOL_KEY));
    } catch (error) {
      if (isAbort(error)) return;
      setPools({ status: 'error', message: errorMessage(error) });
    }
  }, [client]);

  const refreshBindings = useCallback(async (signal?: AbortSignal): Promise<void> => {
    setBindings({ status: 'loading' });
    try {
      const data = await client.domainBindings(signal);
      setBindings({ status: 'ready', data });
    } catch (error) {
      if (isAbort(error)) return;
      setBindings({ status: 'error', message: errorMessage(error) });
    }
  }, [client]);

  useEffect(() => {
    const controller = new AbortController();
    void refreshHealth(controller.signal);
    return () => controller.abort();
  }, [refreshHealth]);

  useEffect(() => {
    const controller = new AbortController();
    void refreshPools(controller.signal);
    return () => controller.abort();
  }, [refreshPools]);

  useEffect(() => {
    const controller = new AbortController();
    void refreshBindings(controller.signal);
    return () => controller.abort();
  }, [refreshBindings]);

  /** 配置页按需加载，避免首页携带整页表单；静态资源仍由同一 Worker 托管。 */
  useEffect(() => {
    if (page !== 'config' || ConfigPage) return;
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
    };
  }, [page, ConfigPage, notify]);



  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(null), 3200);
    return () => window.clearTimeout(timer);
  }, [toast]);

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
    client.check(value)
      .then((data) => setCheck({ status: 'ready', data }))
      .catch((error: unknown) => setCheck({ status: 'error', message: errorMessage(error) }));
  };

  const handleRefresh = (): void => {
    void refreshHealth();
    void refreshPools();
    void refreshBindings();
  };

  const handleLoadPool = (): void => {
    setLoadingPool(true);
    client.readPool(poolKey)
      .then(({ content }) => {
        setIpText(content.replace(/\n$/, ''));
        notify(content.trim() ? '已从库中加载' : '该池当前为空', content.trim() ? 'success' : 'error');
      })
      .catch((error: unknown) => notify(errorMessage(error), 'error'))
      .finally(() => setLoadingPool(false));
  };

  const handleCheckBatch = (): void => {
    const text = ipText.trim();
    if (!text) {
      notify('请先输入或从库加载 IP', 'error');
      return;
    }
    setCheckingBatch(true);
    setBatch({ status: 'loading' });
    client.checkBatch(text)
      .then((report) => {
        setBatch({ status: 'ready', data: report });
        const aliveLines = report.items.filter((item) => item.status === 'alive').map((item) => item.line);
        // 检测的语义是“筛出可用项”，因此有可用结果时用合并了元数据的行替换输入框。
        if (aliveLines.length) setIpText(aliveLines.join('\n'));
        notify(
          `检测完成：可用 ${report.alive}，失效 ${report.dead}，未知 ${report.unknown}${report.invalid.length ? `，无效 ${report.invalid.length}` : ''}`,
          report.alive > 0 ? 'success' : 'error',
        );
      })
      .catch((error: unknown) => {
        setBatch({ status: 'error', message: errorMessage(error) });
        notify(errorMessage(error), 'error');
      })
      .finally(() => setCheckingBatch(false));
  };

  const handleSavePool = (): void => {
    if (!ipText.trim()) {
      notify('输入框为空，未写入池', 'error');
      return;
    }
    setSavingPool(true);
    client.savePool(poolKey, ipText)
      .then(async () => {
        await refreshPools();
        notify('已保存到 IP 池');
      })
      .catch((error: unknown) => notify(errorMessage(error), 'error'))
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
      setIpText(result.content.replace(/\n$/, ''));
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
    setIpText(next);
    notify(mode === 'keep' ? `已保留 ${countPoolTextLines(next)} 条` : `已排除，剩余 ${countPoolTextLines(next)} 条`);
  };

  const handleDedupe = (): void => {
    const next = dedupePoolText(ipText);
    if (next === ipText.trim()) {
      notify('没有发现重复条目', 'error');
      return;
    }
    setIpText(next);
    notify(`去重后保留 ${countPoolTextLines(next)} 条`);
  };

  const handleCreatePool = (): void => {
    const name = window.prompt('新建 IP 池名称', '新池')?.trim();
    if (!name) return;
    void runPoolAction('pool-edit', async () => {
      const created = await client.createPool(name);
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

  const handleMovePool = (delta: number): void => {
    if (pools.status !== 'ready') {
      notify('IP 池列表尚未就绪', 'error');
      return;
    }
    const order = pools.data.pools.map((pool) => pool.key);
    const index = order.indexOf(poolKey);
    const target = index + delta;
    if (index < 0 || target < 0 || target >= order.length) {
      notify(delta < 0 ? '已经在最前，无法上移' : '已经在最后，无法下移', 'error');
      return;
    }
    [order[index], order[target]] = [order[target]!, order[index]!];
    void runPoolAction('pool-edit', async () => {
      await client.savePoolOrder(order);
      return '已调整池顺序';
    });
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

  const handleCleanPool = (): void => {
    void runPoolAction('clean-pool', async () => {
      const { content } = await client.readPool(poolKey);
      const cleaned = cleanPoolText(content);
      const before = countPoolTextLines(content);
      if (cleaned === content.trim()) return `${before} 条内容已规范，无需洗库`;
      const result = await client.savePool(poolKey, cleaned, 'replace');
      return `洗库完成：${before} 条 → ${result.count} 条`;
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

  /** 绑定切换先乐观更新下拉，失败时回读服务端真值回滚，避免界面停留在错误状态。 */
  const handleBindPool = async (key: string, nextPoolKey: string): Promise<void> => {
    if (bindings.status !== 'ready') return;
    const items = bindings.data.items.map((item) => (item.key === key ? { ...item, poolKey: nextPoolKey } : item));
    setBindings({ status: 'ready', data: { items } });
    const mapping: Record<string, string> = {};
    for (const item of items) mapping[item.key] = item.poolKey;
    try {
      await client.saveDomainBindings(mapping);
      notify('已更新域名池绑定');
    } catch (error) {
      notify(errorMessage(error), 'error');
      await refreshBindings();
    }
  };

  /** 排序只在面板显示层生效：先把本地列表换位，失败再回读服务端顺序。 */
  const handleMoveBinding = async (index: number, delta: number): Promise<void> => {
    if (bindings.status !== 'ready') return;
    const next = index + delta;
    if (next < 0 || next >= bindings.data.items.length) return;

    const items = [...bindings.data.items];
    const [moved] = items.splice(index, 1);
    if (!moved) return;
    items.splice(next, 0, moved);
    setBindings({ status: 'ready', data: { items } });

    try {
      await client.saveDomainBindingOrder(items.map((item) => item.key));
    } catch (error) {
      notify(errorMessage(error), 'error');
      await refreshBindings();
    }
  };
  const handleRunMaintenance = (): void => {
    if (maintenanceBusy) return;
    setMaintenanceBusy(true);
    setMaintenance({ status: 'loading' });
    client.runMaintenance()
      .then(async (data) => {
        setMaintenance({ status: 'ready', data });
        await refreshBindings();
        await refreshPools();
        notify(
          data.changed ? '维护完成：DNS 已更新' : '维护完成：无需变更',
          data.errors.length || data.probeErrors ? 'error' : 'success',
        );
      })
      .catch((error: unknown) => {
        setMaintenance({ status: 'error', message: errorMessage(error) });
        notify(errorMessage(error), 'error');
      })
      .finally(() => setMaintenanceBusy(false));
  };

  const actions: DashboardActions = {
    lookupSubmit: handleLookupSubmit,
    refresh: handleRefresh,
    loadPool: handleLoadPool,
    checkBatch: handleCheckBatch,
    savePool: handleSavePool,
    loadRemote: handleLoadRemote,
    applyFilter: handleApplyFilter,
    dedupe: handleDedupe,
    removeLines: handleRemoveLines,
    createPool: handleCreatePool,
    renamePool: handleRenamePool,
    movePool: handleMovePool,
    deletePool: handleDeletePool,
    cleanPool: handleCleanPool,
    restoreTrash: handleRestoreTrash,
    clearTrash: handleClearTrash,
    bindPool: handleBindPool,
    moveBinding: (index, delta) => void handleMoveBinding(index, delta),
    refreshBindings: () => void refreshBindings(),
    runMaintenance: handleRunMaintenance,
  };

  return (
    <>
      <Hero
        health={health}
        usageOpen={usageOpen}
        onToggleUsage={() => setUsageOpen((current) => !current)}
        onOpenConfig={() => setPage('config')}
      />

      <div class="container">
        <TopNav page={page} onPageChange={setPage} />
        {page === 'dashboard' ? (
          <DashboardPage
            health={health}
            check={check}
            pools={pools}
            batch={batch}
            lookup={lookup}
            ipText={ipText}
            filterText={filterText}
            remoteUrl={remoteUrl}
            poolKey={poolKey}
            loadingPool={loadingPool}
            checkingBatch={checkingBatch}
            savingPool={savingPool}
            poolBusy={poolBusy}
            bindings={bindings}
            maintenance={maintenance}
            maintenanceBusy={maintenanceBusy}
            actions={actions}
            onLookupChange={setLookup}
            onIpTextChange={setIpText}
            onFilterChange={setFilterText}
            onRemoteUrlChange={setRemoteUrl}
            onPoolChange={setPoolKey}
          />
        ) : ConfigPage ? (
          <ConfigPage client={client} notify={notify} />
        ) : (
          <p class="text-secondary text-center py-4">正在加载配置中心…</p>
        )}
      </div>

      <footer class="container text-center text-secondary small py-3">
        DDNS Pro · {health.status === 'ready' ? health.data.version : 'unknown'}
      </footer>
      <div class={`toast${toast ? ` ${toast.type} show` : ''}`} role="status" aria-live="polite">
        {toast?.message}
      </div>
    </>
  );
}

function readStoredToken(): string {
  try {
    const queryKey = new URLSearchParams(window.location.search).get('key')?.trim();
    if (queryKey) {
      sessionStorage.setItem(TOKEN_KEY, queryKey);
      return queryKey;
    }
    return sessionStorage.getItem(TOKEN_KEY) ?? '';
  } catch {
    return '';
  }
}
