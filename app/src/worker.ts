import { toMaintenanceTargetResult } from './application/maintenance-summary';
import { maintenanceDisplayLines, notificationDisplay } from './domain/maintenance-display';
import { CloudflareDnsRepository } from './adapters/dns/cloudflare-dns';
import { DohLookup } from './adapters/dns/doh-lookup';
import { TelegramNotifier } from './adapters/notify/telegram';
import { KvConfigRepository } from './adapters/storage/kv-config-repository';
import { KvDomainBindingRepository } from './adapters/storage/kv-domain-binding-repository';
import { KvMaintenanceSource } from './adapters/storage/kv-maintenance-source';
import { KvMaintenanceStatsRepository } from './adapters/storage/kv-maintenance-stats-repository';
import { KvPoolCatalog } from './adapters/storage/kv-pool-catalog';
import { KvPoolRepository } from './adapters/storage/kv-pool-repository';
import { CleanPool } from './application/clean-pool';
import { CheckProxy } from './application/check-proxy';
import { CheckTarget } from './application/check-target';
import { ConfigService, type ResolvedConfig } from './application/config-service';
import { DomainBindings } from './application/domain-bindings';
import { MaintainManagedTarget, type MaintainManagedTargetCommand, type MaintenanceReport } from './application/maintain-managed-target';
import { MaintainManagedTargets, type TargetMaintainer } from './application/maintain-managed-targets';
import { PoolService } from './application/pool-service';
import { RemotePoolLoader } from './application/remote-pool-loader';
import { HttpRemotePoolSource } from './adapters/http/remote-pool-source';
import { ResolveTarget } from './application/resolve-target';
import { TargetStatus } from './application/target-status';
import { TargetRecords } from './application/target-records';
import { createProbeAdapterFromConfig, createSubrequestBudget, loadEnvConfig, type RuntimeEnv } from './config/runtime';
import { toProbeConfig, type AppConfig } from './contracts/config';
import { unknown, type ProbeResult } from './domain/probe-result';
import { isProbeResponse } from './contracts/probe';
import { isRecord } from './contracts/parse';
import type { ProbeAdapter } from './ports/probe';
import { appFetch } from './util/fetch';
import { createRequestTimeout } from './util/request-timeout';
import { runMaintenanceJob } from './jobs/maintenance-job';
import type { MaintenanceSource } from './ports/maintenance-source';
import { createHttpApp, streamMaintenanceTask, type HttpAppDependencies, type MaintenanceRunner } from './transport/http';
import { MAINTENANCE_STREAM_TYPE, readMaintenanceStreamResult } from './contracts/maintenance';

export const APP_VERSION = '2026.11.09-20.09';

/** 维护里每次 Cloudflare API 调用的超时；cron 场景不能让单个请求拖垮整轮。 */
const DNS_TIMEOUT_MS = 10_000;
// 每个地址有两个原生出口，留出信任库及存储的连接位置。
const MAX_PARALLEL_PROBE_REQUESTS = 2;

export interface InvocationProps {
  readonly resolved?: ResolvedConfig;
  readonly directProbe?: boolean;
  readonly outbound?: boolean;
  readonly command?: Omit<MaintainManagedTargetCommand, 'signal'>;
  readonly known?: Readonly<Record<string, ProbeResult>>;
}

export interface InvocationRequestInit {
  readonly method: string;
  readonly headers: [string, string][];
  readonly body: string | null;
  readonly redirect: RequestRedirect;
}

export interface InvocationReply {
  readonly status: number;
  readonly headers: [string, string][];
  readonly body: ReadableStream<Uint8Array> | null;
}

interface SelfBinding {
  dispatch(url: string, init: InvocationRequestInit, props: InvocationProps, cancelled: ReadableStream<Uint8Array>): Promise<InvocationReply & Partial<Disposable>>;
}

export function createWorker(createProbe: typeof createProbeAdapterFromConfig = createProbeAdapterFromConfig): ExportedHandler<RuntimeEnv> {
  const handler: ExportedHandler<RuntimeEnv> = {
    async fetch(request, env, executionContext): Promise<Response> {
      const props = (executionContext.props ?? {}) as InvocationProps;
      if (props.outbound) return appFetch(request);
      const url = new URL(request.url);
      const configService = createConfigService(env, url.origin);
      const resolved = props.resolved ?? await configService.resolve();
      if (props.command) {
        const kv = env.IP_DATA;
        if (!kv) throw new Error('maintenance unavailable');
        const command = props.command;
        return streamMaintenanceTask((progress, signal) => createLocalTarget(kv, resolved, executionContext, props.known)
          .execute({ ...command, signal }, progress), request.signal, task => executionContext.waitUntil(task));
      }

      const checkProxy = new CheckProxy(props.directProbe
        ? createProbe(toProbeConfig(resolved.config), { budget: createSubrequestBudget() })
        : createInvocationProbe(resolved, executionContext));
      const kv = env.IP_DATA;
      const maintenanceSource = kv ? new KvMaintenanceSource(kv, resolved.config) : null;
      const maintenance = kv && maintenanceSource
        ? createMaintenanceRunner(kv, resolved, executionContext, maintenanceSource)
        : null;

      const checkTarget = new CheckTarget({
        resolver: new ResolveTarget(new DohLookup({ endpoint: resolved.config.dohApi, timeoutMs: resolved.config.settings.DOH_TIMEOUT })),
        checkProxy,
        concurrency: Math.min(resolved.config.settings.CONCURRENT_CHECKS, MAX_PARALLEL_PROBE_REQUESTS),
      });

      const dependencies: HttpAppDependencies = {
        checkTarget,
        waitUntil: task => executionContext.waitUntil(task),
        version: APP_VERSION,
        ...(typeof request.cf?.colo === 'string' && /^[A-Z]{3}$/.test(request.cf.colo) ? { executionColo: request.cf.colo } : {}),
        authKey: resolved.config.authKey,
        configSource: resolved.source,
        // 鉴权与路由共享本次请求的配置快照，不重复读 KV；下一次请求重新解析。
        config: { resolve: async () => resolved, save: (config) => configService.save(config) },
        remotePoolLoader: new RemotePoolLoader(new HttpRemotePoolSource({ timeoutMs: resolved.config.settings.REMOTE_LOAD_TIMEOUT })),
        ...(kv
          ? {
              ...createPoolDependencies(kv, resolved.config, maintenanceSource!, maintenance),
              targetStatus: new TargetStatus({
                source: maintenanceSource!,
                dns: new CloudflareDnsRepository({ timeoutMs: DNS_TIMEOUT_MS }),
                fallbackZone: { zoneId: resolved.config.zoneId, apiToken: resolved.config.apiKey },
              }),
              targetRecords: new TargetRecords({
                source: maintenanceSource!,
                dns: new CloudflareDnsRepository({ timeoutMs: DNS_TIMEOUT_MS }),
                fallbackZone: { zoneId: resolved.config.zoneId, apiToken: resolved.config.apiKey },
              }),
            }
          : {}),
      };

      return createHttpApp(dependencies).fetch(request, env, executionContext);
    },

    async scheduled(_controller, env, executionContext): Promise<void> {
      if (!env.IP_DATA) {
        console.error('跳过定时维护：请先绑定名为 IP_DATA 的 KV Namespace');
        return;
      }

      const resolved = await createConfigService(env).resolve();
      if (!resolved.config.scheduledEnabled) {
        console.log('定时维护已关闭，跳过执行');
        return;
      }

      const source = new KvMaintenanceSource(env.IP_DATA, resolved.config);
      executionContext.waitUntil(createMaintenanceRunner(env.IP_DATA, resolved, executionContext, source).run(false));
    },
  };

  return handler;
}

/** RPC 使用原始内部绑定，不通过带 props 的普通请求通道。 */
function invocationBinding(context: ExecutionContext, props: InvocationProps): Pick<Fetcher, 'fetch'> {
  const binding = (context.exports as { default?: SelfBinding } | undefined)?.default;
  if (!binding) throw new TypeError('Worker 内部调用不可用');
  return { async fetch(input, init) {
    const request = new Request(input, init);
    let cancellation: ReadableStreamDefaultController<Uint8Array>;
    let stopped = false;
    const stop = () => { if (!stopped) { stopped = true; try { cancellation.close(); } catch {} } };
    const pipe = new ReadableStream<Uint8Array>({ start(controller) { cancellation = controller; } });
    request.signal.addEventListener('abort', stop, { once: true });
    let reply: (InvocationReply & Partial<Disposable>) | undefined;
    const finish = () => { stop(); request.signal.removeEventListener('abort', stop); reply?.[Symbol.dispose]?.(); };
    try {
      request.signal.throwIfAborted();
      const body = request.body ? await request.text() : null;
      request.signal.throwIfAborted();
      reply = await binding.dispatch(request.url, { method: request.method, headers: invocationHeaders(request.headers), body, redirect: request.redirect }, props, pipe);
      return new Response(invocationBody(reply.body, finish), { status: reply.status, headers: reply.headers });
    } catch (error) { finish(); throw error; }
  } };
}

function invocationHeaders(headers: Headers): [string, string][] {
  const entries: [string, string][] = [];
  headers.forEach((value, key) => entries.push([key, value]));
  return entries;
}

function invocationBody(source: ReadableStream<Uint8Array> | null, finish: (cancelled: boolean) => void): ReadableStream<Uint8Array> | null {
  if (!source) { finish(false); return null; }
  const reader = source.getReader();
  let finished = false;
  const end = async (cancelled: boolean) => {
    if (finished) return;
    finished = true;
    if (cancelled) await reader.cancel().catch(() => {});
    finish(cancelled);
  };
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        const { done, value } = await reader.read();
        if (done) { controller.close(); await end(false); }
        else controller.enqueue(value);
      } catch (error) { controller.error(error); await end(true); }
    },
    cancel() { return end(true); },
  });
}

/** 默认入口和本地宿主共用 RPC 的请求重建、流式响应及取消。 */
export async function dispatchWorkerInvocation(worker: ExportedHandler<RuntimeEnv>, env: RuntimeEnv, context: ExecutionContext,
  url: string, init: InvocationRequestInit, props: InvocationProps, cancelled: ReadableStream<Uint8Array>): Promise<InvocationReply> {
  const abort = new AbortController();
  const reader = cancelled.getReader();
  context.waitUntil(reader.read().then(() => abort.abort()).catch(() => abort.abort()));
  const finish = (cancelled: boolean) => { if (cancelled) abort.abort(); void reader.cancel().catch(() => {}); };
  try {
    const request = new Request(url, { ...init, signal: abort.signal });
    const response = await worker.fetch!(request as Parameters<NonNullable<typeof worker.fetch>>[0], env,
      { props, exports: context.exports, waitUntil: task => context.waitUntil(task),
        passThroughOnException: () => context.passThroughOnException() } as ExecutionContext);
    return { status: response.status, headers: invocationHeaders(response.headers), body: invocationBody(response.body, finish) };
  } catch (error) { finish(true); throw error; }
}

function createInvocationFetch(context: ExecutionContext): typeof fetch {
  return (input, init) => invocationBinding(context, { outbound: true }).fetch(input, init);
}

/** 每个地址复用 /api/check，原生连接不再累积到整轮维护调用。 */
function createInvocationProbe(resolved: ResolvedConfig, context: ExecutionContext): ProbeAdapter {
  return { name: 'native', async probe(target, probeContext = {}) {
    const timeout = createRequestTimeout(resolved.config.settings.CHECK_TIMEOUT * 2 + 1_000, probeContext.signal);
    let response: Response | undefined;
    try {
      probeContext.signal?.throwIfAborted();
      response = await invocationBinding(context, { resolved, directProbe: true }).fetch('https://worker.internal/api/check', {
        method: 'POST', headers: { 'Content-Type': 'application/json',
          ...(resolved.config.authKey ? { Authorization: 'Bearer ' + resolved.config.authKey } : {}) },
        body: JSON.stringify({ proxyip: target.authority }), signal: timeout.signal,
      });
      if (!response.ok) return unknown(target, 'CHECK_REQUEST_ERROR', '检测调用 HTTP ' + response.status);
      const data: unknown = await response.json();
      if (!isRecord(data) || data.ok !== true || !Array.isArray(data.items) || data.items.length !== 1
        || !isRecord(data.items[0]) || data.items[0].address !== target.authority || !isProbeResponse(data.items[0].result)) {
        return unknown(target, 'CHECK_REQUEST_ERROR', '检测调用未返回有效的目标结果');
      }
      probeContext.signal?.throwIfAborted();
      return { ...data.items[0].result, target };
    } catch {
      return unknown(target, probeContext.signal?.aborted ? 'CANCELLED' : 'CHECK_REQUEST_ERROR',
        probeContext.signal?.aborted ? '检测已取消' : timeout.didTimeout() ? '检测调用超时，候选状态未知' : '检测调用异常，候选状态未知');
    } finally {
      timeout.cleanup();
      await response?.body?.cancel().catch(() => {});
    }
  } };
}

/** 洗库与维护共用垃圾桶仓库，统一去重、截断和注释格式。 */
function createPoolDependencies(
  kv: KVNamespace,
  config: AppConfig,
  maintenanceSource: MaintenanceSource,
  maintenance: MaintenanceRunner | null,
): Pick<HttpAppDependencies, 'pools' | 'cleanPool' | 'domainBindings' | 'maintenance'> {
  const catalog = new KvPoolCatalog(kv);
  const pools = new PoolService(catalog);
  return {
    pools,
    cleanPool: new CleanPool({
      pools,
      trash: new KvPoolRepository(kv, { maxTrashSize: config.settings.MAX_TRASH_SIZE }),
    }),
    domainBindings: new DomainBindings(maintenanceSource, new KvDomainBindingRepository(kv)),
    ...(maintenance ? { maintenance } : {}),
  };
}

export function createConfigService(env: RuntimeEnv, projectUrl?: string): ConfigService {
  return new ConfigService({
    envConfig: loadEnvConfig(env),
    ...(projectUrl ? { projectUrl } : {}),
    ...(env.IP_DATA
      ? {
          repository: new KvConfigRepository(env.IP_DATA),
        }
      : {}),
  });
}

function createLocalTarget(kv: KVNamespace, resolved: ResolvedConfig, context: ExecutionContext,
  known: Readonly<Record<string, ProbeResult>> = {}): MaintainManagedTarget {
  const config = resolved.config;
  const probe = createInvocationProbe(resolved, context);
  return new MaintainManagedTarget({
    probe: { name: probe.name, async probe(target, options) {
      options?.signal?.throwIfAborted();
      return known[target.key] ?? await probe.probe(target, options);
    } },
    pools: new KvPoolRepository(kv, { maxTrashSize: config.settings.MAX_TRASH_SIZE }),
    dns: new CloudflareDnsRepository({ timeoutMs: DNS_TIMEOUT_MS, fetchImpl: createInvocationFetch(context) }),
    concurrency: Math.min(config.settings.CONCURRENT_CHECKS, MAX_PARALLEL_PROBE_REQUESTS),
  });
}

/** 目标调用与逐地址调用分层，父维护只调度目标并汇总，不累积候选调用数。 */
function createInvocationTarget(resolved: ResolvedConfig, context: ExecutionContext,
  confirmed: Map<string, ProbeResult>): TargetMaintainer {
  return { async execute(command, onProgress) {
    let response: Response | undefined;
    let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    try {
      command.signal?.throwIfAborted();
      const { signal, ...input } = command;
      response = await invocationBinding(context, { resolved, command: input, known: Object.fromEntries(confirmed) })
        .fetch('https://worker.internal/api/maintenance/run', { method: 'POST', ...(signal ? { signal } : {}), headers: { Accept: MAINTENANCE_STREAM_TYPE } });
      if (!response.ok || !response.headers.get('Content-Type')?.startsWith(MAINTENANCE_STREAM_TYPE)) throw new Error('目标维护调用未返回有效响应');
      reader = response.body?.getReader();
      if (!reader) throw new Error('目标维护调用未返回结果');
      const outcome = await readMaintenanceStreamResult<MaintenanceReport>(reader.read.bind(reader), onProgress ?? (() => undefined),
        (value): value is MaintenanceReport => isRecord(value) && value.poolKey === command.poolKey
          && isRecord(value.target) && value.target.domain === command.target.domain && value.target.mode === command.target.mode
          && isRecord(value.plan) && Array.isArray(value.plan.current) && typeof value.plan.activeCount === 'number'
          && typeof value.dnsUpdated === 'boolean' && Array.isArray(value.errors));
      if (!('result' in outcome)) throw new Error(outcome.message);
      command.signal?.throwIfAborted();
      const report = outcome.result;
      const results = [...report.plan.current.map(item => item.item.result), ...(report.candidateResults ?? []).map(item => item.result)];
      for (const result of results) if (result.target && result.status !== 'unknown' && result.code !== 'PARTIAL_EXIT') confirmed.set(result.target.key, result);
      return report;
    } finally {
      if (reader) await reader.cancel().catch(() => {});
      else await response?.body?.cancel().catch(() => {});
    }
  } };
}

/** 手动维护与 cron 共用的依赖装配，业务编排仍留在 `jobs/maintenance-job.ts`。 */
function createMaintenanceRunner(
  kv: KVNamespace,
  resolved: ResolvedConfig,
  executionContext: ExecutionContext,
  source?: MaintenanceSource,
): MaintenanceRunner {
  const config = resolved.config;
  const maintenanceSource = source ?? new KvMaintenanceSource(kv, config);
  const stats = new KvMaintenanceStatsRepository(kv, new KvPoolCatalog(kv));
  const fetchImpl = createInvocationFetch(executionContext);
  const confirmed = new Map<string, ProbeResult>();
  const maintainer = new MaintainManagedTargets({ maintainer: createInvocationTarget(resolved, executionContext, confirmed) });
  const notifier = new TelegramNotifier({
    enabled: config.tgEnabled,
    token: config.tgToken,
    chatId: config.tgId,
    fetchImpl,
  });

  return {
    run: async (isManual, onProgress, signal) => {
      const result = await runMaintenanceJob({
      source: maintenanceSource,
      maintainer,
      notifier,
      stats,
      fallbackZone: { zoneId: config.zoneId, apiToken: config.apiKey },
      isManual,
      projectUrl: config.projectUrl,
      ...(onProgress ? { onProgress } : {}),
      ...(signal ? { signal } : {}),
      });
      for (const target of result.run.results) console.info('[maintenance]', maintenanceDisplayLines(toMaintenanceTargetResult(target)).map(line => line.message).join('\n'));
      const notification = notificationDisplay(result.notification);
      if (notification) console.info('[notification]', notification);
      return result;
    },
  };
}
