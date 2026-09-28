import { CloudflareDnsRepository } from './adapters/dns/cloudflare-dns';
import { TelegramNotifier } from './adapters/notify/telegram';
import { KvConfigRepository } from './adapters/storage/kv-config-repository';
import { KvDomainBindingRepository } from './adapters/storage/kv-domain-binding-repository';
import { KvMaintenanceSource } from './adapters/storage/kv-maintenance-source';
import { KvPoolCatalog } from './adapters/storage/kv-pool-catalog';
import { KvPoolRepository } from './adapters/storage/kv-pool-repository';
import { CheckPoolText } from './application/check-pool';
import { CheckProxy } from './application/check-proxy';
import { ConfigService } from './application/config-service';
import { DomainBindings } from './application/domain-bindings';
import { MaintainManagedTarget } from './application/maintain-managed-target';
import { MaintainManagedTargets } from './application/maintain-managed-targets';
import { PoolService } from './application/pool-service';
import { RemotePoolLoader } from './application/remote-pool-loader';
import { ProbeSelfTest } from './application/probe-self-test';
import type { SocketConnect } from './adapters/probe/socket';
import { createProbeAdapterFromConfig, loadEnvConfig, type ProbeAdapterDeps, type RuntimeEnv } from './config/runtime';
import { toProbeConfig, type AppConfig, type ProbeConfig } from './contracts/config';
import type { MaintenanceSource } from './ports/maintenance-source';
import type { ProbeAdapter } from './ports/probe';
import { runMaintenanceJob } from './jobs/maintenance-job';
import { createHttpApp, type HttpAppDependencies, type MaintenanceRunner } from './transport/http';

export const APP_VERSION = '2026.09.26-10.21';

/** 批量检测并发：与维护流程一样显式限制，避免打满子请求与 CPU。 */
const BATCH_CHECK_CONCURRENCY = 8;
/** 维护里每次 Cloudflare API 调用的超时；cron 场景不能让单个请求拖垮整轮。 */
const DNS_TIMEOUT_MS = 10_000;

/** 运行时只注入 `cloudflare:sockets` 与已构建的前端资源。 */
export interface WorkerOverrides {
  /** `cloudflare:sockets` 的 connect；缺失时 socket 模式按“未配置”处理，不会误判节点失效。 */
  readonly connect?: SocketConnect;
  /** 已内嵌的前端资源；API 测试可不提供。 */
  readonly assets?: Fetcher;
}

/**
 * Worker 入口装配：配置、探针、存储、维护 runner 只有这一份组装顺序，
 * `fetch` 与 `scheduled` 共用它，禁止在构建入口再复制一份。
 */
export function createWorker(overrides: WorkerOverrides = {}): ExportedHandler<RuntimeEnv> {
  const handler: ExportedHandler<RuntimeEnv> = {
    async fetch(request, env, executionContext): Promise<Response> {
      const configService = createConfigService(env);
      const resolved = await configService.resolve();
      const probeDeps = probeAdapterDeps(overrides);
      const createProbe = (config: ProbeConfig): ProbeAdapter => createProbeAdapterFromConfig(config, probeDeps);
      const checkProxy = new CheckProxy(createProbe(toProbeConfig(resolved.config)));
      // 面板密钥以统一配置为准，未配置时仍兼容环境变量 AUTH_KEY。
      const authKey = resolved.config.authKey || env.AUTH_KEY?.trim();
      // 同一份 KV 存储实例既服务维护 runner，也服务域名绑定读写，避免两套读取顺序。
      const kv = env.IP_DATA;
      const assets = overrides.assets;
      const maintenanceSource = kv ? new KvMaintenanceSource(kv) : null;
      const maintenance = kv && maintenanceSource
        ? createMaintenanceRunner(kv, resolved.config, overrides, maintenanceSource)
        : null;

      const dependencies: HttpAppDependencies = {
        checkProxy,
        checkPool: new CheckPoolText(checkProxy, BATCH_CHECK_CONCURRENCY),
        version: APP_VERSION,
        configSource: resolved.source,
        config: configService,
        probeSelfTest: new ProbeSelfTest(createProbe),
        remotePoolLoader: new RemotePoolLoader({ timeoutMs: resolved.config.settings.REMOTE_LOAD_TIMEOUT }),
        ...(authKey ? { authKey } : {}),
        ...(assets ? { assets } : {}),
        ...(kv
          ? {
              pools: new PoolService(new KvPoolCatalog(kv)),
              domainBindings: new DomainBindings(maintenanceSource!, new KvDomainBindingRepository(kv)),
              ...(maintenance ? { maintenance } : {}),
            }
          : {}),
      };

      return createHttpApp(dependencies).fetch(request, env, executionContext);
    },

    /**
     * 定时维护：缺少 KV 绑定或没开启定时维护时直接跳过。
     * 手动维护复用同一个 runner，保证两条路径的装配与行为完全一致。
     */
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

      const source = new KvMaintenanceSource(env.IP_DATA);
      executionContext.waitUntil(createMaintenanceRunner(env.IP_DATA, resolved.config, overrides, source).run(false));
    },
  };

  return handler;
}

/** `exactOptionalPropertyTypes` 下不能把 `connect: undefined` 直接传给适配器，这里收口一次。 */
function probeAdapterDeps(overrides: WorkerOverrides): ProbeAdapterDeps {
  return overrides.connect ? { connect: overrides.connect } : {};
}

/**
 * 入口与 cron 共用同一套配置装配：少一份重复的读取顺序，
 * 也保证“面板看到的配置”和“定时维护用的配置”永远一致。
 */
export function createConfigService(env: RuntimeEnv): ConfigService {
  return new ConfigService({
    envConfig: loadEnvConfig(env),
    ...(env.IP_DATA
      ? {
          repository: new KvConfigRepository(env.IP_DATA),
        }
      : {}),
  });
}

/** 手动维护与 cron 共用的依赖装配，业务编排仍留在 `jobs/maintenance-job.ts`。 */
export function createMaintenanceRunner(
  kv: KVNamespace,
  config: AppConfig,
  overrides: WorkerOverrides = {},
  source?: MaintenanceSource,
): MaintenanceRunner {
  const maintenanceSource = source ?? new KvMaintenanceSource(kv);
  const maintainer = new MaintainManagedTargets({
    maintainer: new MaintainManagedTarget({
      probe: createProbeAdapterFromConfig(toProbeConfig(config), probeAdapterDeps(overrides)),
      pools: new KvPoolRepository(kv, { maxTrashSize: config.settings.MAX_TRASH_SIZE }),
      dns: new CloudflareDnsRepository({ timeoutMs: DNS_TIMEOUT_MS }),
    }),
  });
  const notifier = new TelegramNotifier({
    enabled: config.tgEnabled,
    token: config.tgToken,
    chatId: config.tgId,
  });

  return {
    run: (isManual) => runMaintenanceJob({
      source: maintenanceSource,
      maintainer,
      notifier,
      fallbackZone: { zoneId: config.zoneId, apiToken: config.apiKey },
      isManual,
    }),
  };
}

