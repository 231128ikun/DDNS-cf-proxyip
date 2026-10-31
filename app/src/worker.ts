import { CloudflareDnsRepository } from './adapters/dns/cloudflare-dns';
import { DohLookup } from './adapters/dns/doh-lookup';
import { TelegramNotifier } from './adapters/notify/telegram';
import { KvConfigRepository } from './adapters/storage/kv-config-repository';
import { KvDomainBindingRepository } from './adapters/storage/kv-domain-binding-repository';
import { KvMaintenanceSource } from './adapters/storage/kv-maintenance-source';
import { KvMaintenanceStatsRepository } from './adapters/storage/kv-maintenance-stats-repository';
import { KvPoolCatalog } from './adapters/storage/kv-pool-catalog';
import { KvPoolRepository } from './adapters/storage/kv-pool-repository';
import { CheckPoolText } from './application/check-pool';
import { CleanPool } from './application/clean-pool';
import { CheckProxy } from './application/check-proxy';
import { CheckTarget } from './application/check-target';
import { ConfigService } from './application/config-service';
import { DomainBindings } from './application/domain-bindings';
import { MaintainManagedTarget } from './application/maintain-managed-target';
import { MaintainManagedTargets } from './application/maintain-managed-targets';
import { PoolService } from './application/pool-service';
import { RemotePoolLoader } from './application/remote-pool-loader';
import { HttpRemotePoolSource } from './adapters/http/remote-pool-source';
import { ResolveTarget } from './application/resolve-target';
import { TargetStatus } from './application/target-status';
import { TargetRecords } from './application/target-records';
import { createProbeAdapterFromConfig, loadEnvConfig, type RuntimeEnv } from './config/runtime';
import { toProbeConfig, type AppConfig, type ProbeConfig } from './contracts/config';
import { runMaintenanceJob } from './jobs/maintenance-job';
import type { MaintenanceSource } from './ports/maintenance-source';
import type { ProbeAdapter } from './ports/probe';
import { createHttpApp, type HttpAppDependencies, type MaintenanceRunner } from './transport/http';

export const APP_VERSION = '2026.10.31-15.16';

/** 维护里每次 Cloudflare API 调用的超时；cron 场景不能让单个请求拖垮整轮。 */
const DNS_TIMEOUT_MS = 10_000;

/**
 * Worker 入口装配：配置、探针、存储、维护 runner 只有这一份组装顺序，
 * `fetch` 与 `scheduled` 共用它，禁止在构建入口再复制一份。
 */
export function createWorker(): ExportedHandler<RuntimeEnv> {
  const handler: ExportedHandler<RuntimeEnv> = {
    async fetch(request, env, executionContext): Promise<Response> {
      const url = new URL(request.url);
      const configService = createConfigService(env, url.origin);
      const resolved = await configService.resolve();

      const createProbe = (config: ProbeConfig): ProbeAdapter => createProbeAdapterFromConfig(config);
      const checkProxy = new CheckProxy(createProbe(toProbeConfig(resolved.config)));
      // 同一份 KV 存储实例既服务维护 runner，也服务域名绑定读写，避免两套读取顺序。
      const kv = env.IP_DATA;
      const maintenanceSource = kv ? new KvMaintenanceSource(kv) : null;
      const maintenance = kv && maintenanceSource
        ? createMaintenanceRunner(kv, resolved.config, maintenanceSource)
        : null;

      const checkPool = new CheckPoolText(checkProxy, resolved.config.settings.CONCURRENT_CHECKS);
      const checkTarget = new CheckTarget({
        resolver: new ResolveTarget(new DohLookup({ endpoint: resolved.config.dohApi, timeoutMs: resolved.config.settings.DOH_TIMEOUT })),
        checkProxy,
        concurrency: resolved.config.settings.CONCURRENT_CHECKS,
      });

      const dependencies: HttpAppDependencies = {
        checkTarget,
        checkPool,
        version: APP_VERSION,
        authKey: resolved.config.authKey,
        configSource: resolved.source,
        // 鉴权与路由共享本次请求的配置快照，不重复读 KV；下一次请求重新解析。
        config: { resolve: async () => resolved, save: (config) => configService.save(config) },
        remotePoolLoader: new RemotePoolLoader(new HttpRemotePoolSource({ timeoutMs: resolved.config.settings.REMOTE_LOAD_TIMEOUT })),
        ...(kv
          ? {
              ...createPoolDependencies(kv, checkPool, resolved.config, maintenanceSource!, maintenance),
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
      executionContext.waitUntil(createMaintenanceRunner(env.IP_DATA, resolved.config, source).run(false));
    },
  };

  return handler;
}

/**
 * 池相关依赖只在绑定 KV 时装配：洗库与维护共用同一个垃圾桶仓库，
 * 「垃圾桶只有一个写入入口」在装配层也成立。
 */
function createPoolDependencies(
  kv: KVNamespace,
  checkPool: CheckPoolText,
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
      catalog,
      trash: new KvPoolRepository(kv, { maxTrashSize: config.settings.MAX_TRASH_SIZE }),
      checkPool,
    }),
    domainBindings: new DomainBindings(maintenanceSource, new KvDomainBindingRepository(kv)),
    ...(maintenance ? { maintenance } : {}),
  };
}

/**
 * 入口与 cron 共用同一套配置装配：少一份重复的读取顺序，
 * 也保证“面板看到的配置”和“定时维护用的配置”永远一致。
 */
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

/** 手动维护与 cron 共用的依赖装配，业务编排仍留在 `jobs/maintenance-job.ts`。 */
export function createMaintenanceRunner(
  kv: KVNamespace,
  config: AppConfig,
  source?: MaintenanceSource,
): MaintenanceRunner {
  const maintenanceSource = source ?? new KvMaintenanceSource(kv);
  const stats = new KvMaintenanceStatsRepository(kv, new KvPoolCatalog(kv));
  const maintainer = new MaintainManagedTargets({
    maintainer: new MaintainManagedTarget({
      probe: createProbeAdapterFromConfig(toProbeConfig(config)),
      pools: new KvPoolRepository(kv, { maxTrashSize: config.settings.MAX_TRASH_SIZE }),
      dns: new CloudflareDnsRepository({ timeoutMs: DNS_TIMEOUT_MS }),
      concurrency: config.settings.CONCURRENT_CHECKS,
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
      stats,
      fallbackZone: { zoneId: config.zoneId, apiToken: config.apiKey },
      isManual,
      projectUrl: config.projectUrl,
    }),
  };
}
