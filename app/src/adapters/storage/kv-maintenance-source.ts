import type { AppConfig } from '../../contracts/config';
import { DOMAIN_POOL_MAPPING_KEY, POOL_NAMES_KEY } from '../../contracts/pool';
import { normalizeManagedTarget } from '../../domain/managed-target';
import type { MaintenanceSource, MaintenanceSourceData } from '../../ports/maintenance-source';
import { readKvStringRecord } from './kv-json';

export class KvMaintenanceSource implements MaintenanceSource {
  constructor(private readonly kv: KVNamespace, private readonly config: AppConfig) {}

  async load(): Promise<MaintenanceSourceData> {
    const [poolMapping, poolNames] = await Promise.all([
      readKvStringRecord(this.kv, DOMAIN_POOL_MAPPING_KEY),
      readKvStringRecord(this.kv, POOL_NAMES_KEY),
    ]);

    return {
      zones: this.config.zones.map((zone) => ({ zoneId: zone.zoneId, apiToken: zone.apiKey })),
      targets: this.config.targets.flatMap((config) => {
        const target = normalizeManagedTarget(config);
        return target ? [{ target, zoneIndex: config.zoneIndex, enabled: config.enabled }] : [];
      }),
      poolMapping,
      poolNames,
    };
  }
}
