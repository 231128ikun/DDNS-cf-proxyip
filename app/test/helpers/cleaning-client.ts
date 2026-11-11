import { CheckProxy } from '../../src/application/check-proxy';
import { CheckTarget } from '../../src/application/check-target';
import { MAX_CHECK_BATCH_SIZE } from '../../src/contracts/probe';
import { CleanPool } from '../../src/application/clean-pool';
import { PoolService } from '../../src/application/pool-service';
import { ResolveTarget } from '../../src/application/resolve-target';
import type { PoolCatalog } from '../../src/ports/pool-catalog';
import type { PoolRepository } from '../../src/ports/pool-repository';
import type { ProbeAdapter } from '../../src/ports/probe';
import { createHttpApp } from '../../src/transport/http';
import { ApiClient } from '../../web/src/api/client';

export function cleaningClient(catalog: PoolCatalog, trash: PoolRepository, probe: ProbeAdapter) {
  const pools = new PoolService(catalog);
  const cleanPool = new CleanPool({pools, trash});
  const requests: {path:string; method:string; probes:number}[] = [];
  const request: typeof fetch = async (input, init) => {
    const entry = {path:String(input), method:init?.method ?? 'GET', probes:0};
    requests.push(entry);
    const checkProxy = new CheckProxy({name:probe.name, probe: (target, context) => {
      if (++entry.probes > MAX_CHECK_BATCH_SIZE || entry.path !== '/api/check') throw new Error('单个 Worker 请求的探针预算已耗尽');
      return probe.probe(target, context);
    }});
    return createHttpApp({pools, cleanPool, version:'test', checkTarget:new CheckTarget({checkProxy,
      resolver:new ResolveTarget({query:async () => ({ok:true, values:[]})})})}).request(String(input), init);
  };
  return {client:new ApiClient({fetchImpl:request}), requests, request};
}
