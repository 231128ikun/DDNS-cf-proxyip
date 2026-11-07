import { WorkerEntrypoint } from 'cloudflare:workers';
import { createWorker, dispatchWorkerInvocation, type InvocationProps, type InvocationRequestInit } from './worker';
import type { RuntimeEnv } from './config/runtime';

const worker = createWorker();

export default class DdnsWorker extends WorkerEntrypoint<RuntimeEnv> {
  fetch(request: Request) {
    return worker.fetch!(request as Parameters<NonNullable<typeof worker.fetch>>[0], this.env, this.ctx);
  }

  scheduled(controller: ScheduledController) {
    return worker.scheduled!(controller, this.env, this.ctx);
  }

  dispatch(url: string, init: InvocationRequestInit, props: InvocationProps, cancelled: ReadableStream<Uint8Array>) {
    return dispatchWorkerInvocation(worker, this.env, this.ctx, url, init, props, cancelled);
  }
}
