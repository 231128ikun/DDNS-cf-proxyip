import type { RemoteUrlRejection } from '../domain/remote-url';

export type RemoteLoadFailure =
  | RemoteUrlRejection
  | 'too-many-redirects'
  | 'http-error'
  | 'timeout'
  | 'network-error'
  | 'too-large';

export type RemotePoolLoadResult =
  | { readonly ok: true; readonly content: string; readonly finalUrl: string }
  | { readonly ok: false; readonly reason: RemoteLoadFailure };

export interface RemoteLoadRequestOptions {
  readonly signal?: AbortSignal;
}

export interface RemotePoolSource {
  load(rawUrl: string, options?: RemoteLoadRequestOptions): Promise<RemotePoolLoadResult>;
}
