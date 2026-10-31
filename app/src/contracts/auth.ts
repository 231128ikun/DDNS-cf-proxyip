export interface AuthStatusResponse {
  readonly ok: true;
  readonly enabled: boolean;
  readonly authenticated: boolean;
}

export interface AuthLoginRequest {
  readonly key?: string;
}
