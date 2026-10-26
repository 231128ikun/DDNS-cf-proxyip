export type RequestState<T> =
  | { readonly status: 'idle' }
  | { readonly status: 'loading' }
  | {
    readonly status: 'ready';
    readonly data: T;
    readonly refreshing?: boolean;
    readonly refreshError?: string;
  }
  | {
    readonly status: 'error';
    readonly message: string;
    /** 503 表示存储未绑定；这是"还没初始化"，不该按故障展示。 */
    readonly unavailable?: boolean;
  };
