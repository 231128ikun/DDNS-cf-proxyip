import { useLayoutEffect, useMemo, useRef, useState } from 'preact/hooks';
import type { ConfigResponse } from '../../src/contracts/config';
import { ApiClient, ApiError } from './api/client';
import { errorMessage } from './api/errors';
import { LoadingState } from './components/loading-state';

type AppComponent = typeof import('./app').App;
type AuthState =
  | { readonly phase: 'checking' }
  | { readonly phase: 'login'; readonly error?: string }
  | { readonly phase: 'loading-app' }
  | { readonly phase: 'ready' };

export function AuthGate() {
  const client = useMemo(() => new ApiClient(), []);
  const [state, setState] = useState<AuthState>({ phase: 'checking' });
  const [key, setKey] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [AppComponent, setAppComponent] = useState<AppComponent | null>(null);
  const [initialConfig, setInitialConfig] = useState<ConfigResponse | undefined>();
  const appModule = useRef<Promise<typeof import('./app')> | null>(null);

  const loadSession = async (signal?: AbortSignal): Promise<ConfigResponse | undefined> => {
    try {
      // 已有会话直接读取配置：同一请求完成鉴权，不再先往返一次 auth/status。
      return await client.config(signal, false);
    } catch (error) {
      if (signal?.aborted || (error instanceof ApiError && error.status === 401)) throw error;
      // 配置接口异常时仍允许已鉴权用户进入面板重试，不把服务故障说成密钥错误。
      const status = await client.authStatus(signal);
      if (!status.authenticated) throw new ApiError('未授权', 401);
      return undefined;
    }
  };

  const openApp = (config?: ConfigResponse): void => {
    setInitialConfig(config);
    setState({ phase: 'loading-app' });
    void (appModule.current ?? import('./app'))
      .then((module) => {
        setAppComponent(() => module.App);
        setState({ phase: 'ready' });
      })
      .catch((error: unknown) => {
        appModule.current = null;
        setState({ phase: 'login', error: errorMessage(error) });
      });
  };

  useLayoutEffect(() => {
    let cancelled = false;
    // 只预取公开静态代码；管理页面和数据仍等待鉴权成功。
    const loading = import('./app');
    appModule.current = loading;
    void loading.catch(() => { if (appModule.current === loading) appModule.current = null; });
    const queryKey = new URL(window.location.href).searchParams.get('key')?.trim() ?? '';
    const clearQueryKey = (): void => {
      if (!queryKey) return;
      const url = new URL(window.location.href);
      url.searchParams.delete('key');
      window.history.replaceState(null, '', `${url.pathname}${url.search}${url.hash}`);
    };
    const controller = new AbortController();
    const initial = queryKey ? client.login(queryKey, controller.signal).then(() => loadSession(controller.signal))
      : loadSession(controller.signal);
    initial
      .then((config) => {
        if (cancelled) return;
        clearQueryKey();
        openApp(config);
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          clearQueryKey();
          const unauthorized = error instanceof ApiError && error.status === 401;
          const message = unauthorized ? (queryKey ? '访问密钥无效' : '') : errorMessage(error);
          setState({ phase: 'login', ...(message ? { error: message } : {}) });
        }
      });
    return () => { cancelled = true; controller.abort(); };
  }, [client]);

  if (state.phase === 'ready' && AppComponent) {
    return <div class="app-entrance"><AppComponent client={client} {...(initialConfig ? { initialConfig } : {})} /></div>;
  }
  if (state.phase === 'checking' || state.phase === 'loading-app' || (state.phase === 'ready' && !AppComponent)) {
    return <LoadingState phase={state.phase === 'checking' ? 'checking' : 'loading-app'} />;
  }

  const submit = (event: Event): void => {
    event.preventDefault();
    const value = key.trim();
    if (!value || submitting) return;
    setSubmitting(true);
    setState({ phase: 'login' });
    client.login(value)
      .then(() => loadSession())
      .then(openApp)
      .catch((error: unknown) => setState({ phase: 'login', error: errorMessage(error) }))
      .finally(() => setSubmitting(false));
  };
  const loginError = state.phase === 'login' ? state.error : undefined;

  return (
    <div class="container auth-gate">
      <main class="auth-card" aria-labelledby="auth-title">
        <h1 id="auth-title">DDNS Pro</h1>
        <p>该面板已开启访问保护，输入访问密钥后会保持登录状态。</p>
        <form onSubmit={submit}>
          <label for="auth-key">访问密钥</label>
          <input
            id="auth-key"
            name="key"
            type="password"
            autocomplete="current-password"
            autofocus
            required
            value={key}
            onInput={(event) => setKey(event.currentTarget.value)}
          />
          {loginError && <p class="auth-error" role="alert">{loginError}</p>}
          <button type="submit" disabled={submitting || !key.trim()}>
            {submitting ? '正在验证…' : '进入面板'}
          </button>
          <div class="auth-hint">未配置 AUTH_KEY 时会直接进入面板</div>
        </form>
      </main>
    </div>
  );
}
