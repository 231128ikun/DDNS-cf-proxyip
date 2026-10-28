import { useEffect, useMemo, useState } from 'preact/hooks';
import { ApiClient } from './api/client';
import { errorMessage } from './api/errors';

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

  const openApp = (): void => {
    setState({ phase: 'loading-app' });
    void import('./app')
      .then((module) => {
        setAppComponent(() => module.App);
        setState({ phase: 'ready' });
      })
      .catch((error: unknown) => setState({ phase: 'login', error: errorMessage(error) }));
  };

  useEffect(() => {
    let cancelled = false;
    const queryKey = new URL(window.location.href).searchParams.get('key')?.trim() ?? '';
    const clearQueryKey = (): void => {
      if (!queryKey) return;
      const url = new URL(window.location.href);
      url.searchParams.delete('key');
      window.history.replaceState(null, '', `${url.pathname}${url.search}${url.hash}`);
    };
    const initial = queryKey ? client.login(queryKey) : client.authStatus();
    initial
      .then((status) => {
        if (cancelled) return;
        clearQueryKey();
        if (status.authenticated) openApp();
        else setState({ phase: 'login' });
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          clearQueryKey();
          setState({ phase: 'login', error: queryKey ? '访问密钥无效' : errorMessage(error) });
        }
      });
    return () => { cancelled = true; };
  }, [client]);

  if (state.phase === 'ready' && AppComponent) return <AppComponent client={client} />;
  if (state.phase === 'checking' || state.phase === 'loading-app' || (state.phase === 'ready' && !AppComponent)) {
    return <div class="container py-5 text-center text-secondary">正在验证访问权限…</div>;
  }

  const submit = (event: Event): void => {
    event.preventDefault();
    const value = key.trim();
    if (!value || submitting) return;
    setSubmitting(true);
    setState({ phase: 'login' });
    client.login(value)
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
