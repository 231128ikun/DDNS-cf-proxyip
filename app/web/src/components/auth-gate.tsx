import { useState } from 'preact/hooks';

interface AuthGateProps {
  readonly invalid: boolean;
  readonly onSubmit: (key: string) => void;
}

export function AuthGate({ invalid, onSubmit }: AuthGateProps) {
  const [key, setKey] = useState('');

  return (
    <main class="container auth-gate">
      <section class="card auth-gate-card" aria-labelledby="auth-gate-title">
        <p class="auth-gate-brand">DDNS Pro</p>
        <h1 id="auth-gate-title">输入面板访问 key</h1>
        <p class="text-secondary">验证通过后即可进入管理面板。key 只保存在当前浏览器标签页。</p>
        <form
          class="auth-gate-form"
          onSubmit={(event) => {
            event.preventDefault();
            const value = key.trim();
            if (value) onSubmit(value);
          }}
        >
          <label for="panel-auth-key">面板访问 key</label>
          <input
            id="panel-auth-key"
            class="form-control"
            type="password"
            autoComplete="current-password"
            value={key}
            onInput={(event) => setKey(event.currentTarget.value)}
            required
            autofocus
          />
          {invalid && <p class="auth-gate-error" role="alert">这个 key 未通过鉴权，请检查后重试。</p>}
          <button class="btn btn-primary" type="submit">验证并进入</button>
        </form>
      </section>
    </main>
  );
}
