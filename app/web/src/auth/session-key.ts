const TOKEN_KEY = 'ddns-proxyip-token';

export interface SessionKeyStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

/** URL keys initialize a tab; otherwise reuse the key entered in this tab. */
export function readAuthKey(search: string, session: SessionKeyStorage): string {
  const queryKey = new URLSearchParams(search).get('key')?.trim();
  if (queryKey) {
    session.setItem(TOKEN_KEY, queryKey);
    return queryKey;
  }
  return session.getItem(TOKEN_KEY) ?? '';
}

export function writeAuthKey(key: string, session: SessionKeyStorage): void {
  session.setItem(TOKEN_KEY, key.trim());
}

export function shouldShowAuthFailure(hasSubmittedKey: boolean, unauthorized: boolean): boolean {
  return hasSubmittedKey && unauthorized;
}
