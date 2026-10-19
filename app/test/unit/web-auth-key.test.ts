import { describe, expect, it } from 'vitest';
import { readAuthKey, shouldShowAuthFailure, writeAuthKey } from '../../web/src/auth/session-key';

function createSessionStore(initial: Record<string, string> = {}) {
  const values = new Map(Object.entries(initial));
  return {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => values.set(key, value),
  };
}

describe('panel auth key session', () => {
  it('uses and stores a key provided in the URL', () => {
    const session = createSessionStore({ 'ddns-proxyip-token': 'stale-key' });

    expect(readAuthKey('?key=url-key', session)).toBe('url-key');
    expect(session.getItem('ddns-proxyip-token')).toBe('url-key');
  });

  it('restores the manually entered key for this tab', () => {
    const session = createSessionStore();
    writeAuthKey('entered-key', session);

    expect(readAuthKey('', session)).toBe('entered-key');
  });

  it('does not call an empty first visit an invalid key', () => {
    expect(shouldShowAuthFailure(false, true)).toBe(false);
    expect(shouldShowAuthFailure(true, true)).toBe(true);
  });
});
