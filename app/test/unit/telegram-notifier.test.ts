import { describe, expect, it } from 'vitest';
import { TelegramNotifier } from '../../src/adapters/notify/telegram';

interface RecordedCall {
  readonly url: string;
  readonly init: RequestInit;
}

function createFetch(status = 200, body = '{"ok":true}') {
  const calls: RecordedCall[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    calls.push({ url: String(input), init: init ?? {} });
    return new Response(body, { status });
  }) as typeof fetch;
  return { calls, fetchImpl };
}

function createNotifier(overrides: Partial<ConstructorParameters<typeof TelegramNotifier>[0]> = {}) {
  const fetch = createFetch();
  const notifier = new TelegramNotifier({
    enabled: true,
    token: '123:abc',
    chatId: '-100',
    timeoutMs: 1_000,
    fetchImpl: fetch.fetchImpl,
    ...overrides,
  });
  return { notifier, calls: fetch.calls };
}

describe('TelegramNotifier', () => {
  it('posts an HTML message and reports sent', async () => {
    const { notifier, calls } = createNotifier();

    expect(await notifier.send('<b>hi</b>')).toEqual({ sent: true, reason: 'sent' });
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe('https://api.telegram.org/bot123:abc/sendMessage');
    expect(calls[0]?.init.method).toBe('POST');
    expect(JSON.parse(String(calls[0]?.init.body))).toEqual({
      chat_id: '-100',
      text: '<b>hi</b>',
      parse_mode: 'HTML',
      disable_web_page_preview: true,
    });
  });

  it('reports failed when Telegram answers with a non-2xx status', async () => {
    const fetch = createFetch(403, '{"ok":false}');
    const notifier = new TelegramNotifier({
      enabled: true,
      token: '123:abc',
      chatId: '-100',
      fetchImpl: fetch.fetchImpl,
    });

    expect(await notifier.send('x')).toEqual({ sent: false, reason: 'failed' });
  });

  it('reports failed instead of throwing when the request itself fails', async () => {
    const notifier = new TelegramNotifier({
      enabled: true,
      token: '123:abc',
      chatId: '-100',
      fetchImpl: (async () => {
        throw new Error('network down');
      }) as typeof fetch,
    });

    expect(await notifier.send('x')).toEqual({ sent: false, reason: 'failed' });
  });

  it('skips the request when credentials are incomplete', async () => {
    const { notifier, calls } = createNotifier({ chatId: '   ' });

    expect(await notifier.send('x')).toEqual({ sent: false, reason: 'not_configured' });
    expect(calls).toHaveLength(0);
  });

  it('skips the request when notifications are disabled', async () => {
    const { notifier, calls } = createNotifier({ enabled: false });

    expect(await notifier.send('x')).toEqual({ sent: false, reason: 'disabled' });
    expect(calls).toHaveLength(0);
  });
});