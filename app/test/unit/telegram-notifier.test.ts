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

    expect(await notifier.send('x')).toMatchObject({ sent: false, reason: 'failed' });
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

    expect(await notifier.send('x')).toMatchObject({ sent: false, reason: 'failed' });
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
it('does not report a Telegram JSON rejection as sent even when HTTP is 200', async () => {
  const fetch = createFetch(200, '{"ok":false,"error_code":400,"description":"Bad Request"}');
  const result = await new TelegramNotifier({ enabled: true, token: 'fixture-token', chatId: 'fixture-chat', fetchImpl: fetch.fetchImpl }).send('test');
  expect(result).toMatchObject({ sent: false, reason: 'failed' });
});

it('splits long reports at complete HTML lines without silently dropping addresses', async () => {
  const fetch = createFetch();
  const text = Array.from({ length: 500 }, (_, index) => '<code>node-' + index + '.example:443</code>').join('\n');
  const result = await new TelegramNotifier({ enabled: true, token: 'fixture-token', chatId: 'fixture-chat', fetchImpl: fetch.fetchImpl }).send(text);
  expect(result.sent).toBe(true);
  expect(fetch.calls.length).toBeGreaterThan(1);
  const parts = fetch.calls.map(call => JSON.parse(String(call.init.body)).text as string);
  expect(parts.join('\n')).toBe(text);
  expect(parts.every(part => part.length <= 3500)).toBe(true);
});

it('reports partial delivery without claiming complete success', async () => {
  let count = 0;
  const fetchImpl = (async () => new Response(++count === 1 ? '{"ok":true}' : '{"ok":false}', { status: count === 1 ? 200 : 503 })) as typeof fetch;
  const notifier = new TelegramNotifier({ enabled: true, token: 'fixture-token', chatId: 'fixture-chat', fetchImpl });
  const result = await notifier.send(Array.from({ length: 500 }, (_, index) => '<code>node-' + index + '.example:443</code>').join('\n'));
  expect(result).toMatchObject({ sent: false, reason: 'failed', delivered: 1, code: 'HTTP_503' });
  expect(result.total).toBeGreaterThan(1);
  expect(count).toBe(2);
});

it('does not accept malformed Telegram JSON or lose blank lines between report parts', async () => {
  const invalid = createFetch(200, 'not json');
  expect(await new TelegramNotifier({ enabled: true, token: 'fixture', chatId: 'fixture', fetchImpl: invalid.fetchImpl }).send('report'))
    .toMatchObject({ sent: false, reason: 'failed', code: 'INVALID_RESPONSE' });
  const valid = createFetch();
  const text = Array.from({ length: 300 }, (_, index) => '<code>node-' + index + '.example:443</code>\n').join('\n');
  await new TelegramNotifier({ enabled: true, token: 'fixture', chatId: 'fixture', fetchImpl: valid.fetchImpl }).send(text);
  expect(valid.calls.map(call => JSON.parse(String(call.init.body)).text).join('\n')).toBe(text);
});
