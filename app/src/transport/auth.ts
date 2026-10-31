import type { AuthLoginRequest, AuthStatusResponse } from '../contracts/auth';

const AUTH_COOKIE = 'ddns_auth';

export interface AuthDecision {
  readonly enabled: boolean;
  readonly authorized: boolean;
  readonly shouldSetCookie: boolean;
}

/** 与 main 保持同一组认证入口：Bearer、X-Auth-Key、查询参数和 HttpOnly Cookie。 */
export function checkRequestAuth(request: Request, url: URL, configuredKey: string): AuthDecision {
  const requiredKey = configuredKey.trim();
  if (!requiredKey) return { enabled: false, authorized: true, shouldSetCookie: false };

  const authorization = request.headers.get('Authorization') ?? '';
  const bearer = authorization.toLowerCase().startsWith('bearer ')
    ? authorization.slice(7).trim() : '';
  const headerKey = (request.headers.get('X-Auth-Key') ?? '').trim();
  const queryKey = (url.searchParams.get('key') ?? '').trim();
  const cookieKey = readCookie(request.headers.get('Cookie') ?? '', AUTH_COOKIE);
  const authorized = [bearer, headerKey, queryKey, cookieKey].includes(requiredKey);

  return {
    enabled: true,
    authorized,
    shouldSetCookie: authorized && queryKey === requiredKey && cookieKey !== requiredKey,
  };
}

/** 登录和状态接口属于认证入口本身，必须在受保护 API 中间件之前处理。 */
export async function handleAuthRoute(
  request: Request,
  url: URL,
  configuredKey: string,
): Promise<Response | null> {
  const auth = checkRequestAuth(request, url, configuredKey);
  if (url.pathname === '/api/auth/status' && request.method === 'GET') {
    const response = Response.json({
      ok: true,
      enabled: auth.enabled,
      authenticated: auth.authorized,
    } satisfies AuthStatusResponse);
    return auth.shouldSetCookie ? addAuthCookie(response, configuredKey) : response;
  }
  if (url.pathname === '/api/auth/login' && request.method === 'POST') {
    let body: AuthLoginRequest | null = null;
    try {
      body = await request.json() as AuthLoginRequest;
    } catch {
      return Response.json({ error: 'invalid json' }, { status: 400 });
    }
    if (!auth.enabled) {
      return Response.json({ ok: true, enabled: false, authenticated: true } satisfies AuthStatusResponse);
    }
    if (typeof body?.key !== 'string' || body.key.trim() !== configuredKey.trim()) {
      return unauthorizedResponse();
    }
    return addAuthCookie(Response.json({
      ok: true,
      enabled: true,
      authenticated: true,
    } satisfies AuthStatusResponse), configuredKey);
  }
  return null;
}

export function addAuthCookie(response: Response, key: string): Response {
  const headers = new Headers(response.headers);
  headers.set('Set-Cookie', `${AUTH_COOKIE}=${encodeURIComponent(key)}; Path=/; HttpOnly; Secure; SameSite=Lax`);
  headers.set('Cache-Control', 'no-store');
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

export function unauthorizedResponse(): Response {
  return Response.json({ error: '未授权' }, {
    status: 401,
    headers: { 'Cache-Control': 'no-store' },
  });
}

function readCookie(header: string, name: string): string {
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index < 0 || part.slice(0, index).trim() !== name) continue;
    const value = part.slice(index + 1).trim();
    try {
      return decodeURIComponent(value);
    } catch {
      return value;
    }
  }
  return '';
}
