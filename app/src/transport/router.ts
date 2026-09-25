import type { ApiErrorResponse } from '../contracts/probe';

export interface RouteContext {
  readonly request: Request;
  readonly url: URL;
  readonly params: Readonly<Record<string, string>>;
}

export type RouteHandler = (context: RouteContext) => Promise<Response> | Response;

interface Route {
  readonly method: string;
  readonly segments: readonly string[];
  readonly handler: RouteHandler;
}

/**
 * 极小的 Worker 路由器：精确匹配路径与 `:param` 段，不做中间件、不做正则路由。
 * 返回 null 表示没有命中，由调用方决定回退到静态资源还是 404。
 */
export class Router {
  private readonly routes: Route[] = [];

  get(path: string, handler: RouteHandler): this {
    return this.add('GET', path, handler);
  }

  post(path: string, handler: RouteHandler): this {
    return this.add('POST', path, handler);
  }

  put(path: string, handler: RouteHandler): this {
    return this.add('PUT', path, handler);
  }

  delete(path: string, handler: RouteHandler): this {
    return this.add('DELETE', path, handler);
  }

  add(method: string, path: string, handler: RouteHandler): this {
    this.routes.push({ method, segments: path.split('/').filter(Boolean), handler });
    return this;
  }

  async handle(request: Request): Promise<Response | null> {
    const url = new URL(request.url);
    const parts = url.pathname.split('/').filter(Boolean);

    for (const route of this.routes) {
      if (route.method !== request.method || route.segments.length !== parts.length) continue;
      const params = matchSegments(route.segments, parts);
      if (!params) continue;
      return await route.handler({ request, url, params });
    }
    return null;
  }
}

function matchSegments(routeSegments: readonly string[], parts: readonly string[]): Record<string, string> | null {
  const params: Record<string, string> = {};
  for (let index = 0; index < routeSegments.length; index += 1) {
    const segment = routeSegments[index]!;
    const part = parts[index]!;
    if (segment.startsWith(':')) {
      params[segment.slice(1)] = decodeURIComponent(part);
      continue;
    }
    if (segment !== part) return null;
  }
  return params;
}

export function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
  });
}

export function errorResponse(error: string, status: number): Response {
  const body: ApiErrorResponse = { error };
  return jsonResponse(body, status);
}

export async function readJsonBody(request: Request): Promise<{ readonly ok: true; readonly value: unknown } | { readonly ok: false }> {
  try {
    return { ok: true, value: await request.json() };
  } catch {
    return { ok: false };
  }
}