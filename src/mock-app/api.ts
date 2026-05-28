export type ApiResult = unknown;

export interface ApiCallMeta {
  id: string;
  path: string;
  method: string;
  ok: boolean;
  status: number;
  startedAt: string;
  durationMs: number;
  requestBody?: unknown;
  responseBody?: unknown;
  errorBody?: unknown;
}

export interface AuthState {
  accessToken: string;
  refreshToken: string;
  sessionId: string;
  challengeToken: string;
}

export class ApiCallError extends Error {
  constructor(public readonly meta: ApiCallMeta) {
    super(`API call failed: ${meta.method} ${meta.path} -> ${meta.status}`);
  }
}

export async function callApi(path: string, options: RequestInit = {}, accessToken?: string): Promise<{ data: ApiResult; meta: ApiCallMeta }> {
  const method = String(options.method ?? 'GET').toUpperCase();
  const started = performance.now();
  const startedAt = new Date().toISOString();
  const headers = new Headers(options.headers ?? {});
  headers.set('content-type', 'application/json');
  if (accessToken) headers.set('authorization', `Bearer ${accessToken}`);

  const requestBody = parseMaybeJson(options.body);

  try {
    const response = await fetch(path, {
      ...options,
      headers
    });

    const body = await response.json().catch(() => ({}));
    const meta: ApiCallMeta = {
      id: crypto.randomUUID(),
      path,
      method,
      ok: response.ok,
      status: response.status,
      startedAt,
      durationMs: Math.round(performance.now() - started),
      requestBody,
      responseBody: response.ok ? body : undefined,
      errorBody: response.ok ? undefined : body
    };

    if (!response.ok) {
      throw new ApiCallError(meta);
    }

    return { data: body, meta };
  } catch (error) {
    if (error instanceof ApiCallError) {
      throw error;
    }

    const meta: ApiCallMeta = {
      id: crypto.randomUUID(),
      path,
      method,
      ok: false,
      status: 0,
      startedAt,
      durationMs: Math.round(performance.now() - started),
      requestBody,
      errorBody: {
        code: 'NETWORK_OR_RUNTIME_ERROR',
        message: error instanceof Error ? error.message : 'Unknown request error'
      }
    };
    throw new ApiCallError(meta);
  }
}

function parseMaybeJson(body: BodyInit | null | undefined): unknown {
  if (typeof body !== 'string') return undefined;
  try {
    return JSON.parse(body);
  } catch {
    return body;
  }
}

export function pretty(value: unknown): string {
  return JSON.stringify(value, null, 2);
}
