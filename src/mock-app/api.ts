export type ApiResult = unknown;

export interface AuthState {
  accessToken: string;
  refreshToken: string;
  sessionId: string;
  challengeToken: string;
}

export async function callApi(path: string, options: RequestInit = {}, accessToken?: string): Promise<ApiResult> {
  const headers = new Headers(options.headers ?? {});
  headers.set('content-type', 'application/json');
  if (accessToken) headers.set('authorization', `Bearer ${accessToken}`);

  const response = await fetch(path, {
    ...options,
    headers
  });

  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw body;
  }
  return body;
}

export function pretty(value: unknown): string {
  return JSON.stringify(value, null, 2);
}
