import axios, {
  AxiosAdapter,
  AxiosError,
  AxiosHeaders,
  AxiosInstance,
  InternalAxiosRequestConfig,
} from 'axios';
import type { ApiError, ApiSuccessResponse } from '../types/auth';

export const API_BASE_URL =
  import.meta.env?.VITE_API_BASE_URL?.trim() ||
  (typeof window !== 'undefined' ? window.location.origin : 'http://localhost:8080');

export interface ApiRequestOptions {
  captchaToken?: string;
  humanToken?: string;
}

type TokenStorage = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;

interface TokenPair {
  access_token: string;
  refresh_token: string;
}

interface ApiHttpClientOptions {
  apiBaseUrl: string;
  timeout?: number;
  storage?: TokenStorage | null;
  onExpired?: () => void;
  adapter?: AxiosAdapter;
}

interface RetryableRequestConfig extends InternalAxiosRequestConfig {
  _retry?: boolean;
  _skipAuthRefresh?: boolean;
  _skipBearer?: boolean;
}

export interface ApiHttpError extends Error {
  status?: number;
}

const PUBLIC_AUTH_PATHS = new Set([
  '/login',
  '/login/2fa/verify',
  '/register',
  '/email/send-code',
  '/password/forgot',
  '/password/reset',
  '/public-config',
  '/refresh',
]);

function browserStorage(): TokenStorage | null {
  if (typeof window === 'undefined') {
    return null;
  }
  return window.localStorage;
}

function browserExpiredRedirect() {
  if (typeof window !== 'undefined') {
    window.location.href = '/login?expired=1';
  }
}

function clearStoredTokens(storage: TokenStorage | null) {
  storage?.removeItem('access_token');
  storage?.removeItem('refresh_token');
}

function requestPath(config: { url?: string }) {
  return String(config.url ?? '').split('?')[0];
}

function isPublicAuthPath(config: { url?: string }) {
  return PUBLIC_AUTH_PATHS.has(requestPath(config));
}

function setAuthorization(config: InternalAxiosRequestConfig, token: string) {
  if (config.headers instanceof AxiosHeaders) {
    config.headers.set('Authorization', `Bearer ${token}`);
    return;
  }
  config.headers = AxiosHeaders.from(config.headers);
  config.headers.set('Authorization', `Bearer ${token}`);
}

function unwrapTokenPair(body: unknown): TokenPair {
  const record = body as { data?: unknown; access_token?: unknown; refresh_token?: unknown };
  const data = (record?.data ?? body) as { access_token?: unknown; refresh_token?: unknown };
  if (typeof data?.access_token !== 'string' || typeof data?.refresh_token !== 'string') {
    throw new Error('刷新登录态失败：响应格式不匹配');
  }
  return {
    access_token: data.access_token,
    refresh_token: data.refresh_token,
  };
}

function createApiHttpError(message: string, status?: number): ApiHttpError {
  const error = new Error(message) as ApiHttpError;
  if (status !== undefined) {
    error.status = status;
  }
  return error;
}

function errorMessage(error: AxiosError<ApiError & { message?: string }>) {
  return error.response?.data?.error || error.response?.data?.message || error.message || '请求失败';
}

export function createApiHttpClients(options: ApiHttpClientOptions): {
  authClient: AxiosInstance;
  v1Client: AxiosInstance;
} {
  const storage = options.storage === undefined ? browserStorage() : options.storage;
  const onExpired = options.onExpired ?? browserExpiredRedirect;
  let refreshPromise: Promise<TokenPair> | null = null;

  const authClient: AxiosInstance = axios.create({
    baseURL: `${options.apiBaseUrl}/v1/auth`,
    headers: {
      'Content-Type': 'application/json',
    },
    withCredentials: true,
    timeout: options.timeout ?? 10000,
    adapter: options.adapter,
  });

  const v1Client: AxiosInstance = axios.create({
    baseURL: `${options.apiBaseUrl}/v1`,
    headers: {
      'Content-Type': 'application/json',
    },
    withCredentials: true,
    timeout: options.timeout ?? 10000,
    adapter: options.adapter,
  });

  async function refreshStoredTokens(): Promise<TokenPair> {
    if (refreshPromise) {
      return refreshPromise;
    }

    const refreshToken = storage?.getItem('refresh_token');
    if (!refreshToken) {
      throw new Error('missing refresh token');
    }

    refreshPromise = authClient.post('/refresh', { refresh_token: refreshToken }, {
      _skipAuthRefresh: true,
      _skipBearer: true,
    } as RetryableRequestConfig)
      .then((response) => {
        const tokens = unwrapTokenPair(response.data);
        storage?.setItem('access_token', tokens.access_token);
        storage?.setItem('refresh_token', tokens.refresh_token);
        return tokens;
      })
      .finally(() => {
        refreshPromise = null;
      });
    return refreshPromise;
  }

  function expireSession(): ApiHttpError {
    clearStoredTokens(storage);
    onExpired();
    return createApiHttpError('登录已过期，请重新登录', 401);
  }

  function attachBearerToken(skipPublicAuthBearer: boolean) {
    return (config: InternalAxiosRequestConfig) => {
      const retryConfig = config as RetryableRequestConfig;
      if (retryConfig._skipBearer || (skipPublicAuthBearer && isPublicAuthPath(config))) {
        return config;
      }
      const token = storage?.getItem('access_token');
      if (token) {
        setAuthorization(config, token);
      }
      return config;
    };
  }

  function attachAuthRefresh(client: AxiosInstance, skipPublicAuthRefresh: boolean) {
    client.interceptors.response.use(
      (response) => response,
      async (error: AxiosError<ApiError & { message?: string }>) => {
        const config = error.config as RetryableRequestConfig | undefined;
        const isPublicAuthFailure = Boolean(config && skipPublicAuthRefresh && isPublicAuthPath(config));
        if (error.response?.status === 401 && config && !config._retry && !config._skipAuthRefresh && !isPublicAuthFailure) {
          config._retry = true;
          try {
            const tokens = await refreshStoredTokens();
            setAuthorization(config, tokens.access_token);
            return client(config);
          } catch {
            return Promise.reject(expireSession());
          }
        }

        if (error.response?.status === 401 && config?._skipAuthRefresh) {
          return Promise.reject(error);
        }

        if (error.response?.status === 401 && !isPublicAuthFailure) {
          return Promise.reject(expireSession());
        }

        return Promise.reject(createApiHttpError(errorMessage(error), error.response?.status));
      }
    );
  }

  authClient.interceptors.request.use(attachBearerToken(true));
  v1Client.interceptors.request.use(attachBearerToken(false));
  attachAuthRefresh(authClient, true);
  attachAuthRefresh(v1Client, false);

  return { authClient, v1Client };
}

const { authClient: client, v1Client } = createApiHttpClients({
  apiBaseUrl: API_BASE_URL,
});

export async function apiPost<T>(path: string, data?: unknown, options?: ApiRequestOptions): Promise<T> {
  return apiPostWithClient<T>(client, path, data, options);
}

export async function apiPostWithClient<T>(httpClient: AxiosInstance, path: string, data?: unknown, options?: ApiRequestOptions): Promise<T> {
  const response = await httpClient.post<ApiSuccessResponse<T>>(path, data, {
    headers: requestOptionHeaders(options),
  });
  return response.data.data;
}

export async function apiPostV1<T>(path: string, data?: unknown, options?: ApiRequestOptions): Promise<T> {
  const response = await v1Client.post<ApiSuccessResponse<T>>(path, data, {
    headers: requestOptionHeaders(options),
  });
  return response.data.data;
}

function requestOptionHeaders(options?: ApiRequestOptions): Record<string, string> | undefined {
  const headers: Record<string, string> = {};
  if (options?.captchaToken) {
    headers['X-Captcha-Token'] = options.captchaToken;
  }
  if (options?.humanToken) {
    headers['X-Human-Token'] = options.humanToken;
  }
  return Object.keys(headers).length > 0 ? headers : undefined;
}

export async function apiPostFormV1<T>(path: string, data: FormData): Promise<T> {
  const response = await v1Client.post<ApiSuccessResponse<T>>(path, data, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  });
  return response.data.data;
}

export async function apiPatchV1<T>(path: string, data?: unknown): Promise<T> {
  const response = await v1Client.patch<ApiSuccessResponse<T>>(path, data);
  return response.data.data;
}

export async function apiDeleteV1<T>(path: string): Promise<T> {
  const response = await v1Client.delete<ApiSuccessResponse<T>>(path);
  return response.data.data;
}

export async function apiGetV1<T>(path: string): Promise<T> {
  const response = await v1Client.get<ApiSuccessResponse<T>>(path);
  return response.data.data;
}

export async function apiGet<T>(path: string): Promise<T> {
  const response = await client.get<ApiSuccessResponse<T>>(path);
  return response.data.data;
}

export default client;
