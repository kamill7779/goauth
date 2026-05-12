import axios, {
  AxiosAdapter,
  AxiosError,
  AxiosHeaders,
  AxiosInstance,
  InternalAxiosRequestConfig,
} from 'axios';

type TokenStorage = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;

interface AdminHttpClientOptions {
  baseURL: string;
  timeout?: number;
  storage?: TokenStorage | null;
  onExpired?: () => void;
  adapter?: AxiosAdapter;
}

interface RetryableRequestConfig extends InternalAxiosRequestConfig {
  _retry?: boolean;
  _skipAuthRefresh?: boolean;
}

interface TokenPair {
  access_token: string;
  refresh_token: string;
}

export interface AdminHttpError extends Error {
  status?: number;
}

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

function clearStoredTokens(storage: TokenStorage | null) {
  storage?.removeItem('access_token');
  storage?.removeItem('refresh_token');
}

function createAdminHttpError(message: string, status?: number): AdminHttpError {
  const error = new Error(message) as AdminHttpError;
  if (status !== undefined) {
    error.status = status;
  }
  return error;
}

export function createAdminHttpClient(options: AdminHttpClientOptions): AxiosInstance {
  const storage = options.storage === undefined ? browserStorage() : options.storage;
  const onExpired = options.onExpired ?? browserExpiredRedirect;
  let refreshPromise: Promise<TokenPair> | null = null;

  const client = axios.create({
    baseURL: options.baseURL,
    headers: { 'Content-Type': 'application/json' },
    timeout: options.timeout ?? 15000,
    adapter: options.adapter,
  });

  client.interceptors.request.use((config) => {
    const token = storage?.getItem('access_token');
    if (token) {
      setAuthorization(config, token);
    }
    return config;
  });

  async function refreshStoredTokens(): Promise<TokenPair> {
    if (refreshPromise) {
      return refreshPromise;
    }

    const refreshToken = storage?.getItem('refresh_token');
    if (!refreshToken) {
      throw new Error('missing refresh token');
    }

    refreshPromise = client.post('/auth/refresh', { refresh_token: refreshToken }, { _skipAuthRefresh: true } as RetryableRequestConfig)
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

  function expireSession(): AdminHttpError {
    clearStoredTokens(storage);
    onExpired();
    return createAdminHttpError('登录已过期，请重新登录', 401);
  }

  client.interceptors.response.use(
    (response) => response,
    async (error: AxiosError<{ error?: string; message?: string }>) => {
      const config = error.config as RetryableRequestConfig | undefined;
      if (error.response?.status === 401 && config && !config._retry && !config._skipAuthRefresh) {
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

      if (error.response?.status === 401) {
        return Promise.reject(expireSession());
      }

      const msg = error.response?.data?.error || error.response?.data?.message || error.message || '请求失败';
      return Promise.reject(createAdminHttpError(msg, error.response?.status));
    }
  );

  return client;
}
