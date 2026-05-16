import axios, { AxiosError, AxiosInstance, InternalAxiosRequestConfig } from 'axios';
import type { ApiError, ApiSuccessResponse } from '../types/auth';

export const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL?.trim() ||
  (typeof window !== 'undefined' ? window.location.origin : 'http://localhost:8080');

export interface ApiRequestOptions {
  captchaToken?: string;
}

const client: AxiosInstance = axios.create({
  baseURL: `${API_BASE_URL}/v1/auth`,
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true,
  timeout: 10000,
});

const v1Client: AxiosInstance = axios.create({
  baseURL: `${API_BASE_URL}/v1`,
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true,
  timeout: 10000,
});

function attachBearerToken(config: InternalAxiosRequestConfig) {
  const token = typeof window !== 'undefined' ? window.localStorage.getItem('access_token') : null;
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
}

client.interceptors.request.use(attachBearerToken);
v1Client.interceptors.request.use(attachBearerToken);

client.interceptors.response.use(
  (response) => response,
  (error: AxiosError<ApiError>) => {
    const message = error.response?.data?.error || error.message || '请求失败';
    return Promise.reject(new Error(message));
  }
);

v1Client.interceptors.response.use(
  (response) => response,
  (error: AxiosError<ApiError>) => {
    const message = error.response?.data?.error || error.message || '请求失败';
    return Promise.reject(new Error(message));
  }
);

export async function apiPost<T>(path: string, data?: unknown, options?: ApiRequestOptions): Promise<T> {
  const response = await client.post<ApiSuccessResponse<T>>(path, data, {
    headers: options?.captchaToken
      ? {
          'X-Captcha-Token': options.captchaToken,
        }
      : undefined,
  });
  return response.data.data;
}

export async function apiPostV1<T>(path: string, data?: unknown, options?: ApiRequestOptions): Promise<T> {
  const response = await v1Client.post<ApiSuccessResponse<T>>(path, data, {
    headers: options?.captchaToken
      ? {
          'X-Captcha-Token': options.captchaToken,
        }
      : undefined,
  });
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
