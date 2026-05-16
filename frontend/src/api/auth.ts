import { apiGet, apiPost, apiPostV1, type ApiRequestOptions } from './client';
import type { AuthSession, LoginInput, LoginResponse, RegisterInput, SendCodeInput } from '../types/auth';

export type AuthRequestOptions = ApiRequestOptions;

export async function login(input: LoginInput, options?: AuthRequestOptions): Promise<LoginResponse> {
  return apiPost<LoginResponse>('/login', input, options);
}

export async function register(input: RegisterInput, options?: AuthRequestOptions): Promise<{ id: number; email: string }> {
  return apiPost<{ id: number; email: string }>('/register', input, options);
}

export async function sendEmailCode(input: SendCodeInput, options?: AuthRequestOptions): Promise<{ sent: boolean }> {
  return apiPost<{ sent: boolean }>('/email/send-code', input, options);
}

export async function forgotPassword(email: string, options?: AuthRequestOptions): Promise<{ sent: boolean }> {
  return apiPost<{ sent: boolean }>('/password/forgot', { email }, options);
}

export async function resetPassword(input: {
  email: string;
  new_password: string;
  email_code: string;
}): Promise<{ reset: boolean }> {
  return apiPost<{ reset: boolean }>('/password/reset', input);
}

export async function exchangeGitHubLogin(code: string): Promise<{
  tokens: LoginResponse;
  return_to?: string;
  user: { id: number; email: string };
}> {
  return apiPostV1('/external/github/exchange', { code });
}

export async function me(): Promise<AuthSession> {
  return apiGet<AuthSession>('/me');
}
