import { apiGet, apiPost } from './client';
import type { AuthSession, LoginInput, LoginResponse, RegisterInput, SendCodeInput } from '../types/auth';

export async function login(input: LoginInput): Promise<LoginResponse> {
  return apiPost<LoginResponse>('/login', input);
}

export async function register(input: RegisterInput): Promise<{ id: number; email: string }> {
  return apiPost<{ id: number; email: string }>('/register', input);
}

export async function sendEmailCode(input: SendCodeInput): Promise<{ sent: boolean }> {
  return apiPost<{ sent: boolean }>('/email/send-code', input);
}

export async function forgotPassword(email: string): Promise<{ sent: boolean }> {
  return apiPost<{ sent: boolean }>('/password/forgot', { email });
}

export async function me(): Promise<AuthSession> {
  return apiGet<AuthSession>('/me');
}
