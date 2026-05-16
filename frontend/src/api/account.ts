import { apiGetV1, apiPostV1 } from './client';
import type { AccountMe, AccountSession } from '../types/account';

export function accountSessionRevokePath(sessionId: string): string {
  return `/account/sessions/${encodeURIComponent(sessionId)}/revoke`;
}

export async function getAccountMe(): Promise<AccountMe> {
  return apiGetV1<AccountMe>('/account/me');
}

export async function getAccountSessions(): Promise<{ sessions: AccountSession[] }> {
  return apiGetV1<{ sessions: AccountSession[] }>('/account/sessions');
}

export async function revokeAccountSession(sessionId: string): Promise<{ revoked: boolean }> {
  return apiPostV1<{ revoked: boolean }>(accountSessionRevokePath(sessionId));
}

export async function logoutAllAccountSessions(): Promise<{ revoked: boolean }> {
  return apiPostV1<{ revoked: boolean }>('/account/logout-all');
}
