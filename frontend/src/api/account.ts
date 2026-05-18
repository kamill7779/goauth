import { apiDeleteV1, apiGetV1, apiPatchV1, apiPostFormV1, apiPostV1 } from './client';
import type { AccountMe, AccountSession, AuthorizedApp, IdentityActivity, LoginMethod } from '../types/account';

interface RawAccountUser extends Omit<AccountMe['user'], 'timezone'> {
  timezone?: string;
}

interface RawAccountMe extends Omit<AccountMe, 'user'> {
  user: RawAccountUser;
}

interface RawLoginMethod {
  key: string;
  type: string;
  label: string;
  bound: boolean;
  status: string;
  verified?: boolean;
  identifier?: string;
  can_unbind?: boolean;
  created_at?: string;
  last_used_at?: string | null;
  avatar_url?: string;
}

interface RawAuthorizedApp {
  client_id: string;
  name: string;
  scopes: string[];
  granted_at: string;
  last_access_at: string;
  active: boolean;
}

interface RawActivityItem {
  id: number;
  action: string;
  category: string;
  title: string;
  description: string;
  created_at: string;
}

const LOGIN_METHOD_PLACEHOLDERS: LoginMethod[] = [
  {
    id: 'google',
    name: 'Google',
    status: 'unbound',
    bound: false,
    desc: '用 Google 账号一键登录',
    disabled: true,
    disabledReason: '即将开放',
  },
  {
    id: 'microsoft',
    name: 'Microsoft',
    status: 'unbound',
    bound: false,
    desc: '用 Microsoft / Azure AD 登录',
    disabled: true,
    disabledReason: '即将开放',
  },
  {
    id: 'sso',
    name: '企业 SSO',
    status: 'unbound',
    bound: false,
    desc: '用所在组织的单点登录',
    disabled: true,
    disabledReason: '你的账号未加入任何组织',
  },
];

const APP_COLOR_PALETTE = ['#B8865A', '#5C8B6A', '#7C5635', '#54534F', '#2F5E77', '#8C5E58'];

function relativeTimeLabel(value?: string | null): string | null {
  if (!value) return null;

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }

  const diffMs = Date.now() - date.getTime();
  const minute = 60 * 1000;
  const hour = 60 * minute;
  const day = 24 * hour;

  if (diffMs < hour) {
    return `${Math.max(1, Math.floor(diffMs / minute))} 分钟前`;
  }
  if (diffMs < day) {
    return `${Math.max(1, Math.floor(diffMs / hour))} 小时前`;
  }
  if (diffMs < day * 2) {
    return '昨天';
  }
  if (diffMs < day * 7) {
    return `${Math.max(1, Math.floor(diffMs / day))} 天前`;
  }

  return date.toLocaleDateString('zh-CN');
}

function dateLabel(value?: string | null): string {
  if (!value) return '-';

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleDateString('zh-CN');
}

function stableColor(input: string): string {
  if (!input) return APP_COLOR_PALETTE[0];

  let hash = 0;
  for (let index = 0; index < input.length; index += 1) {
    hash = (hash * 31 + input.charCodeAt(index)) >>> 0;
  }
  return APP_COLOR_PALETTE[hash % APP_COLOR_PALETTE.length];
}

function appInitial(name: string): string {
  const trimmed = name.trim();
  if (!trimmed) return '?';
  return trimmed[0].toUpperCase();
}

function appDescription(app: RawAuthorizedApp): string {
  if (!app.scopes?.length) {
    return app.active ? '已接入统一身份登录' : '授权已结束';
  }
  return `已获授权访问：${app.scopes.join('、')}`;
}

function methodDescription(method: RawLoginMethod): string {
  if (method.key === 'password') {
    return '用账号密码登录';
  }
  if (method.key === 'email') {
    return method.identifier?.trim() || '用于接收安全通知和重置密码';
  }
  if (!method.bound) {
    return `用 ${method.label} 账号一键登录`;
  }
  if (method.identifier?.trim()) {
    return `已绑定 ${method.label} 账号 ${method.identifier.trim()}`;
  }
  return `已绑定 ${method.label} 登录`;
}

function mapLoginMethodStatus(method: RawLoginMethod): LoginMethod['status'] {
  if (method.key === 'password') return 'primary';
  if (method.key === 'email' && method.verified) return 'verified';
  if (method.bound) return 'bound';
  return 'unbound';
}

function mapLoginMethod(method: RawLoginMethod): LoginMethod {
  let disabledReason: string | undefined;
  if (method.key === 'email') {
    disabledReason = '邮箱换绑即将开放';
  } else if (method.key !== 'password' && method.bound) {
    disabledReason = '账户中心解绑即将开放';
  }

  return {
    id: method.key,
    name: method.key === 'password' ? '密码登录' : method.key === 'email' ? '主邮箱' : method.label,
    status: mapLoginMethodStatus(method),
    bound: method.bound,
    lastUsed: relativeTimeLabel(method.last_used_at),
    desc: methodDescription(method),
    verified: method.verified,
    disabled: Boolean(disabledReason),
    disabledReason,
  };
}

function mapActivityType(category: string): IdentityActivity['type'] {
  switch (category) {
    case 'security':
      return 'security';
    case 'login_method':
      return 'binding';
    case 'profile':
      return 'profile';
    case 'session':
    default:
      return 'auth';
  }
}

function mapActivity(item: RawActivityItem): IdentityActivity {
  return {
    id: item.id,
    type: mapActivityType(item.category),
    title: item.title || item.action,
    desc: item.description || '',
    time: relativeTimeLabel(item.created_at) || dateLabel(item.created_at),
  };
}

function unsupported(message: string): never {
  throw new Error(message);
}

export function accountSessionRevokePath(sessionId: string): string {
  return `/account/sessions/${encodeURIComponent(sessionId)}/revoke`;
}

export async function getAccountMe(): Promise<AccountMe> {
  const data = await apiGetV1<RawAccountMe>('/account/me');
  return {
    ...data,
    user: {
      ...data.user,
      timezone: data.user.timezone?.trim() || 'Asia/Shanghai',
    },
  };
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

export interface UpdateProfileData {
  nickname: string;
  display_name: string;
  username: string;
  email: string;
  locale: string;
  timezone: string;
}

export async function updateAccountProfile(data: UpdateProfileData): Promise<{ updated: boolean }> {
  await apiPatchV1<{ profile: unknown }>('/account/profile', {
    username: data.username,
    nickname: data.nickname,
    display_name: data.display_name,
    locale: data.locale,
  });
  return { updated: true };
}

export async function uploadAccountAvatar(file: File): Promise<{ avatar_url: string }> {
  const data = new FormData();
  data.append('avatar', file);
  return apiPostFormV1<{ avatar_url: string }>('/account/avatar', data);
}

export async function removeAccountAvatar(): Promise<{ removed: boolean }> {
  await apiPatchV1<{ profile: unknown }>('/account/profile', {
    avatar_url: '',
  });
  return { removed: true };
}

export async function getAccountLoginMethods(): Promise<{ methods: LoginMethod[] }> {
  const data = await apiGetV1<{ methods: RawLoginMethod[] }>('/account/login-methods');
  const methods = data.methods.map(mapLoginMethod);
  const seen = new Set(methods.map((method) => method.id));

  for (const placeholder of LOGIN_METHOD_PLACEHOLDERS) {
    if (!seen.has(placeholder.id)) {
      methods.push(placeholder);
    }
  }

  return { methods };
}

export async function bindLoginMethod(methodId: string): Promise<{ bound: boolean }> {
  unsupported(`${methodId} 绑定入口暂未接入账户中心，请先从对应身份提供方发起登录`);
}

export async function unbindLoginMethod(methodId: string): Promise<{ unbound: boolean }> {
  unsupported(`${methodId} 解绑能力暂未开放`);
}

export async function changeAccountPassword(data: { current: string; newPass: string }): Promise<{ changed: boolean }> {
  return apiPostV1<{ changed: boolean }>('/account/password/change', {
    current_password: data.current,
    new_password: data.newPass,
  });
}

export async function getAccountAuthorizedApps(): Promise<{ apps: AuthorizedApp[] }> {
  const data = await apiGetV1<{ apps: RawAuthorizedApp[] }>('/account/authorized-apps');
  return {
    apps: data.apps.map((app) => ({
      id: app.client_id,
      name: app.name,
      desc: appDescription(app),
      grantedAt: dateLabel(app.granted_at),
      lastAccess: relativeTimeLabel(app.last_access_at) || dateLabel(app.last_access_at),
      scopes: app.scopes || [],
      color: stableColor(app.client_id),
      initial: appInitial(app.name),
    })),
  };
}

export async function getAccountActivity(limit = 5): Promise<{ items: IdentityActivity[] }> {
  const safeLimit = Math.max(1, Math.min(100, Math.floor(limit)));
  const data = await apiGetV1<{ items: RawActivityItem[] }>(`/account/activity?limit=${encodeURIComponent(String(safeLimit))}`);
  return { items: data.items.map(mapActivity) };
}

export async function revokeAppAuthorization(appId: string): Promise<{ revoked: boolean }> {
  return apiDeleteV1<{ revoked: boolean }>(`/account/authorized-apps/${encodeURIComponent(appId)}`);
}

export async function getAccount2FAStatus(): Promise<{ enabled: boolean; recoveryCodesAvailable: boolean }> {
  return { enabled: false, recoveryCodesAvailable: false };
}

export async function enable2FA(): Promise<{ secret: string; qrUrl: string }> {
  unsupported('两步验证能力暂未开放');
}

export async function verify2FASetup(_code: string): Promise<{ verified: boolean }> {
  unsupported('两步验证能力暂未开放');
}

export async function disable2FA(): Promise<{ disabled: boolean }> {
  unsupported('两步验证能力暂未开放');
}

export async function regenerateRecoveryCodes(): Promise<{ codes: string[] }> {
  unsupported('两步验证能力暂未开放');
}
