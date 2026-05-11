import axios, { AxiosError, AxiosInstance } from 'axios';
import type {
  User, Tenant, Permission, OAuthClient, Session, AuditLog,
  DashboardPayload, PaginatedResponse,
  CreateUserInput, CreateTenantInput, CreateRoleInput, CreateOAuthClientInput,
} from '../types/admin';
import {
  asCollection,
  asPaginated,
  asSingle,
  memberRoleRequest,
  normalizeOAuthClient,
  normalizeRole,
  normalizeTenant,
  normalizeUser,
  rolePermissionRequest,
} from './adminAdapters';

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL?.trim() ||
  (typeof window !== 'undefined' ? window.location.origin : 'http://localhost:8080');

const v1: AxiosInstance = axios.create({
  baseURL: `${API_BASE_URL}/v1`,
  headers: { 'Content-Type': 'application/json' },
  timeout: 15000,
});

v1.interceptors.request.use((config) => {
  const token = typeof window !== 'undefined' ? window.localStorage.getItem('access_token') : null;
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

v1.interceptors.response.use(
  (response) => response,
  (error: AxiosError<{ error?: string; message?: string }>) => {
    if (error.response?.status === 401 && typeof window !== 'undefined') {
      window.localStorage.removeItem('access_token');
      window.localStorage.removeItem('refresh_token');
      window.location.href = '/login?expired=1';
      return Promise.reject(new Error('登录已过期，请重新登录'));
    }
    const msg = error.response?.data?.error || error.response?.data?.message || error.message || '请求失败';
    return Promise.reject(new Error(msg));
  }
);

function getRaw(path: string, params?: Record<string, unknown>): Promise<unknown> {
  return v1.get(path, { params }).then(r => r.data);
}

function postRaw(path: string, data?: unknown): Promise<unknown> {
  return v1.post(path, data).then(r => r.data);
}

function patchRaw(path: string, data?: unknown): Promise<unknown> {
  return v1.patch(path, data).then(r => r.data);
}

function deleteRaw(path: string): Promise<unknown> {
  return v1.delete(path).then(r => r.data);
}

export const checkAdminAccess = () =>
  getRaw('/admin/users', { page_size: 1 }).then(() => undefined);

export const refreshToken = (token: string) =>
  postRaw('/auth/refresh', { refresh_token: token }).then(asSingle<{ access_token: string; refresh_token: string }>);

export const logout = () =>
  postRaw('/auth/logout', {}).then(() => undefined);

export const logoutAll = () =>
  postRaw('/auth/logout-all', {}).then(() => undefined);

export const getDashboard = () =>
  getRaw('/admin/dashboard').then(asSingle<DashboardPayload>);

export const getUsers = (params?: { search?: string; status?: string; sort?: string; tenant_id?: number; role_id?: number; page?: number; page_size?: number }) =>
  getRaw('/admin/users', params).then((body) => {
    const page = asPaginated<unknown>(body, 'users', params?.page, params?.page_size);
    return {
      ...page,
      data: page.data.map(normalizeUser),
    } satisfies PaginatedResponse<User>;
  });

export const createUser = (input: CreateUserInput) =>
  postRaw('/admin/users', input).then((body) => normalizeUser(asSingle(body)));

export const updateUser = (id: number, input: Partial<CreateUserInput>) =>
  patchRaw(`/admin/users/${id}`, input).then((body) => normalizeUser(asSingle(body)));

export const disableUser = (id: number) =>
  postRaw(`/admin/users/${id}/disable`).then(() => undefined);

export const enableUser = (id: number) =>
  postRaw(`/admin/users/${id}/enable`).then(() => undefined);

export const resetPassword = (id: number, newPassword: string) =>
  postRaw(`/admin/users/${id}/reset-password`, { new_password: newPassword }).then(() => undefined);

export const bulkDisableUsers = (userIds: number[]) =>
  postRaw('/admin/users/bulk-disable', { user_ids: userIds }).then(() => undefined);

export const bulkEnableUsers = (userIds: number[]) =>
  postRaw('/admin/users/bulk-enable', { user_ids: userIds }).then(() => undefined);

export const bulkLogoutUsers = (userIds: number[]) =>
  postRaw('/admin/users/bulk-logout', { user_ids: userIds }).then(() => undefined);

export const bulkAddUsersToTenant = (userIds: number[], tenantId: number, status = 'active') =>
  postRaw('/admin/users/bulk-add-to-tenant', { user_ids: userIds, tenant_id: tenantId, status }).then(() => undefined);

export const bulkRemoveUsersFromTenant = (userIds: number[], tenantId: number) =>
  postRaw('/admin/users/bulk-remove-from-tenant', { user_ids: userIds, tenant_id: tenantId }).then(() => undefined);

export const getTenants = (params?: { search?: string; status?: string; sort?: string; page?: number; page_size?: number }) =>
  getRaw('/admin/tenants', params).then((body) => {
    const page = asPaginated<unknown>(body, 'tenants', params?.page, params?.page_size);
    return {
      ...page,
      data: page.data.map(normalizeTenant),
    } satisfies PaginatedResponse<Tenant>;
  });

export const createTenant = (input: CreateTenantInput) =>
  postRaw('/admin/tenants', input).then((body) => normalizeTenant(asSingle(body)));

export const updateTenant = (id: number, input: Partial<CreateTenantInput>) =>
  patchRaw(`/admin/tenants/${id}`, input).then((body) => normalizeTenant(asSingle(body)));

export const addTenantMember = (tenantId: number, userId: number) =>
  postRaw(`/admin/tenants/${tenantId}/members`, { user_id: userId }).then(() => undefined);

export const removeTenantMember = (tenantId: number, userId: number) =>
  deleteRaw(`/admin/tenants/${tenantId}/members/${userId}`).then(() => undefined);

export const getRoles = (params?: { tenant_id?: number; search?: string; sort?: string; page?: number; page_size?: number }) =>
  getRaw('/admin/roles', params).then((body) => asCollection<unknown>(body, 'roles').map(normalizeRole));

export const createRole = (input: CreateRoleInput) =>
  postRaw('/admin/roles', input).then((body) => normalizeRole(asSingle(body)));

export const updateRole = (id: number, input: Partial<CreateRoleInput>) =>
  patchRaw(`/admin/roles/${id}`, input).then((body) => normalizeRole(asSingle(body)));

export const deleteRole = (id: number) =>
  deleteRaw(`/admin/roles/${id}`).then(() => undefined);

export const addRolePermission = (roleId: number, permissionId: number) =>
  postRaw(`/admin/roles/${roleId}/permissions`, rolePermissionRequest(permissionId)).then(() => undefined);

export const removeRolePermission = (roleId: number, permissionId: number) =>
  deleteRaw(`/admin/roles/${roleId}/permissions/${permissionId}`).then(() => undefined);

export const getPermissions = () =>
  getRaw('/admin/permissions').then((body) => asCollection<Permission>(body, 'permissions'));

export const getOAuthClients = () =>
  getRaw('/admin/oauth-clients').then((body) => asCollection<unknown>(body, 'oauth_clients').map(normalizeOAuthClient));

export const createOAuthClient = (input: CreateOAuthClientInput) => {
  const payload = {
    ...input,
    allowed_scopes: input.allowed_scopes ?? input.scopes ?? [],
    grant_types: input.grant_types ?? ['authorization_code', 'refresh_token'],
    token_endpoint_auth_method: input.token_endpoint_auth_method ?? 'client_secret_post',
  };
  return postRaw('/admin/oauth-clients', payload).then((body) => normalizeOAuthClient(asSingle(body)));
};

export const updateOAuthClientStatus = (clientId: string, status: OAuthClient['status']) =>
  patchRaw(`/admin/oauth-clients/${clientId}/status`, { status }).then((body) => normalizeOAuthClient(asSingle(body)));

export const rotateClientSecret = (clientId: string) =>
  postRaw(`/admin/oauth-clients/${clientId}/rotate-secret`).then(() => undefined);

export const getUserSessions = (userId: number) =>
  getRaw(`/admin/users/${userId}/sessions`).then((body) => asCollection<Session>(body, 'sessions'));

export const revokeUserSessions = (userId: number) =>
  postRaw(`/admin/users/${userId}/logout-all`).then(() => undefined);

export const getAuditLogs = (params?: { action?: string; page?: number; page_size?: number }) =>
  getRaw('/admin/audit-logs', params).then((body) => asPaginated<AuditLog>(body, 'audit_logs', params?.page, params?.page_size));

export const assignMemberRole = (memberId: number, roleId: number) =>
  postRaw(`/admin/members/${memberId}/roles`, memberRoleRequest(roleId)).then(() => undefined);

export const removeMemberRole = (memberId: number, roleId: number) =>
  deleteRaw(`/admin/members/${memberId}/roles/${roleId}`).then(() => undefined);
