import type { OAuthClient, PaginatedResponse, Role, Tenant, User } from '../types/admin';

type UnknownRecord = Record<string, unknown>;

function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function unwrapData(body: unknown): unknown {
  if (isRecord(body) && 'data' in body) {
    return body.data;
  }
  return body;
}

export function asSingle<T>(body: unknown): T {
  return unwrapData(body) as T;
}

export function asCollection<T>(body: unknown, key: string): T[] {
  const data = unwrapData(body);
  if (Array.isArray(data)) {
    return data as T[];
  }
  if (isRecord(data)) {
    const named = data[key];
    if (Array.isArray(named)) {
      return named as T[];
    }
    if (Array.isArray(data.data)) {
      return data.data as T[];
    }
  }
  throw new Error(`响应格式不匹配：缺少 ${key} 列表`);
}

export function asPaginated<T>(body: unknown, key: string, fallbackPage = 1, fallbackPageSize?: number): PaginatedResponse<T> {
  const data = unwrapData(body);
  const items = asCollection<T>(body, key);
  const meta = isRecord(data) ? data : {};
  const page = Number(meta.page ?? fallbackPage) || fallbackPage;
  const pageSize = Number(meta.page_size ?? fallbackPageSize ?? items.length) || items.length;
  const total = Number(meta.total ?? items.length) || items.length;

  return {
    data: items,
    total,
    page,
    page_size: pageSize,
  };
}

function stringValue(value: unknown, fallback = ''): string {
  return typeof value === 'string' ? value : fallback;
}

function numberValue(value: unknown, fallback = 0): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

export function normalizeUser(raw: unknown): User {
  const record = isRecord(raw) ? raw : {};
  const email = stringValue(record.email);
  const displayName = stringValue(record.display_name, email);

  return {
    id: numberValue(record.id),
    display_name: displayName,
    email,
    role: stringValue(record.role, '-'),
    tenant: stringValue(record.tenant, '-'),
    status: stringValue(record.status, 'active') as User['status'],
    email_verified: Boolean(record.email_verified ?? record.email_verified_at),
    last_login: stringValue(record.last_login, ''),
    created_at: stringValue(record.created_at),
  };
}

export function normalizeTenant(raw: unknown): Tenant {
  const record = isRecord(raw) ? raw : {};

  return {
    id: numberValue(record.id),
    name: stringValue(record.name),
    slug: stringValue(record.slug),
    members_count: numberValue(record.members_count),
    status: stringValue(record.status, 'active') as Tenant['status'],
    plan: stringValue(record.plan, '-'),
    created_at: stringValue(record.created_at),
    default_policy: stringValue(record.default_policy, '-'),
  };
}

export function normalizeRole(raw: unknown): Role {
  const record = isRecord(raw) ? raw : {};
  const tenantID = numberValue(record.tenant_id);

  return {
    id: numberValue(record.id),
    tenant_id: tenantID,
    code: stringValue(record.code),
    name: stringValue(record.name),
    description: stringValue(record.description),
    users_count: numberValue(record.users_count),
    permissions_count: numberValue(record.permissions_count),
    tenant_scope: stringValue(record.tenant_scope, tenantID ? `tenant:${tenantID}` : 'global'),
    is_system: Boolean(record.is_system),
  };
}

export function normalizeOAuthClient(raw: unknown): OAuthClient {
  const record = isRecord(raw) ? raw : {};
  const redirectURIs = Array.isArray(record.redirect_uris) ? record.redirect_uris : [];
  const scopes = Array.isArray(record.scopes) ? record.scopes : Array.isArray(record.allowed_scopes) ? record.allowed_scopes : [];

  return {
    client_id: stringValue(record.client_id),
    name: stringValue(record.name),
    redirect_uris: redirectURIs as string[],
    scopes: scopes as string[],
    status: stringValue(record.status, 'active') as OAuthClient['status'],
    auto_provision_members: Boolean(record.auto_provision_members),
    last_rotated: stringValue(record.last_rotated, stringValue(record.updated_at, '-')),
  };
}

export function rolePermissionRequest(permissionId: number) {
  return { permission_ids: [permissionId] };
}

export function memberRoleRequest(roleId: number) {
  return { role_ids: [roleId] };
}
