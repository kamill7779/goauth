import type { OAuthClient, PaginatedResponse, Role, Session, Tenant, User } from '../types/admin';

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

function field(record: UnknownRecord, ...keys: string[]): unknown {
  for (const key of keys) {
    if (key in record) {
      return record[key];
    }
  }
  return undefined;
}

function stringField(record: UnknownRecord, keys: string[], fallback = ''): string {
  return stringValue(field(record, ...keys), fallback);
}

function numberField(record: UnknownRecord, keys: string[], fallback = 0): number {
  return numberValue(field(record, ...keys), fallback);
}

function booleanField(record: UnknownRecord, keys: string[], fallback = false): boolean {
  const value = field(record, ...keys);
  return value === undefined ? fallback : Boolean(value);
}

function numberArrayField(record: UnknownRecord, keys: string[]): number[] {
  const value = field(record, ...keys);
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map(Number).filter(Number.isFinite);
}

export function normalizeUser(raw: unknown): User {
  const record = isRecord(raw) ? raw : {};
  const email = stringField(record, ['email', 'Email']);
  const displayName = stringField(record, ['display_name', 'DisplayName'], email);
  const username = stringField(record, ['username', 'Username']);
  const nickname = stringField(record, ['nickname', 'Nickname'], displayName);

  return {
    id: numberField(record, ['id', 'ID']),
    username,
    nickname,
    display_name: displayName,
    email,
    role: stringField(record, ['role'], '-'),
    tenant: stringField(record, ['tenant'], '-'),
    status: stringField(record, ['status', 'Status'], 'active') as User['status'],
    email_verified: booleanField(record, ['email_verified', 'EmailVerified']) || Boolean(field(record, 'email_verified_at', 'EmailVerifiedAt')),
    last_login: stringField(record, ['last_login', 'LastLogin'], ''),
    created_at: stringField(record, ['created_at', 'CreatedAt']),
  };
}

export function normalizeTenant(raw: unknown): Tenant {
  const record = isRecord(raw) ? raw : {};

  return {
    id: numberField(record, ['id', 'ID']),
    name: stringField(record, ['name', 'Name']),
    slug: stringField(record, ['slug', 'Slug']),
    members_count: numberField(record, ['members_count', 'MembersCount']),
    roles_count: numberField(record, ['roles_count', 'RolesCount']),
    oauth_clients_count: numberField(record, ['oauth_clients_count', 'OAuthClientsCount']),
    status: stringField(record, ['status', 'Status'], 'active') as Tenant['status'],
    plan: stringField(record, ['plan', 'Plan'], '-'),
    created_at: stringField(record, ['created_at', 'CreatedAt']),
    default_policy: stringField(record, ['default_policy', 'DefaultPolicy'], '-'),
  };
}

export function normalizeRole(raw: unknown): Role {
  const record = isRecord(raw) ? raw : {};
  const tenantID = numberField(record, ['tenant_id', 'TenantID']);
  const permissionIDs = numberArrayField(record, ['permission_ids', 'PermissionIDs']);

  return {
    id: numberField(record, ['id', 'ID']),
    tenant_id: tenantID,
    code: stringField(record, ['code', 'Code']),
    name: stringField(record, ['name', 'Name']),
    description: stringField(record, ['description', 'Description']),
    users_count: numberField(record, ['users_count', 'UsersCount']),
    permissions_count: numberField(record, ['permissions_count', 'PermissionsCount'], permissionIDs.length),
    permission_ids: permissionIDs,
    tenant_scope: stringField(record, ['tenant_scope', 'TenantScope'], tenantID ? `tenant:${tenantID}` : 'global'),
    is_system: booleanField(record, ['is_system', 'IsSystem']),
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

export function normalizeSession(raw: unknown): Session {
  const record = isRecord(raw) ? raw : {};

  return {
    id: stringField(record, ['id', 'ID']),
    user_id: numberField(record, ['user_id', 'UserID']),
    tenant_id: numberField(record, ['tenant_id', 'TenantID']),
    user: stringField(record, ['user', 'email', 'Email']),
    client: stringField(record, ['client', 'client_id', 'ClientID'], 'GoAuth'),
    ip: stringField(record, ['ip', 'ip_address', 'IPAddress'], '-'),
    user_agent: stringField(record, ['user_agent', 'UserAgent']),
    created_at: stringField(record, ['created_at', 'CreatedAt']),
    expires_at: stringField(record, ['expires_at', 'ExpiresAt']),
    status: stringField(record, ['status', 'Status'], 'active'),
  };
}

export function rolePermissionRequest(permissionId: number) {
  return { permission_ids: [permissionId] };
}

export function memberRoleRequest(roleId: number) {
  return { role_ids: [roleId] };
}
