export interface User {
  id: number;
  username: string;
  nickname: string;
  display_name: string;
  email: string;
  role: string;
  tenant: string;
  status: 'active' | 'disabled' | 'inactive' | 'pending' | 'suspended';
  email_verified: boolean;
  last_login: string;
  created_at: string;
}

export interface Tenant {
  id: number;
  name: string;
  slug: string;
  members_count: number;
  roles_count: number;
  oauth_clients_count: number;
  status: 'active' | 'disabled' | 'trial' | 'suspended';
  plan: string;
  created_at: string;
  default_policy: string;
}

export interface Role {
  id: number;
  tenant_id: number;
  code: string;
  name: string;
  description: string;
  users_count: number;
  permissions_count: number;
  permission_ids: number[];
  tenant_scope: string;
  is_system: boolean;
}

export interface Permission {
  id: number;
  resource: string;
  action: string;
  description?: string;
}

export interface OAuthClient {
  client_id: string;
  name: string;
  redirect_uris: string[];
  scopes: string[];
  status: 'active' | 'disabled';
  auto_provision_members: boolean;
  last_rotated: string;
}

export interface Session {
  id: string;
  user_id: number;
  tenant_id: number;
  user: string;
  client: string;
  ip: string;
  user_agent: string;
  created_at: string;
  expires_at: string;
  status: string;
}

export interface AuditLog {
  id: number;
  action: string;
  actor: string;
  target: string;
  time: string;
  ip: string;
  status: 'success' | 'failed';
}

export interface DashboardStats {
  total_users: number;
  active_sessions: number;
  total_tenants: number;
  total_oauth_clients: number;
  users_change: string;
  sessions_change: string;
  tenants_change: string;
  clients_change: string;
}

export interface DashboardPayload {
  stats: DashboardStats;
  recent_logins: RecentLogin[];
  permission_changes: PermissionChange[];
  alerts: Alert[];
}

export interface RecentLogin {
  id: number;
  user: string;
  ip: string;
  time: string;
  status: 'success' | 'failed' | 'blocked';
  location: string;
}

export interface PermissionChange {
  user: string;
  action: string;
  time: string;
}

export interface Alert {
  user: string;
  ip: string;
  time: string;
}

export type RuntimeConfigStatus = 'ok' | 'warning' | 'error';

export interface RuntimeConfigItem {
  key: string;
  group: string;
  status: RuntimeConfigStatus;
  configured: boolean;
  required: boolean;
  secret: boolean;
  public_config: boolean;
  source: string;
  message: string;
}

export interface RuntimeConfigGroup {
  key: string;
  items: RuntimeConfigItem[];
}

export interface RuntimeConfigPayload {
  environment: string;
  groups: RuntimeConfigGroup[];
}

export interface CreateUserInput {
  username?: string;
  nickname?: string;
  email: string;
  display_name?: string;
  password: string;
  status?: string;
  tenant_id?: number;
  role_id?: number;
}

export interface CreateTenantInput {
  name: string;
  slug: string;
  status?: string;
}

export interface CreateRoleInput {
  tenant_id: number;
  name: string;
  code: string;
  description: string;
  is_system?: boolean;
}

export interface CreateOAuthClientInput {
  tenant_id: number;
  client_id: string;
  client_secret: string;
  name: string;
  redirect_uris: string[];
  scopes?: string[];
  allowed_scopes?: string[];
  grant_types?: string[];
  token_endpoint_auth_method?: string;
  auto_provision_members?: boolean;
}

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  page_size: number;
}
