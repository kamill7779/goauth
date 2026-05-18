export interface AccountUser {
  id: number;
  email: string;
  username: string;
  nickname: string;
  display_name: string;
  avatar_url: string;
  locale: string;
  timezone: string;
  status: string;
  email_verified: boolean;
  created_at: string;
}

export interface AccountMe {
  user: AccountUser;
  session: {
    id: string;
    tenant_id: number;
  };
  is_admin: boolean;
}

export interface AccountSession {
  id: string;
  tenant_id: number;
  client: string;
  ip: string;
  user_agent: string;
  created_at: string;
  expires_at: string;
  revoked_at?: string | null;
  status: 'active' | 'revoked' | 'expired' | 'inactive' | string;
  current: boolean;
}

export interface LoginMethod {
  id: string;
  name: string;
  status: 'primary' | 'verified' | 'bound' | 'unbound';
  bound: boolean;
  lastUsed?: string | null;
  desc: string;
  verified?: boolean;
  disabled?: boolean;
  disabledReason?: string;
}

export interface AuthorizedApp {
  id: string;
  name: string;
  desc: string;
  grantedAt: string;
  lastAccess: string;
  scopes: string[];
  color: string;
  initial: string;
}

export interface SecurityAlert {
  id: string;
  level: 'danger' | 'warning' | 'info';
  title: string;
  desc: string;
  action: string;
  visible: boolean;
}

export interface IdentityActivity {
  id: number;
  type: 'security' | 'auth' | 'binding' | 'profile';
  title: string;
  desc: string;
  time: string;
}
