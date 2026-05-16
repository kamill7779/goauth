export interface AccountUser {
  id: number;
  email: string;
  username: string;
  nickname: string;
  display_name: string;
  avatar_url: string;
  locale: string;
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
