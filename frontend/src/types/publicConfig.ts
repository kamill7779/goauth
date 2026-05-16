export type RegistrationMode = 'open' | 'invite_only' | 'disabled';

export interface PublicBrandConfig {
  name: string;
  tagline: string;
  icon_text: string;
  icon_url: string;
}

export interface PublicAuthConfig {
  issuer_url: string;
  brand: PublicBrandConfig;
  registration: {
    mode: RegistrationMode;
  };
  local_login: {
    enabled: boolean;
  };
  captcha: {
    provider: string;
    site_key: string;
    actions: string[];
  };
  external_providers: Array<{
    slug: string;
    display_name: string;
    start_url: string;
  }>;
  password_policy: {
    min_length: number;
    require_uppercase: boolean;
    require_lowercase: boolean;
    require_digit: boolean;
    require_special: boolean;
    history_count?: number;
  };
  mailer: {
    provider: string;
  };
}
