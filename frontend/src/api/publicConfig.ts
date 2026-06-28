import client from './client';
import type { PublicAuthConfig, RegistrationMode } from '../types/publicConfig';

const registrationModes = new Set<RegistrationMode>(['open', 'invite_only', 'disabled']);

export const defaultBrandConfig = {
  name: 'GoAuth',
  tagline: '',
  icon_text: 'G',
  icon_url: '',
};

export const defaultPublicConfig: PublicAuthConfig = {
  issuer_url: '',
  brand: defaultBrandConfig,
  registration: { mode: 'open' },
  local_login: { enabled: true },
  captcha: { provider: '', site_key: '', actions: [] },
  human_check: { provider: '', actions: [] },
  external_providers: [],
  password_policy: {
    min_length: 8,
    require_uppercase: false,
    require_lowercase: false,
    require_digit: true,
    require_special: false,
  },
  mailer: { provider: 'console' },
};

export async function getPublicConfig(): Promise<PublicAuthConfig> {
  const response = await client.get<unknown>('/public-config');
  return normalizePublicConfig(unwrapPublicConfig(response.data));
}

export function normalizePublicConfig(input: unknown): PublicAuthConfig {
  const record = asRecord(input);
  const registration = asRecord(record.registration);
  const localLogin = asRecord(record.local_login);
  const captcha = asRecord(record.captcha);
  const humanCheck = asRecord(record.human_check);
  const passwordPolicy = asRecord(record.password_policy);
  const mailer = asRecord(record.mailer);
  const brand = asRecord(record.brand);

  return {
    issuer_url: stringValue(record.issuer_url),
    brand: {
      name: stringValueOrDefault(brand.name, defaultBrandConfig.name),
      tagline: stringValueOrDefault(brand.tagline, defaultBrandConfig.tagline),
      icon_text: stringValueOrDefault(brand.icon_text, defaultBrandConfig.icon_text),
      icon_url: stringValueOrDefault(brand.icon_url, defaultBrandConfig.icon_url),
    },
    registration: {
      mode: normalizeRegistrationMode(registration.mode),
    },
    local_login: {
      enabled: typeof localLogin.enabled === 'boolean' ? localLogin.enabled : defaultPublicConfig.local_login.enabled,
    },
    captcha: {
      provider: stringValue(captcha.provider),
      site_key: stringValue(captcha.site_key),
      actions: captchaActions(captcha.actions),
    },
    human_check: {
      provider: stringValue(humanCheck.provider),
      actions: captchaActions(humanCheck.actions),
    },
    external_providers: externalProviders(record.external_providers),
    password_policy: {
      min_length: numberValue(passwordPolicy.min_length, defaultPublicConfig.password_policy.min_length),
      require_uppercase: booleanValue(passwordPolicy.require_uppercase, defaultPublicConfig.password_policy.require_uppercase),
      require_lowercase: booleanValue(passwordPolicy.require_lowercase, defaultPublicConfig.password_policy.require_lowercase),
      require_digit: booleanValue(passwordPolicy.require_digit, defaultPublicConfig.password_policy.require_digit),
      require_special: booleanValue(passwordPolicy.require_special, defaultPublicConfig.password_policy.require_special),
      history_count: optionalNumber(passwordPolicy.history_count),
    },
    mailer: {
      provider: stringValue(mailer.provider) || defaultPublicConfig.mailer.provider,
    },
  };
}

export function captchaEnabledForAction(config: PublicAuthConfig | null | undefined, action: string): boolean {
  if (!config) {
    return false;
  }
  const provider = config.captcha.provider.trim();
  const siteKey = config.captcha.site_key.trim();
  return Boolean(provider && siteKey && config.captcha.actions.includes(action.trim().toLowerCase()));
}

export function humanCheckEnabledForAction(config: PublicAuthConfig | null | undefined, action: string): boolean {
  if (!config) {
    return false;
  }
  const provider = config.human_check.provider.trim();
  return Boolean(provider && config.human_check.actions.includes(action.trim().toLowerCase()));
}

function unwrapPublicConfig(body: unknown): unknown {
  const record = asRecord(body);
  if (record.success === true && record.data !== undefined) {
    return record.data;
  }
  return body;
}

function normalizeRegistrationMode(value: unknown): RegistrationMode {
  if (typeof value !== 'string') {
    return defaultPublicConfig.registration.mode;
  }
  const mode = value.trim() as RegistrationMode;
  return registrationModes.has(mode) ? mode : defaultPublicConfig.registration.mode;
}

function externalProviders(value: unknown): PublicAuthConfig['external_providers'] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value
    .map(asRecord)
    .map((provider) => ({
      slug: stringValue(provider.slug),
      display_name: stringValue(provider.display_name),
      start_url: stringValue(provider.start_url),
    }))
    .filter((provider) => provider.slug && provider.display_name && provider.start_url);
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' ? value as Record<string, unknown> : {};
}

function stringValue(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function stringValueOrDefault(value: unknown, fallback: string): string {
  return typeof value === 'string' ? value.trim() : fallback;
}

function stringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter((item): item is string => typeof item === 'string').map((item) => item.trim()).filter(Boolean);
}

function captchaActions(value: unknown): string[] {
  return Array.from(new Set(stringArray(value).map((item) => item.toLowerCase())));
}

function booleanValue(value: unknown, fallback: boolean): boolean {
  return typeof value === 'boolean' ? value : fallback;
}

function numberValue(value: unknown, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
}

function optionalNumber(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}
