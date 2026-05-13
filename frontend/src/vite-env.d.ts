/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_BASE_URL?: string;
  readonly VITE_CAPTCHA_PROVIDER?: string;
  readonly VITE_CAPTCHA_SITE_KEY?: string;
  readonly VITE_OIDC_ISSUER_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
