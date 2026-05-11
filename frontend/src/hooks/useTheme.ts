import { useCallback, useEffect, useState } from 'react';

export type ThemePreference = 'light' | 'dark' | 'system';
export type ResolvedTheme = 'light' | 'dark';

const STORAGE_KEY = 'goauth-theme';
const THEME_EVENT = 'goauth-theme-change';

function isPreference(value: unknown): value is ThemePreference {
  return value === 'light' || value === 'dark' || value === 'system';
}

function readStoredPreference(): ThemePreference {
  if (typeof window === 'undefined') {
    return 'system';
  }
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    return isPreference(raw) ? raw : 'system';
  } catch {
    return 'system';
  }
}

function systemTheme(): ResolvedTheme {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
    return 'light';
  }
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function resolveTheme(preference: ThemePreference): ResolvedTheme {
  return preference === 'system' ? systemTheme() : preference;
}

function applyTheme(resolved: ResolvedTheme) {
  if (typeof document === 'undefined') {
    return;
  }
  document.documentElement.dataset.theme = resolved;
}

interface UseThemeResult {
  preference: ThemePreference;
  resolved: ResolvedTheme;
  setPreference: (next: ThemePreference) => void;
}

export function useTheme(): UseThemeResult {
  const [preference, setPreferenceState] = useState<ThemePreference>(() => readStoredPreference());
  const [resolved, setResolved] = useState<ResolvedTheme>(() => resolveTheme(readStoredPreference()));

  useEffect(() => {
    applyTheme(resolved);
  }, [resolved]);

  // Track the system colour scheme so that `preference === 'system'` follows it live.
  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
      return;
    }
    const media = window.matchMedia('(prefers-color-scheme: dark)');
    const handle = () => {
      if (preference === 'system') {
        setResolved(media.matches ? 'dark' : 'light');
      }
    };
    if (typeof media.addEventListener === 'function') {
      media.addEventListener('change', handle);
      return () => media.removeEventListener('change', handle);
    }
    // Safari < 14 fallback
    media.addListener(handle);
    return () => media.removeListener(handle);
  }, [preference]);

  // Cross-tab + cross-component sync via the storage event and a custom event.
  useEffect(() => {
    if (typeof window === 'undefined') {
      return;
    }
    const handleStorage = (event: StorageEvent) => {
      if (event.key !== STORAGE_KEY) {
        return;
      }
      const next = isPreference(event.newValue) ? event.newValue : 'system';
      setPreferenceState(next);
      setResolved(resolveTheme(next));
    };
    const handleLocal = (event: Event) => {
      const detail = (event as CustomEvent<ThemePreference>).detail;
      if (isPreference(detail)) {
        setPreferenceState(detail);
        setResolved(resolveTheme(detail));
      }
    };
    window.addEventListener('storage', handleStorage);
    window.addEventListener(THEME_EVENT, handleLocal);
    return () => {
      window.removeEventListener('storage', handleStorage);
      window.removeEventListener(THEME_EVENT, handleLocal);
    };
  }, []);

  const setPreference = useCallback((next: ThemePreference) => {
    setPreferenceState(next);
    setResolved(resolveTheme(next));
    if (typeof window === 'undefined') {
      return;
    }
    try {
      window.localStorage.setItem(STORAGE_KEY, next);
    } catch {
      /* storage may be unavailable (private mode); ignore */
    }
    window.dispatchEvent(new CustomEvent<ThemePreference>(THEME_EVENT, { detail: next }));
  }, []);

  return { preference, resolved, setPreference };
}
