import type { AccountUser, AccountMe, AccountSession, LoginMethod, AuthorizedApp, IdentityActivity } from '../../../types/account';
import type { ToastItem } from '../AccountToast';

export interface SharedTabProps {
  user: AccountUser;
  account: AccountMe | null;
  sessions: AccountSession[];
  loginMethods: LoginMethod[];
  setLoginMethods: React.Dispatch<React.SetStateAction<LoginMethod[]>>;
  authorizedApps: AuthorizedApp[];
  setAuthorizedApps: React.Dispatch<React.SetStateAction<AuthorizedApp[]>>;
  identityActivities: IdentityActivity[];
  twoFAEnabled: boolean;
  setTwoFAEnabled: React.Dispatch<React.SetStateAction<boolean>>;
  securityScore: number;
  setSecurityScore: React.Dispatch<React.SetStateAction<number>>;
  showToast: (message: string, type?: ToastItem['type']) => void;
  refresh: () => void;
  setTab: (tab: 'overview' | 'profile' | 'login' | 'security' | 'apps') => void;
}
