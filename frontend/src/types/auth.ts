export interface AuthSession {
  user_id: string;
  email: string;
  sid: string;
  tid: number;
}

export interface LoginInput {
  identifier: string;
  password: string;
}

export interface LoginTokenResponse {
  access_token: string;
  refresh_token: string;
  session_id: string;
}

export interface LoginTwoFactorChallengeResponse {
  id?: number;
  email?: string;
  two_factor_required: true;
  challenge_id: string;
  expires_in?: number;
  methods?: string[];
}

export type LoginResponse = LoginTokenResponse | LoginTwoFactorChallengeResponse;

export interface LoginTwoFactorVerifyInput {
  challenge_id: string;
  code?: string;
  recovery_code?: string;
}

export interface RegisterInput {
  username: string;
  nickname: string;
  email: string;
  display_name?: string;
  password: string;
  email_code: string;
}

export interface SendCodeInput {
  purpose: string;
  email: string;
}

export interface ApiSuccessResponse<T> {
  success: boolean;
  data: T;
}

export interface ApiError {
  error: string;
}
