export interface AuthSession {
  user_id: string;
  email: string;
  sid: string;
  tid: number;
}

export interface LoginInput {
  email: string;
  password: string;
}

export interface LoginResponse {
  access_token: string;
  refresh_token: string;
  session_id: string;
}

export interface RegisterInput {
  email: string;
  display_name: string;
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
