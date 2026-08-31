export interface Env {
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  SESSION_SECRET: string;
}

export interface SessionClaims {
  email: string;
  iat: number;
  exp: number;
}
