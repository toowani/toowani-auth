export interface Env {
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  SESSION_SECRET: string;
}

export interface SessionClaims {
  email: string;
  // Optional -- Google doesn't always return these (auth-design.md 14절),
  // and older sessions issued before this field existed won't have them.
  name?: string;
  picture?: string;
  iat: number;
  exp: number;
}
