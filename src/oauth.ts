import type { Env } from './types';

const GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const GOOGLE_USERINFO_URL = 'https://www.googleapis.com/oauth2/v3/userinfo';

// Fixed OAuth redirect_uri, registered once in Google Console -- distinct
// from the app-level `redirect` param, which is where we send the user
// after /callback finishes (auth-design.md 3, 9절).
export const CALLBACK_URL = 'https://auth.toowani.com/callback';

export function buildGoogleAuthUrl(env: Env, state: string): string {
  const params = new URLSearchParams({
    client_id: env.GOOGLE_CLIENT_ID,
    redirect_uri: CALLBACK_URL,
    response_type: 'code',
    scope: 'openid email',
    state,
    prompt: 'select_account',
  });
  return `${GOOGLE_AUTH_URL}?${params.toString()}`;
}

// Access-token + userinfo round trip instead of decoding Google's id_token
// JWT ourselves -- that would require fetching and caching Google's JWKS to
// verify an RS256 signature, which this scope doesn't need.
export async function resolveGoogleEmail(env: Env, code: string): Promise<string | null> {
  const tokenRes = await fetch(GOOGLE_TOKEN_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code,
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      redirect_uri: CALLBACK_URL,
      grant_type: 'authorization_code',
    }),
  });
  if (!tokenRes.ok) return null;

  const tokenJson = (await tokenRes.json()) as { access_token?: string };
  if (!tokenJson.access_token) return null;

  const userRes = await fetch(GOOGLE_USERINFO_URL, {
    headers: { Authorization: `Bearer ${tokenJson.access_token}` },
  });
  if (!userRes.ok) return null;

  const userJson = (await userRes.json()) as { email?: string; email_verified?: boolean };
  if (!userJson.email || userJson.email_verified === false) return null;

  return userJson.email.toLowerCase();
}
