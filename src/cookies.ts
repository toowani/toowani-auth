export const SESSION_COOKIE = 'tw_session';
export const STATE_COOKIE = 'tw_oauth_state';

const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;
const STATE_TTL_SECONDS = 10 * 60;

export function readCookie(request: Request, name: string): string | null {
  const header = request.headers.get('Cookie');
  if (!header) return null;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() === name) return decodeURIComponent(part.slice(eq + 1).trim());
  }
  return null;
}

// Domain=.toowani.com so the cookie rides along to every *.toowani.com
// subdomain -- that's the whole point of a single sign-on session (auth-design.md 4절).
export function buildSessionCookie(value: string): string {
  return `${SESSION_COOKIE}=${encodeURIComponent(value)}; Domain=.toowani.com; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_TTL_SECONDS}`;
}

export function clearSessionCookie(): string {
  return `${SESSION_COOKIE}=; Domain=.toowani.com; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

// Host-only (no Domain attribute) -- /login and /callback are both on
// auth.toowani.com, this never needs to leave that host.
export function buildStateCookie(value: string): string {
  return `${STATE_COOKIE}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${STATE_TTL_SECONDS}`;
}

export function clearStateCookie(): string {
  return `${STATE_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}
