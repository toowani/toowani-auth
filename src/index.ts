import type { Env, SessionClaims } from './types';
import { signJWT, verifyJWT } from './jwt';
import {
  readCookie,
  buildSessionCookie,
  clearSessionCookie,
  buildStateCookie,
  clearStateCookie,
  SESSION_COOKIE,
  STATE_COOKIE,
} from './cookies';
import { sanitizeRedirect, isAllowedOrigin, DEFAULT_REDIRECT } from './redirect';
import { isAuthorized } from './acl';
import { buildGoogleAuthUrl, resolveGoogleEmail } from './oauth';

const STATE_TTL_SECONDS = 10 * 60;
const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;

interface OAuthStateClaims {
  state: string;
  redirect: string;
  exp: number;
}

async function readSession(request: Request, env: Env): Promise<SessionClaims | null> {
  const cookie = readCookie(request, SESSION_COOKIE);
  if (!cookie) return null;
  return verifyJWT<SessionClaims>(cookie, env.SESSION_SECRET);
}

async function handleLogin(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const redirect = sanitizeRedirect(url.searchParams.get('redirect'));
  const state = crypto.randomUUID();

  const now = Math.floor(Date.now() / 1000);
  const stateToken = await signJWT<OAuthStateClaims>(
    { state, redirect, exp: now + STATE_TTL_SECONDS },
    env.SESSION_SECRET
  );

  const headers = new Headers({ Location: buildGoogleAuthUrl(env, state) });
  headers.append('Set-Cookie', buildStateCookie(stateToken));
  return new Response(null, { status: 302, headers });
}

async function handleCallback(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  if (!code || !state) return new Response('missing code or state', { status: 400 });

  const stateCookie = readCookie(request, STATE_COOKIE);
  if (!stateCookie) return new Response('missing state cookie', { status: 400 });

  const claims = await verifyJWT<OAuthStateClaims>(stateCookie, env.SESSION_SECRET);
  if (!claims || claims.state !== state) return new Response('state mismatch', { status: 400 });

  const email = await resolveGoogleEmail(env, code);
  if (!email) return new Response('google authentication failed', { status: 400 });

  const now = Math.floor(Date.now() / 1000);
  const sessionToken = await signJWT<SessionClaims>(
    { email, iat: now, exp: now + SESSION_TTL_SECONDS },
    env.SESSION_SECRET
  );

  const headers = new Headers({ Location: claims.redirect });
  headers.append('Set-Cookie', buildSessionCookie(sessionToken));
  headers.append('Set-Cookie', clearStateCookie());
  return new Response(null, { status: 302, headers });
}

async function handleLogout(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const redirect = url.searchParams.get('redirect')
    ? sanitizeRedirect(url.searchParams.get('redirect'))
    : DEFAULT_REDIRECT;

  const headers = new Headers({ Location: redirect });
  headers.append('Set-Cookie', clearSessionCookie());
  return new Response(null, { status: 302, headers });
}

async function handleMe(request: Request, env: Env): Promise<Response> {
  const session = await readSession(request, env);
  // "{}" rather than an empty body on 401 -- purely so a browser opening
  // this URL directly shows the JSON instead of Chrome's blank error page.
  // The 401 status is still the actual contract; no consumer reads this body.
  const body = session ? JSON.stringify({ email: session.email }) : '{}';

  const headers = new Headers({ 'content-type': 'application/json' });
  // CORS applies only here (auth-design.md 7절) -- /authorize is a
  // server-to-server call and needs none.
  const origin = request.headers.get('Origin');
  if (isAllowedOrigin(origin)) {
    headers.set('Access-Control-Allow-Origin', origin as string);
    headers.set('Access-Control-Allow-Credentials', 'true');
    headers.set('Vary', 'Origin');
  }

  return new Response(body, { status: session ? 200 : 401, headers });
}

async function handleAuthorize(request: Request, env: Env): Promise<Response> {
  const session = await readSession(request, env);
  if (!session) return new Response(null, { status: 401 });

  const url = new URL(request.url);
  const host = url.searchParams.get('host') || '';
  const path = url.searchParams.get('path') || '/';

  const allowed = isAuthorized(session.email, host, path);
  const headers = new Headers({ 'content-type': 'application/json' });
  return new Response(JSON.stringify({ email: session.email }), {
    status: allowed ? 200 : 403,
    headers,
  });
}

export default {
  async fetch(request, env): Promise<Response> {
    const url = new URL(request.url);
    switch (url.pathname) {
      case '/login':
        return handleLogin(request, env);
      case '/callback':
        return handleCallback(request, env);
      case '/logout':
        return handleLogout(request);
      case '/me':
        return handleMe(request, env);
      case '/authorize':
        return handleAuthorize(request, env);
      default:
        return new Response('Not Found', { status: 404 });
    }
  },
} satisfies ExportedHandler<Env>;
