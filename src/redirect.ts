export const DEFAULT_REDIRECT = 'https://toowani.com';

// Open-redirect guard (auth-design.md 5절): must be an absolute https URL
// whose hostname is exactly toowani.com or ends with ".toowani.com". The
// leading dot in endsWith is what blocks "toowani.com.evil.com" -- that
// hostname ends with ".evil.com", not ".toowani.com".
export function isAllowedToowaniHost(hostname: string): boolean {
  return hostname === 'toowani.com' || hostname.endsWith('.toowani.com');
}

export function sanitizeRedirect(raw: string | null): string {
  if (!raw) return DEFAULT_REDIRECT;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return DEFAULT_REDIRECT;
  }
  if (url.protocol !== 'https:') return DEFAULT_REDIRECT;
  if (!isAllowedToowaniHost(url.hostname)) return DEFAULT_REDIRECT;
  return raw;
}

// Same host rule as redirect, applied to a request Origin for CORS on /me.
export function isAllowedOrigin(origin: string | null): boolean {
  if (!origin) return false;
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    return false;
  }
  return url.protocol === 'https:' && isAllowedToowaniHost(url.hostname);
}
