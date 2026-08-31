import aclData from '../acl.json';

interface ACLRule {
  host: string;
  pathPrefix: string;
  emails: string[];
}

interface ACLFile {
  admins: string[];
  rules: ACLRule[];
}

const acl = aclData as ACLFile;
const admins = new Set(acl.admins.map((e) => e.toLowerCase()));

// deny-by-default (auth-design.md 6절): no matching rule, or a matching
// rule whose emails list doesn't include the caller, both fall through to false.
export function isAuthorized(email: string, host: string, path: string): boolean {
  const normalized = email.toLowerCase();
  if (admins.has(normalized)) return true;

  const rule = acl.rules.find((r) => r.host === host && path.startsWith(r.pathPrefix));
  if (!rule) return false;

  return rule.emails.map((e) => e.toLowerCase()).includes(normalized);
}
