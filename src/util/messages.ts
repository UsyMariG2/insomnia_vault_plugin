/**
 * Standardized user-visible status strings returned from template tags.
 *
 * Insomnia renders the return value of a template tag directly into the
 * request (header value, body, etc). Empty strings disappear silently —
 * which the legacy plugin did and which made debugging painful. We always
 * return a `-- kind: detail --` envelope so users can tell at a glance that
 * the tag fired and what state it's in.
 */

export type TagStatus =
  | "token-disabled"
  | "token-in-progress"
  | "token-error"
  | "token-error-cached"
  | "vault-missing"
  | "vault-locked"
  | "missing-config";

export function format(kind: TagStatus, detail = ""): string {
  return detail ? `-- plus4u-oidc-v2 ${kind}: ${detail} --` : `-- plus4u-oidc-v2 ${kind} --`;
}

export function formatIsoDate(date: Date | number): string {
  const d = date instanceof Date ? date : new Date(date * 1000);
  return d.toISOString();
}
