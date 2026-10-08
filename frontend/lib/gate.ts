/**
 * Perimeter gate for the dashboard — the backend's `mykronos/gate.py`, for the
 * Next server.
 *
 * **Why the dashboard needs its own.** The backend gate fronts the API, but the
 * browser never talks to the API: every call is made server-side by Next,
 * carrying `MYKRONOS_ADMIN_TOKEN`. So the backend gate only ever sees Next, and
 * Next always passes it. A dashboard published without this file would serve
 * every page — and every disposition control — with admin rights to anyone
 * who could reach it. That is why the dashboard was unpublished on 2026-09-03,
 * and this is what publishing it again requires.
 *
 * Same credential as the backend, and the Hub's three carriers and names:
 * `X-Hub-Token`, a `hub_token` cookie, or `?_token=` on a link, compared
 * against `MYKRONOS_GATE_TOKEN` - which is NOT the Hub's token, whatever the
 * shared header name suggests. Unset means disabled, as on the backend: a
 * laptop dashboard bound to 127.0.0.1 has nothing to gate.
 *
 * One path is exempt: `/api/healthz`, the container healthcheck, which reads
 * nothing and must answer before anybody has a token - the backend exempts
 * `/healthz` for the same reason. The backend's other exemptions are paths
 * that carry their own proof (ingestion tokens, webhook HMAC); none of those
 * are served here. Next's build assets pass by the proxy matcher: they are the
 * same public bytes for everybody.
 */

export const TOKEN_HEADER = "x-hub-token";
export const TOKEN_COOKIE = "hub_token";
export const TOKEN_QUERY = "_token";

/** Exact match: `/api/healthz/anything` is not the healthcheck. */
export function isExempt(path: string): boolean {
  return path === "/api/healthz";
}

/** One day, as the backend's cookie. */
export const COOKIE_MAX_AGE = 86_400;

export interface Presented {
  header: string | null;
  cookie: string | undefined;
  query: string | null;
}

/** The first carrier that holds anything, in the backend's order. */
export function presentedToken(p: Presented): string {
  return p.header || p.cookie || p.query || "";
}

/**
 * Constant-time equality. Both sides are hashed first so the comparison runs
 * over equal-length digests: a plain loop would return early on a length
 * mismatch and tell a caller how long the token is.
 */
export async function tokensMatch(presented: string, expected: string): Promise<boolean> {
  if (!presented || !expected) return false;
  const enc = new TextEncoder();
  const [a, b] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(presented)),
    crypto.subtle.digest("SHA-256", enc.encode(expected)),
  ]);
  const x = new Uint8Array(a);
  const y = new Uint8Array(b);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}
