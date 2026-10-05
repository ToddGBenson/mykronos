import { NextResponse, type NextRequest } from "next/server";

import {
  COOKIE_MAX_AGE,
  TOKEN_COOKIE,
  TOKEN_HEADER,
  TOKEN_QUERY,
  isExempt,
  presentedToken,
  tokensMatch,
} from "./lib/gate";

/**
 * Every request passes the perimeter gate (`lib/gate.ts`) first; only then
 * does a page get its CSP. The gate covers what the CSP matcher used to skip
 * - `/api/*` route handlers and prefetches - because those carry the admin
 * token to the backend just as pages do.
 */
export async function proxy(request: NextRequest) {
  const expected = process.env.MYKRONOS_GATE_TOKEN ?? "";
  if (expected && !isExempt(request.nextUrl.pathname)) {
    const url = request.nextUrl;
    const fromLink = url.searchParams.get(TOKEN_QUERY);
    const presented = presentedToken({
      header: request.headers.get(TOKEN_HEADER),
      cookie: request.cookies.get(TOKEN_COOKIE)?.value,
      query: fromLink,
    });
    if (!(await tokensMatch(presented, expected))) {
      // Terse and identical for absent, wrong and malformed, as the backend.
      return NextResponse.json(
        { detail: "Not authorised for this host." },
        { status: 401, headers: { "WWW-Authenticate": 'X-Hub-Token realm="mykronos"' } },
      );
    }
    if (fromLink) {
      // Followed a link: keep the token out of the address bar, history and
      // Referer. HttpOnly because nothing in the browser reads it.
      //
      // The redirect is built from the request's own Host / X-Forwarded-*
      // headers, not `nextUrl`: behind the tunnel `nextUrl` can carry the
      // container's bind address, and Next refuses a relative Location.
      const proto = (
        request.headers.get("x-forwarded-proto") ?? url.protocol.replace(":", "")
      ).toLowerCase();
      const host = request.headers.get("x-forwarded-host") ?? request.headers.get("host") ?? url.host;
      const clean = new URL(url.pathname, `${proto}://${host}`);
      url.searchParams.forEach((value, key) => {
        if (key !== TOKEN_QUERY) clean.searchParams.append(key, value);
      });
      const response = NextResponse.redirect(clean, 302);
      response.cookies.set(TOKEN_COOKIE, presented, {
        path: "/",
        sameSite: "lax",
        maxAge: COOKIE_MAX_AGE,
        httpOnly: true,
        secure: proto === "https",
      });
      return response;
    }
  }

  const path = request.nextUrl.pathname;
  const prefetch =
    request.headers.has("next-router-prefetch") || request.headers.get("purpose") === "prefetch";
  if (path === "/api" || path.startsWith("/api/") || prefetch) {
    return NextResponse.next();
  }
  return withCsp(request);
}

/**
 * The Content-Security-Policy, with a per-request nonce.
 *
 * **The static CSP this replaces was breaking the application.**
 * `next.config.ts` served `script-src 'self'` with no nonce and no
 * `'unsafe-inline'`, and the App Router needs inline scripts to hydrate. The
 * browser blocked them, React threw #412, and every client component on the
 * site was inert: the filter dropdowns, the scan buttons, the disposition
 * controls, the surface declaration form. The page rendered and did nothing.
 *
 * That header was verified as *present* earlier and never verified as
 * *harmless*, which is the whole lesson: a security header that ships is not
 * the same as a security header that works, and the check for the second one
 * is opening the console.
 *
 * A nonce rather than `'unsafe-inline'`. `'unsafe-inline'` would fix hydration
 * by permitting every inline script on the page, including one an attacker
 * injected — which is the exact attack the directive exists to stop, so it
 * would leave a CSP that passes a scanner and defends nothing. The nonce is
 * unguessable and regenerated per request, so only the scripts Next.js emitted
 * for *this* response can run.
 *
 * Nonces require dynamic rendering, because Next.js injects them during
 * server-side rendering from the request's own CSP header. Every page here is
 * already `force-dynamic` — they all read live data — so nothing is given up.
 */
function withCsp(request: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");

  // React uses `eval` in development to reconstruct server-side error stacks
  // in the browser. It does not in production, and neither does Next.js.
  const isDev = process.env.NODE_ENV === "development";

  // Styles are split across two directives, and the split is the whole point.
  //
  // The history, because both previous attempts were wrong in instructive
  // ways. First `style-src 'self' 'nonce-…'`, straight from the Next.js CSP
  // guide: that blocked 96 inline styles, because a nonce in a directive makes
  // the browser *ignore* `'unsafe-inline'` in the same directive, and a style
  // *attribute* has nowhere to put a nonce. Then `style-src 'self'
  // 'unsafe-inline'`, which worked and permitted every `<style>` element an
  // attacker could inject — and the platform's own DAST lane opened 46 medium
  // findings against it (ZAP-10055) the next day. Being scanned by the thing
  // you are building is a short feedback loop.
  //
  // Splitting resolves what looked like a straight tradeoff, because the two
  // cases genuinely differ:
  //
  //   style-src      → `<style>` elements. Next.js stamps the nonce onto the
  //                    inline styles it generates (its CSP guide says so
  //                    explicitly), and Tailwind ships an external file that
  //                    `'self'` covers. Nothing here needs the exemption, so
  //                    an injected `<style>` block is now refused.
  //   style-src-attr → `style=""` attributes. React writes these for the EPSS
  //                    bars and every computed width, they cannot carry a
  //                    nonce, and no build step removes them. Genuinely
  //                    required rather than merely convenient.
  //
  // `style-src-attr` has been Baseline since December 2022. A browser older
  // than that ignores it and falls back to `style-src` — stricter, not looser,
  // so the failure mode is an unstyled bar rather than an open door.
  //
  // `script-src` stays at 'self' plus the nonce. The console on the public
  // hostname reports a blocked `static.cloudflareinsights.com` beacon — that
  // is the tunnel injecting analytics, it is blocked deliberately, and adding
  // the origin to make the error go away would be the only edit to this header
  // that materially weakened it (D-099). The `attribution-reporting`
  // Permissions-Policy warning is from the same source and needs nothing.
  const csp = `
    default-src 'self';
    script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isDev ? " 'unsafe-eval'" : ""};
    style-src 'self' 'nonce-${nonce}';
    style-src-attr 'unsafe-inline';
    img-src 'self' blob: data:;
    font-src 'self' data:;
    connect-src 'self';
    object-src 'none';
    base-uri 'self';
    form-action 'self';
    frame-ancestors 'none';
  `
    .replace(/\s{2,}/g, " ")
    .trim();

  // Both directions, and both are load-bearing. The request copy is what
  // Next.js parses to find the nonce it stamps onto its own scripts; the
  // response copy is what the browser enforces.
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", csp);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", csp);
  return response;
}

export const config = {
  // Everything but Next's own build assets, which are the same public bytes for
  // everybody. Narrowing this is narrowing the gate.
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
