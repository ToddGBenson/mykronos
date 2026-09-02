import { NextResponse, type NextRequest } from "next/server";

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
export function proxy(request: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");

  // React uses `eval` in development to reconstruct server-side error stacks
  // in the browser. It does not in production, and neither does Next.js.
  const isDev = process.env.NODE_ENV === "development";

  const csp = `
    default-src 'self';
    script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isDev ? " 'unsafe-eval'" : ""};
    style-src 'self' 'nonce-${nonce}' 'unsafe-inline';
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
  matcher: [
    {
      // Everything but API routes and static assets. A prefetch is excluded
      // too: it never executes a script, so giving it a nonce spends entropy
      // and cache-busts a response that could have been shared.
      source: "/((?!api|_next/static|_next/image|favicon.ico).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
