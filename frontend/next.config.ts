import type { NextConfig } from "next";

/**
 * Security response headers, and the reason each one is here.
 *
 * Not added on principle: every one of these closes findings the platform's
 * own DAST lane reported against this application. A proxy-first scan of the
 * demo environment produced 156 findings, 105 of them these four headers
 * repeated across every route (spec 04 §3, PIP-3).
 *
 * They are equally absent in production - none of them depend on the
 * transport, so the demo environment running plain HTTP does not flatter or
 * exaggerate them. That was checked rather than assumed: the scan produced
 * zero HSTS, cookie-Secure or TLS findings, which are the ones that would
 * have been artefacts of the lower environment.
 *
 * HSTS is deliberately absent. It belongs at the edge, which for this
 * deployment is the Cloudflare tunnel that terminates TLS; setting it from an
 * origin served over plain HTTP inside Docker would be asserting a guarantee
 * this process cannot make.
 */
const securityHeaders = [
  {
    // Clickjacking. The dashboard is read-mostly, but it carries disposition
    // controls - "accept risk" is one click, and one click is what framing
    // steals.
    key: "X-Frame-Options",
    value: "DENY",
  },
  {
    // Stops a browser second-guessing a declared content type, which is how a
    // JSON response gets executed as script.
    key: "X-Content-Type-Options",
    value: "nosniff",
  },
  {
    // Referrer leakage matters here specifically: repository ids and finding
    // ids are in the path, so a full referrer hands an external site the
    // shape of somebody's estate.
    key: "Referrer-Policy",
    value: "strict-origin-when-cross-origin",
  },
  {
    // No feature this dashboard uses needs any of them.
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=(), payment=()",
  },
  {
    // 'unsafe-inline' for styles is Tailwind's runtime, and dropping it would
    // break the application rather than harden it. Scripts get no such
    // exemption: 'self' only, which is the half that matters for XSS.
    //
    // `connect-src 'self'` is load-bearing rather than boilerplate - the
    // dashboard talks to its own API server-side, so a browser has no reason
    // to reach any other origin, and saying so turns exfiltration into a CSP
    // violation.
    key: "Content-Security-Policy",
    value: [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data:",
      "font-src 'self' data:",
      "connect-src 'self'",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "object-src 'none'",
    ].join("; "),
  },
];

const nextConfig: NextConfig = {
  // Removes `X-Powered-By: Next.js`, which tells an attacker the framework
  // and therefore which CVEs to try. 24 findings, one line.
  poweredByHeader: false,

  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
};

export default nextConfig;
