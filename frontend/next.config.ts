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
  // Cross-origin isolation, the three ZAP 90004 reports on every page (first
  // raised by the weekly scanner, D-128). Together they keep this dashboard
  // out of any other origin's process: nothing else may embed our responses
  // (CORP), a page that opens us gets no handle on our window (COOP), and we
  // load nothing that has not opted in (COEP).
  //
  // `require-corp` is safe here only because of what `proxy.ts`'s CSP already
  // allows: images and fonts from `'self'`, `data:` and `blob:`, and
  // `connect-src 'self'` - no cross-origin subresource exists to be blocked.
  // Add a remote image or font to the CSP and this header must be revisited
  // with it, or that resource will silently fail to load.
  {
    key: "Cross-Origin-Resource-Policy",
    value: "same-origin",
  },
  {
    // No flow here opens or is opened by another window (no OAuth popup,
    // no `window.open`), so severing the opener costs nothing.
    key: "Cross-Origin-Opener-Policy",
    value: "same-origin",
  },
  {
    key: "Cross-Origin-Embedder-Policy",
    value: "require-corp",
  },
  // Content-Security-Policy is NOT here. It lives in `proxy.ts`, because it
  // needs a per-request nonce and this file is static.
  //
  // What was here served `script-src 'self'` with no nonce and no
  // `'unsafe-inline'`, and the App Router needs inline scripts to hydrate. The
  // browser blocked them, React threw #412, and every client component on the
  // site was inert — the header was present, correct-looking, and breaking the
  // application. A header that ships is not a header that works.
];

const nextConfig: NextConfig = {
  // Removes `X-Powered-By: Next.js`, which tells an attacker the framework
  // and therefore which CVEs to try. 24 findings, one line.
  poweredByHeader: false,

  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },

  // There is deliberately no `images` block, and its absence is load-bearing.
  //
  // With no `images.remotePatterns`, Next refuses every remote URL handed to
  // the optimizer before it fetches anything:
  //
  //     GET /_next/image?url=https%3A%2F%2Fexample.com%2Fx.avif
  //     400  "url" parameter is not allowed
  //
  // That is currently the only thing standing between this deployment and
  // GHSA-2xp9-vwfh-vxw4 (CVSS 9.5, RCE in libheif via sharp, triggered when
  // an AVIF is optimized). `/_next/image` is enabled, answers 200, and is
  // internet-facing: the tunnel routes everything except /api, /webhooks,
  // /healthz and the docs to this process. The advisory needs an
  // attacker-supplied AVIF, and an empty remotePatterns is what stops one
  // arriving — the optimizer will only touch paths inside this bundle, which
  // is five SVGs.
  //
  // So adding a domain here to serve an avatar or a chart image — an
  // entirely ordinary change — makes this remotely exploitable the same
  // afternoon, until the deployed image carries next >= 16.3.3. The repo
  // pins 16.3.3; the running container was still 16.3.0 when this was
  // written (mykronos#288), and nothing in the build tells you that.
  //
  // If you need remote images before that rebuild has happened: check the
  // deployed version first, not package.json.

};

export default nextConfig;
