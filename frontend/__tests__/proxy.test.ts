/**
 * The dashboard's perimeter gate, run rather than read.
 *
 * `frontend/proxy.ts` and `lib/gate.ts` are the only lock on the public
 * dashboard: the Next server holds the admin token, so whatever this function
 * lets through reaches the backend as admin. The backend's
 * `test_frontend_perimeter_gate.py` checks the source text; these call the
 * real `proxy()` with real `NextRequest`s and assert on the responses it
 * returns.
 */
import { NextRequest } from "next/server";
import {
  getRedirectUrl,
  unstable_doesMiddlewareMatch,
  unstable_getResponseFromNextConfig,
} from "next/experimental/testing/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import nextConfig from "../next.config";
import { config, proxy } from "../proxy";
import { isExempt, presentedToken, tokensMatch } from "../lib/gate";

const TOKEN = "correct-horse-battery-staple";
const BASE = "http://dashboard.test";

function request(path: string, init: { method?: string; headers?: Record<string, string> } = {}) {
  return new NextRequest(new URL(path, BASE), {
    method: init.method ?? "GET",
    headers: init.headers,
  });
}

/** `NextResponse.next()` marks the response it hands back to the router. */
function passedThrough(response: Response): boolean {
  return response.headers.get("x-middleware-next") === "1";
}

async function expectRefused(response: Response) {
  expect(response.status).toBe(401);
  expect(passedThrough(response)).toBe(false);
  expect(response.headers.get("www-authenticate")).toBe('X-Hub-Token realm="mykronos"');
  // Identical for absent, wrong and malformed: nothing that helps a guesser.
  expect(await response.json()).toEqual({ detail: "Not authorised for this host." });
  // A refusal never hands out the cookie.
  expect(response.headers.get("set-cookie")).toBeNull();
}

beforeEach(() => {
  vi.stubEnv("MYKRONOS_GATE_TOKEN", TOKEN);
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

describe("refused without the token", () => {
  it("refuses a page with no token at all", async () => {
    await expectRefused(await proxy(request("/")));
  });

  it("refuses a wrong token in the header", async () => {
    await expectRefused(await proxy(request("/", { headers: { "x-hub-token": "nope" } })));
  });

  it("refuses a wrong token in the cookie", async () => {
    await expectRefused(await proxy(request("/", { headers: { cookie: "hub_token=nope" } })));
  });

  it("refuses a token that is the right one with a byte missing or added", async () => {
    await expectRefused(
      await proxy(request("/", { headers: { "x-hub-token": TOKEN.slice(0, -1) } })),
    );
    await expectRefused(await proxy(request("/", { headers: { "x-hub-token": `${TOKEN}x` } })));
  });

  it("refuses a wrong token on a link, and sets no cookie", async () => {
    await expectRefused(await proxy(request("/findings?_token=nope")));
  });

  it("refuses a prefetch, which the old CSP matcher skipped", async () => {
    await expectRefused(
      await proxy(request("/findings", { headers: { "next-router-prefetch": "1" } })),
    );
    await expectRefused(await proxy(request("/findings", { headers: { purpose: "prefetch" } })));
  });

  it("refuses a POST to an /api route handler", async () => {
    await expectRefused(await proxy(request("/api/findings/1/disposition", { method: "POST" })));
    await expectRefused(await proxy(request("/api", { method: "POST" })));
  });

  it("does not let a wrong header be rescued by a right cookie", async () => {
    // The header is read first, as on the backend; a wrong one is a wrong one.
    await expectRefused(
      await proxy(
        request("/", { headers: { "x-hub-token": "nope", cookie: `hub_token=${TOKEN}` } }),
      ),
    );
  });
});

describe("passed with the token", () => {
  it("passes the token in the X-Hub-Token header", async () => {
    const response = await proxy(request("/", { headers: { "x-hub-token": TOKEN } }));
    expect(response.status).toBe(200);
    expect(passedThrough(response)).toBe(true);
  });

  it("passes the token in the hub_token cookie", async () => {
    const response = await proxy(request("/", { headers: { cookie: `hub_token=${TOKEN}` } }));
    expect(response.status).toBe(200);
    expect(passedThrough(response)).toBe(true);
  });

  it("passes a POST to /api with the token", async () => {
    const response = await proxy(
      request("/api/findings/1/disposition", {
        method: "POST",
        headers: { "x-hub-token": TOKEN },
      }),
    );
    expect(passedThrough(response)).toBe(true);
  });

  it("passes a prefetch with the token", async () => {
    const response = await proxy(
      request("/findings", {
        headers: { "next-router-prefetch": "1", cookie: `hub_token=${TOKEN}` },
      }),
    );
    expect(passedThrough(response)).toBe(true);
  });
});

describe("exemptions", () => {
  it("lets /api/healthz answer without a token", async () => {
    const response = await proxy(request("/api/healthz"));
    expect(passedThrough(response)).toBe(true);
  });

  it.each([
    "/api/healthz/",
    "/api/healthz/x",
    "/api/healthzz",
    "/api/HEALTHZ",
    "/healthz",
    "/api/ingest",
    "/webhooks/github",
    "/api/oracle/evaluate",
  ])("does not exempt %s", async (path) => {
    expect(isExempt(path)).toBe(false);
    await expectRefused(await proxy(request(path)));
  });

  it("runs on everything except Next's own build assets", () => {
    const runs = (url: string, headers?: Record<string, string>) =>
      unstable_doesMiddlewareMatch({ config, nextConfig, url, headers });

    for (const url of ["/", "/findings", "/api", "/api/healthz", "/api/repos/1/findings/export"]) {
      expect(runs(url), url).toBe(true);
    }
    expect(runs("/findings", { "next-router-prefetch": "1" })).toBe(true);

    for (const url of ["/_next/static/chunks/main.js", "/_next/image?url=x", "/favicon.ico"]) {
      expect(runs(url), url).toBe(false);
    }
  });
});

describe("following a ?_token= link", () => {
  it("sets an HttpOnly, lax cookie and redirects to the URL without the token", async () => {
    const response = await proxy(request(`/findings?severity=high&_token=${TOKEN}&repo=2`));

    expect(response.status).toBe(302);
    expect(passedThrough(response)).toBe(false);
    const location = new URL(getRedirectUrl(response)!);
    expect(location.origin).toBe(BASE);
    expect(location.pathname).toBe("/findings");
    expect(location.searchParams.has("_token")).toBe(false);
    expect(location.searchParams.get("severity")).toBe("high");
    expect(location.searchParams.get("repo")).toBe("2");
    expect(response.headers.get("location")).not.toContain(TOKEN);

    const cookie = response.headers.get("set-cookie") ?? "";
    expect(cookie).toContain(`hub_token=${TOKEN}`);
    expect(cookie).toMatch(/;\s*HttpOnly/i);
    expect(cookie).toMatch(/;\s*SameSite=lax/i);
    expect(cookie).toMatch(/;\s*Path=\//i);
    expect(cookie).toMatch(/;\s*Max-Age=86400/i);
    // Plain http: a Secure cookie would never come back and the link would loop.
    expect(cookie).not.toMatch(/;\s*Secure/i);
  });

  it("marks the cookie Secure and redirects to https behind the tunnel", async () => {
    const response = await proxy(
      request(`/findings?_token=${TOKEN}`, {
        headers: {
          "x-forwarded-proto": "https",
          "x-forwarded-host": "mykronos-app.example.org",
        },
      }),
    );

    expect(response.status).toBe(302);
    expect(getRedirectUrl(response)).toBe("https://mykronos-app.example.org/findings");
    expect(response.headers.get("set-cookie") ?? "").toMatch(/;\s*Secure/i);
  });

  it("marks the cookie Secure when the request itself is https", async () => {
    const response = await proxy(
      new NextRequest(`https://dashboard.test/?_token=${TOKEN}`, { headers: { host: "dashboard.test" } }),
    );
    expect(response.status).toBe(302);
    expect(response.headers.get("set-cookie") ?? "").toMatch(/;\s*Secure/i);
  });

  it("strips the token from an /api link as well as a page", async () => {
    const response = await proxy(request(`/api/repos/1/findings/export?format=csv&_token=${TOKEN}`));
    expect(response.status).toBe(302);
    expect(getRedirectUrl(response)).toBe(`${BASE}/api/repos/1/findings/export?format=csv`);
  });
});

describe("security headers", () => {
  it("gives a page a nonce CSP, on the response and on the request Next renders", async () => {
    vi.stubEnv("NODE_ENV", "production");
    const response = await proxy(request("/", { headers: { "x-hub-token": TOKEN } }));
    const csp = response.headers.get("content-security-policy") ?? "";

    const nonce = /'nonce-([^']+)'/.exec(csp)?.[1];
    expect(nonce).toBeTruthy();
    expect(csp).toContain(`script-src 'self' 'nonce-${nonce}' 'strict-dynamic';`);
    expect(csp).toContain(`style-src 'self' 'nonce-${nonce}';`);
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).not.toContain("unsafe-eval");
    expect(csp).not.toMatch(/style-src [^;]*'unsafe-inline'/);

    // `NextResponse.next({ request: { headers } })` forwards overridden
    // request headers as x-middleware-request-*; Next reads the nonce there.
    expect(response.headers.get("x-middleware-request-x-nonce")).toBe(nonce);
    expect(response.headers.get("x-middleware-request-content-security-policy")).toBe(csp);
  });

  it("uses a fresh nonce on every request", async () => {
    const nonceOf = async () =>
      /'nonce-([^']+)'/.exec(
        (await proxy(request("/", { headers: { "x-hub-token": TOKEN } }))).headers.get(
          "content-security-policy",
        ) ?? "",
      )?.[1];
    expect(await nonceOf()).not.toBe(await nonceOf());
  });

  it("sends the static security headers from next.config on every path", async () => {
    const response = await unstable_getResponseFromNextConfig({
      url: `${BASE}/findings`,
      nextConfig,
    });
    expect(response.headers.get("x-frame-options")).toBe("DENY");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("referrer-policy")).toBe("strict-origin-when-cross-origin");
    expect(response.headers.get("cross-origin-opener-policy")).toBe("same-origin");
  });
});

describe("token comparison", () => {
  it("compares SHA-256 digests of both sides, so length never short-circuits", async () => {
    const digest = vi.spyOn(crypto.subtle, "digest");
    expect(await tokensMatch("short", TOKEN)).toBe(false);
    expect(digest).toHaveBeenCalledTimes(2);
    for (const call of digest.mock.calls) expect(call[0]).toBe("SHA-256");
    expect(await tokensMatch(TOKEN, TOKEN)).toBe(true);
  });

  it("never matches an empty token, on either side", async () => {
    expect(await tokensMatch("", "")).toBe(false);
    expect(await tokensMatch("", TOKEN)).toBe(false);
    expect(await tokensMatch(TOKEN, "")).toBe(false);
  });

  it("reads the carriers in the backend's order: header, cookie, link", () => {
    expect(presentedToken({ header: "h", cookie: "c", query: "q" })).toBe("h");
    expect(presentedToken({ header: null, cookie: "c", query: "q" })).toBe("c");
    expect(presentedToken({ header: "", cookie: undefined, query: "q" })).toBe("q");
    expect(presentedToken({ header: null, cookie: undefined, query: null })).toBe("");
  });
});

describe("unconfigured gate", () => {
  // Documented: unset means disabled, as on the backend - a laptop dashboard
  // bound to 127.0.0.1 has nothing to gate. Production compose refuses to
  // start without the variable (`${MYKRONOS_GATE_TOKEN:?...}`).
  it.each([["unset"], ["empty"]])("is disabled when the token is %s", async (how) => {
    if (how === "unset") vi.stubEnv("MYKRONOS_GATE_TOKEN", undefined);
    else vi.stubEnv("MYKRONOS_GATE_TOKEN", "");
    const response = await proxy(request("/api/findings", { method: "POST" }));
    expect(passedThrough(response)).toBe(true);
  });

  it("does not treat an empty presented token as matching an empty configured one", async () => {
    vi.stubEnv("MYKRONOS_GATE_TOKEN", "");
    // Disabled gate: the link is not consumed, so no cookie is minted from it.
    const response = await proxy(request("/?_token="));
    expect(response.headers.get("set-cookie")).toBeNull();
    expect(response.status).not.toBe(302);
  });

  it("an empty header does not shadow a valid cookie", async () => {
    const response = await proxy(
      request("/", { headers: { "x-hub-token": "", cookie: `hub_token=${TOKEN}` } }),
    );
    expect(passedThrough(response)).toBe(true);
  });
});
