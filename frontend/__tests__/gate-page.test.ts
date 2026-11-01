/**
 * The gate's refusal, as a page a person can act on (TheHub #61143, P9).
 *
 * A browser that reached the dashboard without its access link got a bare
 * JSON 401, which says nothing about what to do next. A page navigation now
 * gets an HTML page that names the next step. Everything that made the JSON
 * refusal safe still holds: 401, the same `WWW-Authenticate`, no cookie, and
 * one identical body for an absent, wrong or malformed token. Route handlers,
 * prefetches and anything that did not ask for HTML still get the JSON.
 */
import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { proxy } from "../proxy";

const TOKEN = "correct-horse-battery-staple";
const BASE = "http://dashboard.test";
const HTML = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

function request(path: string, headers: Record<string, string> = {}) {
  return new NextRequest(new URL(path, BASE), { headers });
}

beforeEach(() => {
  vi.stubEnv("MYKRONOS_GATE_TOKEN", TOKEN);
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("a refused page navigation gets a page", () => {
  it("is a 401 HTML page with the same challenge and no cookie", async () => {
    const response = await proxy(request("/", { accept: HTML }));
    expect(response.status).toBe(401);
    expect(response.headers.get("content-type")).toMatch(/^text\/html/);
    expect(response.headers.get("www-authenticate")).toBe('X-Hub-Token realm="mykronos"');
    expect(response.headers.get("set-cookie")).toBeNull();
    expect(response.headers.get("x-middleware-next")).toBeNull();
  });

  it("says what happened and what to do next", async () => {
    const body = await (await proxy(request("/findings", { accept: HTML }))).text();
    expect(body).toMatch(/<html lang="en">/);
    expect(body).toMatch(/<h1>[^<]*access link[^<]*<\/h1>/i);
    expect(body).toContain("Start-Here");
    expect(body).toMatch(/rotated/);
  });

  it("is identical for an absent, a wrong and a malformed token, and never echoes one", async () => {
    const absent = await (await proxy(request("/", { accept: HTML }))).text();
    const wrong = await (
      await proxy(request("/", { accept: HTML, cookie: "hub_token=nope-secret-value" }))
    ).text();
    const link = await (await proxy(request("/?_token=other-secret", { accept: HTML }))).text();
    expect(wrong).toBe(absent);
    expect(link).toBe(absent);
    expect(absent).not.toContain("nope-secret-value");
    expect(absent).not.toContain("other-secret");
    expect(absent).not.toContain(TOKEN);
  });

  it("carries a CSP that allows no script and no frame", async () => {
    const response = await proxy(request("/", { accept: HTML }));
    const csp = response.headers.get("content-security-policy") ?? "";
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).not.toContain("script-src");
    expect(await response.text()).not.toContain("<script");
  });
});

describe("everything else still gets the JSON refusal", () => {
  for (const [name, path, headers] of [
    ["an /api route, even asking for HTML", "/api/findings", { accept: HTML }],
    ["a prefetch", "/findings", { accept: HTML, "next-router-prefetch": "1" }],
    ["a request that did not ask for HTML", "/", { accept: "application/json" }],
  ] as const) {
    it(name, async () => {
      const response = await proxy(request(path, headers));
      expect(response.status).toBe(401);
      expect(await response.json()).toEqual({ detail: "Not authorised for this host." });
    });
  }
});
