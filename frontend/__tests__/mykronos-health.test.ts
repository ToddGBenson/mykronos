import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import { NAV } from "../lib/nav";

// The page imports `@/lib/server`, which is `server-only` and talks to the
// backend; the mock hands the page a result directly so the render is pure.
const getPlatformHealth = vi.fn();
vi.mock("@/lib/server", () => ({ getPlatformHealth }));

const items = NAV.flatMap((group) => group.items);

describe("MyKronos Health (TheHub #60883)", () => {
  it("is the nav label, and the route is unchanged", () => {
    expect(items).toContainEqual({ label: "MyKronos Health", href: "/platform-health" });
    expect(items.map((item) => item.label)).not.toContain("Platform health");
  });

  it("titles the page MyKronos Health", async () => {
    getPlatformHealth.mockResolvedValueOnce({
      ok: true,
      data: { degraded: false, jobs: [], dependencies: [], note: null },
    });
    const { default: PlatformHealthPage } = await import("../app/platform-health/page");
    const html = renderToStaticMarkup(await PlatformHealthPage());
    expect(html).toContain("<h1");
    expect(html).toContain("MyKronos Health</h1>");
    expect(html).not.toContain("Platform health");
  });

  it("names MyKronos Health when the page cannot load", async () => {
    getPlatformHealth.mockResolvedValueOnce({ ok: false, error: "backend down" });
    const { default: PlatformHealthPage } = await import("../app/platform-health/page");
    const html = renderToStaticMarkup(await PlatformHealthPage());
    expect(html).toContain("MyKronos Health unavailable");
  });

  it("shows an unconfigured dependency as not configured, not unreachable (TheHub #60905)", async () => {
    getPlatformHealth.mockResolvedValueOnce({
      ok: true,
      data: {
        degraded: false,
        jobs: [],
        dependencies: [
          { name: "vault", reachable: false, detail: "No Vault", configured: false },
          { name: "ingestion", reachable: true, detail: "Serving", configured: true },
        ],
        note: null,
      },
    });
    const { default: PlatformHealthPage } = await import("../app/platform-health/page");
    const html = renderToStaticMarkup(await PlatformHealthPage());
    expect(html).toContain("Not configured");
    expect(html).not.toContain("Unreachable");
    expect(html).toContain("Healthy");
  });
  describe("Credentials (TheHub #60974)", () => {
    const now = "2026-10-23T00:00:00Z";
    const rows = [
      {
        kind: "ingestion_token",
        repo_full_name: "example-org/due-service",
        actor: null,
        state: "due",
        rotate_after: "2026-10-18T00:00:00Z",
        expires_at: null,
        days_until_due: -5,
        action: "ignored by the page",
      },
      {
        kind: "ingestion_token",
        repo_full_name: "example-org/unverified-service",
        actor: null,
        state: "unverified",
        rotate_after: "2027-01-19T00:00:00Z",
        expires_at: null,
        days_until_due: 88,
        // The page's own wording wins: a backend that sent the wrong
        // instruction must not get it rendered on an unverified row.
        action: "rotate now",
      },
      {
        kind: "agent_credential",
        repo_full_name: null,
        actor: "agent:test-family:aaaa1111",
        state: "expiring",
        rotate_after: null,
        expires_at: "2026-10-30T00:00:00Z",
        days_until_due: 7,
        action: "",
      },
    ];

    async function render(credentials: unknown) {
      getPlatformHealth.mockResolvedValueOnce({
        ok: true,
        data: { degraded: false, jobs: [], dependencies: [], credentials, note: now },
      });
      const { default: PlatformHealthPage } = await import("../app/platform-health/page");
      return renderToStaticMarkup(await PlatformHealthPage());
    }

    function row(html: string, state: string): string {
      const match = html.match(
        new RegExp(`<li data-credential-state="${state}"[^>]*>([\\s\\S]*?)</li>`),
      );
      expect(match, `no ${state} row rendered`).not.toBeNull();
      return match![1];
    }

    it("renders a Credentials section", async () => {
      const html = await render(rows);
      expect(html).toContain("Credentials");
      expect(html).toContain("3 credentials need attention");
    });

    it("tells the operator to rotate a due token by hand", async () => {
      const due = row(await render(rows), "due");
      expect(due).toContain("example-org/due-service");
      expect(due).toContain(
        "rotate by hand (Concourse-scanned repos cannot receive a rotated token, D-086)",
      );
    });

    it("never tells the operator to rotate an unverified token (D-097)", async () => {
      const unverified = row(await render(rows), "unverified");
      expect(unverified).toContain("example-org/unverified-service");
      expect(unverified).toContain("check that scans are arriving - do not rotate (D-097)");
      // "rotate" may appear only as the thing not to do.
      expect(unverified.replaceAll("do not rotate", "").toLowerCase()).not.toMatch(/rotat/);
    });

    it("lists an expiring agent credential by actor and date", async () => {
      const agent = row(await render(rows), "expiring");
      expect(agent).toContain("agent:test-family:aaaa1111");
      expect(agent).toContain("2026-10-30");
      expect(agent.toLowerCase()).not.toMatch(/rotat/);
    });

    it("reads 0 credentials need attention when there are none", async () => {
      expect(await render([])).toContain("0 credentials need attention");
    });

    it("reads 0 credentials need attention against a backend without the field", async () => {
      expect(await render(undefined)).toContain("0 credentials need attention");
    });
  });
});
