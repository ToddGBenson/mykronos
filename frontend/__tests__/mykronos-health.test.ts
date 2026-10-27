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
  const stallJobs = [
    { pipeline: "keel", job: "sast", build: "7", started_at: "2026-10-23T17:20:00Z", url: null },
    { pipeline: "keel", job: "sca", build: "7", started_at: "2026-10-23T17:21:00Z", url: null },
    { pipeline: "keel", job: "iac", build: "7", started_at: "2026-10-23T17:22:00Z", url: null },
  ];
  const checklist = [
    "Restart the Concourse workers",
    "Check Vault is unsealed",
    "Re-trigger the errored jobs",
  ];

  it("shows a Concourse stall as the first row, with its lanes and checklist (TheHub #60975)", async () => {
    getPlatformHealth.mockResolvedValueOnce({
      ok: true,
      data: {
        degraded: true,
        jobs: [{ name: "absences", status: "ok", detail: "fine", last_succeeded_at: null, consecutive_failures: 0 }],
        dependencies: [{ name: "concourse", reachable: true, detail: "ok", configured: true }],
        ci_stall: {
          status: "red",
          detail: "Concourse is stalled: 3 lanes errored within 60 minutes of each other.",
          jobs: stallJobs,
          checklist,
          threshold: 3,
          window_minutes: 60,
          jobs_inspected: 79,
          notified_at: null,
        },
        note: null,
      },
    });
    const { default: PlatformHealthPage } = await import("../app/platform-health/page");
    const html = renderToStaticMarkup(await PlatformHealthPage());
    const stall = html.indexOf('data-testid="ci-stall"');
    expect(stall).toBeGreaterThan(-1);
    expect(stall).toBeLessThan(html.indexOf("Scheduled work"));
    expect(html).toContain("Stalled");
    expect(html).toContain("keel/sast");
    expect(html).toContain("2026-10-23 17:20 UTC");
    for (const step of checklist) expect(html).toContain(step);
  });

  it("keeps a green ci_stall out of the first row", async () => {
    getPlatformHealth.mockResolvedValueOnce({
      ok: true,
      data: {
        degraded: false,
        jobs: [],
        dependencies: [{ name: "concourse", reachable: true, detail: "ok", configured: true }],
        ci_stall: {
          status: "green",
          detail: "1 unpaused lane(s) errored.",
          jobs: stallJobs.slice(0, 1),
          checklist,
          threshold: 3,
          window_minutes: 60,
          jobs_inspected: 79,
          notified_at: null,
        },
        note: null,
      },
    });
    const { default: PlatformHealthPage } = await import("../app/platform-health/page");
    const html = renderToStaticMarkup(await PlatformHealthPage());
    const stall = html.indexOf('data-testid="ci-stall"');
    expect(stall).toBeGreaterThan(html.indexOf("Scheduled work"));
    expect(html).toContain("Not stalled");
    expect(html).not.toContain("Restart the Concourse workers");
  });
});
