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
});
