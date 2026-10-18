/**
 * A declared exposure contradicted by an observation (TheHub #60826).
 * The fixture is the backend's `contradicted_by` entry for TheHub's
 * `Demo backend (tcp/8002)`, declared internal while cloudflared publishes it.
 */
import { describe, expect, it } from "vitest";

import {
  contradictionLine,
  contradictionTitle,
  type SurfaceContradiction,
} from "../lib/surface-contradictions";

const tunnel: SurfaceContradiction = {
  source: "published_ingress",
  assertion: "ingress_published",
  subject: "demo.example.net",
  vantage: "host",
  tool: "Publish-ControlObservations.ps1",
  collector: "Publish-ControlObservations.ps1@LAB",
  collected_at: "2026-10-16T09:00:00",
  detail: "cloudflared routes demo.example.net to http://localhost:8002",
};

describe("surface contradictions", () => {
  it("says what was seen, from where and when", () => {
    expect(contradictionLine(tunnel)).toBe(
      "a tunnel publishes demo.example.net (on the host, Publish-ControlObservations.ps1, 2026-10-16)",
    );
  });

  it("names the claim it contradicts", () => {
    const lan = { ...tunnel, assertion: "port_published", vantage: "lan", subject: "192.168.0.14:8002" };
    const title = contradictionTitle("internal", [tunnel, lan]);
    expect(title.startsWith("Declared internal, but observed within 14 days: ")).toBe(true);
    expect(title).toContain("a port answers at 192.168.0.14:8002 (from the LAN");
  });

  it("says nothing when nothing contradicts", () => {
    expect(contradictionTitle("internal", [])).toBe("");
  });
});
