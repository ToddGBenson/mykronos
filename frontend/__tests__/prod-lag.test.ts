/**
 * The "prod N behind" badge (#452), run rather than read.
 *
 * Unknown must never render as "at head": the failure the issue names is a
 * page that quietly claims production is current because the probe failed.
 */
import { describe, expect, it } from "vitest";

import { prodLagBadge } from "../lib/prod-lag";

describe("prodLagBadge", () => {
  it("says how many commits production is behind", () => {
    const badge = prodLagBadge({
      status: "behind",
      branch: "main",
      behind_by: 40,
      deployed_revision: "a2a7566c0ffee0123",
      checked_at: "2026-10-19T10:00:00",
    });
    expect(badge?.label).toBe("prod 40 behind");
    expect(badge?.tone).toBe("warn");
    expect(badge?.title).toContain("a2a7566c0f");
    expect(badge?.title).toContain("40 commits behind main");
    expect(badge?.title).toContain("2026-10-19 10:00");
  });

  it("says 1 commit, not 1 commits", () => {
    expect(prodLagBadge({ status: "behind", branch: "main", behind_by: 1 })?.title).toContain(
      "1 commit behind main",
    );
  });

  it("marks a deployment off its branch as worse than behind", () => {
    const badge = prodLagBadge({ status: "diverged", branch: "develop", behind_by: 5, not_on_branch: 2 });
    expect(badge?.tone).toBe("critical");
    expect(badge?.label).toBe("prod 5 behind, off develop");
    expect(badge?.title).toContain("2 commits running that are not on develop");
  });

  it("is quiet at head", () => {
    expect(prodLagBadge({ status: "at_head", branch: "main", behind_by: 0 })).toMatchObject({
      tone: "pass",
      label: "prod at head",
    });
  });

  it("keeps unknown apart from current, with the reason", () => {
    const badge = prodLagBadge({
      status: "unknown",
      branch: "main",
      detail: "set MYKRONOS_DEPLOYMENT_PROBE_TOKENS",
    });
    expect(badge?.label).toBe("prod lag unknown");
    expect(badge?.tone).toBe("muted");
    expect(badge?.title).toContain("MYKRONOS_DEPLOYMENT_PROBE_TOKENS");
  });

  it("renders nothing for a repository with no probe", () => {
    expect(prodLagBadge(null)).toBeNull();
    expect(prodLagBadge(undefined)).toBeNull();
  });
});
