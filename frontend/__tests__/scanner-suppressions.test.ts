/**
 * In-repo scanner suppressions on the repository page (TheHub #60963): every
 * column the story names, `no expiry` flagged, and a passed expiry stated as a
 * lane-health fact.
 */
import { readFileSync } from "node:fs";

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { ScannerSuppressions } from "../components/scanner-suppressions";
import type { RepoSuppressions } from "../lib/api";

function row(overrides: Partial<RepoSuppressions["suppressions"][number]>) {
  return {
    repo_full_name: "acme/shop",
    capability: "sast",
    tool: "semgrep",
    branch: "main",
    rule_id: "python.lang.security.audit.eval",
    file_path: "src/app.py",
    line: 12,
    justification: "input is a constant",
    expires_at: null,
    expiry_state: "no_expiry",
    kind: "inSource",
    status: "accepted",
    scan_run_id: "run-1",
    commit_sha: "a91f2c7",
    recorded_at: "2026-10-23T09:00:00",
    ...overrides,
  };
}

const page: RepoSuppressions = {
  repo_full_name: "acme/shop",
  suppressions: [
    row({ rule_id: "r/forever" }),
    row({ rule_id: "r/expired", line: 3, expires_at: "2020-01-01", expiry_state: "expired" }),
    row({ rule_id: "r/later", line: 4, expires_at: "2099-01-01", expiry_state: "active" }),
  ],
  lane_health: [
    "Suppression expired: r/expired at src/app.py:3 (semgrep) passed its expiry 2020-01-01 and still silences the result in the repository. Renew or remove it.",
  ],
  counts: { expired: 1, no_expiry: 1, active: 1 },
};

describe("ScannerSuppressions", () => {
  const html = renderToStaticMarkup(createElement(ScannerSuppressions, { data: page }));

  it("shows every column the story names", () => {
    for (const heading of ["Repo", "Tool", "Rule", "File", "Line", "Justification", "Expiry"]) {
      expect(html).toContain(`>${heading}<`);
    }
    expect(html).toContain("acme/shop");
    expect(html).toContain("semgrep");
    expect(html).toContain("src/app.py");
    expect(html).toContain("input is a constant");
    expect(html).toContain("2099-01-01");
  });

  it("flags a suppression with no expiry as 'no expiry'", () => {
    expect(html).toContain("no expiry");
  });

  it("states a passed expiry as a lane-health fact naming it", () => {
    expect(html).toContain("Suppression expired: r/expired at src/app.py:3");
    expect(html).toContain("expired 2020-01-01");
  });

  it("says so when nothing is suppressed", () => {
    const empty = renderToStaticMarkup(
      createElement(ScannerSuppressions, {
        data: { repo_full_name: "acme/shop", suppressions: [], lane_health: [], counts: {} },
      }),
    );
    expect(empty).toContain("No in-repo suppressions");
  });

  it("is on the Findings tab of the repository page", () => {
    const source = readFileSync("app/repos/[repoId]/page.tsx", "utf8");
    expect(source).toContain("<ScannerSuppressions data={suppressions.data} />");
    expect(source).toContain("getSuppressions(repoId)");
  });
});
