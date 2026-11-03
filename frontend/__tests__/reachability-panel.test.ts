/**
 * The finding record's reachability block (TheHub #60891): a reachable
 * verdict shows the path CodeQL traced, and an unreachable one shows the
 * evidence it rests on rather than just the word.
 */
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { ReachabilityPanel } from "../components/finding-workbench";
import type { components } from "../lib/api-types";

type Reachability = components["schemas"]["FindingReachabilityOut"];

const base: Reachability = {
  verdict: "reachable",
  reason: "A call path from an entry point reaches a call into pyyaml.",
  path: [
    { file_path: "app/web.py", line: 9, label: "function load" },
    { file_path: "app/helpers.py", line: 5, label: "function parse" },
    { file_path: "app/helpers.py", line: 6, label: "call into yaml" },
  ],
  evidence: { basis: "codeql_call_path" },
  language: "python",
  analyser: "codeql",
  analyser_version: "2.27.2",
  commit_sha: "abc123def4567890",
  analysed_at: null,
};

function render(data: Reachability): string {
  return renderToStaticMarkup(createElement(ReachabilityPanel, { data }));
}

describe("ReachabilityPanel", () => {
  it("shows every step of the path, in order", () => {
    const html = render(base);

    expect(html).toContain("reachable");
    const web = html.indexOf("app/web.py:9");
    const parse = html.indexOf("app/helpers.py:5");
    const call = html.indexOf("app/helpers.py:6");
    expect(web).toBeGreaterThan(-1);
    expect(parse).toBeGreaterThan(web);
    expect(call).toBeGreaterThan(parse);
    expect(html).toContain("abc123def456");
    expect(html).not.toContain("abc123def4567");
  });

  it("shows what an unreachable verdict rests on", () => {
    const html = render({
      ...base,
      verdict: "unreachable",
      reason: "Nothing in 12 analysed file(s) imports certifi.",
      path: [],
      evidence: {
        files_analysed: 12,
        import_names: ["certifi"],
        import_count: 0,
        dynamic_imports: 0,
        lockfiles: ["uv.lock"],
        dependents: [],
      },
    });

    expect(html).toContain("never imported");
    expect(html).toContain("uv.lock");
    expect(html).toContain("certifi");
    expect(html).toContain("required by");
  });

  it("says when it is not proven either way", () => {
    const html = render({ ...base, verdict: "unknown", path: [], reason: "Imported, no path." });

    expect(html).toContain("not proven either way");
    expect(html).not.toContain("<ol");
  });
});
