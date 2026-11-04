/**
 * In-repo scanner suppressions on the repository page (TheHub #60963).
 *
 * The Risk management tab lists what the repository silenced itself - a
 * `# nosemgrep`, a `# checkov:skip=`, a SARIF suppression - beside the risks
 * the platform accepted, with the expiry each one carries. One with no expiry
 * is flagged, because a silence nobody dated is the one nobody revisits.
 */
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { SuppressionsTable } from "@/components/suppressions";
import { expiryText, statusTone, type SuppressionRow } from "@/lib/suppressions";

function row(overrides: Partial<SuppressionRow> = {}): SuppressionRow {
  return {
    tool: "Semgrep OSS",
    capability: "sast",
    rule_id: "python.lang.security.audit.eval",
    file_path: "app/views.py",
    line: 42,
    kind: "inSource",
    justification: "input is a constant",
    expires_at: null,
    status: "no_expiry",
    last_seen_at: "2026-11-03T00:00:00Z",
    ...overrides,
  };
}

function render(rows: SuppressionRow[]): string {
  return renderToStaticMarkup(
    createElement(SuppressionsTable, {
      data: {
        repo_full_name: "acme/payments-api",
        suppressions: rows,
        counts: {
          expired: rows.filter((r) => r.status === "expired").length,
          no_expiry: rows.filter((r) => r.status === "no_expiry").length,
          active: rows.filter((r) => r.status === "active").length,
        },
      },
    }),
  );
}

describe("the table", () => {
  it("has the story's columns", () => {
    const html = render([row()]);

    for (const header of ["Tool", "Rule", "File", "Justification", "Expiry"]) {
      expect(html).toContain(`>${header}</th>`);
    }
    expect(html).toContain("Semgrep OSS");
    expect(html).toContain("python.lang.security.audit.eval");
    expect(html).toContain("app/views.py:42");
    expect(html).toContain("input is a constant");
  });

  it("flags a suppression with no expiry", () => {
    expect(render([row()])).toContain("no expiry");
  });

  it("says when one expired, and when", () => {
    const html = render([row({ status: "expired", expires_at: "2020-01-31" })]);

    expect(html).toContain("expired 2020-01-31");
  });

  it("is a captioned table, so a screen reader can name it", () => {
    const html = render([row()]);

    expect(html).toMatch(/<table[^>]*>.*<caption/);
    expect(html).toContain('scope="col"');
  });

  it("says plainly when the repository suppresses nothing", () => {
    const html = render([]);

    expect(html).not.toContain("<table");
    expect(html).toMatch(/No scanner result is suppressed/);
  });

  it("names a missing justification rather than leaving a blank", () => {
    expect(render([row({ justification: "" })])).toContain("none given");
  });
});

describe("the expiry", () => {
  it("reads as a sentence for each status", () => {
    expect(expiryText(row())).toBe("no expiry");
    expect(expiryText(row({ status: "expired", expires_at: "2020-01-31" }))).toBe(
      "expired 2020-01-31",
    );
    expect(expiryText(row({ status: "active", expires_at: "2999-12-31" }))).toBe(
      "until 2999-12-31",
    );
  });

  it("is loudest when expired", () => {
    expect(statusTone("expired")).toBe("critical");
    expect(statusTone("no_expiry")).toBe("warn");
    expect(statusTone("active")).toBe("muted");
  });
});
