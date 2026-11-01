/**
 * The finding page's decision components, rendered rather than read (review
 * of #1065): the lib tests could not catch a response the form mis-typed, or
 * copy that promises more than the approval engine does.
 */
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

// The disposition form refreshes the route after a save; a static render has
// no App Router, and never saves.
vi.mock("next/navigation", () => ({ useRouter: () => ({ refresh: () => undefined }) }));

import { DispositionForm } from "../components/disposition";
import {
  ProposedNotice,
  RiskAcceptanceForm,
  type Proposed,
} from "../components/risk-acceptance-form";

/** `POST /api/risk-acceptances` as the backend returns it: `flags` are the
 *  objects `premise_flags()` and `propose()` build, not strings. */
const proposed = {
  risk_acceptance: { id: "ra-1", findings: 1 },
  approval_request_id: "apr-1",
  tier: "high",
  flags: [
    {
      code: "base_os_eol",
      findings: ["f-1"],
      bases: ["debian 10"],
      images: ["library/postgres:17"],
      reason: "The base OS debian 10 is end of life: no vendor fix will ever ship.",
    },
    {
      code: "unverified_controls",
      controls: [0],
      reason: "No compensating control is verified by a fresh observation.",
    },
  ],
} as unknown as Proposed;

describe("ProposedNotice", () => {
  it("shows the server's flags by their reason, as the backend returns them", () => {
    const html = renderToStaticMarkup(createElement(ProposedNotice, { proposed, repoId: "r1" }));
    expect(html).toContain("The base OS debian 10 is end of life");
    expect(html).toContain("No compensating control is verified");
    expect(html).toContain("apr-1");
    expect(html).toContain("/repos/r1/risk/ra-1");
  });

  it("says a second party approves, and names the single-operator exception", () => {
    const html = renderToStaticMarkup(
      createElement(ProposedNotice, { proposed: { ...proposed, flags: [] }, repoId: "r1" }),
    );
    expect(html).not.toContain("independent of you");
    expect(html).toContain("cooling-off");
  });
});

describe("RiskAcceptanceForm", () => {
  it("does not promise that someone other than you approves", () => {
    const html = renderToStaticMarkup(
      createElement(RiskAcceptanceForm, {
        repo: "o/r",
        repoId: "r1",
        scope: { capability: "containers", image: "library/postgres:17", rule_ids: ["CVE-1"] },
        noFixPublished: true,
        findingSeverity: "high",
        controls: [],
      }),
    );
    expect(html).not.toContain("independent of you");
    expect(html).toContain("cooling-off");
  });
});

describe("DispositionForm", () => {
  it("will not record a disposition while the reason is empty", () => {
    const html = renderToStaticMarkup(
      createElement(DispositionForm, { findingId: "f-1", currentStatus: "open" }),
    );
    expect(html).toMatch(/<textarea[^>]*required/);
    expect(html).toMatch(/<button type="submit" disabled=""/);
  });
});
