import { describe, expect, it } from "vitest";

import type { ToxicChain } from "@/lib/api";
import { chainSteps } from "@/lib/toxic-chain";

const CHAIN: ToxicChain = {
  entry_point: {
    id: "ep-1",
    name: "Public API",
    exposure: "internet",
    declared_via: "manifest",
    evidence_ref: "backend/api/routes.py",
  },
  links: [
    {
      step: "entry_point",
      name: "Public API",
    },
    {
      step: "auth_weakness",
      finding_id: "f-auth",
      capability: "sast",
      severity: "medium",
      title: "Route handler performs no authorization check",
      located_by: "paths `backend/**`",
      qualifies: "an authentication or authorization weakness: sast `x` - declares CWE-862",
    },
    {
      step: "vulnerable_component",
      finding_id: "f-cve",
      capability: "atlas",
      severity: "high",
      title: "urllib3 redirect handling flaw",
      located_by: "paths `backend/**`",
      qualifies: "a known-vulnerable component: atlas `CVE-2024-4812`",
    },
  ],
  note: "declared, not observed",
};

describe("chainSteps", () => {
  it("starts at the declared entry point and says it was declared", () => {
    const [door] = chainSteps(CHAIN);
    expect(door.label).toBe("Way in");
    expect(door.subject).toBe("Public API");
    expect(door.detail).toBe(
      "declared internet-facing in the threat-model file, evidence backend/api/routes.py",
    );
  });

  it("lists each link in order with the selector that placed it and why it qualifies", () => {
    const steps = chainSteps(CHAIN);
    expect(steps.map((s) => s.label)).toEqual([
      "Way in",
      "Authentication weakness",
      "Known-vulnerable component",
    ]);
    expect(steps[1].subject).toBe("sast · medium · Route handler performs no authorization check");
    expect(steps[1].detail).toContain("behind it by paths `backend/**`");
    expect(steps[1].detail).toContain("CWE-862");
    expect(steps[2].key).toBe("f-cve");
  });

  it("names a register declaration and an unknown step as they are", () => {
    const steps = chainSteps({
      ...CHAIN,
      entry_point: { ...CHAIN.entry_point, declared_via: "api", evidence_ref: "" },
      links: [CHAIN.links[0], { step: "something_new", finding_id: "f" }],
    });
    expect(steps[0].detail).toBe("declared internet-facing in the register");
    expect(steps[1].label).toBe("something_new");
  });
});
