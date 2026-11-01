/**
 * The agents and delegations view (TheHub #61144, spec 34 §5.2), run rather
 * than read.
 *
 * The page exists so two things stop being invisible: a credential minted
 * with the 12-hour default, which lapses mid-run and looks like a stale
 * token, and the scope of every standing delegation, which is otherwise only
 * readable as JSON.
 */
import { describe, expect, it } from "vitest";

import {
  agreementNote,
  countdown,
  credentialNote,
  credentialState,
  delegationScope,
  delegationState,
  descendants,
  isDefaultTtl,
  orderCredentials,
  ttlHours,
  type AgentCredential,
  type DelegationRow,
} from "../lib/agents";

function cred(overrides: Partial<AgentCredential> = {}): AgentCredential {
  return {
    actor: "agent:claude-opus-5.5/a1",
    family: "claude-opus-5.5",
    instance: "a1",
    lineage: [],
    on_behalf_of: "operator",
    purpose: "author",
    minted_by: "operator",
    minted_at: "2026-11-01T00:00:00",
    expires_at: "2026-11-01T12:00:00",
    revoked_at: null,
    active: true,
    ...overrides,
  };
}

function delegation(overrides: Partial<DelegationRow> = {}): DelegationRow {
  return {
    id: "dlg-1",
    duty: "finding_disposition",
    tiers: ["low", "medium"],
    approver_families: ["claude-opus-5.5"],
    sampling: 0.2,
    granted_by: "operator",
    grant_request_id: "req-1",
    created_at: "2026-11-01T00:00:00",
    expires_at: "2026-12-01T00:00:00",
    revoked_at: null,
    suspended_at: null,
    suspended_reason: null,
    active: true,
    ...overrides,
  };
}

describe("ttlHours and isDefaultTtl", () => {
  it("measures the lifetime the credential was minted with", () => {
    expect(ttlHours(cred())).toBe(12);
    expect(ttlHours(cred({ expires_at: "2026-11-08T00:00:00" }))).toBe(168);
  });

  it("flags the 12-hour default, and nothing longer", () => {
    expect(isDefaultTtl(cred())).toBe(true);
    expect(isDefaultTtl(cred({ expires_at: "2026-11-02T00:00:00" }))).toBe(false);
  });
});

describe("credentialState", () => {
  it("reads revoked before anything else, then the server's active flag", () => {
    expect(credentialState(cred())).toBe("active");
    expect(credentialState(cred({ active: false }))).toBe("expired");
    expect(credentialState(cred({ active: false, revoked_at: "2026-11-01T03:00:00" }))).toBe(
      "revoked",
    );
  });
});

describe("credentialNote", () => {
  it("says a default-lifetime credential will stop a long run, and how to avoid it", () => {
    const note = credentialNote(cred());
    expect(note).toContain("12-hour default");
    expect(note).toContain("ttl_hours");
  });

  it("names the lapse as the cause when a default credential has expired", () => {
    expect(credentialNote(cred({ active: false }))).toContain(
      "Lapsed on the 12-hour default",
    );
  });

  it("says nothing for a credential minted with a chosen lifetime", () => {
    expect(credentialNote(cred({ expires_at: "2026-11-04T00:00:00" }))).toBeNull();
  });

  it("says a revoked credential took its sub-agents with it", () => {
    expect(credentialNote(cred({ active: false, revoked_at: "2026-11-01T03:00:00" }))).toBe(
      "Revoked. Its sub-agents were revoked with it.",
    );
  });
});

describe("orderCredentials", () => {
  it("puts live credentials first, soonest to lapse first, then the rest newest first", () => {
    const late = cred({ instance: "late", expires_at: "2026-11-03T00:00:00" });
    const soon = cred({ instance: "soon", expires_at: "2026-11-01T06:00:00" });
    const oldGone = cred({ instance: "old", active: false, expires_at: "2026-10-20T00:00:00" });
    const newGone = cred({ instance: "new", active: false, expires_at: "2026-10-30T00:00:00" });
    const { live, ended } = orderCredentials([oldGone, late, newGone, soon]);
    expect(live.map((c) => c.instance)).toEqual(["soon", "late"]);
    expect(ended.map((c) => c.instance)).toEqual(["new", "old"]);
  });

  it("keeps only the most recent ended credentials", () => {
    const many = Array.from({ length: 30 }, (_, i) =>
      cred({
        instance: `x${i}`,
        active: false,
        expires_at: `2026-10-${String(i + 1).padStart(2, "0")}T00:00:00`,
      }),
    );
    const { ended, endedHidden } = orderCredentials(many, 20);
    expect(ended).toHaveLength(20);
    expect(ended[0].instance).toBe("x29");
    expect(endedHidden).toBe(10);
  });
});

describe("descendants", () => {
  it("counts the live sub-agents a revocation takes with it", () => {
    const parent = cred({ instance: "p" });
    const child = cred({ instance: "c", lineage: ["p"] });
    const grandchild = cred({ instance: "g", lineage: ["p", "c"] });
    const gone = cred({ instance: "d", lineage: ["p"], active: false });
    const stranger = cred({ instance: "s" });
    expect(descendants("p", [parent, child, grandchild, gone, stranger])).toEqual(["c", "g"]);
    expect(descendants("s", [parent, child, stranger])).toEqual([]);
  });
});

describe("countdown", () => {
  const now = Date.parse("2026-11-01T09:00:00Z");

  it("reads naive timestamps as UTC and says how long is left", () => {
    expect(countdown("2026-11-01T12:00:00", now)).toBe("lapses in 3h");
    expect(countdown("2026-11-01T09:40:00", now)).toBe("lapses in 40m");
    expect(countdown("2026-11-04T09:00:00", now)).toBe("lapses in 3d");
  });

  it("says how long ago it lapsed", () => {
    expect(countdown("2026-11-01T07:00:00", now)).toBe("lapsed 2h ago");
  });
});

describe("delegationState", () => {
  it("reads revoked, then suspended, then the server's active flag", () => {
    expect(delegationState(delegation())).toBe("active");
    expect(delegationState(delegation({ active: false }))).toBe("expired");
    expect(
      delegationState(delegation({ active: false, suspended_at: "2026-11-02T00:00:00" })),
    ).toBe("suspended");
    expect(
      delegationState(
        delegation({
          active: false,
          suspended_at: "2026-11-02T00:00:00",
          revoked_at: "2026-11-03T00:00:00",
        }),
      ),
    ).toBe("revoked");
  });
});

describe("delegationScope", () => {
  it("says what the agent may decide, as a sentence rather than JSON", () => {
    expect(delegationScope(delegation())).toBe(
      "finding disposition at low and medium, by claude-opus-5.5; 1 in 5 decisions is sampled for your review",
    );
  });

  it("lists three tiers and two families, and every decision when sampling is 1", () => {
    expect(
      delegationScope(
        delegation({
          tiers: ["T1", "T2", "T3"],
          approver_families: ["a", "b"],
          sampling: 1,
        }),
      ),
    ).toBe("finding disposition at T1, T2 and T3, by a or b; every decision is sampled for your review");
  });

  it("gives a percentage when sampling is not a neat fraction", () => {
    expect(delegationScope(delegation({ sampling: 0.15 }))).toContain(
      "15% of decisions are sampled",
    );
  });

  it("says when nothing is sampled", () => {
    expect(delegationScope(delegation({ sampling: 0 }))).toContain("no decision is sampled");
  });
});

describe("agreementNote", () => {
  it("states agreement against the suspension threshold", () => {
    expect(
      agreementNote({ agreed: 18, reviewed: 20, window: 20, threshold: 0.9 }),
    ).toBe("You agreed with 18 of the last 20 sampled decisions (90%). It suspends below 90%.");
  });

  it("says when no sample has been reviewed yet", () => {
    expect(agreementNote({ agreed: 0, reviewed: 0, window: 20, threshold: 0.9 })).toBe(
      "No sampled decision has been reviewed yet. It suspends if agreement falls below 90%.",
    );
  });
});
