import { describe, expect, it } from "vitest";

import {
  credentialDateLine,
  credentialMeaning,
  type Credential,
} from "@/lib/credential-row";

function row(over: Partial<Credential>): Credential {
  return {
    kind: "ingestion_token",
    repo_full_name: "example-org/payments-api",
    state: "unverified",
    rotate_after: "2026-12-01T00:00:00",
    days_until_due: 18,
    action: "",
    ...over,
  } as Credential;
}

describe("a dependabot_unsynced credential row", () => {
  const unsynced = row({
    state: "dependabot_unsynced",
    reason: "The App's installation holds no 'dependabot_secrets'.",
    recorded_at: "2026-11-13T05:33:41",
    owner: "operator",
    action: "grant the App 'Dependabot secrets: Read and write' and accept it",
  });

  it("takes its remedy from the response, not a fixed rotate or check sentence", () => {
    const meaning = credentialMeaning(unsynced);

    expect(meaning.word).toBe("Not in Dependabot secrets");
    expect(meaning.action).toBe(unsynced.action);
    expect(meaning.action).not.toMatch(/rotate|scans are arriving/i);
  });

  it("follows a hand-rotation reason to its own text", () => {
    const meaning = credentialMeaning(
      row({
        state: "dependabot_unsynced",
        action: "Rotate by hand: repair-ingestion-token.ps1",
        owner: "hubops",
      }),
    );

    expect(meaning.action).toBe("Rotate by hand: repair-ingestion-token.ps1");
  });

  it("shows no remedy when the response names none", () => {
    expect(credentialMeaning(row({ state: "dependabot_unsynced", action: "" })).action).toBe("");
  });

  it("never prints a due date: the token is not due, its copy is missing", () => {
    const line = credentialDateLine(unsynced);

    expect(line).toBe("refused 2026-11-13");
    expect(line).not.toMatch(/due|overdue|expires/);
  });

  it("still says something when no as-of was recorded", () => {
    expect(credentialDateLine(row({ state: "dependabot_unsynced" }))).toBe("refusal recorded");
  });
});

describe("the other credential rows are unchanged", () => {
  it("a due token keeps the rotate sentence and its date", () => {
    const due = row({ state: "due", days_until_due: -3 });

    expect(credentialMeaning(due).action).toMatch(/^rotate by hand/);
    expect(credentialDateLine(due)).toBe("due 2026-12-01 (3 days overdue)");
  });

  it("an unverified token never says rotate and carries no date", () => {
    const unverified = row({ state: "unverified" });

    expect(credentialMeaning(unverified).action).toMatch(/do not rotate/);
    expect(credentialDateLine(unverified)).toBe("awaiting delivery confirmation");
  });
});
