import type { components } from "@/lib/api-types";

export type Credential = components["schemas"]["CredentialOut"];

export type CredentialMeaning = {
  tone: "critical" | "warn" | "muted";
  word: string;
  action: string;
};

/**
 * What each credential state asks of the operator (TheHub #60974).
 *
 * Owned by the page, not taken from the response: the one sentence this
 * section must never print is "rotate" against an unverified token, because
 * rotating a token whose stored copy works is how a repository goes dark
 * (D-097). Only `due` is a reason to rotate.
 *
 * `dependabot_unsynced` (TheHub #60855) is the exception that proves it: its
 * remedy depends on the recorded reason (a missing App permission, a hand
 * rotation, a failed write under a held grant), and the backend picks the
 * text from that reason. The response's `action` is therefore used as is, and
 * an empty one is not replaced with a guess.
 */
const CREDENTIAL: Record<string, CredentialMeaning> = {
  due: {
    tone: "critical",
    word: "Due",
    action:
      "rotate by hand (Concourse-scanned repos cannot receive a rotated token, D-086)",
  },
  unverified: {
    tone: "warn",
    word: "Unverified",
    action: "check that scans are arriving - do not rotate (D-097)",
  },
  dependabot_unsynced: {
    tone: "warn",
    word: "Not in Dependabot secrets",
    action: "",
  },
  expiring: {
    tone: "muted",
    word: "Expiring",
    action: "expires on its own; mint a new credential for the next run if one is needed",
  },
};

export function credentialMeaning(credential: Credential): CredentialMeaning {
  const known = CREDENTIAL[credential.state] ?? {
    tone: "muted" as const,
    word: credential.state,
    action: "",
  };
  if (credential.state === "dependabot_unsynced") {
    return { ...known, action: credential.action ?? "" };
  }
  return known;
}

function whenDue(days: number): string {
  // An agent credential is listed only inside 24 hours (TheHub #61052), where a
  // whole-day count reads "in 0 days" or "in 1 day"; give it in hours.
  if (days > 0 && days < 1) {
    const hours = Math.max(1, Math.round(days * 24));
    return `in ${hours} ${hours === 1 ? "hour" : "hours"}`;
  }
  const whole = Math.round(Math.abs(days));
  const unit = whole === 1 ? "day" : "days";
  return days < 0 ? `${whole} ${unit} overdue` : `in ${whole} ${unit}`;
}

/**
 * The date half of a row. An unverified row carries no date at all, and nor
 * does a Dependabot row: "due <date> (N days overdue)" reads as a prompt to
 * rotate, which is wrong for both (D-097 for the first; the second's token is
 * not due, its Dependabot copy is missing). It shows when the refusal was
 * recorded instead.
 */
export function credentialDateLine(credential: Credential): string {
  if (credential.state === "unverified") {
    return "awaiting delivery confirmation";
  }
  if (credential.state === "dependabot_unsynced") {
    return credential.recorded_at
      ? `refused ${credential.recorded_at.slice(0, 10)}`
      : "refusal recorded";
  }
  const date = credential.rotate_after ?? credential.expires_at ?? null;
  return `${credential.rotate_after ? "due" : "expires"} ${
    date ? date.slice(0, 10) : "unknown"
  } (${whenDue(credential.days_until_due)})`;
}
