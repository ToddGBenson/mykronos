/**
 * In-repo scanner suppressions (TheHub #60963, decision #60815 option B):
 * what the repository silenced itself, listed beside the risks the platform
 * accepted. Pure helpers, so the vitest suite can hold the wording.
 */

import type { paths } from "./api-types";

export type RepoSuppressions =
  paths["/api/dashboard/repos/{repo_id}/suppressions"]["get"]["responses"]["200"]["content"]["application/json"];
export type SuppressionRow = RepoSuppressions["suppressions"][number];
export type SuppressionStatus = SuppressionRow["status"];

/** The expiry as a reader says it: "no expiry", "expired 2020-01-31", "until 2999-12-31". */
export function expiryText(row: Pick<SuppressionRow, "status" | "expires_at">): string {
  if (row.status === "no_expiry" || !row.expires_at) return "no expiry";
  return row.status === "expired" ? `expired ${row.expires_at}` : `until ${row.expires_at}`;
}

/** Expired is the loudest; undated is a warning, because nobody will revisit it. */
export function statusTone(status: SuppressionStatus): "critical" | "warn" | "muted" {
  if (status === "expired") return "critical";
  return status === "no_expiry" ? "warn" : "muted";
}

/** `file:line`, or the file alone when the tool gave no line. */
export function location(row: Pick<SuppressionRow, "file_path" | "line">): string {
  return row.line === null || row.line === undefined ? row.file_path : `${row.file_path}:${row.line}`;
}
