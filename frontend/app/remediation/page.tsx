import Link from "next/link";

import { FixEfficacyPanel } from "@/components/fix-efficacy";
import { ErrorPanel, Label, Pill } from "@/components/primitives";
import { getFixEfficacy, getRemediationDigest } from "@/lib/server";

export const dynamic = "force-dynamic";

const SEVERITY_TONE: Record<string, "critical" | "warn" | "muted"> = {
  critical: "critical",
  high: "critical",
  medium: "warn",
};

/**
 * The same fix, everywhere it is open (spec 19 §3.4).
 *
 * Ten repositories with the same unpinned dependency means ten draft pull
 * requests, reviewed one at a time with nothing on any of them to say they
 * are the same change. A reviewer who has understood the fix once should not
 * have to rediscover it nine more times.
 *
 * Grouped, never merged. Each of these stays a separate pull request against
 * a separate repository — one pull request touching ten repositories would
 * bypass per-repo review and CODEOWNERS, which is most of what makes a draft
 * PR an acceptable thing for a bot to open at all.
 */
export default async function RemediationPage() {
  // Fetched alongside rather than nested: an efficacy query that fails should
  // not take the digest with it, and vice versa.
  const [digest, efficacy] = await Promise.all([
    getRemediationDigest(),
    getFixEfficacy(),
  ]);

  if (!digest.ok) {
    return <ErrorPanel title="Remediation digest unavailable" detail={digest.error} />;
  }

  const { groups, total_open_prs: total, note } = digest.data;

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-baseline gap-3">
        <h1 className="text-xl font-bold tracking-tight">Remediation</h1>
        <span className="font-mono text-[11px] text-ink-3">
          {total} open pull request{total === 1 ? "" : "s"} in {groups.length} group
          {groups.length === 1 ? "" : "s"}
        </span>
      </div>

      <p className="max-w-prose border-l-2 border-rule bg-paper-2 px-3 py-2 text-[11px] leading-relaxed text-ink-2">
        {note}
      </p>

      {efficacy.ok ? (
        <FixEfficacyPanel efficacy={efficacy.data} />
      ) : (
        <p className="border border-rule bg-paper-2 px-3 py-2 text-[11px] text-critical">
          {efficacy.error}
        </p>
      )}

      {groups.length === 0 ? (
        <p className="border border-dashed border-rule bg-paper-2 px-3 py-3 text-[11px] leading-relaxed text-ink-3">
          No Patchwork pull request is open. That is the resting state — this
          page fills up when the pipeline generates fixes and empties as people
          merge or close them. It is not a sign that nothing is fixable.
        </p>
      ) : (
        <ul className="flex flex-col gap-3">
          {groups.map((group) => (
            <li key={group.rule_id} className="border border-rule bg-paper-2">
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 border-b border-rule-soft px-3 py-2">
                <span className="text-[11px] font-bold">{group.title}</span>
                {group.severity ? (
                  <Pill tone={SEVERITY_TONE[group.severity] ?? "muted"}>
                    {group.severity}
                  </Pill>
                ) : null}
                <span className="font-mono text-[10px] text-ink-3">
                  {group.rule_id}
                </span>
                <span className="ml-auto whitespace-nowrap font-mono text-[10px] text-ink-2">
                  {group.repos.length} repositor
                  {group.repos.length === 1 ? "y" : "ies"}
                </span>
              </div>

              {group.rationale ? (
                <p className="max-w-prose border-b border-rule-soft px-3 py-2 text-[11px] leading-relaxed text-ink-2">
                  {group.rationale}
                </p>
              ) : null}

              <div className="px-3 py-2">
                <Label>Open pull requests</Label>
                <ul className="mt-1.5 flex flex-col gap-1">
                  {group.repos.map((repo) => (
                    <li
                      key={`${repo.repo_full_name}:${repo.finding_id}`}
                      className="flex flex-wrap items-baseline gap-x-3 font-mono text-[10px]"
                    >
                      <span className="text-ink-2">{repo.repo_full_name}</span>
                      {repo.fix_pr_url ? (
                        <Link
                          href={repo.fix_pr_url}
                          className="text-accent hover:underline"
                        >
                          #{repo.fix_pr_number ?? "?"}
                        </Link>
                      ) : null}
                      {/* `human_edited` matters more than it looks: spec 08 §3
                          makes that transition permanent, so this branch is
                          one Patchwork will never touch again. A reviewer
                          batching through the group needs to know which one
                          somebody has already taken over. */}
                      {repo.pr_status === "human_edited" ? (
                        <span className="text-warn">taken over by a person</span>
                      ) : null}
                    </li>
                  ))}
                </ul>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
