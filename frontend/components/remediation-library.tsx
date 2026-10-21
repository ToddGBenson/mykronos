import Link from "next/link";

import { FixEfficacyPanel } from "@/components/fix-efficacy";
import { Label, Pill } from "@/components/primitives";
import { getFixEfficacy, getRemediationDigest, type RemediationDigest } from "@/lib/server";

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
 *
 * Once its own page and its own nav entry ("Remediation library",
 * `/remediation`); now the last section of Remediate today, below the
 * worklist, the way #60820 made the repository page's Patchwork history a
 * section of that tab. The open pull requests are part of today's work — each
 * is a fix waiting only on a reviewer — so they belong on the page that asks
 * what today's work is. `id="library"` is the anchor `/remediation` redirects
 * to (`lib/retired-routes.ts`); renaming it breaks those bookmarks.
 *
 * A failure here renders in place rather than as a page-level error, so a
 * digest that cannot load never takes the worklist above it down with it.
 */
export async function RemediationLibrary() {
  // Fetched alongside rather than nested: an efficacy query that fails should
  // not take the digest with it, and vice versa.
  const [digest, efficacy] = await Promise.all([
    getRemediationDigest(),
    getFixEfficacy(),
  ]);

  return (
    <section id="library" className="flex scroll-mt-4 flex-col gap-3 border-t border-rule pt-5">
      <header className="flex flex-col gap-1">
        <div className="flex flex-wrap items-baseline gap-3">
          <h2 className="text-sm font-bold">Remediation library</h2>
          {digest.ok ? (
            <span className="font-mono text-[13px] text-ink-3">
              {digest.data.total_open_prs} open pull request
              {digest.data.total_open_prs === 1 ? "" : "s"} in {digest.data.groups.length} group
              {digest.data.groups.length === 1 ? "" : "s"}
            </span>
          ) : null}
        </div>
        <p className="max-w-prose text-[14px] leading-relaxed text-ink-3">
          Patchwork&rsquo;s open pull requests across every repository, grouped
          by the fix they make, and how well each fixer&rsquo;s fixes have held.
        </p>
      </header>

      {efficacy.ok ? (
        <FixEfficacyPanel efficacy={efficacy.data} />
      ) : (
        <p className="border border-rule bg-paper-2 px-3 py-2 text-[13px] text-critical">
          {efficacy.error}
        </p>
      )}

      {!digest.ok ? (
        <p className="border border-rule bg-paper-2 px-3 py-2 text-[13px] text-critical">
          Remediation digest unavailable: {digest.error}
        </p>
      ) : (
        <DigestGroups groups={digest.data.groups} note={digest.data.note} />
      )}
    </section>
  );
}

function DigestGroups({ groups, note }: Pick<RemediationDigest, "groups" | "note">) {
  return (
    <>
      <p className="max-w-prose border-l-2 border-rule bg-paper-2 px-3 py-2 text-[14px] leading-relaxed text-ink-2">
        {note}
      </p>
      {groups.length === 0 ? (
        <p className="border border-dashed border-rule bg-paper-2 px-3 py-3 text-[14px] leading-relaxed text-ink-3">
          No Patchwork pull request is open. That is the resting state — this
          section fills up when the pipeline generates fixes and empties as people
          merge or close them. It is not a sign that nothing is fixable.
        </p>
      ) : (
        <ul className="flex flex-col gap-3">
          {groups.map((group) => (
            <li key={group.rule_id} className="border border-rule bg-paper-2">
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 border-b border-rule-soft px-3 py-2">
                <span className="text-[13px] font-bold">{group.title}</span>
                {group.severity ? (
                  <Pill tone={SEVERITY_TONE[group.severity] ?? "muted"}>
                    {group.severity}
                  </Pill>
                ) : null}
                <span className="font-mono text-[12px] text-ink-3">
                  {group.rule_id}
                </span>
                <span className="ml-auto whitespace-nowrap font-mono text-[12px] text-ink-2">
                  {group.repos.length} repositor
                  {group.repos.length === 1 ? "y" : "ies"}
                </span>
              </div>

              {group.rationale ? (
                <p className="max-w-prose border-b border-rule-soft px-3 py-2 text-[14px] leading-relaxed text-ink-2">
                  {group.rationale}
                </p>
              ) : null}

              <div className="px-3 py-2">
                <Label>Open pull requests</Label>
                <ul className="mt-1.5 flex flex-col gap-1">
                  {group.repos.map((repo) => (
                    <li
                      key={`${repo.repo_full_name}:${repo.finding_id}`}
                      className="flex flex-wrap items-baseline gap-x-3 font-mono text-[12px]"
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
    </>
  );
}
