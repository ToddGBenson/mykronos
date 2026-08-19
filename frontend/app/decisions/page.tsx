import Link from "next/link";

import {
  ErrorPanel,
  Label,
  ScoreMeter,
  StatTile,
  Verdict,
} from "@/components/primitives";
import {
  getPolicy,
  getPolicyHistory,
  getPortfolio,
  getShadowMode,
  getTermAnalytics,
} from "@/lib/server";

export const dynamic = "force-dynamic";

/**
 * Oracle, portfolio-wide.
 *
 * Three things a per-repo decision list cannot show: who is worst right now,
 * what blocking mode would have cost had it been on, and the policy every
 * score was produced from. The last one is here rather than buried in the repo
 * because a scoring rule you have to go looking for is one people assume is
 * arbitrary.
 */
export default async function DecisionsPage() {
  const [portfolio, shadow, policy, terms, history] = await Promise.all([
    getPortfolio(),
    getShadowMode(),
    getPolicy(),
    getTermAnalytics(),
    getPolicyHistory(),
  ]);

  if (!portfolio.ok) {
    return <ErrorPanel title="Portfolio unavailable" detail={portfolio.error} />;
  }

  const assessed = portfolio.data.repos
    .filter((repo) => repo.recommendation)
    .sort((a, b) => (b.raw_risk_score ?? 0) - (a.raw_risk_score ?? 0));
  const unassessed = portfolio.data.repos.length - assessed.length;

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-baseline gap-3">
        <h1 className="text-xl font-bold tracking-tight">Risk decisions</h1>
        <span className="font-mono text-[11px] text-ink-3">
          {assessed.length} assessed
          {unassessed > 0 ? ` · ${unassessed} not assessed` : ""}
        </span>
      </div>

      {shadow.ok ? (
        <section className="flex flex-col gap-2">
          <div>
            <h2 className="text-sm font-bold">Shadow mode</h2>
            <p className="mt-0.5 max-w-prose text-[11px] leading-relaxed text-ink-3">
              Oracle is advisory by default, which makes the last{" "}
              {shadow.data.window_days} days a free experiment: every{" "}
              <span className="font-mono">no go</span> that merged anyway is a
              merge blocking mode would have stopped. This is the evidence
              anyone should have to produce before proposing the gate start
              failing builds.
            </p>
          </div>

          <div className="grid grid-cols-2 gap-2 lg:grid-cols-4">
            <StatTile
              label="Would have blocked"
              value={shadow.data.would_have_blocked}
              sub="no go, merged anyway"
              alert={shadow.data.would_have_blocked > 0}
            />
            <StatTile
              label="…with a written reason"
              value={shadow.data.would_have_blocked_and_overridden}
              sub="a human overrode it"
            />
            <StatTile
              label="Merged"
              value={shadow.data.merged}
              sub="of judged pull requests"
            />
            <StatTile
              label="Closed unmerged"
              value={shadow.data.closed_unmerged}
              sub="abandoned, not shipped"
            />
          </div>

          {shadow.data.decisions_with_a_known_outcome === 0 ? (
            <p className="border border-dashed border-rule bg-paper-2 px-3 py-2 text-[11px] text-ink-3">
              No judged pull request has closed yet, so there is nothing to
              measure. The counters start moving on the first merge after
              Oracle scores a pull request.
            </p>
          ) : (
            <p className="border-l-2 border-rule bg-paper-2 px-3 py-2 text-[11px] leading-relaxed text-ink-2">
              {shadow.data.interpretation}
            </p>
          )}
        </section>
      ) : (
        <ErrorPanel title="Shadow-mode report unavailable" detail={shadow.error} />
      )}

      <section className="flex flex-col gap-2">
        <div>
          <h2 className="text-sm font-bold">Standing scores</h2>
          <p className="mt-0.5 max-w-prose text-[11px] leading-relaxed text-ink-3">
            Refreshed daily, ranked by the pre-clamp score so two repositories
            both showing 100 still have an order.
          </p>
        </div>

        {assessed.length === 0 ? (
          <p className="border border-dashed border-rule bg-paper-2 px-3 py-3 text-[11px] text-ink-3">
            No repository has enabled the <span className="font-mono">oracle</span>{" "}
            capability yet. Scanning without it is deliberate and supported —
            consent to being scanned is not consent to being scored.
          </p>
        ) : (
          <div className="scroll-x border border-rule">
            <table className="w-full min-w-[640px] border-collapse bg-paper-2 font-mono text-[11px]">
              <thead>
                <tr className="border-b-2 border-ink-2 text-left">
                  {["Repository", "Score", "Verdict", "Open C/H", "Assessed"].map(
                    (heading) => (
                      <th
                        key={heading}
                        className="whitespace-nowrap px-2 py-2 text-[9px] font-semibold uppercase tracking-[0.1em] text-ink-3"
                      >
                        {heading}
                      </th>
                    ),
                  )}
                </tr>
              </thead>
              <tbody>
                {assessed.map((repo) => (
                  <tr
                    key={repo.repo_id}
                    className="border-b border-rule-soft last:border-b-0 hover:bg-paper-3"
                  >
                    <td className="px-2 py-2">
                      <Link
                        href={`/repos/${repo.repo_id}?tab=decisions`}
                        className="font-semibold text-ink hover:text-accent"
                      >
                        {repo.repo_full_name}
                      </Link>
                    </td>
                    <td className="px-2 py-2">
                      <ScoreMeter score={repo.risk_score ?? 0} />
                    </td>
                    <td className="px-2 py-2">
                      <Verdict
                        recommendation={repo.recommendation}
                        score={repo.risk_score}
                      />
                    </td>
                    <td className="tabular px-2 py-2 text-ink-2">
                      {repo.severity_counts.critical ?? 0} /{" "}
                      {repo.severity_counts.high ?? 0}
                    </td>
                    <td className="whitespace-nowrap px-2 py-2 text-ink-3">
                      {repo.risk_assessed_at
                        ? new Date(repo.risk_assessed_at).toISOString().slice(0, 10)
                        : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="flex flex-col gap-2">
        <div>
          <h2 className="text-sm font-bold">What is driving the score</h2>
          <p className="mt-0.5 max-w-prose text-[11px] leading-relaxed text-ink-3">
            The table above says which repositories are worst. This says why —
            every term summed across the fleet, from the snapshot each decision
            already stores. One decision per repository, its latest, so a
            repository scanned ten times a day does not outweigh one scanned
            weekly.
          </p>
        </div>

        {!terms.ok ? (
          <ErrorPanel title="Term analytics unavailable" detail={terms.error} />
        ) : terms.data.terms.length === 0 ? (
          <p className="border border-dashed border-rule bg-paper-2 px-3 py-3 text-[11px] text-ink-3">
            No standing decision in the last {terms.data.window_days} days has
            any scoring term. Either nothing is onboarded to Oracle yet, or
            every repository is genuinely at zero.
          </p>
        ) : (
          <div className="scroll-x border border-rule">
            <table className="w-full min-w-[560px] border-collapse bg-paper-2 font-mono text-[11px]">
              <thead>
                <tr className="border-b-2 border-ink-2 text-left">
                  {["Term", "Points", "Repos", "…scoring no go"].map((heading) => (
                    <th
                      key={heading}
                      className="whitespace-nowrap px-2 py-2 text-[9px] font-semibold uppercase tracking-[0.1em] text-ink-3"
                    >
                      {heading}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {terms.data.terms.map((term) => (
                  <tr
                    key={term.key}
                    className="border-b border-rule-soft last:border-b-0 hover:bg-paper-3"
                  >
                    <td className="px-2 py-2 text-ink">{term.label}</td>
                    <td className="tabular px-2 py-2 text-ink-2">
                      {term.total_contribution.toFixed(1)}
                    </td>
                    <td className="tabular px-2 py-2 text-ink-3">{term.repos}</td>
                    <td className="tabular px-2 py-2 text-ink-3">
                      {term.no_go_repos}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {terms.ok && terms.data.terms.length > 0 ? (
          <p className="max-w-prose text-[11px] leading-relaxed text-ink-3">
            {terms.data.note}
          </p>
        ) : null}
      </section>

      <section id="policy" className="flex flex-col gap-2 scroll-mt-4">
        <div>
          <h2 className="text-sm font-bold">
            Policy{" "}
            {history.ok && history.data.versions.length > 0 ? (
          <div className="flex flex-col gap-1.5">
            <Label>Versions that have scored something</Label>
            <div className="scroll-x border border-rule">
              <table className="w-full min-w-[520px] border-collapse bg-paper-2 font-mono text-[11px]">
                <thead>
                  <tr className="border-b-2 border-ink-2 text-left">
                    {["Version", "Decisions", "Repos", "no go", "Last used"].map(
                      (heading) => (
                        <th
                          key={heading}
                          className="whitespace-nowrap px-2 py-2 text-[9px] font-semibold uppercase tracking-[0.1em] text-ink-3"
                        >
                          {heading}
                        </th>
                      ),
                    )}
                  </tr>
                </thead>
                <tbody>
                  {history.data.versions.map((entry) => (
                    <tr
                      key={entry.version}
                      className="border-b border-rule-soft last:border-b-0"
                    >
                      <td className="px-2 py-2 text-ink">
                        {entry.version}
                        {entry.current ? (
                          <span className="ml-1.5 text-[9px] text-accent">
                            in force
                          </span>
                        ) : null}
                      </td>
                      <td className="tabular px-2 py-2 text-ink-2">
                        {entry.decisions}
                      </td>
                      <td className="tabular px-2 py-2 text-ink-3">{entry.repos}</td>
                      <td className="tabular px-2 py-2 text-ink-3">
                        {entry.no_go_decisions}
                      </td>
                      <td className="whitespace-nowrap px-2 py-2 text-ink-3">
                        {entry.last_used ? entry.last_used.slice(0, 10) : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="max-w-prose text-[11px] leading-relaxed text-ink-3">
              {history.data.note}
            </p>
          </div>
        ) : null}

        {policy.ok ? (
              <span className="font-mono text-[11px] font-normal text-ink-3">
                v{policy.data.version}
              </span>
            ) : null}
          </h2>
          <p className="mt-0.5 max-w-prose text-[11px] leading-relaxed text-ink-3">
            {policy.ok
              ? policy.data.note
              : "The rules every score above was produced from."}
          </p>
        </div>

        {policy.ok ? (
          <>
            <pre className="scroll-x max-h-96 border border-rule bg-paper-2 p-3 font-mono text-[10px] leading-relaxed">
              {JSON.stringify(policy.data.source, null, 2)}
            </pre>
            <p className="text-[11px] text-ink-3">
              <Label>Why this is readable by everyone</Label>
              <br />
              A risk score you are not allowed to inspect is one people learn to
              route around. Anyone whose pull request Oracle judges can read the
              rule that judged it.
            </p>
          </>
        ) : (
          <ErrorPanel title="Policy unavailable" detail={policy.error} />
        )}
      </section>
    </div>
  );
}
