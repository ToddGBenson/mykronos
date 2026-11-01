import Link from "next/link";

import { AgeChart, RiskMatrix } from "@/components/risk-page";
import { EmptyState, ErrorPanel } from "@/components/primitives";
import { buildRiskPage } from "@/lib/risk-page";
import { getRiskInputs } from "@/lib/server-risk";

export const dynamic = "force-dynamic";

/**
 * Risk (TheHub #61139; design v2, P4 and P6): products as rows, health as
 * columns, so "is anything broken?" has one page instead of three. Every
 * cell opens the filtered view behind it.
 */
export default async function RiskPage({
  searchParams,
}: {
  searchParams: Promise<{ problems?: string; benchmark?: string }>;
}) {
  const params = await searchParams;
  const problemsOnly = params.problems === "1";
  const benchmark = params.benchmark === "1";
  const result = await getRiskInputs({ benchmark });

  if (!result.ok) {
    return <ErrorPanel title="Risk unavailable" detail={result.error} />;
  }

  const page = buildRiskPage(result.data, { now: result.asOf, problemsOnly, benchmark });
  const asOf = new Date(result.asOf).toISOString().slice(11, 16);

  const href = (patch: { problems?: boolean; benchmark?: boolean }) => {
    const next = new URLSearchParams();
    if (patch.problems ?? problemsOnly) next.set("problems", "1");
    if (patch.benchmark ?? benchmark) next.set("benchmark", "1");
    const query = next.toString();
    return query ? `/risk?${query}` : "/risk";
  };
  const chip = (on: boolean) =>
    `inline-flex min-h-11 items-center rounded-full border px-3 text-[12px] ${
      on ? "border-accent font-semibold text-accent" : "border-rule text-ink-2 hover:border-accent"
    }`;

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <h1 className="text-xl font-bold tracking-tight">Risk</h1>
        <span className="font-mono text-[13px] text-ink-3">
          {page.scannedRecently} of {page.products} scanned in the last 24h · as of {asOf} UTC
        </span>
        <nav aria-label="Show" className="ml-auto flex flex-wrap gap-1.5">
          <Link href={href({ problems: false })} className={chip(!problemsOnly)} aria-current={!problemsOnly ? "true" : undefined}>
            All products
          </Link>
          <Link href={href({ problems: true })} className={chip(problemsOnly)} aria-current={problemsOnly ? "true" : undefined}>
            Problems only
          </Link>
          <Link href={href({ benchmark: !benchmark })} className={chip(benchmark)} aria-pressed={benchmark}>
            Include benchmark
          </Link>
        </nav>
      </div>

      {page.incomplete.length ? (
        <p className="border border-rule bg-paper-2 px-3 py-2 text-[13px] text-ink-2">
          Some reads failed for {page.incomplete.join(", ")}. Those cells say{" "}
          <span className="font-mono">unknown</span> or <span className="font-mono">?</span> rather
          than zero, and the estate totals are floors.
        </p>
      ) : null}

      {page.products === 0 ? (
        <EmptyState title="No products onboarded yet" detail="Onboard a repository and it appears here." />
      ) : page.rows.length === 0 ? (
        <>
          <EmptyState title="No product has a problem" detail="Every product passed every column." />
          <RiskMatrix page={page} />
        </>
      ) : (
        <RiskMatrix page={page} />
      )}

      <div className="grid gap-4 lg:grid-cols-[1fr_320px]">
        <AgeChart buckets={page.buckets} coverage={page.ageCoverage} />
        <section className="flex flex-col gap-2 border border-rule bg-paper-2 p-3">
          <h2 className="text-[15px] font-semibold text-ink">How to read it</h2>
          <p className="text-[13px] leading-relaxed text-ink-3">
            Columns run from &ldquo;can it ship&rdquo; on the left to &ldquo;what is old&rdquo; on
            the right. Gate is the verdict on the newest commit the gate judged on the default
            branch. Oldest is the oldest open high or critical against its own remediation target.
            Every cell opens the matching filtered view: a count opens the findings filtered to
            it, one red lane opens that lane&rsquo;s run history, and Needs you opens the review
            queue. A cell that could not be read says <span className="font-mono">unknown</span>,
            never zero.
          </p>
        </section>
      </div>
    </div>
  );
}
