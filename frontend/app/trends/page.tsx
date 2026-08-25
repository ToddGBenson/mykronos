import { ErrorPanel, Label, Pill, StatTile } from "@/components/primitives";
import type { MaturityRepo, TrendSeries } from "@/lib/api";
import { getMaturity, getTrends } from "@/lib/server";

export const dynamic = "force-dynamic";

/**
 * Maturity and trends (spec 10 §2.3).
 *
 * Two questions no other view answers: is this getting better, and what
 * should this team do next.
 *
 * The maturity half deliberately does not show a score out of ten or a
 * league table. A tier is a description of where a repository has got to,
 * with the specific next step attached; a number would invite comparison
 * between repositories whose circumstances have nothing in common, and the
 * team with the oldest codebase would come last forever.
 */
export default async function TrendsPage() {
  const [trends, maturity] = await Promise.all([getTrends(), getMaturity()]);

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-baseline gap-3">
        <h1 className="text-xl font-bold tracking-tight">Trends &amp; maturity</h1>
        {maturity.ok ? (
          <span className="font-mono text-[11px] text-ink-3">
            model v{maturity.data.model_version}
          </span>
        ) : null}
      </div>

      {trends.ok ? <Trends series={trends.data} /> : (
        <ErrorPanel title="Trends unavailable" detail={trends.error} />
      )}

      {maturity.ok ? (
        <Maturity
          repos={maturity.data.repos}
          tiers={maturity.data.tiers}
        />
      ) : (
        <ErrorPanel title="Maturity unavailable" detail={maturity.error} />
      )}
    </div>
  );
}

function Trends({ series }: { series: TrendSeries }) {
  const points = series.points;
  const latest = points[points.length - 1];
  const first = points[0];
  const mttf = series.mean_time_to_fix_days;

  return (
    <section className="flex flex-col gap-3">
      <div>
        <h2 className="text-sm font-bold">Last {series.days} days</h2>
        <p className="mt-0.5 max-w-prose text-[11px] leading-relaxed text-ink-3">
          {series.note}
        </p>
      </div>

      <div className="grid grid-cols-2 gap-2 lg:grid-cols-4">
        <StatTile
          label="Open critical"
          value={latest?.open_critical ?? 0}
          sub={delta(first?.open_critical, latest?.open_critical)}
          alert={(latest?.open_critical ?? 0) > 0}
        />
        <StatTile
          label="Open high"
          value={latest?.open_high ?? 0}
          sub={delta(first?.open_high, latest?.open_high)}
        />
        <StatTile
          label="Open total"
          value={latest?.open_total ?? 0}
          sub={delta(first?.open_total, latest?.open_total)}
        />
        <StatTile
          label="Mean time to fix"
          value={mttf === null ? "—" : `${mttf.toFixed(1)}d`}
          sub={mttf === null ? "nothing fixed yet" : "fixed findings only"}
        />
      </div>

      <Sparklines points={points} />

      <RegressionCoverageBanner coverage={series.regression_coverage} />
    </section>
  );
}

/**
 * Which of the vulnerabilities we have already fixed would we notice coming
 * back? (spec 31 §3)
 *
 * The only number on this page that measures the estate getting
 * *structurally* safer rather than temporarily cleaner. Everything above it
 * counts what is open; this counts what was learned, which is why it sits
 * beside them rather than on a page of its own.
 */
function RegressionCoverageBanner({
  coverage,
}: {
  coverage: TrendSeries["regression_coverage"];
}) {
  // An empty denominator, not a failing grade. `0%` on an estate that has
  // never fixed anything would be a verdict on work nobody has had the chance
  // to do yet.
  if (!coverage.available || coverage.ratio === null) {
    return (
      <div className="border border-rule bg-paper-2 px-3 py-2">
        <Label>Regression coverage</Label>
        <p className="mt-1 max-w-prose text-[11px] leading-relaxed text-ink-3">
          Nothing has been fixed across the portfolio yet, so there is no
          coverage to report.
        </p>
      </div>
    );
  }

  return (
    <div className="border border-rule bg-paper-2 px-3 py-2">
      <Label>Regression coverage</Label>
      <p className="mt-1 flex flex-wrap items-baseline gap-x-2 text-[11px] text-ink-2">
        <span className="tabular font-mono text-xl font-bold leading-none text-ink">
          {Math.round(coverage.ratio * 100)}%
        </span>
        <span>
          — {coverage.covered} of {coverage.fixed_findings} fixed findings have
          a test pinned.
        </span>
        <span className="font-mono text-[10px] text-ink-3">
          {coverage.demonstrated} demonstrated · {coverage.asserted} asserted
        </span>
        {/* Beside the headline, never folded into it: a pinned test whose lane
            stopped running is a protection that quietly expired, and hiding
            that would make this a number that only ever goes up. */}
        {coverage.stale > 0 ? (
          <span className="border border-high bg-high-wash px-1 font-mono text-[9px] uppercase tracking-[0.08em] text-high">
            {coverage.stale} stale
          </span>
        ) : null}
      </p>
      <p className="mt-1 max-w-prose text-[10px] leading-relaxed text-ink-3">
        {coverage.note}
      </p>
    </div>
  );
}

/** "3 fewer than 90 days ago" reads better than an arrow nobody can decode. */
function delta(from: number | undefined, to: number | undefined): string {
  if (from === undefined || to === undefined) return "";
  const change = to - from;
  if (change === 0) return "unchanged over the window";
  const direction = change > 0 ? "more" : "fewer";
  return `${Math.abs(change)} ${direction} than at the start`;
}

function Sparklines({ points }: { points: TrendSeries["points"] }) {
  const lines: {
    key: string;
    label: string;
    values: (number | null)[];
    tone: string;
    max: number;
    /** Whether a rising line is good news. Trust score is the odd one out,
     *  and colouring it like the others would read exactly backwards. */
    higherIsBetter?: boolean;
  }[] = [
    {
      key: "critical",
      label: "Open critical",
      values: points.map((p) => p.open_critical),
      tone: "text-critical",
      max: Math.max(1, ...points.map((p) => p.open_critical)),
    },
    {
      key: "total",
      label: "Open findings",
      values: points.map((p) => p.open_total),
      tone: "text-high",
      max: Math.max(1, ...points.map((p) => p.open_total)),
    },
    {
      key: "risk",
      label: "Risk score",
      values: points.map((p) => p.risk_score),
      tone: "text-medium",
      max: 100,
    },
    {
      key: "trust",
      label: "Supply-chain trust",
      values: points.map((p) => p.trust_score),
      tone: "text-pass",
      max: 100,
      higherIsBetter: true,
    },
  ];

  return (
    <div className="grid gap-3 md:grid-cols-2">
      {lines.map((line) => (
        <div key={line.key} className="border border-rule bg-paper-2 p-3">
          <div className="flex items-baseline justify-between">
            <Label>{line.label}</Label>
            <span className="tabular font-mono text-[10px] text-ink-3">
              {describeLatest(line.values)}
              {line.higherIsBetter ? " · higher is better" : ""}
            </span>
          </div>
          <Spark values={line.values} max={line.max} tone={line.tone} />
        </div>
      ))}
    </div>
  );
}

function describeLatest(values: (number | null)[]): string {
  const known = values.filter((v): v is number => v !== null);
  if (known.length === 0) return "no data";
  return String(known[known.length - 1]);
}

function Spark({
  values,
  max,
  tone,
}: {
  values: (number | null)[];
  max: number;
  tone: string;
}) {
  const width = 300;
  const height = 40;
  const known = values.filter((v): v is number => v !== null);

  if (known.length < 2) {
    return (
      <p className="mt-2 text-[11px] text-ink-3">
        {known.length === 0
          ? "Nothing recorded in this window."
          : "One data point. A line needs two."}
      </p>
    );
  }

  // Nulls are gaps, not zeros. Drawing a missing risk score as 0 would show a
  // repository at its safest exactly when nothing was measuring it.
  const step = width / Math.max(1, values.length - 1);
  const segments: string[] = [];
  let current: string[] = [];
  values.forEach((value, index) => {
    if (value === null) {
      if (current.length > 1) segments.push(current.join(" "));
      current = [];
      return;
    }
    const x = index * step;
    const y = height - (Math.min(value, max) / max) * height;
    current.push(`${x.toFixed(1)},${y.toFixed(1)}`);
  });
  if (current.length > 1) segments.push(current.join(" "));

  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      className={`mt-2 h-10 w-full ${tone}`}
      role="img"
      aria-label={`Trend, currently ${known[known.length - 1]}`}
    >
      {segments.map((points) => (
        <polyline
          key={points.slice(0, 24)}
          points={points}
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
        />
      ))}
    </svg>
  );
}

function Maturity({
  repos,
  tiers,
}: {
  repos: MaturityRepo[];
  tiers: { id: string; name: string; summary: string }[];
}) {
  return (
    <section className="flex flex-col gap-3">
      <div>
        <h2 className="text-sm font-bold">Maturity</h2>
        <p className="mt-0.5 max-w-prose text-[11px] leading-relaxed text-ink-3">
          Every criterion measures <em>evidence</em>, never configuration.
          Nothing here can be satisfied by changing a setting, and no tier
          rewards turning Oracle&rsquo;s gate on — spec 09 §6 makes that
          conditional on shadow-mode data, so the model asks whether the data
          exists instead of whether the switch is flipped.
        </p>
      </div>

      <ol className="flex flex-wrap gap-1.5">
        {tiers.map((tier, index) => (
          <li
            key={tier.id}
            title={tier.summary}
            className="border border-rule px-2 py-1 font-mono text-[9px] text-ink-3"
          >
            {index}. {tier.name}
          </li>
        ))}
      </ol>

      {repos.length === 0 ? (
        <p className="text-[11px] text-ink-3">No active repositories yet.</p>
      ) : (
        <ul className="flex flex-col gap-2">
          {repos.map((repo) => (
            <RepoMaturity key={repo.repo_full_name} repo={repo} />
          ))}
        </ul>
      )}
    </section>
  );
}

function RepoMaturity({ repo }: { repo: MaturityRepo }) {
  return (
    <li className="border border-rule bg-paper-2">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 border-b border-rule-soft px-3 py-2">
        <span className="font-mono text-[11px] font-bold">
          {repo.repo_full_name}
        </span>
        <Pill tone={repo.next_tier_name ? "warn" : "pass"}>{repo.tier_name}</Pill>
        <span className="font-mono text-[10px] text-ink-3">
          {repo.tier_index + 1} of {repo.total_tiers}
        </span>
      </div>

      <p className="max-w-prose px-3 py-2 text-[11px] leading-relaxed text-ink-2">
        {repo.tier_summary}
      </p>

      {repo.blocking.length > 0 ? (
        <div className="border-t border-rule-soft px-3 py-2">
          <Label>To reach {repo.next_tier_name}</Label>
          <ul className="mt-1.5 flex flex-col gap-1.5">
            {repo.blocking.map((criterion) => (
              <li key={criterion.key} className="text-[11px] leading-relaxed">
                <span className="text-ink-2">{criterion.label}</span>{" "}
                <span className="font-mono text-[10px] text-ink-3">
                  — {criterion.measured}, needs {criterion.threshold}
                </span>
                {criterion.why ? (
                  <p className="max-w-prose text-[11px] text-ink-3">
                    {criterion.why}
                  </p>
                ) : null}
              </li>
            ))}
          </ul>
        </div>
      ) : (
        <p className="border-t border-rule-soft px-3 py-2 text-[11px] text-ink-3">
          Top tier. The model has nothing further to ask for — which is a
          statement about the model, not a claim that the work is finished.
        </p>
      )}

      {/* Every criterion, not only the blocking ones: spec 10 §6 forbids a
          derived label whose working cannot be inspected. */}
      <details className="border-t border-rule-soft px-3 py-2">
        <summary className="cursor-pointer font-mono text-[10px] text-ink-3">
          All {repo.criteria.length} criteria
        </summary>
        <table className="mt-2 w-auto border-collapse font-mono text-[10px]">
          <tbody>
            {repo.criteria.map((criterion) => (
              <tr key={criterion.key}>
                <td className="py-0.5 pr-3">
                  <span className={criterion.passed ? "text-pass" : "text-ink-3"}>
                    {criterion.passed ? "pass" : "—"}
                  </span>
                </td>
                <td className="py-0.5 pr-4 text-ink-2">{criterion.label}</td>
                <td className="tabular py-0.5 pr-3 text-right text-ink-3">
                  {criterion.measured}
                </td>
                <td className="py-0.5 text-ink-3">{criterion.threshold}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </li>
  );
}
