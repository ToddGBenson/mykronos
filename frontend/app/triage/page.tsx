import Link from "next/link";

import {
  EmptyState,
  ErrorPanel,
  Label,
  Pill,
  RelativeTime,
  SeverityText,
  StatTile,
  Verdict,
} from "@/components/primitives";
import { ClassificationReview } from "@/components/classification-review";
import { WorklistKeys } from "@/components/worklist";
import { FilterSelect } from "@/components/filter-select";
import { SEVERITY_ORDER, type Severity, type TriageItem } from "@/lib/api";
import { getBriefing, getTriage } from "@/lib/server";

export const dynamic = "force-dynamic";

/**
 * The capabilities that produce *findings*, which is not the same list as
 * `ALL_CAPABILITIES`.
 *
 * `atlas` was missing, and it is the one that mattered: every SCA finding in
 * the lake is filed under it — osv-scanner uploads with `--capability atlas` —
 * so dependency vulnerabilities were the one class this queue could show but
 * never filter down to. Easy to miss because the capability is *named* after
 * the supply-chain product rather than after "dependencies".
 *
 * Deliberately absent: `aegis` records insider-risk signals, `patchwork`
 * opens pull requests, and `oracle` scores what the others found. None of the
 * three writes a Finding, so a filter for them would always come back empty —
 * which reads as "no insider risk" rather than "wrong question".
 */
const CAPABILITIES = ["sast", "dast", "secrets", "containers", "iac", "cloud", "atlas"];

const CLASSIFICATIONS = [
  {
    value: "likely_false_positive",
    label: "likely FP",
    hint: "The classifier thinks this is not a defect. It cannot act on that — confirm or reject it here.",
  },
  {
    value: "needs_human_judgment",
    label: "needs a human",
    hint: "The classifier declined to judge. Nothing will happen to these until somebody looks.",
  },
  {
    value: "true_positive",
    label: "true positive",
    hint: "The classifier believes this is real.",
  },
  {
    value: "toxic_combination",
    label: "toxic combo",
    hint: "Only dangerous together with something else, and cannot be judged alone.",
  },
] as const;

const CLASSIFICATION_LABEL: Record<string, string> = {
  likely_false_positive: "likely FP",
  needs_human_judgment: "needs a human",
  true_positive: "true positive",
  toxic_combination: "toxic combo",
};

export default async function TriagePage({
  searchParams,
}: {
  searchParams: Promise<{
    severity?: string;
    capability?: string;
    rule_id?: string;
    kev_only?: string;
    min_epss?: string;
    owner?: string;
    order?: string;
    triage?: string;
    /** Which finding the detail pane is showing. In the URL rather than in
     *  state, so the row somebody is looking at survives a refresh. */
    finding?: string;
  }>;
}) {
  const query = await searchParams;
  const result = await getTriage({
    severity: query.severity,
    capability: query.capability,
    rule_id: query.rule_id,
    kev_only: query.kev_only === "1",
    min_epss: query.min_epss ? Number(query.min_epss) : undefined,
    owner: query.owner,
    order: query.order === "rank" ? "rank" : undefined,
    triage: query.triage,
  });

  if (!result.ok) {
    return <ErrorPanel title="Queue unavailable" detail={result.error} />;
  }

  const { items, open_by_severity, total_open, truncated } = result.data;

  // The scanners' own remediation, fetched once for the whole estate rather
  // than per selection: the queue spans repositories, so a per-finding lookup
  // would be a request every time somebody pressed `j`.
  //
  // A failed briefing costs the "what to do" block and nothing else. The queue
  // was the page before this and still is.
  const briefing = await getBriefing();
  const fixByRule: Record<string, { fix: string; source: string; effort: string }> = {};
  if (briefing.ok) {
    for (const capability of briefing.data.guidance) {
      for (const rule of capability.rules) {
        fixByRule[rule.rule_id] = {
          fix: rule.fix,
          source: rule.source,
          effort: rule.effort,
        };
      }
    }
  }

  // Selection lives in the URL, like every other part of this view, so the row
  // somebody is looking at survives a refresh and can be sent to somebody else.
  const selected = items.find((item) => item.finding_id === query.finding);

  const filterHref = (patch: Record<string, string | undefined>) => {
    const next = new URLSearchParams();
    for (const [key, value] of Object.entries({ ...query, ...patch })) {
      if (value) next.set(key, value);
    }
    const qs = next.toString();
    return qs ? `/triage?${qs}` : "/triage";
  };

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap items-baseline gap-3">
        <h1 className="text-xl font-bold tracking-tight">Triage queue</h1>
        <span className="font-mono text-[11px] text-ink-3">
          {total_open} open across the portfolio
        </span>
        <Link
          href="/"
          className="ml-auto border border-rule px-2 py-1 font-mono text-[10px] text-ink-3 hover:border-accent hover:text-accent"
        >
          portfolio view
        </Link>
      </div>

      <div className="grid grid-cols-2 gap-2 lg:grid-cols-4">
        <StatTile
          label="Critical"
          value={open_by_severity.critical ?? 0}
          alert={(open_by_severity.critical ?? 0) > 0}
        />
        <StatTile label="High" value={open_by_severity.high ?? 0} />
        <StatTile label="Medium" value={open_by_severity.medium ?? 0} />
        <StatTile
          label="Low + info"
          value={(open_by_severity.low ?? 0) + (open_by_severity.info ?? 0)}
        />
      </div>

      {/* Dropdowns rather than chips. Thirteen capabilities and five
          severities on one line meant reading eighteen controls to find the
          one that was on; the URL is still the state, so a filtered view is
          still a link. */}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <FilterSelect
          label="Severity"
          name="severity"
          value={query.severity}
          anyLabel="Any severity"
          options={SEVERITY_ORDER.map((severity: Severity) => ({
            value: severity,
            label: severity,
          }))}
        />
        <FilterSelect
          label="Capability"
          name="capability"
          value={query.capability}
          anyLabel="Any capability"
          options={CAPABILITIES.map((capability) => ({
            value: capability,
            label: capability,
          }))}
        />
        {/* What the classifier concluded (B-019). The per-repo findings view
            has had this filter since spec 18; the queue did not, so "show me
            everything the machine could not judge" meant one request per
            repository. */}
        <FilterSelect
          label="Classifier"
          name="triage"
          value={query.triage}
          anyLabel="Any verdict"
          options={CLASSIFICATIONS.map((entry) => ({
            value: entry.value,
            label: entry.label,
            hint: entry.hint,
          }))}
        />
      </div>

      {/* Same GET-form pattern as the per-repo Findings tab (spec 17 §3) —
          the query lives in the URL for every other filter here too. */}
      <form method="get" action="/triage" className="flex items-center gap-1.5">
        {query.severity ? <input type="hidden" name="severity" value={query.severity} /> : null}
        {query.capability ? (
          <input type="hidden" name="capability" value={query.capability} />
        ) : null}
        <Label>Rule / CVE</Label>
        <input
          type="search"
          name="rule_id"
          defaultValue={query.rule_id ?? ""}
          placeholder="e.g. CWE-89 or CVE-2024-…"
          className="border border-rule bg-paper px-1.5 py-0.5 font-mono text-[9px] text-ink placeholder:text-ink-3 focus:border-accent focus:outline-none"
        />
        {query.rule_id ? (
          <Link
            href={filterHref({ rule_id: undefined })}
            className="border border-accent bg-accent-wash px-1.5 py-0.5 font-mono text-[9px] text-accent"
          >
            {query.rule_id} ✕
          </Link>
        ) : null}
      </form>

      <div className="flex flex-wrap items-center gap-1.5">
        {/* Severity stays the default and stays available: "show me every
            critical" is a legitimate question, and a queue that refuses to
            answer it is a worse queue (spec 27 §1.1). */}
        <Label>Order</Label>
        {(["severity", "rank"] as const).map((mode) => (
          <Link
            key={mode}
            href={filterHref({ order: mode === "severity" ? undefined : mode })}
            className={`border px-1.5 py-0.5 font-mono text-[9px] ${
              (query.order === "rank" ? "rank" : "severity") === mode
                ? "border-accent bg-accent-wash text-accent"
                : "border-rule text-ink-3 hover:border-accent"
            }`}
            title={
              mode === "rank"
                ? "Risk removed per unit of work: severity, plus exploitation, deadline, blast radius and whether a fix already exists"
                : "Worst first, then oldest"
            }
          >
            {mode === "rank" ? "by rank" : "by severity"}
          </Link>
        ))}
      </div>

      <div className="flex flex-wrap items-center gap-1.5">
        <Label>Threat intel</Label>
        <Link
          href={filterHref({ kev_only: query.kev_only === "1" ? undefined : "1" })}
          className={`border px-1.5 py-0.5 font-mono text-[9px] ${
            query.kev_only === "1"
              ? "border-critical bg-critical-wash text-critical"
              : "border-rule text-ink-3 hover:border-accent"
          }`}
        >
          KEV only
        </Link>
        <Link
          href={filterHref({ min_epss: query.min_epss === "0.5" ? undefined : "0.5" })}
          className={`border px-1.5 py-0.5 font-mono text-[9px] ${
            query.min_epss === "0.5"
              ? "border-high bg-high-wash text-high"
              : "border-rule text-ink-3 hover:border-accent"
          }`}
        >
          EPSS ≥ 50%
        </Link>
      </div>

      {items.length === 0 ? (
        <EmptyState
          title={
            query.severity || query.capability || query.rule_id || query.kev_only || query.min_epss
              ? "Nothing matches these filters"
              : "Nothing open"
          }
          detail={
            query.severity || query.capability || query.rule_id || query.kev_only || query.min_epss ? (
              "Clear the filters to see the whole queue."
            ) : (
              <>
                Either every finding is resolved, or nothing has scanned yet.
                The portfolio view distinguishes the two — a repo awaiting its
                first scan is marked there rather than counted as clean here.
              </>
            )
          }
        />
      ) : (
        <>
          {/* Layout option 2: the queue and the thing you are working on stop
              competing for one screen.

              The ten-column table this replaces made every field equally
              prominent and none of them readable — a truncated title beside a
              truncated location beside a rank breakdown nobody could parse at
              that width. The list now carries only what you scan for, and
              everything else moved right, where there is room for it. */}
          <WorklistKeys ids={items.map((item) => item.finding_id)} />
          <div className="flex flex-col gap-3 lg:h-[calc(100vh-16rem)] lg:flex-row lg:gap-0">
            {/* Scrolls on its own, so working an item never loses your place
                in the queue — the single reason this shape is worth building
                rather than widening the aside. */}
            <div className="lg:w-[24rem] lg:shrink-0 lg:overflow-y-auto lg:border-r lg:border-rule">
              <ul className="flex flex-col">
                {items.map((item) => {
                  const on = query.finding === item.finding_id;
                  return (
                    <li key={item.finding_id}>
                      <Link
                        href={filterHref({ finding: item.finding_id })}
                        scroll={false}
                        aria-current={on ? "true" : undefined}
                        className={`flex flex-col gap-0.5 border-b border-rule-soft px-2.5 py-2 ${
                          on
                            ? "border-l-2 border-l-accent bg-accent-wash"
                            : "border-l-2 border-l-transparent hover:bg-paper-3"
                        }`}
                      >
                        <span className="flex flex-wrap items-baseline gap-1.5">
                          <SeverityText severity={item.severity as Severity} />
                          {item.in_kev ? (
                            <span className="font-mono text-[8px] uppercase tracking-wide text-critical">
                              kev
                            </span>
                          ) : null}
                          <span className="font-mono text-[9px] text-ink-3">
                            {item.capability}
                          </span>
                        </span>
                        <span className="line-clamp-2 text-[11px] leading-snug text-ink">
                          {item.title}
                        </span>
                        <span className="truncate font-mono text-[9px] text-ink-3">
                          {item.repo_full_name}
                        </span>
                      </Link>
                    </li>
                  );
                })}
              </ul>
            </div>

            <div className="min-w-0 grow lg:overflow-y-auto lg:px-4">
              {selected ? (
                <WorklistDetail item={selected} fix={fixByRule[selected.rule_id]} />
              ) : (
                <div className="border border-rule bg-paper-2 px-3 py-4 text-[11px] leading-relaxed text-ink-3">
                  Choose a finding, or press <span className="font-mono">j</span>.
                  Everything the old table showed in ten columns is here, with
                  room to read it.
                </div>
              )}
            </div>
          </div>
        </>
      )}

      {truncated ? (
        <p className="border-l-2 border-high bg-high-wash px-3 py-2 text-[11px] text-ink-2">
          <strong className="text-high">Showing the first 100.</strong> There are{" "}
          {total_open} open findings in scope — narrow by severity or capability
          to see the rest.
        </p>
      ) : null}

      <p className="max-w-prose text-[11px] leading-relaxed text-ink-3">
        <Label>Reading this queue</Label>
        <br />
        Ordered by severity, then by <em>age</em> rather than recency: an old
        critical is worse than a new one, because it has been exploitable for
        longer and has already survived somebody deciding not to fix it. Only
        active repositories appear — a removed repo&rsquo;s findings are still in
        the lake and still on its own page, but a queue is a list of work.{" "}
        <Pill tone="muted">verdict</Pill> is the repository&rsquo;s standing
        Oracle score, carried here so the same critical can be read differently
        in a repo already called <span className="font-mono">no go</span>.
      </p>
    </div>
  );
}

/**
 * One finding, with room (layout option 2).
 *
 * Everything the ten-column table showed, plus the two things it had nowhere
 * to put: the classifier's rationale — which was a `title` attribute, so it
 * existed only for people who hovered and knew to — and the scanner's own
 * remediation, which was on `/remediate` and nowhere near the finding it
 * applied to.
 *
 * Ordered by what somebody opening a row wants: what it is, what to do, why
 * the machine thinks what it thinks, then where it is and how it ranked.
 */
function WorklistDetail({
  item,
  fix,
}: {
  item: TriageItem;
  fix?: { fix: string; source: string; effort: string };
}) {
  return (
    <article className="flex flex-col gap-3 border border-rule bg-paper-2 p-3">
      <div className="flex flex-col gap-1">
        <span className="flex flex-wrap items-baseline gap-2">
          <SeverityText severity={item.severity as Severity} />
          {item.in_kev ? <Pill tone="critical">KEV</Pill> : null}
          <span className="font-mono text-[10px] text-ink-3">{item.capability}</span>
        </span>
        <h2 className="text-[13px] font-semibold leading-snug">{item.title}</h2>
        <span className="font-mono text-[10px] text-ink-3">
          {item.rule_id}
          {item.cve_id ? ` · ${item.cve_id}` : ""}
        </span>
      </div>

      {/* First, because it is why the row was opened. */}
      {fix ? (
        <div className="border-l-2 border-accent-2 bg-paper-3 px-2.5 py-2">
          <div className="flex flex-wrap items-baseline gap-2">
            <Label>What to do</Label>
            <span className="text-[8px] uppercase tracking-wide text-ink-3">{fix.effort}</span>
            {fix.source === "standing" ? (
              <span
                className="text-[8px] uppercase tracking-wide text-ink-3"
                title="Written by this platform, not the scanner."
              >
                ours, not the scanner&rsquo;s
              </span>
            ) : null}
          </div>
          <p className="mt-1 text-[11px] leading-relaxed text-ink">{fix.fix}</p>
        </div>
      ) : null}

      {item.triage ? (
        <div className="flex flex-col gap-1">
          <Label>What the classifier concluded</Label>
          <span className="font-mono text-[10px] text-ink-2">
            {CLASSIFICATION_LABEL[item.triage] ?? item.triage}
          </span>
          {/* Was a `title` attribute on a table cell, so it existed only for
              somebody who hovered and knew to. It is the reasoning; it gets to
              be visible. */}
          {item.triage_rationale ? (
            <p className="max-w-prose text-[11px] leading-relaxed text-ink-2">
              {item.triage_rationale}
            </p>
          ) : null}
          <ClassificationReview
            findingId={item.finding_id}
            classification={item.triage}
            rationale={item.triage_rationale ?? ""}
          />
        </div>
      ) : null}

      <div className="flex flex-col gap-1">
        <Label>Where</Label>
        <Link
          href={`/repos/${item.repo_id}?tab=findings`}
          className="font-mono text-[10px] text-accent hover:underline"
        >
          {item.repo_full_name}
        </Link>
        <span className="break-all font-mono text-[10px] text-ink-2">
          {item.file_path
            ? `${item.file_path}${item.line_start ? `:${item.line_start}` : ""}`
            : item.package_name
              ? `${item.package_name}@${item.package_version ?? "?"}`
              : "—"}
        </span>
        <span className="flex flex-wrap items-baseline gap-1.5 font-mono text-[9px] text-ink-3">
          first seen <RelativeTime value={item.first_seen_at} />
          {item.effort ? <>· {item.effort}</> : null}
          {/* `Verdict` rather than the raw string: it renders "not assessed"
              distinctly from a real recommendation, and risk decisions are
              opt-in — flattening both to text would let an unjudged repository
              read as a judged one. */}
          ·<Verdict recommendation={item.repo_recommendation} />
        </span>
      </div>

      {/* The rank was a column of comma-joined terms nobody could read at that
          width. Same numbers, one per line, which is all it ever needed. */}
      {item.rank_terms?.length ? (
        <div className="flex flex-col gap-0.5">
          <Label>Why it ranks here {item.rank ? `· ${item.rank.toFixed(0)}` : ""}</Label>
          {item.rank_terms.map((term) => (
            <span key={term.detail} className="font-mono text-[9px] text-ink-2">
              {term.points > 0 ? "+" : ""}
              {term.points} {term.detail}
            </span>
          ))}
        </div>
      ) : null}
    </article>
  );
}
