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
import { AutoTriageUndo } from "@/components/auto-triage-undo";
import { ClusterDisposition } from "@/components/cluster-disposition";
import { WorklistKeys } from "@/components/worklist";
import { FilterSelect } from "@/components/filter-select";
import {
  SEVERITY_ORDER,
  type AutoTriageDigest,
  type ClusterQueue,
  type Severity,
  type TriageCluster,
  type TriageItem,
} from "@/lib/api";
import { actionHeadline, digestLine, undoable } from "@/lib/auto-triage";
import { CLUSTER_KIND_LABEL, clusterSpread, type ClusterKind } from "@/lib/clusters";
import { environmentalLine, rankTermLine, rankingCaveat } from "@/lib/rank-terms";
import {
  getAutoTriageDigest,
  getBriefing,
  getTriage,
  getTriageClusters,
} from "@/lib/server";

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
    /** `cluster` groups the queue by cluster (TheHub #60887). */
    group?: string;
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

  const { items, open_by_severity, total_open, truncated, ranking } = result.data;

  // The same filters, one row per cluster (TheHub #60887). Fetched only when
  // asked for: building clusters reads every open finding, not one page.
  const grouped = query.group === "cluster";
  const clusterResult = grouped
    ? await getTriageClusters({
        severity: query.severity,
        capability: query.capability,
        rule_id: query.rule_id,
        kev_only: query.kev_only === "1",
        min_epss: query.min_epss ? Number(query.min_epss) : undefined,
        owner: query.owner,
        order: query.order === "rank" ? "rank" : undefined,
        triage: query.triage,
      })
    : null;

  // The scanners' own remediation, fetched once for the whole estate rather
  // than per selection: the queue spans repositories, so a per-finding lookup
  // would be a request every time somebody pressed `j`.
  //
  // A failed briefing costs the "what to do" block and nothing else. The queue
  // was the page before this and still is.
  const briefing = await getBriefing();
  // What the platform closed by itself (TheHub #60888). A failed read costs
  // this panel and nothing else.
  const autoTriage = await getAutoTriageDigest(24);
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
  // Falls back to the first item rather than to an empty pane. Landing on an
  // explanation of what the pane *would* show wastes two-thirds of the viewport
  // and asks the reader to do something before the page does anything; opening
  // on the top of the queue is also the right default, because the queue is
  // ordered by what to work on next.
  const selected =
    items.find((item) => item.finding_id === query.finding) ?? items[0];

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
        <span className="font-mono text-[13px] text-ink-3">
          {total_open} open across the portfolio
        </span>
        <Link
          href="/"
          className="ml-auto border border-rule px-2 py-1 font-mono text-[12px] text-ink-3 hover:border-accent hover:text-accent"
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
          className="border border-rule bg-paper px-1.5 py-0.5 font-mono text-[11px] text-ink placeholder:text-ink-3 focus:border-accent focus:outline-none"
        />
        {query.rule_id ? (
          <Link
            href={filterHref({ rule_id: undefined })}
            className="border border-accent bg-accent-wash px-1.5 py-0.5 font-mono text-[11px] text-accent"
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
            className={`border px-1.5 py-0.5 font-mono text-[11px] ${
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

      {/* What the order is *not* made of, at the point of ordering (B-033).
          The rank carries its working for every term it used; without this it
          presented itself as a risk ranking while never having consulted
          business context at all. Oracle's check run has said "not yet
          consulted" since it shipped — this is the same honesty, on the page
          where somebody decides what to work on. */}
      {ranking?.not_consulted?.length ? (
        <p className="max-w-prose border-l-2 border-high bg-high-wash px-2.5 py-1.5 text-[13px] leading-relaxed text-ink-2">
          <span className="font-semibold text-high">Not consulted:</span>{" "}
          {ranking.not_consulted.map((gap) => gap.input).join(", ")} —{" "}
          {ranking.not_consulted[0]?.reason}.{" "}
          <span className="text-ink-3">{rankingCaveat(ranking.environmental)}</span>
        </p>
      ) : null}

      {/* The one term through which business context reaches the rank
          (TheHub #60829): its weight, and how many open findings it reads. */}
      {query.order === "rank" && environmentalLine(ranking?.environmental) ? (
        <p className="max-w-prose text-[12px] leading-relaxed text-ink-3">
          {environmentalLine(ranking?.environmental)}
        </p>
      ) : null}

      {autoTriage.ok ? <AutoTriagePanel digest={autoTriage.data} /> : null}

      {/* One decision for a group (TheHub #60887): the same CVE across images
          and repositories, or the same weakness at the same place from
          several scanners, is one row with its members underneath. */}
      <div className="flex flex-wrap items-center gap-1.5">
        <Label>Group</Label>
        {(["finding", "cluster"] as const).map((mode) => (
          <Link
            key={mode}
            href={filterHref({ group: mode === "cluster" ? "cluster" : undefined, finding: undefined })}
            className={`border px-1.5 py-0.5 font-mono text-[11px] ${
              (grouped ? "cluster" : "finding") === mode
                ? "border-accent bg-accent-wash text-accent"
                : "border-rule text-ink-3 hover:border-accent"
            }`}
            title={
              mode === "cluster"
                ? "Findings one decision covers, grouped, with the reason shown"
                : "One row per finding"
            }
          >
            {mode === "cluster" ? "by cluster" : "by finding"}
          </Link>
        ))}
      </div>

      <div className="flex flex-wrap items-center gap-1.5">
        <Label>Threat intel</Label>
        <Link
          href={filterHref({ kev_only: query.kev_only === "1" ? undefined : "1" })}
          className={`border px-1.5 py-0.5 font-mono text-[11px] ${
            query.kev_only === "1"
              ? "border-critical bg-critical-wash text-critical"
              : "border-rule text-ink-3 hover:border-accent"
          }`}
        >
          KEV only
        </Link>
        <Link
          href={filterHref({ min_epss: query.min_epss === "0.5" ? undefined : "0.5" })}
          className={`border px-1.5 py-0.5 font-mono text-[11px] ${
            query.min_epss === "0.5"
              ? "border-high bg-high-wash text-high"
              : "border-rule text-ink-3 hover:border-accent"
          }`}
        >
          EPSS ≥ 50%
        </Link>
      </div>

      {clusterResult ? (
        clusterResult.ok ? (
          <ClusterList data={clusterResult.data} />
        ) : (
          <ErrorPanel title="Clusters unavailable" detail={clusterResult.error} />
        )
      ) : items.length === 0 ? (
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
            <div className="lg:w-[30rem] lg:shrink-0 lg:overflow-y-auto lg:border-r lg:border-rule">
              <ul className="flex flex-col">
                {items.map((item) => {
                  const on = selected?.finding_id === item.finding_id;
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
                            <span className="font-mono text-[10px] uppercase tracking-wide text-critical">
                              kev
                            </span>
                          ) : null}
                          <span className="font-mono text-[11px] text-ink-3">
                            {item.capability}
                          </span>
                        </span>
                        <span className="line-clamp-3 text-[13px] leading-snug text-ink">
                          {item.title}
                        </span>
                        <span className="truncate font-mono text-[11px] text-ink-3">
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
              ) : null}
            </div>
          </div>
        </>
      )}

      {truncated && !grouped ? (
        <p className="border-l-2 border-high bg-high-wash px-3 py-2 text-[13px] text-ink-2">
          <strong className="text-high">Showing the first 100.</strong> There are{" "}
          {total_open} open findings in scope — narrow by severity or capability
          to see the rest.
        </p>
      ) : null}

      <p className="max-w-prose text-[14px] leading-relaxed text-ink-3">
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
          <span className="font-mono text-[12px] text-ink-3">{item.capability}</span>
        </span>
        <h2 className="text-[13px] font-semibold leading-snug">{item.title}</h2>
        <span className="font-mono text-[12px] text-ink-3">
          {item.rule_id}
          {item.cve_id ? ` · ${item.cve_id}` : ""}
        </span>
      </div>

      {/* First, because it is why the row was opened. */}
      {fix ? (
        <div className="border-l-2 border-accent-2 bg-paper-3 px-2.5 py-2">
          <div className="flex flex-wrap items-baseline gap-2">
            <Label>What to do</Label>
            <span className="text-[10px] uppercase tracking-wide text-ink-3">{fix.effort}</span>
            {fix.source === "standing" ? (
              <span
                className="text-[10px] uppercase tracking-wide text-ink-3"
                title="Written by this platform, not the scanner."
              >
                ours, not the scanner&rsquo;s
              </span>
            ) : null}
          </div>
          <p className="mt-1 text-[14px] leading-relaxed text-ink">{fix.fix}</p>
        </div>
      ) : null}

      {item.triage ? (
        <div className="flex flex-col gap-1">
          <Label>What the classifier concluded</Label>
          <span className="font-mono text-[12px] text-ink-2">
            {CLASSIFICATION_LABEL[item.triage] ?? item.triage}
          </span>
          {/* Was a `title` attribute on a table cell, so it existed only for
              somebody who hovered and knew to. It is the reasoning; it gets to
              be visible. */}
          {item.triage_rationale ? (
            <p className="max-w-prose text-[14px] leading-relaxed text-ink-2">
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
          className="font-mono text-[12px] text-accent hover:underline"
        >
          {item.repo_full_name}
        </Link>
        <span className="break-all font-mono text-[12px] text-ink-2">
          {item.file_path
            ? `${item.file_path}${item.line_start ? `:${item.line_start}` : ""}`
            : item.package_name
              ? `${item.package_name}@${item.package_version ?? "?"}`
              : "—"}
        </span>
        <span className="flex flex-wrap items-baseline gap-1.5 font-mono text-[11px] text-ink-3">
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
          {item.rank_terms.map((term) => {
            // The environmental term is listed at zero too: "no score" and
            // "lapsed" are answers, and its detail names the facts behind a
            // move (TheHub #60829).
            const line = rankTermLine(term);
            return (
              <span
                key={`${term.key}:${term.detail}`}
                className={`font-mono text-[11px] ${
                  line.environmental === "none" ? "text-ink-3" : "text-ink-2"
                }`}
              >
                {line.points} {line.detail}
              </span>
            );
          })}
        </div>
      ) : null}
    </article>
  );
}

/**
 * The queue by cluster (TheHub #60887, D-168).
 *
 * Each row is one decision: the worst member's severity, what the members
 * share, and the sentence saying why they belong together. The members are
 * underneath, all of them - the filters choose which clusters show and never
 * trim one, because the verdict beside it closes every member.
 */
function ClusterList({ data }: { data: ClusterQueue }) {
  if (data.clusters.length === 0) {
    return (
      <EmptyState
        title="Nothing matches these filters"
        detail="No cluster has a member matching them. Clear the filters to see every cluster."
      />
    );
  }
  return (
    <div className="flex flex-col gap-2">
      <p className="font-mono text-[12px] text-ink-3">
        {data.total_clusters} cluster{data.total_clusters === 1 ? "" : "s"} covering{" "}
        {data.total_findings} open finding{data.total_findings === 1 ? "" : "s"}
        {data.truncated ? ` - showing the first ${data.clusters.length}` : ""}
      </p>
      {data.pool_truncated ? (
        <p className="border-l-2 border-high bg-high-wash px-3 py-2 text-[13px] text-ink-2">
          <strong className="text-high">Clustered from a capped pool.</strong> More open
          findings exist than were grouped, so a cluster here may be missing members.
        </p>
      ) : null}
      <ul className="flex flex-col gap-1.5">
        {data.clusters.map((cluster) => (
          <li key={cluster.cluster_id}>
            <ClusterRow cluster={cluster} />
          </li>
        ))}
      </ul>
    </div>
  );
}

function ClusterRow({ cluster }: { cluster: TriageCluster }) {
  const representative = cluster.representative;
  return (
    <details className="border border-rule bg-paper-2">
      <summary className="flex cursor-pointer flex-col gap-0.5 px-2.5 py-2 hover:bg-paper-3">
        <span className="flex flex-wrap items-baseline gap-1.5">
          <SeverityText severity={cluster.max_severity as Severity} />
          <span className="font-mono text-[11px] text-ink-3">
            {CLUSTER_KIND_LABEL[cluster.kind as ClusterKind] ?? cluster.kind}
          </span>
          <span className="font-mono text-[11px] text-ink-3">· {clusterSpread(cluster)}</span>
        </span>
        <span className="text-[13px] leading-snug text-ink">{representative.title}</span>
        <span className="max-w-prose text-[12px] leading-snug text-ink-2">{cluster.reason}</span>
      </summary>
      <div className="flex flex-col gap-2 border-t border-rule-soft px-2.5 py-2">
        <ClusterDisposition
          clusterId={cluster.cluster_id}
          memberIds={cluster.members.map((member) => member.finding_id)}
        />
        <ul className="flex flex-col">
          {cluster.members.map((member) => (
            <li
              key={member.finding_id}
              className="flex flex-wrap items-baseline gap-1.5 border-b border-rule-soft py-1 last:border-b-0"
            >
              <SeverityText severity={member.severity as Severity} />
              <span className="font-mono text-[11px] text-ink-3">{member.capability}</span>
              <Link
                href={`/repos/${member.repo_id}?tab=findings`}
                className="font-mono text-[11px] text-accent hover:underline"
              >
                {member.repo_full_name}
              </Link>
              <span className="break-all font-mono text-[11px] text-ink-2">
                {member.file_path
                  ? `${member.file_path}${member.line_start ? `:${member.line_start}` : ""}`
                  : member.package_name
                    ? `${member.package_name}@${member.package_version ?? "?"}`
                    : member.rule_id}
              </span>
              {cluster.folded_ids?.includes(member.finding_id) ? (
                <Pill tone="muted">folded {member.rule_id}</Pill>
              ) : null}
              {member.finding_id === representative.finding_id ? (
                <span className="font-mono text-[10px] uppercase tracking-wide text-ink-3">
                  representative
                </span>
              ) : null}
            </li>
          ))}
        </ul>
      </div>
    </details>
  );
}

/**
 * What auto-triage closed in the last 24 hours (TheHub #60888, D-169).
 *
 * Collapsed by default and above the queue: these findings left the queue
 * without anybody deciding, so the place to notice one that should not have
 * is where the queue is read. Each action names its rule, its evidence and
 * offers the undo.
 */
function AutoTriagePanel({ digest }: { digest: AutoTriageDigest }) {
  return (
    <details className="border border-rule-soft bg-paper-2">
      <summary className="cursor-pointer px-2.5 py-1.5 font-mono text-[12px] text-ink-3 hover:text-accent">
        Closed by the platform · {digestLine(digest)}
      </summary>
      {digest.actions.length ? (
        <ul className="flex flex-col border-t border-rule-soft">
          {digest.actions.map((action) => (
            <li
              key={action.id}
              className="flex flex-col gap-0.5 border-b border-rule-soft px-2.5 py-1.5 last:border-b-0"
            >
              <span className="flex flex-wrap items-baseline gap-1.5">
                <SeverityText severity={action.severity as Severity} />
                <span className="font-mono text-[11px] text-ink-2">{actionHeadline(action)}</span>
                <span className="font-mono text-[11px] text-ink-3">{action.repo_full_name}</span>
                <span className="font-mono text-[11px] text-ink-3">
                  <RelativeTime value={action.applied_at} />
                </span>
                {action.undone_at ? (
                  <Pill tone="muted">undone by {action.undone_by}</Pill>
                ) : null}
              </span>
              <span className="max-w-prose text-[12px] leading-snug text-ink-2">
                {action.summary}
              </span>
              {undoable(action) ? <AutoTriageUndo actionId={action.id} /> : null}
            </li>
          ))}
        </ul>
      ) : null}
    </details>
  );
}
