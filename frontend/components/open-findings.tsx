/**
 * Open findings: one row per problem, triaged, with the toxic combinations
 * named (spec 10 §2.2, spec 08 §5).
 *
 * Three things separate this from the flat list the API also serves, and they
 * all pull the same way — towards a list of decisions rather than a list of
 * reports:
 *
 * **Open only.** A list that mixes outstanding findings with ones somebody
 * already accepted cannot be counted, and a count nobody trusts gets ignored.
 * The other statuses are one click away and clearly labelled.
 *
 * **Deduplicated.** One rule firing in forty files is one decision. The row
 * carries every occurrence, so nothing is hidden and each occurrence keeps its
 * own disposition — accepting the risk in one file is not accepting it in
 * forty.
 *
 * **Correlated.** A toxic combination is drawn first and coloured loudest,
 * because its members are individually unremarkable by definition. Two mediums
 * that add up to an unauthenticated database sort below a lone high on every
 * severity-ordered list ever built, which is exactly the failure this panel
 * exists to correct.
 */

import Link from "next/link";

import { WorklistKeys } from "@/components/worklist";

import { DispositionForm } from "@/components/disposition";
import {
  FindingsFilterBar,
  type PillDef,
  type PillOption,
} from "@/components/findings-filter-bar";
import { RemediationAction } from "@/components/remediation-action";
import {
  CAPABILITY_META,
  EmptyState,
  Label,
  Pill,
  RelativeTime,
  SeverityText,
} from "@/components/primitives";
import type {
  FindingGroup,
  OpenFindingsPage,
  ToxicCombination,
} from "@/lib/api";
import { rescoreChips, shift } from "@/lib/environmental-severity";
import {
  CLEAR_SELECTION,
  DUE_LABELS,
  EXPOSURE_LABELS,
  OWNER_QUEUE_LABELS,
  RESCORED_LABELS,
  SEVERITIES,
  STATUS_LABELS,
  TRIAGE_LABELS,
  findingsHref,
  hasNarrowingFilters,
  normalizeQuery,
  sortGroups,
  toggleValue,
  valuesOf,
  type FindingsQuery,
} from "@/lib/findings-filters";
import { findingsSummary, type SummaryCount } from "@/lib/findings-summary";

export type { FindingsQuery } from "@/lib/findings-filters";

const TRIAGE: Record<string, { tone: "critical" | "warn" | "accent" | "muted"; label: string }> = {
  toxic_combination: { tone: "critical", label: TRIAGE_LABELS.toxic_combination },
  true_positive: { tone: "accent", label: TRIAGE_LABELS.true_positive },
  likely_false_positive: { tone: "muted", label: TRIAGE_LABELS.likely_false_positive },
  needs_human_judgment: { tone: "warn", label: TRIAGE_LABELS.needs_human_judgment },
};

/** The bar's fill per severity, from the theme's own severity tokens. */
const SEVERITY_BG: Record<string, string> = {
  critical: "bg-critical",
  high: "bg-high",
  medium: "bg-medium",
  low: "bg-low",
  info: "bg-info",
};

/**
 * A combination's rationale is written for a pull-request body, where `**` and
 * backticks render. Here the name, the members and the file are already on
 * screen above it, so the markers are noise — stripped rather than rendered,
 * because a markdown pipeline for one sentence is not worth the dependency.
 */
function plain(text: string): string {
  return text.replace(/\*\*/g, "").replace(/`/g, "");
}

type Href = (patch: Partial<FindingsQuery>) => string;

/** A deadline, shown as its state first and its date second.
 *
 *  `no_target` renders as an em dash rather than as "on track": a finding with
 *  no deadline is unmeasured, and this column must not imply otherwise. */
function DueCell({
  state,
  at,
  source,
}: {
  state?: string;
  at?: string | null;
  source?: string | null;
}) {
  if (!state || state === "no_target" || !at) {
    return <span className="text-ink-3" title="No remediation target applies">—</span>;
  }
  const tone =
    state === "overdue" ? "critical" : state === "due_soon" ? "warn" : "muted";
  const when = new Date(at).toISOString().slice(0, 10);
  return (
    <Pill
      tone={tone}
      title={
        source === "kev"
          ? `CISA KEV due date: ${when}`
          : `Remediation target from policy: ${when}`
      }
    >
      {state === "overdue" ? "overdue" : when}
      {source === "kev" ? " · KEV" : ""}
    </Pill>
  );
}

export function OpenFindings({
  repoId,
  page,
  query: rawQuery,
  detail,
  fixByRule = {},
}: {
  repoId: string;
  page: OpenFindingsPage;
  query: FindingsQuery;
  /** Rendered in the aside when one occurrence is selected. */
  detail?: React.ReactNode;
  /** Rule id -> what the scanner said to do about it. Empty when the guidance
   *  fetch failed, which costs the "what to do" block and nothing else. */
  fixByRule?: Record<string, { fix: string; source: string; effort: string }>;
}) {
  // Next hands a repeated parameter over as an array; everything below reads
  // one comma-joined string per filter.
  const query = normalizeQuery(rawQuery as Record<string, unknown>);
  // Always explicit, never stripped (spec 17 §2.4): this component renders
  // behind its own "Findings" tab, so a filter link that dropped `tab` would
  // silently bounce the reader back to the default tab on every click.
  const href: Href = (patch) => findingsHref(repoId, query, patch);
  const groups = sortGroups(page.groups, query.sort);
  const narrowed = hasNarrowingFilters(query);

  // Same default as the triage queue: the first group, not an empty pane.
  const selected =
    (query.group ? groups.find((group) => group.group_key === query.group) : undefined) ??
    groups[0];

  return (
    <div className="flex flex-col gap-3">
      <Summary page={page} query={query} href={href} />
      <FindingsFilterBar
        repoId={repoId}
        query={query}
        primary={primaryPills(page)}
        secondary={secondaryPills(page)}
      />

      {page.toxic_combinations.length > 0 ? (
        <ToxicCombinations combinations={page.toxic_combinations} />
      ) : null}

      {groups.length === 0 ? (
        <EmptyState
          title={
            narrowed
              ? "Nothing matches these filters"
              : `No ${valuesOf(query, "status")
                  .map((status) => STATUS_LABELS[status] ?? status)
                  .join(" or ") || "open"} findings`
          }
          detail={
            narrowed
              ? "Clear the filters to see everything outstanding."
              : "Either nothing has been found, or nothing has scanned yet — the scan health boxes above say which."
          }
        />
      ) : (
        <>
          {/* Layout option 2, as applied to the triage queue. The eight-column
              table this replaces could not live in a narrow pane — it carried a
              680px minimum and would have scrolled sideways inside a column —
              so the same trade is made here: the list keeps what you scan for
              and the columns move right, where there is room to read them. */}
          <WorklistKeys
            ids={groups.map((group) => group.group_key)}
            param="group"
            clears={["finding"]}
          />
          <div className="flex flex-col gap-3 lg:h-[calc(100vh-22rem)] lg:flex-row lg:gap-0">
            <div className="lg:w-[28rem] lg:shrink-0 lg:overflow-y-auto lg:border-r lg:border-rule">
              <GroupList groups={groups} selectedKey={selected?.group_key} href={href} />
              {page.truncated ? (
                <p className="px-2 py-1 font-mono text-[11px] text-high">
                  Showing the worst {page.shown} of {page.matching}. Filter to
                  reach the rest — a list that silently stops reads as
                  &ldquo;that is all of it&rdquo;.
                </p>
              ) : null}
            </div>

            <div className="min-w-0 grow lg:overflow-y-auto lg:pl-4">
              {selected ? (
                <GroupDetail
                  group={selected}
                  query={query}
                  href={href}
                  detail={detail}
                  remediation={fixByRule[selected.rule_id]}
                  repoId={repoId}
                />
              ) : null}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

const capabilityLabel = (capability: string) =>
  CAPABILITY_META[capability as keyof typeof CAPABILITY_META]?.label ?? capability;

const capabilityAbbr = (capability: string) =>
  CAPABILITY_META[capability as keyof typeof CAPABILITY_META]?.abbr ?? capability;

/** The always-visible pills, with the backend's before-filter counts. */
function primaryPills(page: OpenFindingsPage): PillDef[] {
  const byCapability = page.by_capability ?? {};
  const capabilities = Object.keys(CAPABILITY_META).sort(
    (a, b) => (byCapability[b] ?? 0) - (byCapability[a] ?? 0) || a.localeCompare(b),
  );
  return [
    {
      kind: "multi",
      key: "status",
      label: "Status",
      anyLabel: "open",
      options: Object.entries(STATUS_LABELS).map(([value, label]) => ({
        value,
        label,
        count: page.by_status?.[value] ?? 0,
      })),
    },
    {
      kind: "multi",
      key: "severity",
      label: "Severity",
      options: SEVERITIES.map((severity) => ({
        value: severity,
        label: severity,
        count: page.by_severity[severity] ?? 0,
      })),
    },
    {
      kind: "multi",
      key: "capability",
      label: "Scan type",
      options: capabilities.map((capability) => ({
        value: capability,
        label: capabilityLabel(capability),
        count: byCapability[capability] ?? 0,
      })),
    },
    {
      kind: "multi",
      key: "exposure",
      label: "Exposure",
      hint: "From the declared surface (Threat Model tab) that places each finding.",
      options: Object.entries(EXPOSURE_LABELS).map(([value, label]) => ({
        value,
        label,
        count: page.by_exposure?.[value] ?? 0,
      })),
    },
    {
      kind: "multi",
      key: "due",
      label: "Due",
      options: Object.entries(DUE_LABELS).map(([value, label]) => ({ value, label })),
    },
  ];
}

/** The less-used filters, behind "+ Add filter". */
function secondaryPills(page: OpenFindingsPage): PillDef[] {
  const owners: PillOption[] = [
    { value: "unclaimed", label: OWNER_QUEUE_LABELS.unclaimed },
    {
      value: "unresolved",
      label: OWNER_QUEUE_LABELS.unresolved,
      count: page.by_owner?.unresolved ?? 0,
    },
    ...Object.entries(page.by_owner ?? {})
      .filter(([owner]) => owner !== "unresolved")
      .sort(([a, x], [b, y]) => y - x || a.localeCompare(b))
      .map(([owner, count]) => ({ value: owner, label: owner, count })),
  ];
  return [
    {
      kind: "multi",
      key: "effective",
      label: "Effective severity",
      hint: "The severity here, after environmental rescoring.",
      options: SEVERITIES.map((severity) => ({
        value: severity,
        label: severity,
        count: page.by_effective_severity?.[severity] ?? 0,
      })),
    },
    {
      kind: "text",
      key: "rule_id",
      label: "Rule / CVE",
      placeholder: "e.g. CWE-89 or CVE-2024-…",
      hint: "Matched against the rule id and the title.",
    },
    {
      kind: "multi",
      key: "component",
      label: "Component",
      hint: "Declared surfaces from the Threat Model tab.",
      options: (page.by_component ?? []).map((entry) => ({
        value: entry.value,
        label:
          entry.value === "none"
            ? entry.label
            : `${entry.label} · ${EXPOSURE_LABELS[entry.exposure] ?? entry.exposure}`,
        count: entry.count,
      })),
    },
    {
      kind: "text",
      key: "path",
      label: "Path",
      placeholder: "e.g. web/ or *.tf or urllib3",
      hint: "File path or package. Use * and ? as wildcards.",
    },
    { kind: "multi", key: "owner", label: "Owner", options: owners },
    {
      kind: "multi",
      key: "triage",
      label: "Triage",
      hint: "The classifier's verdict per row.",
      options: Object.entries(TRIAGE_LABELS).map(([value, label]) => ({ value, label })),
    },
    { kind: "intel", label: "Threat intel" },
    {
      kind: "toggle",
      key: "fixable",
      label: "Fixable",
      onLabel: "fix available",
      // `false` and "nobody has looked" are different facts, so there is a
      // "fixable" filter and deliberately no "not fixable" one (spec 19 §3.2).
      hint: "Rows auto-remediation produced a fix for.",
    },
    {
      kind: "multi",
      key: "rescored",
      label: "Rescored",
      options: Object.entries(RESCORED_LABELS).map(([value, label]) => ({
        value,
        label,
        count: page.by_rescoring?.[value] ?? 0,
      })),
    },
    { kind: "age", label: "First seen" },
  ];
}

/**
 * Total, by severity, by scan type (TheHub #60821) — the three questions the
 * operator asks of this tab before reading a single row — and the quickest way
 * to filter by the last two.
 *
 * The counts are the backend's, for the status the list is showing and before
 * any other filter, so each one is exactly what clicking it lists. They do not
 * move as filters are applied: a count that changed when you pressed it would
 * describe the answer rather than the choice. Each segment and bar toggles
 * its value in the filter; an outlined one is filtering.
 */
function Summary({
  page,
  query,
  href,
}: {
  page: OpenFindingsPage;
  query: FindingsQuery;
  href: Href;
}) {
  const summary = findingsSummary(page, query, capabilityLabel);
  const segments = summary.bySeverity.filter((entry) => entry.count > 0 || entry.active);
  const widest = Math.max(1, ...summary.byCapability.map((entry) => entry.count));
  const narrowed = hasNarrowingFilters(query);
  const toggle = (key: "severity" | "capability", entry: SummaryCount) =>
    href(toggleValue(query, key, entry.value));

  return (
    <section
      aria-label="Findings summary — click a severity or scan type to filter"
      className="grid gap-x-8 gap-y-4 border border-rule bg-paper-2 px-4 py-3 md:grid-cols-[10rem_minmax(0,1fr)_minmax(0,1fr)]"
    >
      <div className="flex flex-col gap-0.5">
        <Label>{summary.status}</Label>
        <span className="font-mono text-[30px] font-semibold leading-tight text-ink">
          {summary.total}
        </span>
        {/* The three numbers are different facts and all three get said:
            how much is outstanding, how much the filters kept, and how much
            of that the grouping collapsed. */}
        <span className="text-[12px] text-ink-2">
          {narrowed ? `${page.matching} match filters` : "no filters applied"}
        </span>
        <span className="font-mono text-[11px] text-ink-3">
          {page.groups.length} row{page.groups.length === 1 ? "" : "s"}
          {page.deduplicated > 0 ? ` · ${page.deduplicated} collapsed` : ""}
        </span>
      </div>

      <div className="flex min-w-0 flex-col gap-1.5">
        <Label>By severity</Label>
        {segments.length === 0 ? (
          <span className="font-mono text-[12px] text-ink-3">none</span>
        ) : (
          <div className="flex h-7 gap-0.5">
            {segments.map((entry) => (
              <Link
                key={entry.value}
                href={toggle("severity", entry)}
                scroll={false}
                aria-current={entry.active ? "true" : undefined}
                aria-label={`${entry.label}: ${entry.count} — ${
                  entry.active ? "filtering, click to remove" : "click to filter"
                }`}
                title={`${entry.label}: ${entry.count}`}
                style={{ flexGrow: Math.max(entry.count, 1) }}
                className={`flex min-w-[2.25rem] basis-0 items-center px-1.5 font-mono text-[11.5px] font-semibold text-paper ${
                  SEVERITY_BG[entry.value] ?? "bg-ink-3"
                } ${
                  entry.active
                    ? "outline-2 outline-offset-1 outline-ink"
                    : "opacity-90 hover:opacity-100"
                } focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-accent`}
              >
                {entry.count}
              </Link>
            ))}
          </div>
        )}
        <div className="flex flex-wrap gap-x-3.5 gap-y-0.5 text-[11.5px] text-ink-2">
          {summary.bySeverity.map((entry) => (
            <span key={entry.value} className="inline-flex items-center gap-1">
              <span aria-hidden className={`inline-block h-2 w-2 ${SEVERITY_BG[entry.value]}`} />
              {entry.label}
              {entry.count === 0 ? <span className="text-ink-3">0</span> : null}
            </span>
          ))}
          <span className="text-ink-3">· outlined = filtering</span>
        </div>
      </div>

      <div className="flex min-w-0 flex-col gap-1">
        <Label>By scan type</Label>
        {summary.byCapability.length === 0 ? (
          <span className="font-mono text-[12px] text-ink-3">none</span>
        ) : (
          <ul className="flex flex-col gap-0.5">
            {summary.byCapability.map((entry) => (
              <li key={entry.value}>
                <Link
                  href={toggle("capability", entry)}
                  scroll={false}
                  aria-current={entry.active ? "true" : undefined}
                  aria-label={`${entry.label}: ${entry.count} — ${
                    entry.active ? "filtering, click to remove" : "click to filter"
                  }`}
                  title={entry.label}
                  className={`grid grid-cols-[4.75rem_minmax(0,1fr)_2.5rem] items-center gap-2 py-0.5 text-[11.5px] hover:bg-paper-3 focus-visible:outline-2 focus-visible:outline-accent ${
                    entry.active ? "outline-1 outline-accent" : ""
                  }`}
                >
                  <span
                    className={`truncate font-mono ${
                      entry.active ? "font-semibold text-accent" : "text-ink"
                    }`}
                  >
                    {capabilityAbbr(entry.value)}
                  </span>
                  <span className="block h-2 bg-paper-3">
                    <span
                      className={`block h-2 ${entry.active ? "bg-accent" : "bg-ink-3/60"}`}
                      style={{ width: `${Math.round((entry.count / widest) * 100)}%` }}
                    />
                  </span>
                  <span className="text-right font-mono text-ink-3">{entry.count}</span>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* From the stored environmental scores, over the same scope as the
          counts above (TheHub #60828): each chip lists exactly that many. */}
      <div className="flex flex-wrap items-center gap-1.5 md:col-span-3">
        <Label>Rescored here</Label>
        {rescoreChips(page.by_rescoring, query).map((entry) => (
          <Link
            key={entry.value}
            href={href(toggleValue(query, "rescored", entry.value))}
            scroll={false}
            aria-current={entry.active ? "true" : undefined}
            title={
              entry.value === "down"
                ? "The environment lowered the severity word. Only observed or confirmed facts can lower a score."
                : entry.value === "not_rescorable"
                  ? "No CVSS vector, so nothing to re-read for this system."
                  : "The environment raised the severity word."
            }
            className={`inline-flex items-baseline gap-1.5 border px-1.5 py-0.5 font-mono text-[11.5px] ${
              entry.active ? "border-accent bg-accent-wash" : "border-rule hover:border-accent"
            } ${entry.count === 0 ? "opacity-60" : ""}`}
          >
            <span className="font-bold text-ink">{entry.count}</span>
            <span className="text-ink-2">{entry.label}</span>
          </Link>
        ))}
        <span className="font-mono text-[11px] text-ink-3">
          · counts are for this status, before the other filters
        </span>
      </div>
    </section>
  );
}

/**
 * Drawn above the table rather than as rows in it, because a combination is
 * not a finding: it is a statement about several of them, and folding it into
 * a severity-ordered list is how it ends up below the individual mediums it
 * is made of.
 */
function ToxicCombinations({
  combinations,
}: {
  combinations: ToxicCombination[];
}) {
  return (
    <div className="border border-critical bg-critical-wash">
      <div className="flex flex-wrap items-baseline gap-x-3 border-b border-critical/30 px-3 py-2">
        <h3 className="font-mono text-[12px] font-bold uppercase tracking-[0.12em] text-critical">
          Toxic combinations
        </h3>
        <span className="font-mono text-[12px] text-ink-2">
          {combinations.length} set{combinations.length === 1 ? "" : "s"} of findings
          that are worse together than apart
        </span>
      </div>
      <ul className="flex flex-col divide-y divide-critical/20">
        {combinations.map((combination) => (
          <li key={combination.combination_id} className="px-3 py-2">
            <div className="flex flex-wrap items-baseline gap-2">
              <SeverityText severity={combination.severity} />
              <span className="text-[12px] font-semibold">{combination.name}</span>
              <span className="font-mono text-[11px] text-ink-3">
                {combination.rule_id}
              </span>
            </div>
            <ul className="mt-1 flex flex-col gap-0.5">
              {combination.members.map((member) => (
                <li key={member.finding_id} className="font-mono text-[12px] text-ink-2">
                  <span aria-hidden>
                    {CAPABILITY_META[member.capability as keyof typeof CAPABILITY_META]?.icon}
                  </span>{" "}
                  <span className="text-ink-3">{member.capability}</span>{" "}
                  {member.rule_id} — {member.title}
                  {member.file_path ? (
                    <span className="text-ink-3"> · {member.file_path}</span>
                  ) : null}
                </li>
              ))}
            </ul>
            <p className="mt-1 max-w-prose text-[14px] leading-relaxed text-ink-2">
              {plain(combination.rationale)}
            </p>
          </li>
        ))}
      </ul>
    </div>
  );
}

/**
 * The effective severity beside the scanner's (TheHub #60828): `→ medium here`
 * when the environment moved the word, `here too` when a score is stored and
 * left it, nothing when there is no score. Nothing rather than the scanner's
 * word again: a finding with no vector was never re-read, and repeating its
 * severity under another label would claim it had been.
 */
function EffectiveMark({
  scanner,
  effective,
}: {
  scanner: string;
  effective?: string | null;
}) {
  if (!effective) return null;
  const moved = shift(scanner, effective);
  if (moved === "same") {
    return (
      <span
        className="font-mono text-[10px] uppercase tracking-wide text-ink-3"
        title="Rescored for this system; the severity word is unchanged"
      >
        here too
      </span>
    );
  }
  return (
    <span
      className={`font-mono text-[10px] uppercase tracking-wide ${
        moved === "down" ? "text-pass" : "text-critical"
      }`}
      title={`The environment moved this ${moved}: ${effective} here, ${scanner} as scanned`}
    >
      → {effective} here
    </span>
  );
}

/**
 * KEV / EPSS, next to severity (spec 17 §4.4). Renders nothing for a group
 * naming no CVE — `in_kev === null` — rather than a dash on every row; the
 * absence of a badge already says "no exploitability data for this one."
 */
function ThreatIntelBadge({ group }: { group: FindingGroup }) {
  if (group.in_kev === null || group.in_kev === undefined) return null;
  const highEpss = typeof group.epss_score === "number" && group.epss_score >= 0.5;
  if (!group.in_kev && !highEpss) return null;

  return (
    <span className="ml-1 inline-flex gap-1">
      {group.in_kev ? (
        <span title={`${group.cve_id} is listed in CISA's Known Exploited Vulnerabilities catalog`}>
          <Pill tone="critical">KEV</Pill>
        </span>
      ) : null}
      {highEpss ? (
        <span
          title={`${group.cve_id}: ${((group.epss_score ?? 0) * 100).toFixed(0)}% EPSS — probability of exploitation in the next 30 days`}
          className="font-mono text-[10px] font-bold uppercase tracking-wider text-high"
        >
          {((group.epss_score ?? 0) * 100).toFixed(0)}% EPSS
        </span>
      ) : null}
    </span>
  );
}

/**
 * The queue, compact enough to live in a column.
 *
 * Replaces an eight-column table with a 680px minimum width, which could not
 * sit in a pane and would have scrolled sideways inside one. Severity, the
 * problem, and how many places it was found are what somebody scans for;
 * owner, due date, age and the rest are in the detail, where they are readable
 * rather than truncated.
 *
 * The toxic-combination marker stays in the list. It is the one flag whose
 * whole purpose is to be noticed without being looked for — its members are
 * individually unremarkable by definition, so a reader scanning severity would
 * pass straight over it.
 */
function GroupList({
  groups,
  selectedKey,
  href,
}: {
  groups: FindingGroup[];
  /** Passed in rather than re-derived from the query: the page falls back to
   *  the first group when nothing is selected, and a list that recomputed that
   *  rule separately would eventually disagree with the pane beside it. */
  selectedKey?: string;
  href: Href;
}) {
  return (
    <ul className="flex flex-col">
      {groups.map((group) => {
        const on = selectedKey === group.group_key;
        return (
          <li key={group.group_key}>
            <Link
              href={href({ ...CLEAR_SELECTION, group: group.group_key })}
              scroll={false}
              aria-current={on ? "true" : undefined}
              className={`flex flex-col gap-0.5 border-b border-rule-soft px-2.5 py-2 ${
                on
                  ? "border-l-2 border-l-accent bg-accent-wash"
                  : "border-l-2 border-l-transparent hover:bg-paper-3"
              }`}
            >
              <span className="flex flex-wrap items-baseline gap-1.5">
                <SeverityText severity={group.severity} />
                <EffectiveMark scanner={group.severity} effective={group.effective_severity} />
                {group.toxic_combination_ids?.length ? (
                  <span
                    className="font-mono text-[10px] uppercase tracking-wide text-critical"
                    title="Part of a toxic combination — individually unremarkable, dangerous together"
                  >
                    combo
                  </span>
                ) : null}
                {group.fixable ? (
                  <span
                    className="font-mono text-[10px] uppercase tracking-wide text-accent"
                    title="Auto-remediation produced a fix for this"
                  >
                    fix
                  </span>
                ) : null}
                <span className="font-mono text-[11px] text-ink-3">
                  {group.capabilities.join(", ")}
                </span>
              </span>
              <span className="line-clamp-3 text-[13px] leading-snug text-ink">
                {group.title}
              </span>
              <span className="font-mono text-[11px] text-ink-3">
                {group.occurrences}&times;
                {group.owner ? ` · ${group.owner}` : ""}
                {group.age_days != null ? ` · ${group.age_days}d` : ""}
              </span>
            </Link>
          </li>
        );
      })}
    </ul>
  );
}

function GroupDetail({
  group,
  query,
  href,
  detail,
  remediation,
  repoId,
}: {
  group: FindingGroup;
  query: FindingsQuery;
  href: Href;
  detail?: React.ReactNode;
  remediation?: { fix: string; source: string; effort: string };
  /** Needed only to link each occurrence to its full record (B-032). */
  repoId: string;
}) {
  const triage = TRIAGE[group.triage] ?? { tone: "muted" as const, label: group.triage };
  return (
    <div className="flex flex-col gap-3 border border-rule bg-paper-2 p-3">
      <div>
        <span className="flex flex-wrap items-baseline gap-1.5">
          <SeverityText severity={group.severity} />
          <EffectiveMark scanner={group.severity} effective={group.effective_severity} />
          {/* Renders nothing unless KEV or EPSS ≥ 0.5, so it costs no room when
              there is nothing to say — and when there is, it outranks the
              severity beside it. */}
          <ThreatIntelBadge group={group} />
        </span>
        <h3 className="mt-1 text-sm font-semibold leading-snug">{group.title}</h3>
        <p className="mt-1 font-mono text-[12px] text-ink-3">
          {group.rule_id} · {group.capabilities.join(", ")}
          {group.cvss_score ? ` · CVSS ${group.cvss_score}` : ""}
        </p>
      </div>

      {/* First, because it is why somebody opened the row. The pane used to
          lead with the classifier's verdict and the scanner's description —
          two paragraphs about the problem before anything about the answer. */}
      {remediation ? (
        <div className="border-l-2 border-accent-2 bg-paper-3 px-2.5 py-2">
          <div className="flex flex-wrap items-baseline gap-2">
            <Label>What to do</Label>
            <span className="text-[10px] uppercase tracking-wide text-ink-3">
              {remediation.effort}
            </span>
            {remediation.source === "standing" ? (
              <span
                className="text-[10px] uppercase tracking-wide text-ink-3"
                title="Written by this platform, not by the scanner. Gitleaks reports a match and no remedy, for instance."
              >
                ours, not the scanner&rsquo;s
              </span>
            ) : null}
          </div>
          <p className="mt-1 text-[14px] leading-relaxed text-ink">{remediation.fix}</p>
        </div>
      ) : null}

      <div>
        <Pill tone={triage.tone}>{triage.label}</Pill>
        <p className="mt-1 max-w-prose text-[14px] leading-relaxed text-ink-2">
          {group.triage_rationale}
        </p>
      </div>

      {/* Collapsible rather than a nested scrollbar. `max-h-32` on the
          scanner's own prose put a second scroll region inside a pane that was
          already scrolling, so reading the whole description meant a
          scrollbar somebody had to find first. */}
      {group.description ? (
        <details>
          <summary className="cursor-pointer list-none">
            <Label>Why the scanner flagged it</Label>
            <span className="ml-1.5 font-mono text-[11px] text-ink-3">
              {group.description.length > 240 ? "expand" : ""}
            </span>
          </summary>
          <p className="mt-1 whitespace-pre-wrap text-[14px] leading-relaxed text-ink-2">
            {group.description}
          </p>
        </details>
      ) : null}

      {/* Owner, due and age lived in table columns that no longer exist. They
          are facts about who answers for this and when it is late — the two
          questions a triage conversation opens with — so they get a row of
          their own rather than being dropped with the table. */}
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1 border-y border-rule-soft py-1.5">
        <span className="font-mono text-[11px] text-ink-3">
          owner{" "}
          {group.owner ? (
            <Link
              href={href(toggleValue(query, "owner", group.owner))}
              className={
                valuesOf(query, "owner").includes(group.owner)
                  ? "text-accent"
                  : "text-ink-2 hover:text-accent"
              }
            >
              {group.owner}
            </Link>
          ) : (
            // Absent, and now genuinely rare. Ownership falls to the account
            // the repository belongs to when CODEOWNERS can be read and
            // matches nothing (B-034), so reaching here means the platform
            // could not work it out at all — which is worth looking at rather
            // than shrugging past.
            <Link
              href={href(toggleValue(query, "owner", "unclaimed"))}
              className="text-critical hover:underline"
            >
              nobody — show the queue
            </Link>
          )}
        </span>
        <DueCell state={group.due_state} at={group.due_at} source={group.due_source} />
        {group.age_days != null ? (
          <span className="font-mono text-[11px] text-ink-3">{group.age_days}d old</span>
        ) : null}
      </div>

      <div>
        <Label>
          {group.occurrences} occurrence{group.occurrences === 1 ? "" : "s"}
        </Label>
        <ul className="mt-1 flex flex-col gap-0.5">
          {group.locations.slice(0, 12).map((location) => (
            <li key={location.finding_id} className="font-mono text-[12px]">
              <Link
                href={href({ finding: location.finding_id })}
                className={`hover:text-accent ${
                  query.finding === location.finding_id ? "text-accent" : "text-ink-2"
                }`}
              >
                {location.file_path ??
                  (group.package_name
                    ? `${group.package_name}@${location.package_version ?? "?"}`
                    : location.finding_id.slice(0, 12))}
                {location.line_start ? `:${location.line_start}` : ""}
              </Link>
              {/* A floor is what the repository permits, not what it runs
                  (B-063). Said next to the version, because the version is
                  the thing being misread: four HIGH advisories were reported
                  against a package no container had installed for months, and
                  the finding named a number that appears nowhere but a lower
                  bound. */}
              {location.version_basis === "declared_floor" ? (
                <span
                  className="ml-1.5 text-[11px] uppercase tracking-wider text-warn"
                  title="The version a requirement permits at its lower bound, not one this repository is known to run. Raising the floor closes it; it changes no running byte."
                >
                  declared floor
                </span>
              ) : null}
              <span className="ml-1.5 text-ink-3">
                {location.capability} ·{" "}
                {location.effective_severity ? (
                  <>
                    here {location.effective_severity}
                    {" · "}
                  </>
                ) : null}
                <RelativeTime value={location.first_seen_at ?? null} />
                {/* The whole record for this one occurrence (B-032): whether
                    its lane can close it, whether a fix exists, what the
                    platform could not work out. Facts that used to need four
                    other pages. */}
                {repoId ? (
                  <>
                    {" · "}
                    <Link
                      href={`/repos/${repoId}/findings/${location.finding_id}`}
                      className="underline decoration-dotted underline-offset-2 hover:text-accent"
                    >
                      full record
                    </Link>
                  </>
                ) : null}
              </span>
            </li>
          ))}
        </ul>
        {group.locations.length > 12 ? (
          <p className="mt-1 font-mono text-[11px] text-ink-3">
            +{group.locations.length - 12} more occurrence
            {group.locations.length - 12 === 1 ? "" : "s"}. Capped so the
            disposition control below stays reachable — a row with twenty-three
            identical locations used to push it off the end of the pane.
          </p>
        ) : null}
      </div>

      {detail ?? (
        <p className="border-t border-rule pt-2 text-[12px] text-ink-3">
          Choose an occurrence to see its detail and record a disposition
          against it. A disposition applies to the occurrence, not to the row —
          accepting the risk in one file is not accepting it everywhere.
        </p>
      )}
    </div>
  );
}

/** The one thing a disposition needs that the group does not carry. */
export function OccurrenceDisposition({
  findingId,
  status,
}: {
  findingId: string;
  status: string;
}) {
  return (
    <div className="border-t border-rule pt-3">
      <Label>Disposition</Label>
      <div className="mt-2">
        <DispositionForm findingId={findingId} currentStatus={status} />
      </div>
      <div className="mt-3 border-t border-rule-soft pt-3">
        <Label>Remediation</Label>
        <div className="mt-2">
          <RemediationAction key={findingId} findingId={findingId} />
        </div>
      </div>
    </div>
  );
}
