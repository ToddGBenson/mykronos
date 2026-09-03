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

import { FilterSelect } from "@/components/filter-select";

import { DispositionForm } from "@/components/disposition";
import { GroomButton } from "@/components/groom-button";
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
  Severity,
  ToxicCombination,
} from "@/lib/api";

/**
 * The statuses a person can ask for. `open` is the default and the point.
 *
 * `suppressed` and `superseded` (spec 05 §5a, spec 17 §5.1) used to be real
 * `Finding.status` values the backend already accepted with no UI way to ask
 * for them — a superseded finding's replacement (`superseded_by`, shown in
 * its detail pane) was unreachable by name, the same gap §5.1 closes.
 */
const STATUSES = [
  { id: "open", label: "open" },
  { id: "accepted_risk", label: "accepted risk" },
  { id: "false_positive", label: "false positive" },
  { id: "fixed", label: "fixed" },
  { id: "suppressed", label: "suppressed" },
  { id: "superseded", label: "superseded" },
] as const;

const TRIAGE: Record<string, { tone: "critical" | "warn" | "accent" | "muted"; label: string }> = {
  toxic_combination: { tone: "critical", label: "toxic combo" },
  true_positive: { tone: "accent", label: "true positive" },
  likely_false_positive: { tone: "muted", label: "likely false positive" },
  needs_human_judgment: { tone: "warn", label: "needs judgment" },
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

/**
 * Changing a filter clears the selection. The row that was open is routinely
 * not in the new list, and a detail pane describing something the table no
 * longer shows is worse than an empty one.
 */
const CLEAR_SELECTION = { group: undefined, finding: undefined };

export type FindingsQuery = {
  tab?: string;
  severity?: string;
  capability?: string;
  status?: string;
  /** Free-text, matched against rule_id and title (spec 17 §3). */
  rule_id?: string;
  /** "1" when set — CISA KEV-listed CVEs only (spec 17 §3, #20). */
  kev_only?: string;
  /** EPSS threshold as a string, e.g. "0.5" (spec 17 §3, #20). */
  min_epss?: string;
  /** classify()'s classification, plus toxic_combination (spec 18 §5.1). */
  triage?: string;
  /** "1" when set — only groups Patchwork produced a fix for (spec 19 §3.2). */
  fixable?: string;
  /** A CODEOWNERS handle or team, or one of two queues: `unresolved` (the
   *  platform could not work it out) and `unclaimed` (nobody has taken it by
   *  name — it has an owner only because the repository does). */
  owner?: string;
  /** overdue | due_soon | on_track | no_target (spec 24 §2.4). */
  due?: string;
  /** Which deduplicated row is open. */
  group?: string;
  /** Which occurrence inside that row is open. */
  finding?: string;
};

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
  query,
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
  const href = (patch: Record<string, string | undefined>) => {
    const next = new URLSearchParams();
    // Always explicit, never stripped (spec 17 §2.4): this component now
    // renders behind its own "Findings" tab rather than at the default
    // route, so a filter link that dropped `tab` would silently bounce the
    // reader back to the Harness tab on every click.
    next.set("tab", "findings");
    for (const [key, value] of Object.entries({ ...query, ...patch })) {
      if (value && key !== "tab") next.set(key, value);
    }
    return `/repos/${repoId}?${next.toString()}`;
  };

  // Same default as the triage queue: the first group, not an empty pane.
  const selected =
    (query.group
      ? page.groups.find((group) => group.group_key === query.group)
      : undefined) ?? page.groups[0];

  return (
    <div className="flex flex-col gap-3">
      <Filters repoId={repoId} page={page} query={query} href={href} />

      {page.toxic_combinations.length > 0 ? (
        <ToxicCombinations repoId={repoId} combinations={page.toxic_combinations} />
      ) : null}

      {page.groups.length === 0 ? (
        <EmptyState
          title={
            query.severity ||
            query.capability ||
            query.rule_id ||
            query.kev_only ||
            query.min_epss ||
            query.triage ||
            query.fixable
              ? "Nothing matches these filters"
              : `No ${(query.status ?? "open").replace("_", " ")} findings`
          }
          detail={
            query.severity ||
            query.capability ||
            query.rule_id ||
            query.kev_only ||
            query.min_epss ||
            query.triage ||
            query.fixable
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
            ids={page.groups.map((group) => group.group_key)}
            param="group"
            clears={["finding"]}
          />
          <div className="flex flex-col gap-3 lg:h-[calc(100vh-22rem)] lg:flex-row lg:gap-0">
            <div className="lg:w-[28rem] lg:shrink-0 lg:overflow-y-auto lg:border-r lg:border-rule">
              <GroupList
                groups={page.groups}
                selectedKey={selected?.group_key}
                href={href}
              />
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
                />
              ) : null}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function Filters({
  repoId,
  page,
  query,
  href,
}: {
  repoId: string;
  page: OpenFindingsPage;
  query: FindingsQuery;
  href: (patch: Record<string, string | undefined>) => string;
}) {
  const status = query.status ?? "open";
  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        {/* `open` is the default rather than an option that reads as a filter:
            selecting it removes the parameter, which is what every link into
            this view already produces. */}
        <FilterSelect
          label="Status"
          name="status"
          value={query.status}
          anyLabel="open (default)"
          clears={["group", "finding"]}
          options={STATUSES.filter((entry) => entry.id !== "open").map((entry) => ({
            value: entry.id,
            label: entry.label,
          }))}
        />
        {/* The three numbers are different facts and all three get said: how
            much is outstanding, how much the filters kept, and how much of
            that the grouping collapsed. A single number here would be read as
            whichever one the reader expected. */}
        <span className="ml-auto font-mono text-[12px] text-ink-3">
          {page.total} {status.replace("_", " ")}
          {page.matching !== page.total ? ` · ${page.matching} match the filters` : ""} ·{" "}
          {page.groups.length} row{page.groups.length === 1 ? "" : "s"}
          {page.deduplicated > 0 ? ` · ${page.deduplicated} collapsed as duplicates` : ""}
        </span>
      </div>

      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        {/* The counts move into the option labels rather than being lost:
            "how many criticals" is the question that made the chips worth
            reading, and a bare dropdown would have thrown it away. */}
        <FilterSelect
          label="Severity"
          name="severity"
          value={query.severity}
          anyLabel="Any severity"
          clears={["group", "finding"]}
          options={(["critical", "high", "medium", "low", "info"] as Severity[]).map(
            (severity) => ({
              value: severity,
              label: `${severity} (${page.by_severity[severity] ?? 0})`,
            }),
          )}
        />
        {query.capability ? (
          <Link
            href={href({ capability: undefined, ...CLEAR_SELECTION })}
            className="border border-accent bg-accent-wash px-1.5 py-0.5 font-mono text-[11px] text-accent"
          >
            {query.capability} ✕
          </Link>
        ) : null}
      </div>

      {/* A plain GET form rather than a client component with `useState` and
          a debounced fetch — the query already lives in the URL for every
          other filter here, and a search box that broke that pattern would
          be the one filter that didn't survive a page refresh or a shared
          link (spec 17 §3). */}
      <form method="get" action={`/repos/${repoId}`} className="flex items-center gap-1.5">
        <input type="hidden" name="tab" value="findings" />
        {query.status ? <input type="hidden" name="status" value={query.status} /> : null}
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
            href={href({ rule_id: undefined, ...CLEAR_SELECTION })}
            className="border border-accent bg-accent-wash px-1.5 py-0.5 font-mono text-[11px] text-accent"
          >
            {query.rule_id} ✕
          </Link>
        ) : null}
      </form>

      {/* Threat intel (spec 17 §3, #20) — a fact and a probability, so two
          separate toggles rather than one "exploitable" checkbox that would
          conflate them. */}
      <div className="flex flex-wrap items-center gap-1.5">
        <Label>Threat intel</Label>
        <Link
          href={href({
            kev_only: query.kev_only === "1" ? undefined : "1",
            ...CLEAR_SELECTION,
          })}
          className={`border px-1.5 py-0.5 font-mono text-[11px] ${
            query.kev_only === "1"
              ? "border-critical bg-critical-wash text-critical"
              : "border-rule text-ink-3 hover:border-accent"
          }`}
        >
          KEV only
        </Link>
        <Link
          href={href({
            min_epss: query.min_epss === "0.5" ? undefined : "0.5",
            ...CLEAR_SELECTION,
          })}
          className={`border px-1.5 py-0.5 font-mono text-[11px] ${
            query.min_epss === "0.5"
              ? "border-high bg-high-wash text-high"
              : "border-rule text-ink-3 hover:border-accent"
          }`}
        >
          EPSS ≥ 50%
        </Link>
      </div>

      {/* What Patchwork actually did (spec 19 §3.2). Deliberately only a
          "fixable" chip and not a "not fixable" one: `false` and "nobody has
          looked" are different facts, and one chip cannot honestly stand for
          both. */}
      <div className="flex flex-wrap items-center gap-1.5">
        <Label>Remediation</Label>
        <Link
          href={href({
            fixable: query.fixable === "1" ? undefined : "1",
            ...CLEAR_SELECTION,
          })}
          className={`border px-1.5 py-0.5 font-mono text-[11px] ${
            query.fixable === "1"
              ? "border-pass bg-pass-wash text-pass"
              : "border-rule text-ink-3 hover:border-accent"
          }`}
        >
          fix available
        </Link>
      </div>

      {/* classify()'s own output (spec 18 §5.1) — the same classification
          already rendered per group as a Pill, now also a filter. */}
      <div className="flex flex-wrap items-center gap-1.5">
        <Label>Triage</Label>
        {Object.entries(TRIAGE).map(([id, meta]) => (
          <Link
            key={id}
            href={href({
              triage: query.triage === id ? undefined : id,
              ...CLEAR_SELECTION,
            })}
            className={`border px-1.5 py-0.5 font-mono text-[11px] ${
              query.triage === id
                ? "border-accent bg-accent-wash text-accent"
                : "border-rule text-ink-3 hover:border-accent"
            }`}
          >
            {meta.label}
          </Link>
        ))}
      </div>
    </div>
  );
}

/**
 * Drawn above the table rather than as rows in it, because a combination is
 * not a finding: it is a statement about several of them, and folding it into
 * a severity-ordered list is how it ends up below the individual mediums it
 * is made of.
 */
function ToxicCombinations({
  repoId,
  combinations,
}: {
  repoId: string;
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
            <div className="mt-1.5">
              <GroomButton
                url={`/api/triage/repos/${repoId}/combinations/${combination.combination_id}/groom`}
              />
            </div>
          </li>
        ))}
      </ul>
    </div>
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
  href: (patch: Record<string, string | undefined>) => string;
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
}: {
  group: FindingGroup;
  query: FindingsQuery;
  href: (patch: Record<string, string | undefined>) => string;
  detail?: React.ReactNode;
  remediation?: { fix: string; source: string; effort: string };
}) {
  const triage = TRIAGE[group.triage] ?? { tone: "muted" as const, label: group.triage };
  return (
    <div className="flex flex-col gap-3 border border-rule bg-paper-2 p-3">
      <div>
        <span className="flex flex-wrap items-baseline gap-1.5">
          <SeverityText severity={group.severity} />
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
              href={href({ owner: query.owner === group.owner ? undefined : group.owner })}
              className={query.owner === group.owner ? "text-accent" : "text-ink-2 hover:text-accent"}
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
              href={href({ owner: query.owner === "unclaimed" ? undefined : "unclaimed" })}
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
              <span className="ml-1.5 text-ink-3">
                {location.capability} ·{" "}
                <RelativeTime value={location.first_seen_at ?? null} />
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
      <div className="mt-3 border-t border-rule-soft pt-3">
        <Label>i2i</Label>
        <div className="mt-2">
          <GroomButton url={`/api/triage/${findingId}/groom`} />
        </div>
      </div>
    </div>
  );
}
