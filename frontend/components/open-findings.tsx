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

import { DispositionForm } from "@/components/disposition";
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
  /** Which deduplicated row is open. */
  group?: string;
  /** Which occurrence inside that row is open. */
  finding?: string;
};

export function OpenFindings({
  repoId,
  page,
  query,
  detail,
}: {
  repoId: string;
  page: OpenFindingsPage;
  query: FindingsQuery;
  /** Rendered in the aside when one occurrence is selected. */
  detail?: React.ReactNode;
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

  const selected = query.group
    ? page.groups.find((group) => group.group_key === query.group)
    : undefined;

  return (
    <div className="flex flex-col gap-3">
      <Filters repoId={repoId} page={page} query={query} href={href} />

      {page.toxic_combinations.length > 0 ? (
        <ToxicCombinations combinations={page.toxic_combinations} />
      ) : null}

      {page.groups.length === 0 ? (
        <EmptyState
          title={
            query.severity || query.capability || query.rule_id
              ? "Nothing matches these filters"
              : `No ${(query.status ?? "open").replace("_", " ")} findings`
          }
          detail={
            query.severity || query.capability || query.rule_id
              ? "Clear the filters to see everything outstanding."
              : "Either nothing has been found, or nothing has scanned yet — the scan health boxes above say which."
          }
        />
      ) : (
        <div className="flex flex-col gap-3 lg:flex-row">
          <div className="min-w-0 flex-1">
            <GroupTable groups={page.groups} query={query} href={href} />
            {page.truncated ? (
              <p className="mt-1 font-mono text-[9px] text-high">
                Showing the worst {page.shown} of {page.matching}. Filter by
                severity or capability to reach the rest — a list that silently
                stops reads as &ldquo;that is all of it&rdquo;.
              </p>
            ) : null}
          </div>

          <aside className="w-full shrink-0 lg:w-[26rem]">
            {selected ? (
              <GroupDetail group={selected} query={query} href={href} detail={detail} />
            ) : (
              <div className="border border-dashed border-rule bg-paper-2 p-4 text-[11px] text-ink-3">
                Select a row to see every place it was reported, why it was
                triaged that way, and to record a disposition.
              </div>
            )}
          </aside>
        </div>
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
      <div className="flex flex-wrap items-center gap-1.5">
        <Label>Status</Label>
        {STATUSES.map((entry) => (
          <Link
            key={entry.id}
            href={href({
              status: entry.id === "open" ? undefined : entry.id,
              ...CLEAR_SELECTION,
            })}
            className={`border px-1.5 py-0.5 font-mono text-[9px] ${
              status === entry.id
                ? "border-accent bg-accent-wash text-accent"
                : "border-rule text-ink-3 hover:border-accent"
            }`}
          >
            {entry.label}
          </Link>
        ))}
        {/* The three numbers are different facts and all three get said: how
            much is outstanding, how much the filters kept, and how much of
            that the grouping collapsed. A single number here would be read as
            whichever one the reader expected. */}
        <span className="ml-auto font-mono text-[10px] text-ink-3">
          {page.total} {status.replace("_", " ")}
          {page.matching !== page.total ? ` · ${page.matching} match the filters` : ""} ·{" "}
          {page.groups.length} row{page.groups.length === 1 ? "" : "s"}
          {page.deduplicated > 0 ? ` · ${page.deduplicated} collapsed as duplicates` : ""}
        </span>
      </div>

      <div className="flex flex-wrap items-center gap-1.5">
        <Label>Severity</Label>
        {(["critical", "high", "medium", "low", "info"] as Severity[]).map((severity) => (
          <Link
            key={severity}
            href={href({
              severity: query.severity === severity ? undefined : severity,
              ...CLEAR_SELECTION,
            })}
            className={`border px-1.5 py-0.5 font-mono text-[9px] ${
              query.severity === severity
                ? "border-accent bg-accent-wash text-accent"
                : "border-rule text-ink-3 hover:border-accent"
            }`}
          >
            {severity} {page.by_severity[severity] ?? 0}
          </Link>
        ))}
        {query.capability ? (
          <Link
            href={href({ capability: undefined, ...CLEAR_SELECTION })}
            className="border border-accent bg-accent-wash px-1.5 py-0.5 font-mono text-[9px] text-accent"
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
          className="border border-rule bg-paper px-1.5 py-0.5 font-mono text-[9px] text-ink placeholder:text-ink-3 focus:border-accent focus:outline-none"
        />
        {query.rule_id ? (
          <Link
            href={href({ rule_id: undefined, ...CLEAR_SELECTION })}
            className="border border-accent bg-accent-wash px-1.5 py-0.5 font-mono text-[9px] text-accent"
          >
            {query.rule_id} ✕
          </Link>
        ) : null}
      </form>
    </div>
  );
}

/**
 * Drawn above the table rather than as rows in it, because a combination is
 * not a finding: it is a statement about several of them, and folding it into
 * a severity-ordered list is how it ends up below the individual mediums it
 * is made of.
 */
function ToxicCombinations({ combinations }: { combinations: ToxicCombination[] }) {
  return (
    <div className="border border-critical bg-critical-wash">
      <div className="flex flex-wrap items-baseline gap-x-3 border-b border-critical/30 px-3 py-2">
        <h3 className="font-mono text-[10px] font-bold uppercase tracking-[0.12em] text-critical">
          Toxic combinations
        </h3>
        <span className="font-mono text-[10px] text-ink-2">
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
              <span className="font-mono text-[9px] text-ink-3">
                {combination.rule_id}
              </span>
            </div>
            <ul className="mt-1 flex flex-col gap-0.5">
              {combination.members.map((member) => (
                <li key={member.finding_id} className="font-mono text-[10px] text-ink-2">
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
            <p className="mt-1 max-w-prose text-[11px] leading-relaxed text-ink-2">
              {plain(combination.rationale)}
            </p>
          </li>
        ))}
      </ul>
    </div>
  );
}

function GroupTable({
  groups,
  query,
  href,
}: {
  groups: FindingGroup[];
  query: FindingsQuery;
  href: (patch: Record<string, string | undefined>) => string;
}) {
  return (
    <div className="scroll-x border border-rule">
      <table className="w-full min-w-[680px] border-collapse bg-paper-2 font-mono text-[11px]">
        <thead>
          <tr className="border-b-2 border-ink-2 text-left">
            {["Sev", "Problem", "Where", "Found by", "Triage", "Age"].map((heading) => (
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
          {groups.map((group) => {
            const triage = TRIAGE[group.triage] ?? { tone: "muted" as const, label: group.triage };
            const first = group.locations[0];
            return (
              <tr
                key={group.group_key}
                className={`border-b border-rule-soft last:border-b-0 hover:bg-paper-3 ${
                  query.group === group.group_key ? "bg-accent-wash" : ""
                } ${group.toxic_combination_ids?.length ? "border-l-2 border-l-critical" : ""}`}
              >
                <td className="px-2 py-2">
                  <SeverityText severity={group.severity} />
                </td>
                <td className="px-2 py-2">
                  <Link
                    href={href({ ...CLEAR_SELECTION, group: group.group_key })}
                    className="text-ink hover:text-accent"
                  >
                    {group.rule_id}
                  </Link>
                  <div className="max-w-[36ch] truncate text-[10px] text-ink-3">
                    {group.title}
                  </div>
                </td>
                <td className="max-w-[24ch] px-2 py-2 text-ink-2">
                  <span className="block truncate">
                    {group.package_name ?? first?.file_path ?? "—"}
                    {first?.line_start ? `:${first.line_start}` : ""}
                  </span>
                  {group.occurrences > 1 ? (
                    <span className="text-[9px] text-ink-3">
                      + {group.occurrences - 1} more occurrence
                      {group.occurrences === 2 ? "" : "s"}
                    </span>
                  ) : null}
                </td>
                <td className="whitespace-nowrap px-2 py-2 text-ink-3">
                  {group.capabilities.map((capability) => (
                    <span
                      key={capability}
                      title={
                        CAPABILITY_META[capability as keyof typeof CAPABILITY_META]?.label ??
                        capability
                      }
                    >
                      {CAPABILITY_META[capability as keyof typeof CAPABILITY_META]?.icon ?? "•"}
                    </span>
                  ))}
                  <span className="ml-1 text-[9px]">{group.capabilities.join(", ")}</span>
                </td>
                <td className="whitespace-nowrap px-2 py-2">
                  <Pill tone={triage.tone}>{triage.label}</Pill>
                </td>
                <td className="whitespace-nowrap px-2 py-2 tabular text-ink-3">
                  {typeof group.age_days === "number" ? `${group.age_days}d` : "—"}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function GroupDetail({
  group,
  query,
  href,
  detail,
}: {
  group: FindingGroup;
  query: FindingsQuery;
  href: (patch: Record<string, string | undefined>) => string;
  detail?: React.ReactNode;
}) {
  const triage = TRIAGE[group.triage] ?? { tone: "muted" as const, label: group.triage };
  return (
    <div className="flex flex-col gap-3 border border-rule bg-paper-2 p-3">
      <div>
        <SeverityText severity={group.severity} />
        <h3 className="mt-1 text-sm font-semibold leading-snug">{group.title}</h3>
        <p className="mt-1 font-mono text-[10px] text-ink-3">
          {group.rule_id} · {group.capabilities.join(", ")}
          {group.cvss_score ? ` · CVSS ${group.cvss_score}` : ""}
        </p>
      </div>

      <div>
        <Pill tone={triage.tone}>{triage.label}</Pill>
        <p className="mt-1 max-w-prose text-[11px] leading-relaxed text-ink-2">
          {group.triage_rationale}
        </p>
      </div>

      {group.description ? (
        <p className="max-h-32 overflow-y-auto whitespace-pre-wrap text-[11px] leading-relaxed text-ink-2">
          {group.description}
        </p>
      ) : null}

      <div>
        <Label>
          {group.occurrences} occurrence{group.occurrences === 1 ? "" : "s"}
        </Label>
        <ul className="mt-1 flex flex-col gap-0.5">
          {group.locations.map((location) => (
            <li key={location.finding_id} className="font-mono text-[10px]">
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
      </div>

      {detail ?? (
        <p className="border-t border-rule pt-2 text-[10px] text-ink-3">
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
    </div>
  );
}
