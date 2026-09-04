/**
 * What Patchwork did, and did not do (spec 08 §7).
 *
 * The stages that produced *nothing* matter as much as the ones that opened a
 * pull request, and get equal room here. "We looked at this and could not fix
 * it" is a useful thing for a dashboard to say; a finding that simply never
 * appears is not, and a view that showed only successes would quietly turn
 * this capability into a highlight reel.
 */

import { EmptyState, Label, Pill, RelativeTime } from "@/components/primitives";
import { RemediationAction } from "@/components/remediation-action";
import type { RemediationEvent } from "@/lib/api";

/** Stages worth a second look from here (spec 18 §7.3) — a person starting
 *  from this tab rather than from the finding itself, for exactly the rows
 *  where nothing happened yet and something still could. */
const RETRYABLE_STAGES = new Set(["no_fix_available", "triaged"]);

const STAGE_LABEL: Record<string, string> = {
  pr_opened: "Draft PR open",
  fix_generated: "Fix generated, PR failed",
  no_fix_available: "No fix available",
  skipped_low_confidence: "Skipped — low confidence",
  triaged: "Triaged only",
  correlated: "Toxic combination",
  queued: "Queued",
  superseded: "Already resolved",
};

const STAGE_TONE: Record<string, "critical" | "warn" | "pass" | "muted" | "accent"> = {
  pr_opened: "accent",
  correlated: "critical",
  fix_generated: "warn",
  skipped_low_confidence: "warn",
  queued: "warn",
  superseded: "pass",
};

const PR_TONE: Record<string, "critical" | "warn" | "pass" | "muted" | "accent"> = {
  draft_open: "accent",
  human_edited: "accent",
  merged: "pass",
  closed_unmerged: "muted",
};

const PR_LABEL: Record<string, string> = {
  draft_open: "draft, awaiting review",
  human_edited: "edited by a person",
  merged: "merged",
  closed_unmerged: "closed unmerged",
};

export function RemediationTab({
  events,
  openDraftPrs,
  note,
}: {
  events: RemediationEvent[];
  openDraftPrs: number;
  note: string;
}) {
  if (events.length === 0) {
    return (
      <EmptyState
        title="Auto-remediation has not run here"
        detail={
          <>
            Enable the <span className="font-mono">patchwork</span> capability
            to have high and critical findings triaged, and mechanical fixes
            opened as draft pull requests. It cannot merge anything — the
            GitHub client it uses exposes no merge operation at all.
          </>
        }
      />
    );
  }

  const opened = events.filter((e) => e.fix_pr_number);
  const merged = events.filter((e) => e.pr_status === "merged").length;
  const abandoned = events.filter(
    (e) => e.pr_status === "closed_unmerged",
  ).length;

  return (
    <div className="flex flex-col gap-3">
      <div className="border-l-2 border-accent bg-accent-wash px-3 py-2">
        <Label>The guarantee</Label>
        <p className="mt-1 max-w-prose text-[14px] leading-relaxed text-ink-2">
          {note}
        </p>
      </div>

      <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1 font-mono text-[12px] text-ink-3">
        <span>{events.length} finding(s) considered</span>
        <span>{openDraftPrs} awaiting review</span>
        {merged > 0 ? <span className="text-pass">{merged} merged</span> : null}
        {abandoned > 0 ? (
          <span
            className="text-high"
            title="Worth asking whether the fixes were wrong or simply unwanted"
          >
            {abandoned} closed unmerged
          </span>
        ) : null}
        {opened.length > 0 && merged + abandoned === 0 ? (
          <span>no verdict yet</span>
        ) : null}
      </div>

      <ul className="flex flex-col gap-2">
        {events.map((event) => (
          <EventCard key={event.event_id} event={event} />
        ))}
      </ul>
    </div>
  );
}

function EventCard({ event }: { event: RemediationEvent }) {
  const stage = event.pipeline_stage_reached;
  const isCombination = Boolean(event.toxic_combination_id);

  return (
    <li className="border border-rule bg-paper-2">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 border-b border-rule-soft px-3 py-2">
        <Pill tone={STAGE_TONE[stage] ?? "muted"}>
          {STAGE_LABEL[stage] ?? stage.replace(/_/g, " ")}
        </Pill>

        {isCombination ? (
          <span className="font-mono text-[12px] text-ink-3">
            {(event.contributing_finding_ids ?? []).length} findings together
          </span>
        ) : (
          <span className="font-mono text-[12px] text-ink-3">
            {event.finding_id.slice(0, 12)}
          </span>
        )}

        <span className="font-mono text-[12px] text-ink-3">
          {event.triage_classification.replace(/_/g, " ")}
        </span>

        {event.fix_pr_number ? (
          <a
            href={event.fix_pr_url ?? "#"}
            className="font-mono text-[12px] text-accent underline-offset-2 hover:underline"
          >
            #{event.fix_pr_number}
          </a>
        ) : null}

        {event.pr_status ? (
          <Pill tone={PR_TONE[event.pr_status] ?? "muted"}>
            {PR_LABEL[event.pr_status] ?? event.pr_status}
          </Pill>
        ) : null}

        <span className="ml-auto whitespace-nowrap font-mono text-[12px] text-ink-3">
          <RelativeTime value={event.updated_at as string | null} />
        </span>
      </div>

      <p className="max-w-prose px-3 py-2 text-[14px] leading-relaxed text-ink-2">
        {event.rationale}
      </p>

      {/* Not offered for a combination event — there is no single finding_id
          to fix alone, which is the entire reason it is a combination. */}
      {RETRYABLE_STAGES.has(stage) && !isCombination ? (
        <div className="border-t border-rule-soft px-3 py-2">
          <Label>Preview and fix</Label>
          <div className="mt-1.5">
            <RemediationAction key={event.finding_id} findingId={event.finding_id} />
          </div>
        </div>
      ) : null}
    </li>
  );
}
