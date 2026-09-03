import { Label, Pill, Section, StatTile } from "@/components/primitives";
import type { components } from "@/lib/api-types";

type Practice = components["schemas"]["PracticeOut"];
type Ssdf = components["schemas"]["SsdfOut"];

const STATUS: Record<string, { tone: "pass" | "warn" | "muted"; word: string }> = {
  met: { tone: "pass", word: "Evidenced" },
  partial: { tone: "warn", word: "Partial" },
  not_evidenced: { tone: "muted", word: "Not evidenced" },
  not_applicable: { tone: "muted", word: "N/A" },
};

/**
 * Practices in their SSDF group order, which is also the order they happen in:
 * prepare, protect, produce, respond. Sorting by status instead would put the
 * green rows at the top, and the reader is here for the other ones.
 */
const GROUPS = [
  "Prepare the Organization",
  "Protect the Software",
  "Produce Well-Secured Software",
  "Respond to Vulnerabilities",
] as const;

function PracticeRow({ practice }: { practice: Practice }) {
  const status = STATUS[practice.status] ?? STATUS.not_evidenced;
  return (
    <div className="border-t border-rule-soft px-3 py-2.5">
      <div className="flex flex-wrap items-baseline gap-x-2.5 gap-y-1">
        <span className="font-mono text-[12px] font-bold tabular text-ink">
          {practice.practice_id}
        </span>
        <span className="text-[13px] text-ink">{practice.title}</span>
        <span className="ml-auto">
          <Pill tone={status.tone} title={`SSDF ${practice.practice_id}: ${status.word}`}>
            {status.word}
          </Pill>
        </span>
      </div>

      {practice.evidence.length > 0 ? (
        <ul className="mt-1.5 flex flex-col gap-0.5">
          {practice.evidence.map((line) => (
            <li key={line} className="text-[12px] text-pass">
              <span aria-hidden="true">✓ </span>
              {line}
            </li>
          ))}
        </ul>
      ) : null}

      {practice.missing.length > 0 ? (
        <ul className="mt-0.5 flex flex-col gap-0.5">
          {practice.missing.map((line) => (
            <li key={line} className="text-[12px] text-ink-3">
              <span aria-hidden="true">· </span>
              {line}
            </li>
          ))}
        </ul>
      ) : null}

      {/* Shown only when it is the answer to something. On a met practice it
          would be advice about a problem the reader does not have. */}
      {practice.status !== "met" && practice.how_to_evidence ? (
        <p className="mt-1.5 max-w-prose text-[12px] text-ink-2">
          <span className="text-ink-3">To evidence it: </span>
          {practice.how_to_evidence}
        </p>
      ) : null}

      {practice.nist_800_53.length > 0 ? (
        <p className="mt-1 font-mono text-[11px] text-ink-3">
          Cross-reference: SP 800-53 {practice.nist_800_53.join(", ")}
        </p>
      ) : null}
    </div>
  );
}

/**
 * SSDF adherence for one repository.
 *
 * There is no percentage and no score here on purpose, and the note below the
 * counts says why: the practices are not equally weighted or equally
 * applicable, so a single figure would be a number nobody could defend to the
 * auditor it was made for.
 */
export function SsdfTab({ data }: { data: Ssdf }) {
  const counts = data.counts;
  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
        <StatTile
          label="Evidenced"
          value={counts.met ?? 0}
          sub={`of ${data.practices.length} practices`}
        />
        <StatTile label="Partial" value={counts.partial ?? 0} sub="some evidence" />
        <StatTile
          label="Not evidenced"
          value={counts.not_evidenced ?? 0}
          sub="nothing observed"
        />
      </div>

      <p className="max-w-prose text-[13px] text-ink-2">{data.note}</p>

      {GROUPS.map((group) => {
        const practices = data.practices.filter((p) => p.group === group);
        if (practices.length === 0) return null;
        return (
          <Section key={group} title={group}>
            {practices.map((practice) => (
              <PracticeRow key={practice.practice_id} practice={practice} />
            ))}
          </Section>
        );
      })}

      <div className="border border-rule bg-paper-2 px-3 py-2.5">
        <Label>Not assessed here</Label>
        {/* Named rather than silently dropped. A reader who knows SSDF will
            look for PO.1 and PO.2, and "we cannot see them" is a better
            answer than their absence. */}
        <p className="mt-1 max-w-prose text-[12px] text-ink-2">
          PO.1 (define security requirements) and PO.2 (roles and
          responsibilities) are organisational. Nothing in a pipeline observes
          them, so they are absent rather than reported as unmet — a view that
          lists practices it cannot assess teaches people to ignore the ones it
          can.
        </p>
      </div>
    </div>
  );
}
