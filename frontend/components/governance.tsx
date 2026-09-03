/**
 * The controls that would catch a bad change (spec 30 §2).
 *
 * Above the signals, because it explains them. Aegis's nine signals each
 * describe a pull request after the fact — `self_approval` fires when somebody
 * approved their own change, which is a symptom. *"Self-approval is permitted
 * on the default branch"* is the cause, and it was invisible from anywhere in
 * this platform until this panel.
 *
 * **Each row names what it would have prevented.** That link is the point: it
 * converts a log of oddities into a diagnosis with a remedy the team can
 * action themselves, in their own repository settings, without asking anybody.
 *
 * **Unknown is a state and it is drawn as one.** A control the platform could
 * not read is a dash and a sentence, never a red cross. A permissions gap is
 * not a security failure and must not look like one — and the panel says which
 * permission would answer the question.
 */

import { Label, Pill, RelativeTime } from "@/components/primitives";
import type { GovernancePosture } from "@/lib/api";

type Control = NonNullable<GovernancePosture["controls"]>[number];
type ControlDrift = NonNullable<GovernancePosture["drift"]>[number];

const CONTROL_LABEL: Record<string, string> = {
  pull_request_required: "Pull request required on default branch",
  approving_reviews_required: "Approving reviews required",
  dismiss_stale_reviews: "Stale reviews dismissed on push",
  codeowner_review_required: "Code-owner review required",
  codeowners_coverage: "CODEOWNERS coverage",
  enforced_for_admins: "Enforced for administrators",
  signed_commits_required: "Signed commits required",
  required_status_checks: "Required status checks",
  force_push_blocked: "Force pushes blocked",
};

const SIGNAL_LABEL: Record<string, string> = {
  self_approval: "approved their own change",
  sole_approver: "single approver",
  sensitive_path: "sensitive path",
  fast_approval: "approved faster than readable",
};

const STATE: Record<string, { mark: string; tone: string; title: string }> = {
  on: { mark: "✓", tone: "text-pass", title: "In force" },
  partial: { mark: "~", tone: "text-high", title: "Present, and weaker than it looks" },
  off: { mark: "✕", tone: "text-critical", title: "Not in force" },
  unknown: { mark: "—", tone: "text-ink-3", title: "Could not be read" },
};

function scoreTone(score: number | null | undefined) {
  // Higher is better here, like the trust score and unlike the risk score.
  if (score == null) return "muted" as const;
  if (score >= 80) return "pass" as const;
  if (score >= 50) return "warn" as const;
  return "critical" as const;
}

export function GovernancePanel({ posture }: { posture: GovernancePosture }) {
  const controls = posture.controls ?? [];

  return (
    <section className="border border-rule bg-paper-2">
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1 border-b border-rule-soft px-3 py-2">
        <Label>Change governance</Label>
        <span className="font-mono text-[12px] text-ink-3">
          what would stop a bad change getting in
        </span>

        <span className="ml-auto flex items-baseline gap-2">
          {/* Null is not zero. A repository whose settings could not be read
              has no posture, not a bad one. */}
          <Pill tone={scoreTone(posture.governance_score)}>
            {posture.governance_score == null
              ? "not scored"
              : `${posture.governance_score}/100`}
          </Pill>
          {posture.read_at ? (
            <span className="font-mono text-[11px] text-ink-3">
              read <RelativeTime value={posture.read_at} />
            </span>
          ) : null}
        </span>
      </div>

      {!posture.readable ? (
        <p className="max-w-prose px-3 py-2 text-[14px] leading-relaxed text-ink-2">
          {posture.unreadable_reason}
        </p>
      ) : (
        <>
          <table className="w-full border-collapse font-mono text-[13px]">
            <tbody>
              {controls.map((control) => (
                <ControlRow key={control.key} control={control} />
              ))}
            </tbody>
          </table>

          <Drift drift={posture.drift ?? []} />

          <p className="max-w-prose border-t border-rule-soft px-3 py-2 text-[12px] leading-relaxed text-ink-3">
            {posture.note}
          </p>
        </>
      )}
    </section>
  );
}

/**
 * Controls that changed state since the platform last looked.
 *
 * The table above says what is true now, which is what a panel is for. This
 * says what *moved*, which is what monitoring is for — and until the sweep
 * shipped, a repository could drop its review requirement and leave no trace
 * anywhere but a score nobody was watching.
 *
 * Absent when nothing has changed rather than shown empty: "no drift" is the
 * normal state and a permanent empty section trains people to skip the region
 * of the page where the one thing that matters will appear.
 */
function Drift({ drift }: { drift: ControlDrift[] }) {
  if (drift.length === 0) return null;

  return (
    <div className="border-t border-rule-soft px-3 py-2">
      <Label>Changed since we last looked</Label>
      <ul className="mt-1 flex flex-col gap-0.5">
        {drift.map((row) => (
          <li
            key={`${row.control_key}-${row.observed_at}`}
            className="font-mono text-[12px]"
          >
            {/* A transition to `unknown` is a read that failed, not a control
                that was removed. Colouring them alike would send somebody to
                fix a security regression that is actually a missing App
                permission. */}
            <span className={row.regression ? "text-critical" : "text-ink-2"}>
              {row.regression ? "▼ " : "· "}
              {CONTROL_LABEL[row.control_key] ?? row.control_key}
            </span>{" "}
            <span className="text-ink-3">
              {row.to_state === "unknown"
                ? "could no longer be read"
                : `${row.from_state} → ${row.to_state}`}
              {" · "}
              <RelativeTime value={row.observed_at} />
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function ControlRow({ control }: { control: Control }) {
  const state = STATE[control.state] ?? STATE.unknown;
  const prevents = control.prevents ?? [];

  return (
    <tr className="border-t border-rule-soft first:border-t-0 align-baseline">
      <td className={`w-6 px-2 py-1.5 text-center ${state.tone}`} title={state.title}>
        {state.mark}
      </td>
      <td className="px-2 py-1.5 text-ink-2">
        {CONTROL_LABEL[control.key] ?? control.key}
      </td>
      <td className="px-2 py-1.5 text-ink-3">{control.detail}</td>
      <td className="px-2 py-1.5 text-right">
        {/* Only where the control is not doing its job. Naming what a working
            control "would have prevented" reads as an accusation about
            something that did not happen. */}
        {prevents.length > 0 && control.state !== "on" ? (
          <span className="text-[12px] text-ink-3">
            would stop: {prevents.map((s) => SIGNAL_LABEL[s] ?? s).join(", ")}
          </span>
        ) : null}
      </td>
    </tr>
  );
}

export function MergeCounts({ merges }: { merges: GovernancePosture["merges"] }) {
  const data = merges as
    | {
        available?: boolean;
        reason?: string;
        days?: number;
        assessed?: number;
        sole_approver_on_sensitive_path?: number;
        approved_faster_than_readable?: number;
        self_approved?: number;
        note?: string;
      }
    | undefined;

  if (!data?.available) {
    return null;
  }

  const rows: [string, number | undefined][] = [
    ["Single approver on a sensitive path", data.sole_approver_on_sensitive_path],
    ["Approved faster than the diff could be read", data.approved_faster_than_readable],
    ["Approved by their own author", data.self_approved],
  ];

  return (
    <section className="border border-rule bg-paper-2">
      <div className="flex flex-wrap items-baseline gap-x-3 border-b border-rule-soft px-3 py-2">
        <Label>Merges in the last {data.days} days</Label>
        <span className="font-mono text-[12px] text-ink-3">
          {data.assessed} assessed
        </span>
      </div>

      <table className="w-full border-collapse font-mono text-[13px]">
        <tbody>
          {rows.map(([label, value]) => (
            <tr key={label} className="border-t border-rule-soft first:border-t-0">
              <td
                className={`tabular w-12 px-2 py-1.5 text-right ${
                  value ? "text-high" : "text-ink-3"
                }`}
              >
                {value ?? 0}
              </td>
              <td className="px-2 py-1.5 text-ink-2">{label}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {/* The sentence that keeps this inside spec 06 §9. */}
      <p className="max-w-prose border-t border-rule-soft px-3 py-2 text-[12px] leading-relaxed text-ink-3">
        {data.note}
      </p>
    </section>
  );
}
