"use client";

/**
 * Proposing a formal risk acceptance from a finding (TheHub #61140, spec 33).
 *
 * Until this form, `/api/risk-acceptances` had no page: an acceptance was
 * proposed with curl or by an agent, and a person deciding a finding could
 * only set the row-level `accepted_risk`, which carries no owner, no premise
 * the platform can check, and no way out.
 *
 * It asks for what the server requires, in the order a person thinks of it:
 * why, how bad it still is, until when, what it rests on, and how it ends. It
 * says before sending what the server would refuse (`proposalProblems`), and
 * shows the server's own refusal verbatim when the policy differs.
 *
 * Proposing is not accepting. The response names the approval request, and a
 * person independent of the requester has to approve it.
 */

import Link from "next/link";
import { useState } from "react";

import {
  DEVIATION_TYPES,
  INTERIM_REVIEW_DAYS,
  LEVELS,
  LEVEL_LABEL,
  SIMPLE_PREMISES,
  buildProposal,
  effectiveResidual,
  interimReviewOwed,
  maxDurationDays,
  proposalProblems,
  residualSeverity,
  type AcceptanceDraft,
  type DeviationType,
  type Level,
} from "@/lib/finding-decision";

type Proposed = {
  risk_acceptance: { id: string; findings: number };
  approval_request_id: string;
  tier: string;
  flags: string[];
};

function isoDay(offsetDays: number): string {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() + offsetDays);
  return d.toISOString().slice(0, 10);
}

const field = "border border-rule bg-paper p-1.5 text-[13px] text-ink min-h-11";
const caption = "font-mono text-[11px] uppercase tracking-[0.12em] text-ink-3";

export function RiskAcceptanceForm({
  repo,
  repoId,
  scope,
  noFixPublished,
  controls,
  findingSeverity,
}: {
  repo: string;
  repoId: string;
  scope: Record<string, unknown>;
  noFixPublished: boolean;
  /** The finding's own severity: the residual's floor unless the reason is a
   *  risk adjustment, as on the server. */
  findingSeverity?: string;
  controls: { control_id: string; description: string; kind: string }[];
}) {
  const [draft, setDraft] = useState<AcceptanceDraft>(() => ({
    repo,
    scope,
    deviation_type: noFixPublished ? "vendor_dependency" : "risk_adjustment",
    justification: "",
    residual_likelihood: "low",
    residual_impact: "moderate",
    risk_owner: "",
    requested_until: isoDay(30),
    premises: noFixPublished ? ["no_fixed_version"] : [],
    control_id: "",
    milestone_title: noFixPublished ? "Apply the fix within 30 days of its release" : "",
    milestone_due: isoDay(30),
    response: "accept",
    finding_severity: findingSeverity,
  }));
  const [today] = useState(() => isoDay(0));
  const [tried, setTried] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [proposed, setProposed] = useState<Proposed | null>(null);

  const set = <K extends keyof AcceptanceDraft>(key: K, value: AcceptanceDraft[K]) =>
    setDraft((d) => ({ ...d, [key]: value }));
  const togglePremise = (type: string) =>
    setDraft((d) => ({
      ...d,
      premises: d.premises.includes(type)
        ? d.premises.filter((p) => p !== type)
        : [...d.premises, type],
    }));

  const matrix = residualSeverity(draft.residual_likelihood, draft.residual_impact);
  const residual = effectiveResidual(draft);
  const problems = proposalProblems(draft, today);
  const interim = interimReviewOwed(
    draft.deviation_type,
    draft.control_id ? [{ control_id: draft.control_id }] : [],
    draft.premises,
  );
  const deviation = DEVIATION_TYPES.find((t) => t.value === draft.deviation_type);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setTried(true);
    setError(null);
    if (problems.length) return;
    setBusy(true);
    try {
      const response = await fetch("/api/risk-acceptances", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(buildProposal(draft)),
      });
      const body = await response.json().catch(() => null);
      if (!response.ok) {
        setError(
          typeof body?.detail === "string"
            ? body.detail
            : `The proposal was refused (HTTP ${response.status}).`,
        );
        return;
      }
      setProposed(body as Proposed);
    } catch {
      setError("Could not reach the server.");
    } finally {
      setBusy(false);
    }
  }

  if (proposed) {
    return (
      <div className="flex flex-col gap-1.5 text-[13px]">
        <p className="text-pass">
          Proposed. It covers {proposed.risk_acceptance.findings} finding
          {proposed.risk_acceptance.findings === 1 ? "" : "s"} and is not in force until someone
          independent of you approves request{" "}
          <span className="font-mono">{proposed.approval_request_id}</span> ({proposed.tier}).
        </p>
        {proposed.flags.length ? (
          <ul className="ml-4 list-disc text-high">
            {proposed.flags.map((flag) => (
              <li key={flag}>{flag}</li>
            ))}
          </ul>
        ) : null}
        <Link
          href={`/repos/${repoId}/risk/${proposed.risk_acceptance.id}`}
          className="text-accent underline-offset-2 hover:underline"
        >
          Open the acceptance
        </Link>
      </div>
    );
  }

  return (
    <form onSubmit={submit} className="flex flex-col gap-3" noValidate>
      <fieldset className="flex flex-col gap-1">
        <legend className={caption}>Why it is acceptable</legend>
        <div className="flex flex-wrap gap-1.5">
          {DEVIATION_TYPES.map((t) => (
            <button
              key={t.value}
              type="button"
              aria-pressed={draft.deviation_type === t.value}
              onClick={() => set("deviation_type", t.value as DeviationType)}
              className={`min-h-11 border px-2 font-mono text-[12px] ${
                draft.deviation_type === t.value
                  ? "border-accent bg-accent-wash text-accent"
                  : "border-rule text-ink-3 hover:border-accent hover:text-accent"
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>
        {deviation ? <p className="text-[12px] text-ink-3">{deviation.hint}</p> : null}
      </fieldset>

      <label className="flex flex-col gap-1">
        <span className={caption}>Reason (required)</span>
        <textarea
          rows={3}
          value={draft.justification}
          onChange={(e) => set("justification", e.target.value)}
          placeholder="What makes this acceptable here, in a sentence an auditor can check."
          className={field}
        />
      </label>

      <div className="flex flex-wrap gap-3">
        <label className="flex flex-col gap-1">
          <span className={caption}>Likelihood, after controls</span>
          <select
            value={draft.residual_likelihood}
            onChange={(e) => set("residual_likelihood", e.target.value as Level)}
            className={field}
          >
            {LEVELS.map((l) => (
              <option key={l} value={l}>
                {LEVEL_LABEL[l]}
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1">
          <span className={caption}>Impact</span>
          <select
            value={draft.residual_impact}
            onChange={(e) => set("residual_impact", e.target.value as Level)}
            className={field}
          >
            {LEVELS.map((l) => (
              <option key={l} value={l}>
                {LEVEL_LABEL[l]}
              </option>
            ))}
          </select>
        </label>
        <p className="self-end pb-2 text-[13px] text-ink-2">
          Residual <strong>{residual}</strong>: at most {maxDurationDays(residual)} days.
          {residual !== matrix ? (
            <span className="block text-[12px] text-ink-3">
              Not {matrix}: only a risk adjustment can go below the finding&apos;s own
              severity.
            </span>
          ) : null}
        </p>
      </div>

      <div className="flex flex-wrap gap-3">
        <label className="flex flex-col gap-1">
          <span className={caption}>Expires</span>
          <input
            type="date"
            value={draft.requested_until}
            onChange={(e) => set("requested_until", e.target.value)}
            className={field}
          />
        </label>
        <label className="flex flex-col gap-1">
          <span className={caption}>Risk owner (a person)</span>
          <input
            type="text"
            value={draft.risk_owner}
            onChange={(e) => set("risk_owner", e.target.value)}
            placeholder="who answers for it"
            className={field}
          />
        </label>
      </div>

      <p className="border-l-2 border-rule px-2 text-[12px] leading-relaxed text-ink-2">
        {interim
          ? `Interim review: nothing the platform monitors watches this reason, so it asks a person to look again ${INTERIM_REVIEW_DAYS} days after it takes effect. Unreviewed, it reads "needs review" everywhere.`
          : draft.deviation_type === "vendor_dependency"
            ? "No interim review: it re-opens the day a scan reports a fixed version."
            : "No interim review: a monitored premise re-reads it every day and re-opens it if it fails."}
      </p>

      <fieldset className="flex flex-col gap-1">
        <legend className={caption}>What it rests on (premises the platform checks)</legend>
        {SIMPLE_PREMISES.map((p) => (
          <label key={p.value} className="flex min-h-11 items-start gap-2 text-[13px]">
            <input
              type="checkbox"
              className="mt-1"
              checked={draft.premises.includes(p.value)}
              onChange={() => togglePremise(p.value)}
            />
            <span>
              {p.label}
              <span className="block text-[12px] text-ink-3">{p.hint}</span>
            </span>
          </label>
        ))}
      </fieldset>

      <label className="flex flex-col gap-1">
        <span className={caption}>Compensating control (optional)</span>
        <select
          value={draft.control_id}
          onChange={(e) => set("control_id", e.target.value)}
          className={field}
        >
          <option value="">None</option>
          {controls.map((c) => (
            <option key={c.control_id} value={c.control_id}>
              {c.kind}: {c.description || c.control_id}
            </option>
          ))}
        </select>
        <span className="text-[12px] text-ink-3">
          {controls.length
            ? "Only declared controls: free text cannot be checked, so the server refuses it."
            : "No control is declared for this repository. Declare one on the Threat Model tab to cite it here."}
        </span>
      </label>

      <fieldset className="flex flex-col gap-1">
        <legend className={caption}>How it ends</legend>
        <div className="flex flex-wrap gap-3">
          <input
            type="text"
            value={draft.milestone_title}
            onChange={(e) => set("milestone_title", e.target.value)}
            placeholder="the change that ends the weakness"
            aria-label="Milestone that ends the weakness"
            className={`${field} min-w-64 flex-1`}
          />
          <input
            type="date"
            value={draft.milestone_due}
            onChange={(e) => set("milestone_due", e.target.value)}
            aria-label="Milestone due date"
            className={field}
          />
        </div>
      </fieldset>

      {tried && problems.length ? (
        <ul role="alert" className="ml-4 list-disc text-[13px] text-critical">
          {problems.map((p) => (
            <li key={p}>{p}</li>
          ))}
        </ul>
      ) : null}
      {error ? (
        <p role="alert" className="text-[13px] text-critical">
          {error}
        </p>
      ) : null}

      <button
        type="submit"
        disabled={busy}
        className="min-h-11 self-start border border-accent bg-accent-wash px-3 font-mono text-[12px] font-bold text-accent disabled:opacity-50"
      >
        {busy ? "Proposing…" : "Propose the acceptance"}
      </button>
      <p className="text-[12px] text-ink-3">
        This opens an approval request. Nothing is accepted until someone independent of you
        approves it.
      </p>
    </form>
  );
}
