import Link from "next/link";

import { Label, Pill, RelativeTime } from "@/components/primitives";
import type { components } from "@/lib/api-types";
import type { FindingDossier } from "@/lib/server";

type Step = components["schemas"]["RescoreStepOut"];
type StepFact = components["schemas"]["RescoreStepFactOut"];
type Exploitability = components["schemas"]["ExploitabilityOut"];

const FRESHNESS_TONE: Record<StepFact["freshness"], "pass" | "warn" | "critical" | "muted"> = {
  fresh: "pass",
  expiring: "warn",
  lapsed: "critical",
  undated: "muted",
};

function freshnessLine(fact: StepFact): string {
  const parts: string[] = [];
  if (fact.age_days != null) parts.push(`${fact.age_days}d old`);
  if (fact.expires_in_days != null) {
    parts.push(
      fact.expires_in_days < 0
        ? `lapsed ${-fact.expires_in_days}d ago`
        : `lapses in ${fact.expires_in_days}d`,
    );
  }
  return parts.join(" · ");
}

/**
 * The working behind "Severity here", in order (TheHub #60889): base, then
 * every fact the environment considered with what it changed and how fresh
 * it is, then how the scanner's word became the effective severity.
 */
export function RescoreSteps({
  steps,
  recomputedBecause,
}: {
  steps: Step[];
  recomputedBecause?: string | null;
}) {
  if (steps.length === 0) return null;
  return (
    <div className="border-t border-rule-soft px-3 py-2">
      <Label>How this was worked out</Label>
      {recomputedBecause ? (
        <p className="mt-0.5 text-[12px] text-high">
          Computed now, not read from the store: {recomputedBecause}.
        </p>
      ) : null}
      <ol className="mt-1 flex flex-col gap-2">
        {steps.map((step, index) => (
          <li key={step.key} className="text-[13px] leading-relaxed">
            <span className="font-mono text-[11px] text-ink-3">{index + 1}.</span>{" "}
            <span className="font-semibold">{step.label}</span>
            {step.score != null ? (
              <span className="tabular ml-1.5 font-mono">{step.score.toFixed(1)}</span>
            ) : null}
            {step.severity ? (
              <span className="ml-1.5 font-mono text-[11px] uppercase text-ink-3">
                {step.severity}
              </span>
            ) : null}
            <span className="block text-ink-2">{step.detail}</span>
            {(step.facts ?? []).length > 0 ? (
              <ul className="mt-1 flex flex-col gap-0.5 pl-4">
                {(step.facts ?? []).map((fact) => (
                  <li
                    key={`${fact.metric}:${fact.to_value}:${fact.source_kind}:${fact.source_id}`}
                    className="flex flex-wrap items-baseline gap-x-2 text-[12px]"
                  >
                    <span
                      className={`font-mono font-semibold ${
                        fact.applied ? "" : "text-ink-3 line-through"
                      }`}
                    >
                      {fact.metric} {fact.from_value} → {fact.to_value}
                    </span>
                    <Pill tone={FRESHNESS_TONE[fact.freshness]}>{fact.freshness}</Pill>
                    <span className="font-mono text-[11px] text-ink-3">
                      {fact.tier} · {fact.source_kind}
                      {freshnessLine(fact) ? ` · ${freshnessLine(fact)}` : ""}
                    </span>
                    {fact.because ? <span className="text-ink-2">{fact.because}</span> : null}
                    {!fact.applied && fact.not_applied_reason ? (
                      <span className="text-high">not applied: {fact.not_applied_reason}</span>
                    ) : null}
                  </li>
                ))}
              </ul>
            ) : null}
            {(step.notes ?? []).map((note) => (
              <span key={note} className="block text-[12px] text-critical">
                {note}
              </span>
            ))}
          </li>
        ))}
      </ol>
    </div>
  );
}

const VERDICT_LABEL: Record<Exploitability["verdict"], string> = {
  exploited: "exploited in the wild",
  weaponized: "weaponised",
  public_poc: "public exploit",
  elevated_epss: "elevated EPSS",
  no_known_exploit: "no known exploit",
  not_checked: "not checked yet",
  no_cve: "no CVE",
};

const VERDICT_TONE: Record<Exploitability["verdict"], "critical" | "warn" | "pass" | "muted"> = {
  exploited: "critical",
  weaponized: "critical",
  public_poc: "warn",
  elevated_epss: "warn",
  no_known_exploit: "pass",
  not_checked: "muted",
  no_cve: "muted",
};

export function verdictLabel(verdict: Exploitability["verdict"]): string {
  return VERDICT_LABEL[verdict];
}

/** Can somebody exploit this today, and on whose word (TheHub #60890). */
export function ExploitabilityPanel({ data }: { data: Exploitability }) {
  return (
    <section className="border border-rule bg-paper-2">
      <div className="flex flex-wrap items-baseline gap-x-3 border-b border-rule-soft px-3 py-1.5">
        <Label as="h2">Exploitability</Label>
        {data.checked_at ? (
          <span className="font-mono text-[11px] text-ink-3">
            catalogs checked <RelativeTime value={data.checked_at} />
          </span>
        ) : null}
      </div>
      <div className="flex flex-col gap-1.5 px-3 py-2.5">
        <span className="flex flex-wrap items-baseline gap-2">
          <Pill tone={VERDICT_TONE[data.verdict]}>{VERDICT_LABEL[data.verdict]}</Pill>
          {data.cve_id ? (
            <span className="font-mono text-[12px] text-ink-3">{data.cve_id}</span>
          ) : null}
        </span>
        <p className="text-[13px] leading-relaxed text-ink-2">{data.summary}</p>
        {(data.sources ?? []).length > 0 ? (
          <ul className="flex flex-col gap-0.5">
            {(data.sources ?? []).map((source) => (
              <li key={`${source.source}:${source.url}:${source.detail}`} className="text-[12px]">
                <span className="font-semibold">{source.label}</span>{" "}
                <span className="text-ink-2">{source.detail}</span>{" "}
                {source.url ? (
                  <a
                    href={source.url}
                    rel="noopener noreferrer nofollow"
                    target="_blank"
                    className="font-mono text-[11px] text-accent underline-offset-2 hover:underline"
                  >
                    source
                  </a>
                ) : null}
              </li>
            ))}
          </ul>
        ) : null}
        <p className="border-t border-rule-soft pt-1.5 text-[12px] text-ink-2">
          <span className="font-semibold">Fix: </span>
          {data.fix.detail}
        </p>
      </div>
    </section>
  );
}

const GRADE_TONE = {
  agree: "pass",
  disagree: "critical",
  pending: "muted",
  ineligible: "muted",
} as const;

/**
 * What somebody reads before deciding (TheHub #60893): history, how the same
 * rule was decided elsewhere, the cluster, and model proposals in shadow.
 */
export function DossierPanel({ dossier }: { dossier: FindingDossier }) {
  return (
    <section className="border border-rule bg-paper-2">
      <div className="border-b border-rule-soft px-3 py-1.5">
        <Label as="h2">Investigation dossier</Label>
      </div>
      <div className="flex flex-col gap-3 px-3 py-2.5 text-[13px]">
        {dossier.cluster ? (
          <div>
            <Label>Cluster</Label>
            <p className="text-ink-2">
              {dossier.cluster.reason}{" "}
              <Link
                href={`/triage?group=cluster`}
                className="text-accent underline-offset-2 hover:underline"
              >
                {dossier.cluster.count} member{dossier.cluster.count === 1 ? "" : "s"}
              </Link>
            </p>
          </div>
        ) : null}

        <div>
          <Label>Similar past decisions</Label>
          {dossier.similar_dispositions.length === 0 ? (
            <p className="text-ink-3">Nobody has dispositioned this rule anywhere else.</p>
          ) : (
            <ul className="flex flex-col gap-0.5">
              {dossier.similar_dispositions.map((s) => (
                <li key={s.finding_id} className="text-[12px]">
                  <Pill tone="muted">{s.status.replace(/_/g, " ")}</Pill>{" "}
                  {s.repo_id ? (
                    <Link
                      href={`/repos/${s.repo_id}/findings/${s.finding_id}`}
                      className="font-mono text-[11px] underline decoration-dotted underline-offset-2"
                    >
                      {s.repo_full_name}
                      {s.where ? ` · ${s.where}` : ""}
                    </Link>
                  ) : (
                    <span className="font-mono text-[11px]">
                      {s.repo_full_name}
                      {s.where ? ` · ${s.where}` : ""}
                    </span>
                  )}
                  {s.reason ? <span className="text-ink-2"> — {s.reason}</span> : null}
                  {s.decided_by ? (
                    <span className="font-mono text-[11px] text-ink-3"> · {s.decided_by}</span>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
        </div>

        <div>
          <Label>Model proposals (shadow — never applied)</Label>
          {dossier.proposals.length === 0 ? (
            <p className="text-ink-3">No model has proposed a verdict on this finding.</p>
          ) : (
            <ul className="flex flex-col gap-1">
              {dossier.proposals.map((p) => (
                <li key={p.id} className="text-[12px]">
                  <span className="font-semibold">{p.proposed_status.replace(/_/g, " ")}</span>
                  {p.confidence != null ? ` (${Math.round(p.confidence * 100)}%)` : ""}{" "}
                  <Pill tone={GRADE_TONE[p.grade]}>{p.grade}</Pill>
                  {p.human_verdict ? (
                    <span className="text-ink-3"> person said {p.human_verdict.replace(/_/g, " ")}</span>
                  ) : null}
                  <span className="block text-ink-2">{p.rationale}</span>
                  <span className="font-mono text-[11px] text-ink-3">
                    {p.model} · <RelativeTime value={p.created_at} />
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div>
          <Label>History</Label>
          <ol className="flex flex-col gap-0.5 font-mono text-[11px] text-ink-2">
            {dossier.history.map((e, i) => (
              <li key={`${e.at}:${e.event}:${i}`}>
                <RelativeTime value={e.at} /> · {e.event}
                {e.actor ? ` · ${e.actor}` : ""}
                {e.detail ? ` · ${e.detail}` : ""}
              </li>
            ))}
          </ol>
        </div>
      </div>
    </section>
  );
}
