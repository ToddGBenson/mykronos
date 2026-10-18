"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";

import { EmptyState, Label, Pill } from "@/components/primitives";
import type { RuleVectorRule, RuleVectorsPage, RuleVectorTemplate } from "@/lib/api";
import {
  CONFIRM_TITLE,
  PROPOSE_TITLE,
  fromWord,
  ruleStateLine,
  scopeWord,
  statusTone,
  statusWord,
  unscoredSummary,
} from "@/lib/rule-vectors";

/**
 * Rule vectors (TheHub #60832, D3).
 *
 * SAST, DAST and secrets findings name a rule, not a CVE, so nothing publishes
 * a CVSS vector for them and they have no environmental score (D-106 left
 * them unscored on purpose). This lists those rules and lets a person record
 * a vector for one, pre-filled from a reviewed CWE-class template.
 *
 * **A proposal scores nothing.** Only a confirmed vector does, and confirming
 * is a person's act: the backend refuses an agent's credential, and every row
 * says which of the two states it is in.
 */
export function RuleVectors({ repoId, data }: { repoId: string; data: RuleVectorsPage }) {
  return (
    <section className="flex flex-col gap-3">
      <div className="flex flex-wrap items-baseline gap-3">
        <Label>Rule vectors</Label>
        <span className="font-mono text-[12px] text-ink-3">
          {unscoredSummary(data.unscored_rules, data.unscored_findings)}
        </span>
      </div>

      <p className="max-w-prose text-[12px] leading-relaxed text-ink-2">
        <strong className="text-ink">No CVE, so no published vector.</strong>{" "}
        These rules&rsquo; findings have no CVSS score until a person records one
        for the rule. A template pre-fills the vector from the rule&rsquo;s CWE;
        edit it to what the findings show. A proposal changes nothing — only a
        confirmed vector is scored, through the same environment as every other
        finding, and a published vector always wins over it.
      </p>

      {data.rules.length === 0 ? (
        <EmptyState
          title="Every open finding has a published vector, or none is open"
          detail="Rules appear here when their open findings have no CVE and so no vector from NVD or a scanner advisory."
        />
      ) : (
        <div className="flex flex-col divide-y divide-rule-soft border border-rule">
          {data.rules.map((rule) => (
            <RuleRowView
              key={`${rule.capability}|${rule.tool}|${rule.rule_id}`}
              repoId={repoId}
              rule={rule}
              templates={data.templates}
            />
          ))}
        </div>
      )}
    </section>
  );
}

function RuleRowView({
  repoId,
  rule,
  templates,
}: {
  repoId: string;
  rule: RuleVectorRule;
  templates: RuleVectorTemplate[];
}) {
  const proposal = rule.vectors.find((v) => v.status === "proposed");
  return (
    <div className="flex flex-col gap-1.5 bg-paper-2 px-3 py-2">
      <div className="flex flex-wrap items-baseline gap-2">
        <span className="font-mono text-[11px] uppercase tracking-[0.1em] text-ink-3">
          {rule.capability} · {rule.tool || "unknown tool"}
        </span>
        <span className="break-all font-mono text-[12px] font-bold text-ink">{rule.rule_id}</span>
        {rule.cwes.length > 0 ? (
          <span className="font-mono text-[11px] text-ink-3">{rule.cwes.join(", ")}</span>
        ) : null}
      </div>
      {rule.title ? <div className="text-[12px] text-ink-2">{rule.title}</div> : null}
      <div className="font-mono text-[11px] text-ink-2">{ruleStateLine(rule)}</div>

      {rule.vectors.map((v) => (
        <VectorLine key={v.id} vector={v} />
      ))}

      {proposal ? (
        <ConfirmForm proposalId={proposal.id} vector={proposal.vector} />
      ) : (
        <ProposeForm repoId={repoId} rule={rule} templates={templates} />
      )}
    </div>
  );
}

function VectorLine({ vector }: { vector: RuleVectorRule["vectors"][number] }) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);

  async function retire() {
    setError(null);
    const response = await fetch(`/api/rule-vectors/${encodeURIComponent(vector.id)}/retire`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    if (!response.ok) {
      const body = (await response.json().catch(() => null)) as { detail?: string } | null;
      setError(body?.detail ?? `Retiring was refused (HTTP ${response.status}).`);
      return;
    }
    startTransition(() => router.refresh());
  }

  return (
    <div className="flex flex-wrap items-center gap-2 font-mono text-[11px] text-ink-2">
      <Pill tone={statusTone(vector.status)}>{statusWord(vector.status)}</Pill>
      <span className="break-all text-ink">{vector.vector}</span>
      {typeof vector.base_score === "number" ? (
        <span>base {vector.base_score.toFixed(1)}</span>
      ) : null}
      <span className="text-ink-3">
        {scopeWord(vector.scope)} · {fromWord(vector.proposed_from)} · proposed by{" "}
        {vector.asserted_by}
        {vector.confirmed_by ? ` · confirmed by ${vector.confirmed_by}` : ""}
      </span>
      <button
        type="button"
        onClick={() => void retire()}
        disabled={pending}
        title={
          vector.status === "confirmed"
            ? "Withdraw this vector: its findings go back to unscored."
            : "Withdraw this proposal."
        }
        className="px-1 text-ink-3 hover:text-accent disabled:opacity-40"
      >
        retire
      </button>
      {error ? <span className="text-critical">{error}</span> : null}
    </div>
  );
}

function ConfirmForm({ proposalId, vector }: { proposalId: string; vector: string }) {
  const router = useRouter();
  const [edited, setEdited] = useState(vector);
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  async function confirm() {
    setError(null);
    const response = await fetch(`/api/rule-vectors/${encodeURIComponent(proposalId)}/confirm`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...(edited.trim() !== vector ? { vector: edited.trim() } : {}),
        ...(note.trim() ? { note: note.trim() } : {}),
      }),
    });
    if (!response.ok) {
      const body = (await response.json().catch(() => null)) as { detail?: string } | null;
      setError(body?.detail ?? `The confirmation was refused (HTTP ${response.status}).`);
      return;
    }
    startTransition(() => router.refresh());
  }

  return (
    <div className="flex flex-col gap-1">
      <div className="flex flex-wrap items-center gap-2">
        <input
          type="text"
          value={edited}
          onChange={(event) => setEdited(event.target.value)}
          aria-label="CVSS 3.1 vector to confirm"
          className="min-w-[24rem] flex-1 border border-rule bg-paper px-1.5 py-1 font-mono text-[12px] text-ink focus:border-accent focus:outline-none"
        />
        <input
          type="text"
          value={note}
          onChange={(event) => setNote(event.target.value)}
          placeholder="what you checked"
          className="min-w-[12rem] flex-1 border border-rule bg-paper px-1.5 py-1 font-mono text-[12px] text-ink placeholder:text-ink-3 focus:border-accent focus:outline-none"
        />
        <button
          type="button"
          onClick={() => void confirm()}
          disabled={pending || !edited.trim()}
          title={CONFIRM_TITLE}
          className="border border-rule px-2 py-0.5 font-mono text-[12px] text-ink-2 hover:border-accent hover:text-accent disabled:opacity-40"
        >
          confirm
        </button>
      </div>
      {error ? (
        <p className="max-w-prose text-[11px] leading-snug text-critical">{error}</p>
      ) : null}
    </div>
  );
}

function ProposeForm({
  repoId,
  rule,
  templates,
}: {
  repoId: string;
  rule: RuleVectorRule;
  templates: RuleVectorTemplate[];
}) {
  const router = useRouter();
  const suggested = rule.suggested_template;
  const [open, setOpen] = useState(false);
  const [templateId, setTemplateId] = useState<string>(suggested?.id ?? "");
  const [vector, setVector] = useState<string>(suggested?.vector ?? "");
  const [estate, setEstate] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();
  const template = templates.find((t) => t.id === templateId);

  function pick(id: string) {
    setTemplateId(id);
    const chosen = templates.find((t) => t.id === id);
    if (chosen) setVector(chosen.vector);
  }

  async function propose() {
    setError(null);
    const response = await fetch(`/api/repos/${encodeURIComponent(repoId)}/rule-vectors`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        capability: rule.capability,
        tool: rule.tool,
        rule_id: rule.rule_id,
        ...(templateId ? { template_id: templateId } : {}),
        vector: vector.trim(),
        estate,
      }),
    });
    if (!response.ok) {
      const body = (await response.json().catch(() => null)) as { detail?: string } | null;
      setError(body?.detail ?? `The proposal was refused (HTTP ${response.status}).`);
      return;
    }
    setOpen(false);
    startTransition(() => router.refresh());
  }

  if (!open) {
    return (
      <button
        type="button"
        onClick={() => setOpen(true)}
        disabled={!rule.tool}
        title={rule.tool ? PROPOSE_TITLE : "No tool is recorded for these findings, so a vector cannot be keyed to one."}
        className="self-start border border-rule px-2 py-0.5 font-mono text-[12px] text-ink-2 hover:border-accent hover:text-accent disabled:opacity-40"
      >
        {suggested ? `propose from ${suggested.cwe}` : "propose a vector"}
      </button>
    );
  }

  return (
    <div className="flex flex-col gap-1.5 border border-rule bg-paper p-2">
      <div className="flex flex-wrap items-center gap-2">
        <select
          value={templateId}
          onChange={(event) => pick(event.target.value)}
          className="border border-rule bg-paper p-1 font-mono text-[12px] text-ink"
        >
          <option value="">no template</option>
          {templates.map((t) => (
            <option key={t.id} value={t.id}>
              {t.cwe} {t.name}
            </option>
          ))}
        </select>
        <input
          type="text"
          value={vector}
          onChange={(event) => setVector(event.target.value)}
          placeholder="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          aria-label="CVSS 3.1 base vector"
          className="min-w-[24rem] flex-1 border border-rule bg-paper px-1.5 py-1 font-mono text-[12px] text-ink placeholder:text-ink-3 focus:border-accent focus:outline-none"
        />
      </div>
      {template ? (
        <p className="max-w-prose text-[11px] leading-snug text-ink-3">
          <span className="text-ink-2">
            {template.cwe}, base {template.base_score.toFixed(1)}:
          </span>{" "}
          {template.rationale}
        </p>
      ) : null}
      <div className="flex flex-wrap items-center gap-2">
        <label className="flex items-center gap-1 font-mono text-[11px] text-ink-3">
          <input
            type="checkbox"
            checked={estate}
            onChange={(event) => setEstate(event.target.checked)}
          />
          for every repository
        </label>
        <button
          type="button"
          onClick={() => void propose()}
          disabled={pending || !vector.trim()}
          title={PROPOSE_TITLE}
          className="border border-rule px-2 py-0.5 font-mono text-[12px] text-ink-2 hover:border-accent hover:text-accent disabled:opacity-40"
        >
          propose
        </button>
        <button
          type="button"
          onClick={() => {
            setOpen(false);
            setError(null);
          }}
          className="px-1 font-mono text-[12px] text-ink-3 hover:text-accent"
        >
          cancel
        </button>
      </div>
      {error ? (
        <p className="max-w-prose text-[11px] leading-snug text-critical">{error}</p>
      ) : null}
    </div>
  );
}
