"use client";

/**
 * What this application *is*, as an asset (spec 21 §1.5).
 *
 * Every other input on the Risk Decision tab is derived from what a scanner
 * found. This one cannot be: nothing a scan sees says whether an application
 * is internet-facing or handles regulated data. It sits beside the term
 * breakdown it now feeds rather than on a page of its own — a score and the
 * facts that produced it belong in the same place.
 *
 * A full replace, not a patch (spec 21 §1.3): the form always submits every
 * field, so a value cleared here is a value the writer is saying they no
 * longer assert, not one that silently persists from an earlier edit.
 */

import { useState } from "react";

import { Label, Pill, RelativeTime } from "@/components/primitives";
import type { RiskProfile } from "@/lib/api";
import type { paths } from "@/lib/api-types";

type ProfileProposal =
  paths["/api/dashboard/repos/{repo_id}/risk-profile/proposal"]["get"]["responses"]["200"]["content"]["application/json"];

const CLASSIFICATIONS = ["public", "internal", "confidential", "regulated"] as const;
const CRITICALITIES = ["low", "medium", "high", "critical"] as const;
/** The regimes worth a one-click chip. Anything else is still recordable —
 *  the backend takes any string — this is just the common set. */
const REGIMES = ["pci", "hipaa", "soc2", "gdpr", "fedramp"] as const;

export function RiskProfileCard({
  repoId,
  profile,
  proposal,
}: {
  repoId: string;
  profile: RiskProfile;
  /** What the platform can evidence, and what it refuses to guess (B-041).
   *  Turns an empty form into a short list of evidence to go and get. */
  proposal?: ProfileProposal | null;
}) {
  const [editing, setEditing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [current, setCurrent] = useState(profile);

  const [internetFacing, setInternetFacing] = useState<boolean | null>(
    profile.internet_facing ?? null,
  );
  const [classification, setClassification] = useState<string | null>(
    profile.data_classification ?? null,
  );
  const [criticality, setCriticality] = useState<string | null>(
    profile.business_criticality ?? null,
  );
  const [scope, setScope] = useState<string[]>(profile.compliance_scope ?? []);
  const [owner, setOwner] = useState(profile.owner ?? "");
  const [notes, setNotes] = useState(profile.notes ?? "");

  async function save() {
    setSaving(true);
    setError(null);
    try {
      const response = await fetch(`/api/repos/${repoId}/risk-profile`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          internet_facing: internetFacing,
          data_classification: classification,
          business_criticality: criticality,
          compliance_scope: scope,
          owner: owner.trim() || null,
          notes: notes.trim() || null,
        }),
      });
      const body = await response.json().catch(() => null);
      if (!response.ok) {
        setError(
          typeof body?.detail === "string"
            ? body.detail
            : `The request was refused (HTTP ${response.status}).`,
        );
        return;
      }
      setCurrent(body as RiskProfile);
      setEditing(false);
    } catch {
      setError("Could not reach the server.");
    } finally {
      setSaving(false);
    }
  }

  if (!editing) {
    return (
      <div className="border border-rule bg-paper-2">
        <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1 border-b border-rule-soft px-3 py-2">
          <h2 className="font-mono text-[12px] font-bold uppercase tracking-[0.12em] text-ink">
            Risk profile
          </h2>
          <span className="font-mono text-[12px] text-ink-3">
            what this application is — recorded, never inferred
          </span>
          <button
            type="button"
            onClick={() => setEditing(true)}
            className="ml-auto border border-rule px-1.5 py-0.5 font-mono text-[11px] text-ink-3 hover:border-accent hover:text-accent"
          >
            {current.exists ? "edit" : "record one"}
          </button>
        </div>

        {current.exists ? (
          <div className="flex flex-col gap-2 px-3 py-2">
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 font-mono text-[12px]">
              <Fact label="Internet-facing" value={boolWord(current.internet_facing)} />
              <Fact label="Data" value={current.data_classification} />
              <Fact label="Criticality" value={current.business_criticality} />
              {/* Optional in the generated type (it has a server-side
                  default), so read through a fallback rather than widening
                  every use site. An empty list is a real answer — "none
                  apply" — not a missing one. */}
              <Fact
                label="Compliance"
                value={(current.compliance_scope ?? []).join(", ") || "none"}
              />
              {current.owner ? <Fact label="Owner" value={current.owner} /> : null}
            </div>
            {current.notes ? (
              <p className="max-w-prose whitespace-pre-wrap text-[14px] leading-relaxed text-ink-2">
                {current.notes}
              </p>
            ) : null}
            <p className="font-mono text-[11px] text-ink-3">
              {current.updated_by ? `recorded by ${current.updated_by}` : "recorded"}
              {current.updated_at ? (
                <>
                  {" "}
                  <RelativeTime value={current.updated_at} />
                </>
              ) : null}
            </p>
          </div>
        ) : (
          <div className="flex flex-col gap-3 px-3 py-2">
            <p className="max-w-prose text-[14px] leading-relaxed text-ink-2">
              Nothing recorded. Oracle reports this input as{" "}
              <span className="font-mono">unavailable</span> and it contributes
              nothing — deliberately, rather than assuming an internal,
              low-criticality application. An internal build tool and a public
              payments API otherwise score identically for the same finding.
            </p>

            {/* The proposal, when there is one. A blank form asks somebody to
                remember four facts; this tells them which the platform can
                already evidence and, for the rest, exactly what would settle
                each one. The refusals are the useful half. */}
            {proposal?.proposals?.length ? (
              <div className="flex flex-col gap-1.5 border-t border-rule-soft pt-2.5">
                <Label>What the platform can tell you</Label>
                <ul className="flex flex-col gap-2">
                  {proposal.proposals.map((item) => (
                    <li key={item.field} className="text-[13px] leading-relaxed">
                      <span className="font-mono text-ink">{item.field}</span>{" "}
                      <span
                        className={
                          item.confidence === "observed"
                            ? "font-mono text-[11px] text-pass"
                            : item.confidence === "inferred"
                              ? "font-mono text-[11px] text-high"
                              : "font-mono text-[11px] text-ink-3"
                        }
                      >
                        {item.confidence}
                      </span>
                      {item.value != null ? (
                        <span className="ml-1.5 font-mono text-ink-2">
                          {String(item.value)}
                        </span>
                      ) : null}
                      <p className="text-ink-3">{item.evidence}</p>
                      {item.what_would_settle_it ? (
                        <p className="text-ink-2">
                          <span className="text-ink-3">to settle it: </span>
                          {item.what_would_settle_it}
                        </p>
                      ) : null}
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="border border-accent bg-paper-2">
      <div className="flex flex-wrap items-baseline gap-x-3 border-b border-rule-soft px-3 py-2">
        <h2 className="font-mono text-[12px] font-bold uppercase tracking-[0.12em] text-ink">
          Risk profile
        </h2>
        <span className="font-mono text-[12px] text-ink-3">
          every field is submitted — clearing one un-asserts it
        </span>
      </div>

      <div className="flex flex-col gap-3 px-3 py-3">
        <Row label="Internet-facing">
          <Choice
            options={[
              { id: "yes", label: "yes" },
              { id: "no", label: "no" },
            ]}
            selected={internetFacing === null ? null : internetFacing ? "yes" : "no"}
            onSelect={(id) => setInternetFacing(id === null ? null : id === "yes")}
          />
        </Row>

        <Row label="Data classification">
          <Choice
            options={CLASSIFICATIONS.map((c) => ({ id: c, label: c }))}
            selected={classification}
            onSelect={setClassification}
          />
        </Row>

        <Row label="Business criticality">
          <Choice
            options={CRITICALITIES.map((c) => ({ id: c, label: c }))}
            selected={criticality}
            onSelect={setCriticality}
          />
        </Row>

        <Row label="Compliance scope">
          <div className="flex flex-wrap gap-1">
            {REGIMES.map((regime) => (
              <button
                key={regime}
                type="button"
                onClick={() =>
                  setScope((previous) =>
                    previous.includes(regime)
                      ? previous.filter((r) => r !== regime)
                      : [...previous, regime],
                  )
                }
                className={`border px-1.5 py-0.5 font-mono text-[11px] uppercase ${
                  scope.includes(regime)
                    ? "border-accent bg-accent-wash text-accent"
                    : "border-rule text-ink-3 hover:border-accent"
                }`}
              >
                {regime}
              </button>
            ))}
          </div>
        </Row>

        <Row label="Owner">
          <input
            type="text"
            value={owner}
            onChange={(event) => setOwner(event.target.value)}
            placeholder="a team or person — context only, never scored"
            className="w-full max-w-md border border-rule bg-paper px-1.5 py-0.5 font-mono text-[12px] text-ink placeholder:text-ink-3 focus:border-accent focus:outline-none"
          />
        </Row>

        <Row label="Notes">
          <textarea
            value={notes}
            onChange={(event) => setNotes(event.target.value)}
            rows={3}
            placeholder="why these choices — for whoever edits this next. Never scored."
            className="w-full max-w-md border border-rule bg-paper px-1.5 py-1 font-mono text-[12px] text-ink placeholder:text-ink-3 focus:border-accent focus:outline-none"
          />
        </Row>

        {error ? <p className="font-mono text-[12px] text-critical">{error}</p> : null}

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={save}
            disabled={saving}
            className={`border border-accent bg-accent-wash px-2 py-1 font-mono text-[12px] text-accent ${
              saving ? "opacity-40" : "hover:bg-accent hover:text-paper"
            }`}
          >
            {saving ? "saving…" : "save profile"}
          </button>
          <button
            type="button"
            onClick={() => setEditing(false)}
            disabled={saving}
            className="border border-rule px-2 py-1 font-mono text-[12px] text-ink-3 hover:border-critical hover:text-critical"
          >
            cancel
          </button>
        </div>
      </div>
    </div>
  );
}

function Fact({ label, value }: { label: string; value: string | null | undefined }) {
  return (
    <span className="flex items-baseline gap-1.5">
      <Label>{label}</Label>
      {value ? (
        <Pill tone="muted">{value}</Pill>
      ) : (
        <span className="text-ink-3" title="Not recorded — contributes nothing.">
          not stated
        </span>
      )}
    </span>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <Label>{label}</Label>
      {children}
    </div>
  );
}

/**
 * A radio group where re-clicking the selected option clears it — "not
 * stated" has to stay reachable, because it is a real answer (spec 21 §1)
 * and not a placeholder for one.
 */
function Choice({
  options,
  selected,
  onSelect,
}: {
  options: { id: string; label: string }[];
  selected: string | null;
  onSelect: (id: string | null) => void;
}) {
  return (
    <div className="flex flex-wrap items-center gap-1">
      {options.map((option) => (
        <button
          key={option.id}
          type="button"
          onClick={() => onSelect(selected === option.id ? null : option.id)}
          className={`border px-1.5 py-0.5 font-mono text-[11px] ${
            selected === option.id
              ? "border-accent bg-accent-wash text-accent"
              : "border-rule text-ink-3 hover:border-accent"
          }`}
        >
          {option.label}
        </button>
      ))}
      {selected === null ? (
        <span className="ml-1 font-mono text-[11px] text-ink-3">not stated</span>
      ) : null}
    </div>
  );
}

function boolWord(value: boolean | null | undefined): string | null {
  if (value === null || value === undefined) return null;
  return value ? "yes" : "no";
}
