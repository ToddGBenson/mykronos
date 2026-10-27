"use client";

import { useState, useTransition } from "react";

import { Label, Pill } from "@/components/primitives";
import type { LibraryRequest } from "@/lib/api";

const ECOSYSTEMS = ["npm", "pypi", "golang", "maven", "cargo", "nuget"];
const POLICIES = ["minimum", "same_major", "exact", "any"];

/**
 * The library request form (TheHub #60895). Posts through the Next server's
 * proxy and shows the vetting report the backend returns: each check with its
 * status and source, and the tier that decides who may approve it.
 */
export function LibraryRequestForm({
  initial,
}: {
  initial: { ecosystem: string; name: string; version: string };
}) {
  const [ecosystem, setEcosystem] = useState(initial.ecosystem);
  const [name, setName] = useState(initial.name);
  const [version, setVersion] = useState(initial.version);
  const [reason, setReason] = useState("");
  const [owner, setOwner] = useState("");
  const [policy, setPolicy] = useState("minimum");
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<LibraryRequest | null>(null);
  const [pending, startTransition] = useTransition();

  function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    startTransition(async () => {
      const response = await fetch("/api/libraries/requests", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ecosystem,
          package_name: name,
          version,
          reason,
          owner,
          version_policy: policy,
        }),
      });
      const body = (await response.json()) as LibraryRequest & { detail?: unknown };
      if (!response.ok) {
        setError(typeof body.detail === "string" ? body.detail : "The request was refused.");
        return;
      }
      setResult(body);
    });
  }

  const field = "border border-rule bg-paper-2 px-2 py-1 font-mono text-[13px]";

  return (
    <div className="flex flex-col gap-4">
      <form onSubmit={submit} className="grid max-w-2xl grid-cols-1 gap-3 sm:grid-cols-2">
        <label className="flex flex-col gap-1">
          <Label>Ecosystem</Label>
          <select
            className={field}
            value={ecosystem}
            onChange={(e) => setEcosystem(e.target.value)}
          >
            {ECOSYSTEMS.map((eco) => (
              <option key={eco} value={eco}>
                {eco}
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1">
          <Label>Package</Label>
          <input
            className={field}
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
          />
        </label>
        <label className="flex flex-col gap-1">
          <Label>Version</Label>
          <input
            className={field}
            value={version}
            onChange={(e) => setVersion(e.target.value)}
            required
          />
        </label>
        <label className="flex flex-col gap-1">
          <Label>Version policy</Label>
          <select className={field} value={policy} onChange={(e) => setPolicy(e.target.value)}>
            {POLICIES.map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1 sm:col-span-2">
          <Label>Owner</Label>
          <input className={field} value={owner} onChange={(e) => setOwner(e.target.value)} />
        </label>
        <label className="flex flex-col gap-1 sm:col-span-2">
          <Label>Why this library, and why not one we already use</Label>
          <textarea
            className={`${field} min-h-24`}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            minLength={20}
            required
          />
        </label>
        <div className="sm:col-span-2">
          <button
            type="submit"
            disabled={pending}
            className="border border-accent px-3 py-1 font-mono text-[13px] text-accent hover:bg-paper-3 disabled:opacity-50"
          >
            {pending ? "Vetting…" : "Request and vet"}
          </button>
        </div>
      </form>

      {error ? <p className="text-[14px] text-critical">{error}</p> : null}

      {result ? (
        <section className="flex flex-col gap-2 border border-rule bg-paper-2 p-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono">
              {result.ecosystem} {result.package_name}@{result.version}
            </span>
            <Pill tone={result.tier === "clean" ? "pass" : "warn"}>{result.tier}</Pill>
            <span className="text-[13px] text-ink-3">
              {result.tier === "clean" ? "awaiting approval" : "awaiting approval by a person"}
            </span>
          </div>
          <VettingChecks vetting={result.vetting} />
        </section>
      ) : null}
    </div>
  );
}

type Check = { status?: string; source?: string };

/** Each vetting check with its status and source; flags first. */
export function VettingChecks({ vetting }: { vetting: Record<string, unknown> }) {
  const checks = (vetting.checks ?? {}) as Record<string, Check>;
  const flags = (vetting.flags ?? []) as string[];
  return (
    <div className="flex flex-col gap-1 text-[13px]">
      {flags.length ? (
        <div className="flex flex-wrap gap-1">
          {flags.map((flag) => (
            <Pill key={flag} tone="warn">
              {flag.replaceAll("_", " ")}
            </Pill>
          ))}
        </div>
      ) : null}
      <ul className="flex flex-col gap-0.5">
        {Object.entries(checks).map(([name, check]) => (
          <li key={name} className="flex flex-wrap gap-2">
            <span className="w-28 font-mono text-ink-3">{name}</span>
            <span className={check.status === "ok" ? "text-ink-2" : "text-high"}>
              {check.status}
            </span>
            {check.source ? (
              <span className="break-all font-mono text-[11px] text-ink-3">{check.source}</span>
            ) : null}
          </li>
        ))}
      </ul>
    </div>
  );
}
