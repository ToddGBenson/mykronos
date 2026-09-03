"use client";

/**
 * Pin the test that would fail if this came back (spec 31 §2).
 *
 * **Why this control exists at all.** Nothing this platform has ever fixed is
 * protected from coming back silently: 0 of 519 fixed findings on this estate
 * have a test pinned. A fix that closes a finding and leaves no test behind is
 * a fix that will be made again.
 *
 * The two words the result uses are not interchangeable, and the platform is
 * careful about which it claims. `demonstrated` means the platform watched the
 * test fail against the vulnerable code and pass against the fixed code.
 * `asserted` means somebody said so. One is evidence; the other is somebody's
 * word, and a control that blurred them would make the coverage number
 * worthless.
 */

import { useState } from "react";

import type { paths } from "@/lib/api-types";

type LinkResult =
  paths["/api/dashboard/findings/{finding_id}/regression-test"]["post"]["responses"]["200"]["content"]["application/json"];

const LANES = ["unit", "functional", "qa"] as const;

export function PinRegressionTest({ findingId }: { findingId: string }) {
  const [open, setOpen] = useState(false);
  const [identifier, setIdentifier] = useState("");
  const [capability, setCapability] = useState<(typeof LANES)[number]>("unit");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<LinkResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      const response = await fetch(`/api/findings/${findingId}/regression-test`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ test_identifier: identifier.trim(), capability }),
      });
      const body = await response.json().catch(() => null);
      if (!response.ok) {
        setError(
          typeof body?.detail === "string"
            ? body.detail
            : `The link was rejected (HTTP ${response.status}).`,
        );
        return;
      }
      setResult(body as LinkResult);
      setOpen(false);
    } catch {
      setError("Could not reach Mykronos.");
    } finally {
      setBusy(false);
    }
  }

  if (result) {
    return (
      <div className="border border-pass bg-pass-wash px-3 py-2 text-[13px] leading-relaxed">
        <span className="font-mono text-[12px] text-pass">test pinned</span>{" "}
        <span className="font-mono">{result.test_identifier}</span>
        <p className="mt-1 text-ink-2">
          Recorded as <span className="font-mono">{result.evidence}</span>. If this
          finding comes back, that test is what fails.
        </p>
      </div>
    );
  }

  if (!open) {
    return (
      <div className="flex flex-col gap-1">
        <button
          type="button"
          onClick={() => setOpen(true)}
          className="tap w-fit border border-rule px-2 py-1 font-mono text-[12px] text-ink-2 hover:border-accent hover:text-accent"
        >
          pin a regression test
        </button>
        {error ? <p className="text-[13px] text-critical">{error}</p> : null}
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-2 border border-rule bg-paper px-3 py-2.5">
      <label className="flex flex-col gap-1">
        <span className="font-mono text-[11px] uppercase tracking-[0.12em] text-ink-3">
          Test identifier
        </span>
        <input
          value={identifier}
          onChange={(event) => setIdentifier(event.target.value)}
          placeholder="tests.test_auth.TestLogin.test_rejects_expired_token"
          className="w-full border border-rule bg-paper-2 px-2 py-1 font-mono text-[12px]"
        />
      </label>
      <p className="text-[12px] leading-relaxed text-ink-3">
        A JUnit <span className="font-mono">classname.name</span>, exactly as the
        runner reports it — this is matched against what the lane uploads, so a
        name that does not appear there links to nothing.
      </p>

      <label className="flex items-center gap-2">
        <span className="font-mono text-[11px] uppercase tracking-[0.12em] text-ink-3">
          Lane
        </span>
        <select
          value={capability}
          onChange={(event) =>
            setCapability(event.target.value as (typeof LANES)[number])
          }
          className="border border-rule bg-paper-2 px-2 py-1 font-mono text-[12px]"
        >
          {LANES.map((lane) => (
            <option key={lane} value={lane}>
              {lane}
            </option>
          ))}
        </select>
      </label>

      {error ? <p className="text-[13px] text-critical">{error}</p> : null}

      <div className="flex gap-2">
        <button
          type="button"
          disabled={busy || !identifier.trim()}
          onClick={submit}
          className="tap border border-accent bg-accent-wash px-2 py-1 font-mono text-[12px] text-accent disabled:opacity-50"
        >
          {busy ? "pinning…" : "pin it"}
        </button>
        <button
          type="button"
          onClick={() => setOpen(false)}
          className="tap border border-rule px-2 py-1 font-mono text-[12px] text-ink-3 hover:border-accent"
        >
          cancel
        </button>
      </div>
    </div>
  );
}
