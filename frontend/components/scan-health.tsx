/**
 * Scan health as one box per check (spec 10 §2.2).
 *
 * The table this replaces made you read seven columns per row to answer one
 * question — is this check working? The box leads with the answer: what
 * fraction of this capability's runs succeeded, with the counts underneath so
 * the percentage can be checked rather than believed.
 *
 * A box is drawn for every *enabled* capability, not only for the ones with
 * run history. A lane that was switched on and has never run is precisely the
 * gap that shows up nowhere else: the repository believes it is covered, and
 * no failing run disagrees, because there is no run.
 */

import Link from "next/link";

import { CAPABILITY_META, Label, RelativeTime } from "@/components/primitives";
import type { ScanHealth } from "@/lib/api";
import { checkHref, scanRunHref } from "@/lib/checks";

type Row = ScanHealth["capabilities"][number];

/** Aegis assesses pull requests and writes no ScanRun (spec 06 §3). Looking
 *  for it here reports a permanent failure for a capability that is working,
 *  which is the kind of false alarm that teaches people to ignore a panel. */
const NO_SCAN_RUNS = new Set(["aegis", "oracle", "patchwork"]);

function tone(row: Row | undefined, capability: string) {
  if (!row || row.runs === 0) {
    return NO_SCAN_RUNS.has(capability)
      ? { border: "border-rule", text: "text-ink-3" }
      : { border: "border-high", text: "text-high" };
  }
  const success = row.succeeded / row.runs;
  if (success >= 0.9) return { border: "border-pass", text: "text-pass" };
  if (success >= 0.7) return { border: "border-high", text: "text-high" };
  return { border: "border-critical", text: "text-critical" };
}

export function ScanHealthBoxes({
  repoId,
  capabilities,
  health,
}: {
  /** Links each box to its latest run (TheHub #60761) and to its run
   *  history (TheHub #60819). */
  repoId: string;
  /** Everything enabled for this repo, plus anything that has reported. */
  capabilities: string[];
  health: Row[];
}) {
  const byCapability = new Map(health.map((row) => [row.capability, row]));

  if (capabilities.length === 0) {
    return (
      <p className="px-3 py-3 text-[13px] text-ink-3">
        No checks are enabled for this repository yet, so there is nothing to
        report on. Enable one above and its box appears here.
      </p>
    );
  }

  return (
    <div className="grid grid-cols-2 gap-px bg-rule-soft sm:grid-cols-3 lg:grid-cols-5">
      {capabilities.map((capability) => {
        const row = byCapability.get(capability);
        const meta = CAPABILITY_META[capability as keyof typeof CAPABILITY_META];
        const colours = tone(row, capability);
        const success = row && row.runs ? row.succeeded / row.runs : null;

        return (
          <div
            key={capability}
            className={`flex flex-col gap-1 border-l-2 bg-paper-2 p-2.5 ${colours.border}`}
          >
            <span className="flex items-baseline gap-1.5">
              <span aria-hidden>{meta?.icon ?? "•"}</span>
              {/* The check itself opens its run history (TheHub #60819). */}
              <Link
                href={checkHref(repoId, capability)}
                className="hover:text-accent"
                title={`${capability}: every run, newest first`}
              >
                <Label>{capability}</Label>
              </Link>
              {row?.flaky ? (
                <span
                  className="border border-high bg-high-wash px-1 font-mono text-[10px] uppercase tracking-[0.08em] text-high"
                  title="Same commit, disagreeing status on the last two runs — a flake, not a regression."
                >
                  flaky
                </span>
              ) : null}
            </span>

            <Link
              href={checkHref(repoId, capability)}
              className={`tabular text-2xl font-bold leading-none tracking-tight hover:underline ${colours.text}`}
            >
              {success === null ? "—" : `${Math.round(success * 100)}%`}
            </Link>

            <span className="font-mono text-[11px] leading-relaxed text-ink-3">
              {row && row.runs > 0 ? (
                <>
                  {row.succeeded} of {row.runs} runs succeeded
                  {row.failed ? ` · ${row.failed} failed` : ""}
                  {row.no_applicable_targets
                    ? ` · ${row.no_applicable_targets} had nothing to scan`
                    : ""}
                  <br />
                  {row.last_run_at ? (
                    <>
                      last <RelativeTime value={row.last_run_at} />
                    </>
                  ) : (
                    "never run"
                  )}
                  {row.last_scan_run_id ? (
                    <>
                      {" · "}
                      <Link className="underline" href={scanRunHref(repoId, row.last_scan_run_id)}>
                        open run
                      </Link>
                    </>
                  ) : null}
                  {" · "}
                  <Link className="underline" href={checkHref(repoId, capability)}>
                    history
                  </Link>
                  {/* The most recent run's own message (spec 19 §1.2) — a
                      failed lane says why, not just that. */}
                  {row.detail ? (
                    <>
                      <br />
                      <span className="text-ink-2">{row.detail}</span>
                    </>
                  ) : null}
                </>
              ) : NO_SCAN_RUNS.has(capability) ? (
                "records no scan runs by design"
              ) : (
                "enabled, no run has ever reported"
              )}
            </span>
          </div>
        );
      })}
    </div>
  );
}
