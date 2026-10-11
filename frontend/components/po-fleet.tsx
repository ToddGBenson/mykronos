import { FailureLine, Windows } from "@/components/po-console";
import { EmptyState, Pill, Section, StatTile } from "@/components/primitives";
import type { PoFleet } from "@/lib/po-console";

/**
 * What the agents did for this repository (spec 35 §8.6, D-140): autonomy
 * runs, verification verdicts, cost, and the RACI owner of every gate failure.
 * A dry run is labelled as one and never counted as shipped. With TheHub not
 * connected the view says so, rather than showing zeros that would read as
 * "the agents did nothing".
 */

function money(value: number | null | undefined): string {
  return value === null || value === undefined ? "—" : `$${value.toFixed(2)}`;
}

export function FleetView({ repoId, data }: { repoId: string; data: PoFleet }) {
  if (!data.hub.connected || data.outcomes === null) {
    return (
      <EmptyState
        title="TheHub is not connected"
        detail={
          data.hub.error && data.hub.error !== "TheHub is not connected."
            ? data.hub.error
            : "Autonomy runs, verdicts and cost live in TheHub, so none are shown."
        }
      />
    );
  }
  const outcomes = data.outcomes;
  const aborted = Object.entries(outcomes).filter(
    ([key]) => key !== "shipped" && key !== "dry_run",
  );
  const estate = data.estate;
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-baseline gap-3">
        <span className="font-mono text-[12px] text-ink-2">
          {data.stories_read} stor{data.stories_read === 1 ? "y" : "ies"} read · last{" "}
          {data.days} days
        </span>
        <Windows repoId={repoId} view="fleet" days={data.days} options={[1, 7, 30, 90]} />
      </div>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        <StatTile label="Shipped" value={outcomes.shipped ?? 0} sub="live runs only" />
        <StatTile label="Dry runs" value={outcomes.dry_run ?? 0} sub="never counted as shipped" />
        <StatTile
          label="Stopped"
          value={aborted.reduce((sum, [, count]) => sum + count, 0)}
          sub={aborted.map(([key, count]) => `${key} ${count}`).join(" · ") || "none"}
          alert={aborted.length > 0}
        />
        <StatTile label="Model cost" value={money(data.cost_usd)} sub="runs in the window" />
      </div>

      {estate ? (
        <p className="text-[12px] text-ink-2">
          Estate:{" "}
          {estate.kill_switch_active ? (
            <Pill tone="critical">kill switch on</Pill>
          ) : (
            <Pill tone="muted">kill switch off</Pill>
          )}{" "}
          {estate.dry_run_default ? "dry run by default" : "live by default"} · today{" "}
          {money(estate.daily_cost_used_usd)} of {money(estate.daily_cost_cap_usd)}
          {estate.in_flight.length
            ? ` · in flight here: ${estate.in_flight.map((r) => `#${r.story_id}`).join(", ")}`
            : " · nothing in flight here"}
        </p>
      ) : (
        <p className="text-[12px] text-high">
          TheHub&rsquo;s autonomy dashboard could not be read: {data.estate_error}
        </p>
      )}

      <Section
        title="Gate failures"
        detail={`${data.failures.length} · each names its RACI owner`}
      >
        {data.failures.length === 0 ? (
          <p className="px-3 py-2 text-[12px] text-ink-3">No gate failure recorded in the window.</p>
        ) : (
          data.failures.map((failure, index) => (
            <div
              key={`${failure.story_id}-${failure.kind}-${index}`}
              className="flex flex-wrap items-baseline gap-x-2.5 gap-y-1 border-t border-rule-soft px-3 py-1.5"
            >
              <FailureLine failure={failure} />
            </div>
          ))
        )}
      </Section>

      <Section title="Autonomy runs" detail={`${data.runs.length}`}>
        {data.runs.length === 0 ? (
          <p className="px-3 py-2 text-[12px] text-ink-3">No run started in the window.</p>
        ) : (
          data.runs.map((run) => (
            <div
              key={`${run.story_id}-${run.run_id}`}
              className="flex flex-wrap items-baseline gap-x-2.5 border-t border-rule-soft px-3 py-1.5"
            >
              <span className="font-mono text-[11px] tabular text-ink-3">#{run.story_id}</span>
              <span className="text-[13px] text-ink">{run.title}</span>
              {run.dry_run ? (
                <Pill
                  tone="muted"
                  title={
                    run.status_as_written && run.status_as_written !== run.status
                      ? `Written as '${run.status_as_written}'; corrected on read.`
                      : undefined
                  }
                >
                  dry run
                </Pill>
              ) : (
                <Pill tone={run.shipped ? "pass" : "warn"}>{run.status ?? "unknown"}</Pill>
              )}
              <span className="ml-auto font-mono text-[11px] text-ink-3">
                {money(run.cost_usd)} · {run.started_at?.slice(0, 10) ?? "—"}
              </span>
            </div>
          ))
        )}
      </Section>

      <Section title="Verification verdicts" detail={`${data.verdicts.length}`}>
        {data.verdicts.length === 0 ? (
          <p className="px-3 py-2 text-[12px] text-ink-3">
            No story read here has been handed to verification.
          </p>
        ) : (
          data.verdicts.map((verdict) => (
            <div
              key={verdict.story_id}
              className="flex flex-wrap items-baseline gap-x-2.5 border-t border-rule-soft px-3 py-1.5"
            >
              <span className="font-mono text-[11px] tabular text-ink-3">
                #{verdict.story_id}
              </span>
              <Pill
                tone={
                  verdict.status === "approved"
                    ? "pass"
                    : verdict.status === "rejected"
                      ? "critical"
                      : "muted"
                }
              >
                {verdict.status}
              </Pill>
              <span className="font-mono text-[11px] text-ink-2">
                built by {verdict.implementer_agent ?? "?"}, checked by{" "}
                {verdict.verifier_agent ?? "nobody yet"}
              </span>
              {verdict.reason ? (
                <span className="text-[12px] text-ink-2">{verdict.reason}</span>
              ) : null}
            </div>
          ))
        )}
      </Section>

      {data.unread.length || data.not_read ? (
        <p className="text-[11px] text-high">
          {data.unread.length
            ? `${data.unread.length} story read(s) failed and are not counted. `
            : ""}
          {data.not_read ? `${data.not_read} more stories were not read (cap).` : ""}
        </p>
      ) : null}
    </div>
  );
}
