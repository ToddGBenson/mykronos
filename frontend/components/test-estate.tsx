import { Label, Pill, Section } from "@/components/primitives";
import type { components } from "@/lib/api-types";

type Estate = components["schemas"]["TestEstateOut"];
type Kind = components["schemas"]["TestKindOut"];
type Lane = components["schemas"]["TestLaneOut"];

/**
 * Coverage in the three states it actually has.
 *
 * `never_reported` is the one that matters and the one a percentage would
 * destroy: 227 unit runs with no coverage document is not 0%, and showing a
 * zero would be a fabricated measurement of a real suite. It renders as a
 * sentence rather than a figure so nobody can read it as one.
 */
function Coverage({ lane }: { lane: Lane }) {
  if (lane.coverage_state === "reported" && lane.line_coverage !== null) {
    return (
      <span className="tabular font-mono text-[12px] text-ink">
        {Math.round(lane.line_coverage * 100)}% lines
      </span>
    );
  }
  if (lane.coverage_state === "never_reported") {
    return (
      <span
        className="font-mono text-[12px] text-ink-3"
        title="Not zero percent. The suite ran and no coverage document was written, so nothing measured it."
      >
        never measured
      </span>
    );
  }
  return <span className="font-mono text-[12px] text-ink-3">&mdash;</span>;
}

function LaneRow({ lane }: { lane: Lane }) {
  const rate = lane.runs > 0 ? Math.round((lane.succeeded / lane.runs) * 100) : null;
  return (
    <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1 border-t border-rule-soft px-3 py-2">
      <span className="font-mono text-[12px] font-bold uppercase tracking-[0.08em] text-ink">
        {lane.capability}
      </span>
      {lane.runs === 0 ? (
        // Said, not left blank. A repository with no tests and one this
        // platform was never pointed at are different problems.
        <span className="text-[12px] text-ink-3">
          {lane.enabled
            ? "enabled, and has never run here"
            : "not enabled for this repository"}
        </span>
      ) : (
        <>
          <span className="tabular font-mono text-[12px] text-ink-2">
            {lane.succeeded}/{lane.runs} runs green
            {rate !== null ? ` (${rate}%)` : ""}
          </span>
          {lane.failed > 0 ? (
            <span className="tabular font-mono text-[12px] text-high">
              {lane.failed} failed
            </span>
          ) : null}
          <span className="ml-auto flex items-baseline gap-2">
            <Coverage lane={lane} />
            {lane.last_run_at ? (
              <span className="font-mono text-[11px] text-ink-3">
                last {lane.last_run_at.slice(0, 10)}
              </span>
            ) : null}
          </span>
        </>
      )}
    </div>
  );
}

function KindRow({ kind }: { kind: Kind }) {
  const observed = kind.presence === "observed";
  return (
    <div className="border-t border-rule-soft px-3 py-2.5">
      <div className="flex flex-wrap items-baseline gap-x-2.5 gap-y-1">
        <span className="text-[13px] font-semibold text-ink">{kind.name}</span>
        <span className="text-[12px] text-ink-3">{kind.why}</span>
        <span className="ml-auto">
          <Pill
            tone={observed ? "pass" : "muted"}
            title={observed ? "The platform watched this happen" : "Nothing here produces this"}
          >
            {observed ? "Evidenced" : "Nothing"}
          </Pill>
        </span>
      </div>

      {kind.evidence.length > 0 ? (
        <ul className="mt-1 flex flex-col gap-0.5">
          {kind.evidence.map((line) => (
            <li key={line} className="text-[12px] text-pass">
              <span aria-hidden="true">✓ </span>
              {line}
            </li>
          ))}
        </ul>
      ) : (
        <p className="mt-1 max-w-prose text-[12px] text-ink-2">
          <span className="text-ink-3">To evidence it: </span>
          {kind.how_to_evidence}
        </p>
      )}
    </div>
  );
}

/**
 * What testing exists here, and what kinds of it do not.
 *
 * Sits above the run buttons because it is the question they are part of:
 * "run the unit suite" is only reassuring once you know whether a unit suite
 * is the only kind of testing this repository has.
 *
 * The absent kinds are listed by name, which is the whole point — a view that
 * shows only the testing a repository does can never tell anybody what it is
 * missing, and no number replaces that. There is deliberately no test-maturity
 * score: the kinds are not equally applicable, so a library would lose points
 * for correctly having no post-deploy smoke test.
 */
export function TestEstate({ data }: { data: Estate }) {
  const observed = data.kinds.filter((k) => k.presence === "observed");
  const absent = data.kinds.filter((k) => k.presence === "absent");

  return (
    <div className="flex flex-col gap-4">
      <Section
        title="Test lanes"
        detail="runs, pass rate and coverage"
        aside={
          <span className="font-mono text-[12px] text-ink-3">
            {observed.length} of {data.kinds.length} kinds evidenced
          </span>
        }
      >
        {data.lanes.map((lane) => (
          <LaneRow key={lane.capability} lane={lane} />
        ))}
      </Section>

      {observed.length > 0 ? (
        <Section title="Kinds of testing evidenced here">
          {observed.map((kind) => (
            <KindRow key={kind.key} kind={kind} />
          ))}
        </Section>
      ) : null}

      {absent.length > 0 ? (
        <Section
          title="Kinds of testing nothing here does"
          detail="named rather than omitted"
        >
          {absent.map((kind) => (
            <KindRow key={kind.key} kind={kind} />
          ))}
        </Section>
      ) : null}

      <div className="border border-rule bg-paper-2 px-3 py-2.5">
        <Label>How to read this</Label>
        <p className="mt-1 max-w-prose text-[12px] text-ink-2">{data.note}</p>
      </div>
    </div>
  );
}
