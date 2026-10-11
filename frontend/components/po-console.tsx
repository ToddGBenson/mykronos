import Link from "next/link";

import { DecideApproval } from "@/components/po-approval-decide";
import { EmptyState, Pill, Section, StatTile } from "@/components/primitives";
import type {
  PoDelivery,
  PoDeliveryRow,
  PoGateFailure,
  PoInbox,
  PoRetro,
  PoRoles,
} from "@/lib/po-console";

/**
 * The Product Owner console's phase 2 views (spec 35 §8). Each renders one
 * read endpoint. Absent evidence is shown as absent: "not recorded", "unread",
 * "TheHub is not connected", never a zero or a blank that reads as "clean".
 */

function short(sha: string): string {
  return sha.slice(0, 10);
}

function day(value: string | null | undefined): string {
  return value ? value.slice(0, 10) : "—";
}

function Windows({
  repoId,
  view,
  days,
  options,
}: {
  repoId: string;
  view: string;
  days: number;
  options: number[];
}) {
  return (
    <span className="flex items-baseline gap-1 font-mono text-[11px]">
      {options.map((option) => (
        <Link
          key={option}
          href={`/repos/${repoId}?tab=product-owner&view=${view}&days=${option}`}
          className={option === days ? "font-bold text-ink" : "text-ink-3 hover:text-accent"}
        >
          {option}d
        </Link>
      ))}
    </span>
  );
}

// --------------------------------------------------------------------------
// Delivery (§8.1)
// --------------------------------------------------------------------------

function DeliveryRow({ data, row }: { data: PoDelivery; row: PoDeliveryRow }) {
  const decision = row.decision;
  return (
    <div className="flex flex-wrap items-baseline gap-x-2.5 gap-y-1 border-t border-rule-soft px-3 py-1.5">
      <a
        href={row.commit_url}
        rel="noreferrer"
        className="font-mono text-[12px] text-ink hover:text-accent"
      >
        {short(row.sha)}
      </a>
      {row.pr_numbers.map((pr) => (
        <a
          key={pr}
          href={`https://github.com/${data.repo_full_name}/pull/${pr}`}
          rel="noreferrer"
          className="font-mono text-[11px] text-ink-2 hover:text-accent"
        >
          #{pr}
        </a>
      ))}
      <span className="font-mono text-[11px] text-ink-3">
        {row.scans.length} scan{row.scans.length === 1 ? "" : "s"}
        {row.scan_failures ? `, ${row.scan_failures} not successful` : ""}
      </span>
      {decision ? (
        <Pill
          tone={
            decision.recommendation === "no_go"
              ? "critical"
              : decision.recommendation === "go"
                ? "pass"
                : "warn"
          }
          title={`${decision.decision_type ?? ""} · score ${decision.score ?? "—"}${
            decision.human_override ? ` · overridden: ${decision.human_override}` : ""
          }`}
        >
          {decision.recommendation ?? "no recommendation"}
        </Pill>
      ) : (
        <span className="font-mono text-[11px] text-ink-3">no Oracle decision</span>
      )}
      {decision?.gate_outcome ? (
        <span className="font-mono text-[11px] text-ink-3">{decision.gate_outcome}</span>
      ) : null}
      <span className="ml-auto flex items-baseline gap-2">
        {row.deployed === "running" ? (
          <Pill tone="pass">running</Pill>
        ) : (
          <span
            className="font-mono text-[11px] text-ink-3"
            title="MyKronos records only the running revision, so it cannot say whether this commit was ever deployed."
          >
            deploy not recorded
          </span>
        )}
        <span className="font-mono text-[11px] text-ink-3">{day(row.last_seen)}</span>
      </span>
    </div>
  );
}

export function DeliveryView({
  repoId,
  data,
}: {
  repoId: string;
  data: PoDelivery;
}) {
  const probe = data.deployment;
  return (
    <div className="flex flex-col gap-3">
      <p className="max-w-prose text-[12px] text-ink-2">
        Running revision:{" "}
        {probe.running_revision ? (
          <span className="font-mono">{short(probe.running_revision)}</span>
        ) : (
          "not known"
        )}{" "}
        <span className="font-mono text-[11px] text-ink-3">
          (probe {probe.probe_status}
          {probe.observed_at ? `, ${day(probe.observed_at)}` : ""})
        </span>
        . Only the running revision is recorded, so other commits say &ldquo;deploy not
        recorded&rdquo;, not &ldquo;not deployed&rdquo;.
      </p>
      {data.error ? <p className="text-[12px] text-critical">{data.error}</p> : null}
      <Section
        title="Shipped"
        detail={`${data.shipped.length} · last ${data.days} days`}
        aside={<Windows repoId={repoId} view="delivery" days={data.days} options={[7, 30, 90]} />}
      >
        {data.shipped.length === 0 ? (
          <p className="px-3 py-2 text-[12px] text-ink-3">
            No commit was scanned on {data.default_branch} or merged in this window.
          </p>
        ) : (
          data.shipped.map((row) => <DeliveryRow key={row.sha} data={data} row={row} />)
        )}
      </Section>
      {data.not_shipped.length > 0 ? (
        <Section title="Not on the default branch yet" detail={`${data.not_shipped.length}`}>
          {data.not_shipped.map((row) => (
            <DeliveryRow key={row.sha} data={data} row={row} />
          ))}
        </Section>
      ) : null}
    </div>
  );
}

// --------------------------------------------------------------------------
// Approvals inbox (§8.2)
// --------------------------------------------------------------------------

export function ApprovalsView({ repoId, data }: { repoId: string; data: PoInbox }) {
  return (
    <div className="flex flex-col gap-3">
      <p className="max-w-prose text-[12px] text-ink-2">
        Decisions made here go to the spec 34 approvals engine, which applies every
        independence rule for the request&rsquo;s tier. When it refuses, its reason is shown
        as it wrote it.
        {data.estate_wide_pending
          ? ` ${data.estate_wide_pending} pending request(s) name no repository and are decided in the approvals API, not here.`
          : ""}
      </p>
      {data.pending.length === 0 ? (
        <EmptyState
          title="Nothing waiting"
          detail={`No pending approval request names ${data.repo_full_name}.`}
        />
      ) : (
        data.pending.map((item) => (
          <Section
            key={item.id}
            title={`${item.duty} · ${item.tier}`}
            detail={item.summary || item.subject_ref}
            aside={
              item.overdue ? (
                <Pill tone="critical">expired</Pill>
              ) : (
                <span className="font-mono text-[11px] text-ink-3">
                  expires {day(item.expires_at)}
                </span>
              )
            }
          >
            <div className="flex flex-col gap-1 px-3 py-2 text-[12px] text-ink-2">
              <span>
                Requested by <span className="font-mono">{item.requested_by}</span> (
                {item.requester_kind}) on {day(item.created_at)}.
              </span>
              {item.requester_statement ? (
                <span>
                  <span className="font-mono text-[11px] text-ink-3">
                    requester&rsquo;s claim, not evidence:
                  </span>{" "}
                  {item.requester_statement}
                </span>
              ) : null}
              {item.needs ? (
                <span className="font-mono text-[11px] text-ink-3">
                  approvers:{" "}
                  {item.needs.approvers
                    .map((a) => `${a.kind}${a.delegation_required ? " (delegated)" : ""}`)
                    .join(", ")}{" "}
                  · quorum {item.needs.quorum} · independence:{" "}
                  {item.needs.independence.join(", ") || "—"}
                  {item.needs.cooling_off_hours
                    ? ` · cooling-off ${item.needs.cooling_off_hours}h`
                    : ""}
                </span>
              ) : (
                <span className="font-mono text-[11px] text-critical">
                  The approval policy no longer has this duty or tier.
                </span>
              )}
              {item.decisions.map((decision, index) => (
                <span key={index} className="text-[12px]">
                  <Pill tone={decision.verdict === "approve" ? "pass" : "warn"}>
                    {decision.verdict}
                  </Pill>{" "}
                  <span className="font-mono">{decision.approver}</span> ({decision.approver_kind}
                  ): {decision.rationale}
                </span>
              ))}
            </div>
            {data.can_decide ? (
              <DecideApproval repoId={repoId} requestId={item.id} digest={item.evidence_digest} />
            ) : (
              <p className="border-t border-rule-soft px-3 py-1.5 font-mono text-[11px] text-ink-3">
                read-only: deciding needs the admin role
              </p>
            )}
          </Section>
        ))
      )}
    </div>
  );
}

// --------------------------------------------------------------------------
// Roles & agents (§8.3)
// --------------------------------------------------------------------------

const AGENT_NOW: Record<string, { tone: "pass" | "warn" | "muted"; word: string }> = {
  yes: { tone: "pass", word: "agent may approve" },
  no_active_delegation: { tone: "warn", word: "agent only under a delegation: none active" },
  humans_only: { tone: "muted", word: "humans only" },
};

export function RolesView({ data }: { data: PoRoles }) {
  return (
    <div className="flex flex-col gap-3">
      <Section title="Declared in the manifest" detail="free text: nothing enforces these">
        {data.declared.length === 0 ? (
          <p className="px-3 py-2 text-[12px] text-ink-3">
            {data.manifest_state === "valid"
              ? "The manifest declares no gates."
              : "This repository declares no valid process, so no gate names a recommender or approver."}
          </p>
        ) : (
          data.declared.map((gate) => (
            <div
              key={gate.id}
              className="flex flex-wrap items-baseline gap-x-2.5 border-t border-rule-soft px-3 py-1.5"
            >
              <span className="font-mono text-[12px] font-bold text-ink">{gate.id}</span>
              <span className="text-[13px] text-ink">{gate.name}</span>
              <span className="text-[12px] text-ink-2">
                recommends: {gate.recommends || "not declared"}
              </span>
              <span className="text-[12px] text-ink-2">
                approves: {gate.approves || "not declared"}
              </span>
            </div>
          ))
        )}
      </Section>
      <Section
        title="Enforced by the platform"
        detail={
          data.error ??
          `approval policy ${data.policy_version ?? "?"}${
            data.single_operator ? " · single operator" : ""
          } · ${data.active_delegations} active delegation(s)`
        }
      >
        {data.enforced.map((tier) => {
          const now = AGENT_NOW[tier.agent_now] ?? AGENT_NOW.humans_only;
          return (
            <div
              key={`${tier.duty}-${tier.tier}`}
              className="flex flex-wrap items-baseline gap-x-2.5 gap-y-1 border-t border-rule-soft px-3 py-1.5"
            >
              <span className="font-mono text-[12px] text-ink">
                {tier.duty} · {tier.tier}
              </span>
              <span className="font-mono text-[11px] text-ink-3">
                {tier.approvers.join(" or ")} · quorum {tier.quorum} ·{" "}
                {tier.independence.join(", ")}
                {tier.cooling_off_hours ? ` · cooling-off ${tier.cooling_off_hours}h` : ""}
              </span>
              <span className="ml-auto flex items-baseline gap-2">
                <Pill tone={now.tone}>{now.word}</Pill>
                {tier.delegations.map((d) => (
                  <span key={d.id} className="font-mono text-[11px] text-ink-3">
                    {d.families.join(", ")} until {day(d.expires_at)}
                  </span>
                ))}
              </span>
            </div>
          );
        })}
      </Section>
    </div>
  );
}

// --------------------------------------------------------------------------
// Retro (§8.4)
// --------------------------------------------------------------------------

const FAILURE_WORD: Record<string, string> = {
  verification_rejected: "verification rejected",
  run_aborted: "autonomy run aborted",
  deploy_failed: "deploy failed",
  gate_check_failed: "gate check failed",
};

export function FailureLine({ failure }: { failure: PoGateFailure }) {
  return (
    <>
      <span className="font-mono text-[11px] tabular text-ink-3">#{failure.story_id}</span>
      <Pill tone="critical">{FAILURE_WORD[failure.kind] ?? failure.kind}</Pill>
      <span className="font-mono text-[11px] text-ink-2">
        at {failure.gate_name ? `${failure.gate_name} (${failure.hub_gate})` : failure.hub_gate}
      </span>
      <span className="text-[12px] text-ink-2">{failure.detail}</span>
    </>
  );
}

export function RetroView({ repoId, data }: { repoId: string; data: PoRetro }) {
  if (!data.hub.connected) {
    return (
      <EmptyState
        title="TheHub is not connected"
        detail={
          data.hub.error && data.hub.error !== "TheHub is not connected."
            ? data.hub.error
            : "The retro is computed from TheHub's record of closed stories, so there is nothing to compute it from."
        }
      />
    );
  }
  return (
    <div className="flex flex-col gap-3">
      <Section
        title="Retrospective"
        detail={`computed from TheHub · last ${data.days} days`}
        aside={<Windows repoId={repoId} view="retro" days={data.days} options={[7, 14, 30]} />}
      >
        <ul className="flex flex-col gap-0.5 px-3 py-2">
          {data.summary.map((line) => (
            <li key={line} className="text-[13px] text-ink">
              {line}
            </li>
          ))}
        </ul>
        <p className="border-t border-rule-soft px-3 py-1.5 text-[11px] text-ink-3">
          {data.limitation}
        </p>
      </Section>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        <StatTile label="Closed" value={data.closed ?? "—"} />
        <StatTile
          label="Failed a gate"
          value={data.failed_stories ?? "—"}
          alert={(data.failed_stories ?? 0) > 0}
        />
        <StatTile
          label="Median cycle"
          value={data.median_cycle_days ?? "—"}
          sub="days, created to closed"
        />
        <StatTile label="Dry runs" value={data.dry_runs ?? "—"} sub="never counted as shipped" />
      </div>
      <Section title="Gates failed on the way" detail={`${data.failures.length}`}>
        {data.failures.length === 0 ? (
          <p className="px-3 py-2 text-[12px] text-ink-3">
            No closed story has a recorded gate failure
            {data.unread.length ? `, and ${data.unread.length} could not be read` : ""}.
          </p>
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
      {data.stories.length > 0 ? (
        <Section title="Closed" detail={`${data.stories.length}`}>
          {data.stories.map((story) => (
            <div
              key={story.id}
              className="flex flex-wrap items-baseline gap-x-2.5 border-t border-rule-soft px-3 py-1.5"
            >
              <span className="font-mono text-[11px] tabular text-ink-3">#{story.id}</span>
              <span className="text-[13px] text-ink">{story.title}</span>
              {story.size ? (
                <span className="font-mono text-[11px] text-ink-3">{story.size}</span>
              ) : null}
              {story.unread.length ? (
                <Pill tone="warn" title={`Could not read: ${story.unread.join(", ")}`}>
                  unread
                </Pill>
              ) : null}
              <span className="ml-auto font-mono text-[11px] text-ink-3">
                {day(story.closed_at)}
              </span>
            </div>
          ))}
        </Section>
      ) : null}
    </div>
  );
}
