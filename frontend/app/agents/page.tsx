import Link from "next/link";

import { AgentCountdown } from "@/components/agent-countdown";
import { EmptyState, ErrorPanel, Pill, Section } from "@/components/primitives";
import { RevokeCredential } from "@/components/revoke-credential";
import {
  agreementNote,
  credentialNote,
  credentialState,
  delegationScope,
  delegationState,
  descendants,
  isDefaultTtl,
  orderCredentials,
  ttlHours,
  type AgentCredential,
  type CredentialState,
  type DelegationRow,
  type DelegationState,
} from "@/lib/agents";
import {
  getAgentCredentials,
  getDelegationStats,
  getDelegations,
  getSampleQueue,
  type DelegationStats,
  type SampleRow,
  type Result,
} from "@/lib/server-agents";

export const dynamic = "force-dynamic";

/**
 * Agents and delegations (TheHub #61144, spec 34 §5.2).
 *
 * Three questions, in the order they go wrong: which agent credentials are
 * live and when each lapses (the 12-hour default is flagged, because a run
 * that outlives it fails with a 401 that looks like a stale token); what each
 * standing delegation lets an agent decide without you; and which of those
 * decisions were sampled for you to check after the fact.
 *
 * Read-only except for revoking a credential, which is a person's act. The
 * sampling queue is listed here and decided where approvals are decided.
 */
export default async function AgentsPage() {
  const [credentials, delegations, samples] = await Promise.all([
    getAgentCredentials(),
    getDelegations(),
    getSampleQueue(),
  ]);

  const standing = delegations.ok
    ? delegations.data.filter((d) => delegationState(d) !== "revoked" && delegationState(d) !== "expired")
    : [];
  const stats = new Map<string, Result<DelegationStats>>(
    await Promise.all(
      standing.map(async (d) => [d.id, await getDelegationStats(d.id)] as const),
    ),
  );

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-baseline gap-3">
        <h1 className="text-xl font-bold tracking-tight">Agents</h1>
        <span className="font-mono text-[13px] text-ink-3">
          credentials, delegations and the sampling queue
        </span>
      </div>

      <Credentials result={credentials} />
      <Delegations result={delegations} stats={stats} />
      <Samples result={samples} />
    </div>
  );
}

const CREDENTIAL_PILL: Record<CredentialState, { tone: "pass" | "muted" | "critical"; word: string }> = {
  active: { tone: "pass", word: "live" },
  expired: { tone: "muted", word: "lapsed" },
  revoked: { tone: "critical", word: "revoked" },
};

function lifetime(c: AgentCredential): string {
  const hours = ttlHours(c);
  return hours >= 48 ? `${Math.round(hours / 24)}d lifetime` : `${Math.round(hours)}h lifetime`;
}

function CredentialRow({ c, all }: { c: AgentCredential; all: AgentCredential[] }) {
  const state = credentialState(c);
  const note = credentialNote(c);
  const pill = CREDENTIAL_PILL[state];
  return (
    <li className="flex flex-col gap-1 border-b border-rule-soft px-3 py-2.5 last:border-b-0">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <Pill tone={pill.tone}>{pill.word}</Pill>
        <span className="font-mono text-[13px] font-bold">{c.actor}</span>
        {c.purpose ? <span className="font-mono text-[12px] text-ink-2">{c.purpose}</span> : null}
        <span className="ml-auto flex flex-wrap items-center gap-3">
          {state === "revoked" ? null : <AgentCountdown expiresAt={c.expires_at} />}
          {state === "active" ? (
            <RevokeCredential instance={c.instance} descendants={descendants(c.instance, all).length} />
          ) : null}
        </span>
      </div>
      <div className="flex flex-wrap gap-x-4 gap-y-0.5 font-mono text-[12px] text-ink-3">
        <span className={isDefaultTtl(c) && state !== "revoked" ? "font-bold text-high" : ""}>
          {lifetime(c)}
          {isDefaultTtl(c) ? " (default)" : ""}
        </span>
        <span>for {c.on_behalf_of}</span>
        <span>minted by {c.minted_by}</span>
        {c.lineage.length > 0 ? <span>sub-agent of {c.lineage[c.lineage.length - 1]}</span> : null}
      </div>
      {note ? <p className="max-w-prose text-[13px] leading-relaxed text-ink-2">{note}</p> : null}
    </li>
  );
}

function Credentials({ result }: { result: Result<AgentCredential[]> }) {
  if (!result.ok) return <ErrorPanel title="Agent credentials unavailable" detail={result.error} />;
  const { live, ended, endedHidden } = orderCredentials(result.data);
  const onDefault = live.filter(isDefaultTtl).length;
  return (
    <>
      <Section
        title="Live credentials"
        detail={
          live.length === 0
            ? "none"
            : `${live.length} live${onDefault ? ` · ${onDefault} on the 12-hour default` : ""} · soonest to lapse first`
        }
      >
        {live.length === 0 ? (
          <EmptyState
            title="No live agent credentials"
            detail="Every agent that acts on the platform needs its own credential (spec 34). None is live, so any agent running now is either idle or using the operator's token."
          />
        ) : (
          <ul>
            {live.map((c) => (
              <CredentialRow key={c.instance} c={c} all={result.data} />
            ))}
          </ul>
        )}
      </Section>
      {ended.length > 0 ? (
        <Section
          title="Recently ended"
          detail={`${ended.length} most recent${endedHidden ? ` · ${endedHidden} older not shown` : ""}`}
        >
          <ul>
            {ended.map((c) => (
              <CredentialRow key={c.instance} c={c} all={result.data} />
            ))}
          </ul>
        </Section>
      ) : null}
    </>
  );
}

const DELEGATION_PILL: Record<DelegationState, { tone: "pass" | "muted" | "critical" | "warn"; word: string }> = {
  active: { tone: "pass", word: "active" },
  suspended: { tone: "warn", word: "suspended" },
  expired: { tone: "muted", word: "expired" },
  revoked: { tone: "critical", word: "revoked" },
};

function DelegationItem({ d, stats }: { d: DelegationRow; stats?: Result<DelegationStats> }) {
  const state = delegationState(d);
  const pill = DELEGATION_PILL[state];
  return (
    <li className="flex flex-col gap-1 border-b border-rule-soft px-3 py-2.5 last:border-b-0">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <Pill tone={pill.tone}>{pill.word}</Pill>
        <span className="text-[14px]">{delegationScope(d)}</span>
        {state === "revoked" ? null : (
          <span className="ml-auto">
            <AgentCountdown expiresAt={d.expires_at} />
          </span>
        )}
      </div>
      <div className="flex flex-wrap gap-x-4 gap-y-0.5 font-mono text-[12px] text-ink-3">
        <span>granted by {d.granted_by}</span>
        <span>
          by request{" "}
          <Link className="text-accent underline" href={`/product-owner/review-queue/${encodeURIComponent(d.grant_request_id)}`}>
            {d.grant_request_id}
          </Link>
        </span>
        <span>{d.id}</span>
      </div>
      {d.suspended_reason ? (
        <p className="max-w-prose text-[13px] text-high">Suspended: {d.suspended_reason}</p>
      ) : null}
      {stats?.ok ? (
        <p className="max-w-prose text-[13px] leading-relaxed text-ink-2">
          {stats.data.decisions} decision{stats.data.decisions === 1 ? "" : "s"} so far
          {Object.keys(stats.data.by_verdict).length
            ? ` (${Object.entries(stats.data.by_verdict)
                .map(([v, n]) => `${n} ${v}`)
                .join(", ")})`
            : ""}
          . {stats.data.sample_queue} sampled and waiting for you. {agreementNote(stats.data.agreement)}
        </p>
      ) : stats ? (
        <p className="font-mono text-[12px] text-ink-3">Track record unavailable: {stats.error}</p>
      ) : null}
    </li>
  );
}

function Delegations({
  result,
  stats,
}: {
  result: Result<DelegationRow[]>;
  stats: Map<string, Result<DelegationStats>>;
}) {
  if (!result.ok) return <ErrorPanel title="Delegations unavailable" detail={result.error} />;
  const standing = result.data.filter((d) => stats.has(d.id));
  const ended = result.data.filter((d) => !stats.has(d.id)).slice(0, 10);
  return (
    <Section
      title="Delegations"
      detail={`${standing.length} standing · what an agent may decide without you`}
    >
      {result.data.length === 0 ? (
        <EmptyState
          title="No delegations"
          detail="Every agent decision still needs a person. A delegation is proposed as a delegation_grant request and exists only once a person approves it."
        />
      ) : (
        <ul>
          {standing.map((d) => (
            <DelegationItem key={d.id} d={d} stats={stats.get(d.id)} />
          ))}
          {ended.map((d) => (
            <DelegationItem key={d.id} d={d} />
          ))}
        </ul>
      )}
    </Section>
  );
}

function Samples({ result }: { result: Result<SampleRow[]> }) {
  if (!result.ok) return <ErrorPanel title="Sampling queue unavailable" detail={result.error} />;
  return (
    <Section
      title="Sampling queue"
      detail={`${result.data.length} delegated decision${result.data.length === 1 ? "" : "s"} waiting for your after-the-fact check · oldest first`}
    >
      {result.data.length === 0 ? (
        <EmptyState
          title="Nothing to check"
          detail="No sampled agent decision is waiting. Each one you review moves its delegation's agreement rate."
        />
      ) : (
        <ul>
          {result.data.map((s) => (
            <li key={s.decision_id} className="flex flex-col gap-1 border-b border-rule-soft px-3 py-2.5 last:border-b-0">
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                <Pill tone={s.verdict === "approve" ? "pass" : s.verdict === "reject" ? "critical" : "muted"}>
                  {s.verdict}
                </Pill>
                <span className="font-mono text-[13px]">
                  {s.duty.replace(/_/g, " ")} · {s.tier}
                </span>
                <span className="font-mono text-[13px] font-bold">{s.subject_ref}</span>
                <span className="ml-auto font-mono text-[12px] text-ink-3">
                  {s.approver}
                  {s.family ? ` (${s.family})` : ""}
                </span>
              </div>
              {s.rationale ? (
                <p className="max-w-prose text-[13px] leading-relaxed text-ink-2">
                  <span className="text-ink-3">Agent&apos;s rationale, a claim: </span>
                  {s.rationale}
                </p>
              ) : null}
            </li>
          ))}
        </ul>
      )}
    </Section>
  );
}
