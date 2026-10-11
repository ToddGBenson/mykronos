import Link from "next/link";
import type { ReactNode } from "react";

import {
  BackToBacklog,
  PullIntoSprint,
  RankControls,
} from "@/components/product-owner-actions";
import { TemplatePicker } from "@/components/product-owner-template";
import { EmptyState, Label, Pill, Section, StatTile } from "@/components/primitives";
import type { PoStory, ProductOwnerView } from "@/lib/api";

/**
 * The Product Owner console (spec 35, D-135): one tab, four sub-views.
 *
 * The process comes from the repository's own `.sdlc/process.yaml` (D-132) and
 * the stories from TheHub (D-133). Each repository's real gate names are shown,
 * mapped onto a shared spine (D-134). When the repository declares nothing, or
 * declares something invalid, the tab says so rather than presenting a default
 * as if it were the repository's process.
 */

export const PO_VIEWS = [
  { id: "overview", label: "Overview" },
  { id: "backlog", label: "Backlog" },
  { id: "sprint", label: "Sprint" },
  { id: "process", label: "Process" },
] as const;

export type PoViewId = (typeof PO_VIEWS)[number]["id"];

/** The manifest as the backend returns it when valid. Typed here because the
 *  API carries it as an open object: it is the repository's document, and
 *  the backend has already validated it strictly. */
type Manifest = {
  version: number;
  name: string;
  spine_map: Record<string, string>;
  gates: {
    id: string;
    name: string;
    recommends: string;
    approves: string;
    doc: string | null;
    story_gates: string[];
    checklist: { id: string; text: string; evidence: string | null }[];
  }[];
  backlog: { source: string; tag: string; include_untagged: boolean };
  delivery: { summary: string; steps: string[] } | null;
  automation_policy: { id: string; text: string; met: boolean }[];
  docs: { label: string; path: string }[];
};

const NEEDS_LABEL: Record<string, string> = {
  invalid_manifest: "manifest",
  sprint_gate_failed: "sprint check",
  ready_manual_item: "manual item",
  process_drift: "drift",
  dod_failed: "not done",
};

const SPINE_LABEL: Record<string, string> = {
  idea: "Idea",
  ready: "Ready",
  building: "Building",
  verifying: "Verifying",
  shipping: "Shipping",
  done: "Done",
};

function fileUrl(data: ProductOwnerView, path: string): string {
  // Paths are validated server-side as relative and inside the repository, so
  // this cannot become a link off GitHub. Encoded per segment regardless.
  const encoded = path.split("/").map(encodeURIComponent).join("/");
  return `https://github.com/${data.repo_full_name}/blob/${encodeURIComponent(
    data.default_branch,
  )}/${encoded}`;
}

export function ProductOwnerTab({
  repoId,
  view,
  data,
}: {
  repoId: string;
  view: PoViewId;
  data: ProductOwnerView;
}) {
  return (
    <div className="flex flex-col gap-4">
      <Header data={data} />
      <nav className="flex flex-wrap gap-1" aria-label="Product Owner views">
        {PO_VIEWS.map((entry) => (
          <Link
            key={entry.id}
            href={`/repos/${repoId}?tab=product-owner&view=${entry.id}`}
            className={`border px-2 py-0.5 font-mono text-[12px] ${
              view === entry.id
                ? "border-accent font-bold text-ink"
                : "border-rule text-ink-3 hover:text-accent"
            }`}
          >
            {entry.label}
          </Link>
        ))}
        {!data.can_write ? (
          <span className="ml-auto self-center font-mono text-[11px] text-ink-3">
            read-only: writes need the admin role
          </span>
        ) : null}
      </nav>
      {view === "backlog" ? (
        <Backlog repoId={repoId} data={data} />
      ) : view === "sprint" ? (
        <Sprint repoId={repoId} data={data} />
      ) : view === "process" ? (
        <Process repoId={repoId} data={data} />
      ) : (
        <Overview data={data} />
      )}
    </div>
  );
}

function Header({ data }: { data: ProductOwnerView }) {
  const manifest = data.manifest.manifest as Manifest | null;
  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex flex-wrap items-baseline gap-3">
        <Label as="h2">Declared process</Label>
        {data.manifest.state === "valid" && manifest ? (
          <>
            <span className="font-mono text-[13px] font-bold text-ink">{manifest.name}</span>
            <Pill tone="pass">declared</Pill>
          </>
        ) : data.manifest.state === "invalid" ? (
          <Pill tone="critical" title={data.manifest.error ?? undefined}>
            invalid manifest
          </Pill>
        ) : data.manifest.state === "unreadable" ? (
          <Pill tone="warn">unreadable</Pill>
        ) : (
          <Pill tone="muted">none declared</Pill>
        )}
        {data.manifest.url ? (
          <a
            href={data.manifest.url}
            className="font-mono text-[11px] text-ink-3 hover:text-accent"
            rel="noreferrer"
          >
            {data.manifest.path}
          </a>
        ) : (
          <span className="font-mono text-[11px] text-ink-3">{data.manifest.path}</span>
        )}
        <span className="font-mono text-[11px] text-ink-3">
          backlog: TheHub, tag {data.backlog_tag}
          {data.include_untagged ? " + untagged" : ""}
          {data.membership_source === "default" ? " (default)" : ""}
        </span>
      </div>
      {data.manifest.state === "absent" ? (
        <p className="max-w-prose text-[12px] text-ink-2">
          This repository declares no process. The spine below is a default, labelled as one,
          and stories are matched by the default tag.
        </p>
      ) : null}
      {data.manifest.state === "invalid" || data.manifest.state === "unreadable" ? (
        <p className="max-w-prose text-[12px] text-critical">{data.manifest.error}</p>
      ) : null}
      {!data.hub.connected ? (
        <p className="border border-rule bg-paper-2 px-3 py-2 text-[12px] text-ink-2">
          <strong className="text-high">TheHub is not connected.</strong>{" "}
          {data.hub.error && data.hub.error !== "TheHub is not connected." ? data.hub.error : null}{" "}
          The declared process is shown; the backlog and sprint are not.
        </p>
      ) : null}
    </div>
  );
}

function Overview({ data }: { data: ProductOwnerView }) {
  const oracle = data.oracle;
  return (
    <div className="flex flex-col gap-4">
      <Section
        title="Needs a human"
        detail={data.needs_human.length ? `${data.needs_human.length}` : "nothing waiting"}
      >
        {data.needs_human.length === 0 ? (
          <p className="px-3 py-2 text-[12px] text-ink-3">
            No sprint story fails a gate check, no Ready story has a manual item, no
            declaration is observed to have drifted, and the manifest is not invalid.
          </p>
        ) : (
          <ul className="flex flex-col">
            {data.needs_human.map((item) => (
              <li
                key={`${item.kind}-${item.story_id ?? "manifest"}`}
                className="flex flex-wrap items-baseline gap-2 border-t border-rule-soft px-3 py-1.5"
              >
                <Pill tone={item.kind === "ready_manual_item" ? "warn" : "critical"}>
                  {NEEDS_LABEL[item.kind] ?? item.kind}
                </Pill>
                {item.story_id ? (
                  <span className="font-mono text-[11px] text-ink-3">#{item.story_id}</span>
                ) : null}
                <span className="text-[13px] text-ink">{item.title}</span>
                <span className="text-[12px] text-ink-3">{item.reason}</span>
                {item.owner ? (
                  <span className="font-mono text-[11px] text-ink-2">owner: {item.owner}</span>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </Section>

      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
        {data.spine.map((step) => (
          <StatTile
            key={step}
            label={SPINE_LABEL[step] ?? step}
            value={data.counts[step] ?? 0}
            sub={data.spine_is_default ? "default spine" : undefined}
          />
        ))}
      </div>

      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        <StatTile
          label="Sprint progress"
          value={`${data.sprint_progress.done} / ${data.sprint_progress.committed}`}
          sub="done / committed"
        />
        <StatTile
          label="Risk decision"
          value={oracle?.recommendation ?? "none"}
          alert={oracle?.recommendation === "no_go"}
          sub={
            oracle
              ? `${oracle.decision_type ?? ""} · score ${oracle.overall_risk_score ?? "—"}${
                  oracle.evaluated_at ? ` · ${oracle.evaluated_at.slice(0, 10)}` : ""
                }`
              : "no decision recorded for this repository"
          }
        />
      </div>
    </div>
  );
}

function CheckBadge({ story }: { story: PoStory }) {
  const check = story.check;
  if (!check.gate_id) {
    return <span className="font-mono text-[11px] text-ink-3">no gate covers {story.gate}</span>;
  }
  const tone = check.failed > 0 ? "critical" : check.total > 0 ? "pass" : "muted";
  const extra = [
    check.manual ? `${check.manual} manual` : null,
    check.unavailable ? `${check.unavailable} not visible` : null,
  ]
    .filter(Boolean)
    .join(", ");
  const title = check.items
    .map((item) => `${item.status.toUpperCase()}: ${item.text}`)
    .join("\n");
  return (
    <span className="flex items-baseline gap-1.5">
      <Pill tone={tone} title={title}>
        {check.passed} / {check.total}
      </Pill>
      {extra ? <span className="font-mono text-[11px] text-ink-3">{extra}</span> : null}
    </span>
  );
}

/** The Definition of Done (spec 35 §7.3), only for a story at a done gate whose
 *  manifest declares one. Labelled DoD so it is never read as the gate check. */
function DodBadge({ story }: { story: PoStory }) {
  const dod = story.dod;
  if (!dod) return null;
  const tone = dod.failed > 0 ? "critical" : dod.total > 0 ? "pass" : "muted";
  const title = dod.items.map((item) => `${item.status.toUpperCase()}: ${item.text}`).join("\n");
  return (
    <Pill tone={tone} title={title}>
      DoD {dod.passed} / {dod.total}
      {dod.unavailable ? `, ${dod.unavailable} not visible` : ""}
    </Pill>
  );
}

function StoryRow({ story, children }: { story: PoStory; children?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-baseline gap-x-2.5 gap-y-1 border-t border-rule-soft px-3 py-1.5">
      <span className="font-mono text-[11px] tabular text-ink-3">#{story.id}</span>
      <span className="text-[13px] text-ink">{story.title}</span>
      <span className="font-mono text-[11px] text-ink-2">
        {story.gate_name ?? story.gate}
        {story.gate_name ? <span className="text-ink-3"> ({story.gate})</span> : null}
      </span>
      {story.size ? <span className="font-mono text-[11px] text-ink-3">{story.size}</span> : null}
      <CheckBadge story={story} />
      <DodBadge story={story} />
      {children ? <span className="ml-auto flex items-baseline gap-2">{children}</span> : null}
    </div>
  );
}

function Backlog({ repoId, data }: { repoId: string; data: ProductOwnerView }) {
  if (!data.hub.connected) return null;
  if (data.backlog.length === 0) {
    return (
      <EmptyState
        title="Nothing in the backlog"
        detail={`No TheHub backlog story carries ${data.backlog_tag}.`}
      />
    );
  }
  return (
    <Section
      title="Backlog"
      detail={`${data.backlog.length} · ranked first, then by gate and age`}
    >
      {data.backlog.map((story, index) => (
        <StoryRow key={story.id} story={story}>
          {story.rank === null ? (
            <span className="font-mono text-[11px] text-ink-3">unranked</span>
          ) : null}
          {data.can_write ? (
            <>
              <RankControls
                repoId={repoId}
                storyId={story.id}
                first={index === 0}
                last={index === data.backlog.length - 1}
              />
              <PullIntoSprint repoId={repoId} storyId={story.id} />
            </>
          ) : null}
        </StoryRow>
      ))}
    </Section>
  );
}

function Sprint({ repoId, data }: { repoId: string; data: ProductOwnerView }) {
  if (!data.hub.connected) return null;
  if (data.sprint.length === 0) {
    return (
      <EmptyState
        title="Nothing in the sprint"
        detail={`No TheHub sprint story carries ${data.backlog_tag}.`}
      />
    );
  }
  return (
    <div className="flex flex-col gap-3">
      {data.spine.map((step) => {
        const stories = data.sprint.filter((story) => story.spine === step);
        if (stories.length === 0) return null;
        return (
          <Section key={step} title={SPINE_LABEL[step] ?? step} detail={`${stories.length}`}>
            {stories.map((story) => (
              <StoryRow key={story.id} story={story}>
                {data.can_write ? <BackToBacklog repoId={repoId} storyId={story.id} /> : null}
              </StoryRow>
            ))}
          </Section>
        );
      })}
    </div>
  );
}

function Process({ repoId, data }: { repoId: string; data: ProductOwnerView }) {
  const manifest = data.manifest.manifest as Manifest | null;
  if (!manifest) {
    return (
      <Section title="Default spine" detail="not this repository's declared process">
        <p className="px-3 py-2 text-[12px] text-ink-2">
          {data.manifest.state === "invalid"
            ? "The manifest is invalid, so nothing here is shown as declared. "
            : "This repository declares no process. "}
          Stories are placed on the shared spine by TheHub gate:{" "}
          {data.spine.map((step) => SPINE_LABEL[step] ?? step).join(" · ")}.
        </p>
        {data.templates.length > 0 ? (
          data.can_write ? (
            <>
              <p className="border-t border-rule-soft px-3 py-2 text-[12px] text-ink-2">
                Start from a template. Each opens a draft pull request adding{" "}
                <span className="font-mono">{data.manifest.path}</span>; nothing is committed to{" "}
                <span className="font-mono">{data.default_branch}</span>.
              </p>
              <TemplatePicker repoId={repoId} templates={data.templates} />
            </>
          ) : (
            <p className="border-t border-rule-soft px-3 py-2 text-[12px] text-ink-3">
              An admin can open a template pull request from here.
            </p>
          )
        ) : null}
      </Section>
    );
  }
  return (
    <div className="flex flex-col gap-3">
      <Section title="Gates" detail={`${manifest.gates.length}`}>
        {manifest.gates.map((gate) => (
          <div key={gate.id} className="border-t border-rule-soft px-3 py-2">
            <div className="flex flex-wrap items-baseline gap-2.5">
              <span className="font-mono text-[12px] font-bold text-ink">{gate.id}</span>
              <span className="text-[13px] text-ink">{gate.name}</span>
              {manifest.spine_map[gate.id] ? (
                <Pill tone="muted">{SPINE_LABEL[manifest.spine_map[gate.id]]}</Pill>
              ) : null}
              <span className="font-mono text-[11px] text-ink-3">
                TheHub: {gate.story_gates.join(", ") || "—"}
              </span>
              {gate.recommends ? (
                <span className="text-[12px] text-ink-2">recommends: {gate.recommends}</span>
              ) : null}
              {gate.approves ? (
                <span className="text-[12px] text-ink-2">approves: {gate.approves}</span>
              ) : null}
              {gate.doc ? (
                <a
                  href={fileUrl(data, gate.doc)}
                  rel="noreferrer"
                  className="ml-auto font-mono text-[11px] text-ink-3 hover:text-accent"
                >
                  {gate.doc}
                </a>
              ) : null}
            </div>
            {gate.checklist.length > 0 ? (
              <ul className="mt-1 flex flex-col gap-0.5">
                {gate.checklist.map((item) => (
                  <li key={item.id} className="text-[12px] text-ink-2">
                    <span aria-hidden="true">· </span>
                    {item.text}{" "}
                    <span className="font-mono text-[11px] text-ink-3">
                      {item.evidence ? `checked: ${item.evidence}` : "manual"}
                    </span>
                  </li>
                ))}
              </ul>
            ) : null}
          </div>
        ))}
      </Section>

      <DeclaredVsObserved data={data} />

      {manifest.delivery ? <Delivery delivery={manifest.delivery} /> : null}

      {manifest.automation_policy.length > 0 ? (
        <Section title="Automation policy" detail="preconditions, as declared">
          {manifest.automation_policy.map((item) => (
            <div
              key={item.id}
              className="flex items-baseline gap-2 border-t border-rule-soft px-3 py-1.5"
            >
              <span className="font-mono text-[11px] font-bold text-ink">{item.id}</span>
              <span className="text-[12px] text-ink">{item.text}</span>
              <span className="ml-auto">
                <Pill tone={item.met ? "pass" : "warn"}>{item.met ? "met" : "not met"}</Pill>
              </span>
            </div>
          ))}
        </Section>
      ) : null}

      {manifest.docs.length > 0 ? (
        <Section title="Docs">
          <ul className="flex flex-wrap gap-3 px-3 py-2">
            {manifest.docs.map((doc) => (
              <li key={doc.path}>
                <a
                  href={fileUrl(data, doc.path)}
                  rel="noreferrer"
                  className="font-mono text-[12px] text-ink-2 hover:text-accent"
                >
                  {doc.label}
                </a>
              </li>
            ))}
          </ul>
        </Section>
      ) : null}
    </div>
  );
}

function Delivery({ delivery }: { delivery: NonNullable<Manifest["delivery"]> }) {
  return (
    <Section title="Delivery" detail={delivery.summary}>
      <ol className="flex flex-wrap gap-1.5 px-3 py-2">
        {delivery.steps.map((step, index) => (
          <li key={`${step}-${index}`} className="font-mono text-[12px] text-ink-2">
            {index + 1}. {step}
            {index < delivery.steps.length - 1 ? " →" : ""}
          </li>
        ))}
      </ol>
    </Section>
  );
}

const OBSERVATION_TONE = {
  consistent: "pass",
  drift: "critical",
  unobserved: "muted",
} as const;

/** Each declaration beside what the platform observes (spec 35 §7.1). Declared
 *  and observed are separate columns: one word for both would hide which side
 *  said what. */
function DeclaredVsObserved({ data }: { data: ProductOwnerView }) {
  if (data.observations.length === 0) return null;
  const drift = data.observations.filter((o) => o.status === "drift").length;
  return (
    <Section
      title="Declared vs observed"
      detail={drift ? `${drift} drift` : "no drift observed"}
    >
      {data.observations.map((o) => (
        <div
          key={o.id}
          className="flex flex-wrap items-baseline gap-x-2.5 gap-y-1 border-t border-rule-soft px-3 py-1.5"
        >
          <Pill
            tone={OBSERVATION_TONE[o.status as keyof typeof OBSERVATION_TONE] ?? "muted"}
          >
            {o.status}
          </Pill>
          <span className="text-[13px] text-ink">{o.subject}</span>
          <span className="font-mono text-[11px] text-ink-2">declared: {o.declared}</span>
          <span className="font-mono text-[11px] text-ink-2">observed: {o.observed}</span>
          <span className="font-mono text-[11px] text-ink-3">owner: {o.owner}</span>
          {o.detail ? <span className="w-full text-[12px] text-ink-3">{o.detail}</span> : null}
        </div>
      ))}
    </Section>
  );
}
