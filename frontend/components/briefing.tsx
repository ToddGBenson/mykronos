/**
 * The morning briefing (TheHub #60864): what the 07:00 Slack DM links to.
 *
 * One rule from the approved prototype runs through it: every line says what
 * changed, so what, and whether it is a merge, a decision or a story. So the
 * lines of each section are grouped by that work, and a section that could
 * not be read says so with its reason rather than rendering empty, which
 * would read as "all clear".
 *
 * Presentational and synchronous, so it renders the same on the server and in
 * a test. `app/briefing/page.tsx` does the fetching.
 */

import Link from "next/link";

import { PrintButton } from "@/components/print-button";
import { Pill } from "@/components/primitives";
import {
  WORK_LABEL,
  briefingHref,
  groupByWork,
  refLink,
  repoHref,
  statusMeta,
  workCounts,
  type BriefingLine,
  type BriefingProduct,
  type BriefingSection,
  type DailyBriefing,
} from "@/lib/briefing";

function Stamp({ value }: { value: string | null }) {
  // Absolute and UTC: the page is printed and read later, and a relative
  // "4m ago" on paper is wrong by the time anyone reads it.
  if (!value) return <span>not read</span>;
  const iso = value.endsWith("Z") ? value : `${value}Z`;
  return <time dateTime={iso}>{iso.slice(0, 16).replace("T", " ")} UTC</time>;
}

function LineRow({
  line,
  repoIds,
}: {
  line: BriefingLine;
  repoIds: Record<string, string>;
}) {
  const link = refLink(line.ref, line.repo_full_name, repoIds);
  const repo = repoHref(line.repo_full_name, repoIds);
  return (
    <li className="border-t border-rule-soft px-3 py-2" data-work={line.work}>
      <p className="text-[13px] text-ink">{line.what}</p>
      <p className="mt-0.5 max-w-prose text-[12px] text-ink-2">{line.so_what}</p>
      <p className="mt-1 flex flex-wrap gap-x-3 font-mono text-[11px] text-ink-3">
        {line.repo_full_name ? (
          repo ? (
            <Link href={repo} className="hover:text-accent">
              {line.repo_full_name}
            </Link>
          ) : (
            <span>{line.repo_full_name}</span>
          )
        ) : null}
        {link ? (
          link.external ? (
            <a href={link.href} target="_blank" rel="noreferrer" className="hover:text-accent">
              {link.label} ↗
            </a>
          ) : (
            <Link href={link.href} className="hover:text-accent">
              {link.label}
            </Link>
          )
        ) : line.ref ? (
          <span>{line.ref}</span>
        ) : null}
      </p>
    </li>
  );
}

export function BriefingSectionCard({
  section,
  repoIds,
}: {
  section: BriefingSection;
  repoIds: Record<string, string>;
}) {
  const meta = statusMeta(section.status);
  const groups = groupByWork(section.lines);
  return (
    <section
      className="ticks border border-rule bg-paper-2"
      data-section={section.key}
      data-status={section.status}
      data-print-keep
    >
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1 border-b border-rule-soft px-3 py-2">
        <h2 className="font-mono text-[12px] font-bold uppercase tracking-[0.12em] text-ink">
          {section.title}
        </h2>
        <span className="ml-auto">
          <Pill tone={meta.tone} title={meta.meaning}>
            {meta.word}
          </Pill>
        </span>
      </div>
      <p className="flex flex-wrap gap-x-4 px-3 pt-2 font-mono text-[11px] text-ink-3">
        <span>source: {section.source}</span>
        <span>
          as of: <Stamp value={section.as_of} />
        </span>
      </p>
      {section.status !== "ok" && section.reason ? (
        <p className="mx-3 mt-2 border-l-2 border-high px-2 text-[12px] text-ink-2" role="note">
          {section.reason}
        </p>
      ) : null}
      {groups.length > 0 ? (
        groups.map((group) => (
          <div key={group.work} className="mt-2" data-group={group.work}>
            <h3 className="px-3 font-mono text-[11px] font-bold uppercase tracking-[0.1em] text-ink-3">
              {WORK_LABEL[group.work]} · {group.lines.length}
            </h3>
            <ul>
              {group.lines.map((line, index) => (
                <LineRow key={`${line.what}-${index}`} line={line} repoIds={repoIds} />
              ))}
            </ul>
          </div>
        ))
      ) : (
        <p className="px-3 py-2 text-[12px] text-ink-3">
          {section.status === "ok"
            ? "Nothing here needs you."
            : section.status === "partial"
              ? "Nothing found in what could be read."
              : "Nothing shown, because nothing was read."}
        </p>
      )}
      <div className="h-2" />
    </section>
  );
}

function ProductSwitcher({
  products,
  selected,
}: {
  products: BriefingProduct[];
  selected: string | null;
}) {
  const options: { repoId: string | null; label: string }[] = [
    { repoId: null, label: "Overall" },
    ...products.map((product) => ({ repoId: product.repoId, label: product.repoFullName })),
  ];
  return (
    <nav aria-label="Briefing scope" className="flex flex-wrap gap-1 print:hidden">
      {options.map((option) => {
        const active = option.repoId === selected;
        return (
          <Link
            key={option.repoId ?? "overall"}
            href={briefingHref(option.repoId)}
            aria-current={active ? "page" : undefined}
            className={`border px-2 py-1 font-mono text-[12px] ${
              active
                ? "border-accent bg-accent-wash text-accent"
                : "border-rule text-ink-2 hover:border-accent hover:text-accent"
            }`}
          >
            {option.label}
          </Link>
        );
      })}
    </nav>
  );
}

export function BriefingView({
  briefing,
  products,
  selectedRepoId,
}: {
  briefing: DailyBriefing;
  products: BriefingProduct[];
  selectedRepoId: string | null;
}) {
  const repoIds = Object.fromEntries(
    products.map((product) => [product.repoFullName, product.repoId]),
  );
  const counts = workCounts(briefing.sections);
  const unread = briefing.sections.filter(
    (section) => section.status === "unavailable" || section.status === "not_available",
  );
  const heading =
    briefing.scope === "product" && briefing.repo_full_name
      ? `Briefing: ${briefing.repo_full_name}`
      : "Morning briefing";

  return (
    <article data-print-report className="flex flex-col gap-4">
      <header className="flex flex-col gap-2">
        <div className="flex flex-wrap items-baseline gap-3">
          <h1 className="text-lg font-bold tracking-tight">{heading}</h1>
          <span className="font-mono text-[12px] text-ink-3">
            generated <Stamp value={briefing.generated_at} />
          </span>
          <span className="ml-auto">
            <PrintButton />
          </span>
        </div>
        <p className="max-w-prose text-[13px] text-ink-2" data-summary>
          Needs you: {counts.merge} merge{counts.merge === 1 ? "" : "s"}, {counts.decision}{" "}
          decision{counts.decision === 1 ? "" : "s"}, {counts.story}{" "}
          {counts.story === 1 ? "story" : "stories"}.
          {unread.length > 0
            ? ` Not read: ${unread.map((section) => section.title).join(", ")}.`
            : ""}
        </p>
        <ProductSwitcher products={products} selected={selectedRepoId} />
      </header>
      {briefing.sections.map((section) => (
        <BriefingSectionCard key={section.key} section={section} repoIds={repoIds} />
      ))}
    </article>
  );
}
