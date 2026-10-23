/**
 * The weekly intelligence page (TheHub #60865, B7): one Monday page per
 * application. Every item says what, so what, the action, a confidence with
 * its reason, and its source; a section that could not be read, or has no
 * feed, says so with its reason rather than rendering empty.
 *
 * Presentational and synchronous. `app/briefing/weekly/page.tsx` fetches.
 */

import Link from "next/link";

import { Pill } from "@/components/primitives";
import { statusMeta } from "@/lib/briefing";
import {
  CONFIDENCE_WORD,
  flashes,
  newThisWeek,
  sourceLink,
  weeklyHref,
  type WeeklyBriefing,
  type WeeklyItem,
  type WeeklyPage,
  type WeeklySection,
} from "@/lib/weekly-briefing";

function ItemRow({ item }: { item: WeeklyItem }) {
  const link = sourceLink(item.source);
  return (
    <li
      className="border-t border-rule-soft px-3 py-2"
      data-item={item.key}
      data-flash={item.flash ? "true" : undefined}
    >
      <p className="flex flex-wrap items-baseline gap-x-2 text-[13px] text-ink">
        {item.flash ? (
          <Pill tone="critical" title={item.flash_reason}>
            Flash
          </Pill>
        ) : null}
        {item.new_this_week ? <Pill tone="warn">New</Pill> : null}
        <span>{item.what}</span>
      </p>
      <p className="mt-0.5 max-w-prose text-[12px] text-ink-2">{item.so_what}</p>
      <p className="mt-0.5 max-w-prose text-[12px] text-ink">{item.action}</p>
      <p className="mt-1 flex flex-wrap gap-x-3 font-mono text-[11px] text-ink-3">
        <span>
          {CONFIDENCE_WORD[item.confidence]}: {item.confidence_reason}
        </span>
        {link ? (
          link.external ? (
            <a href={link.href} target="_blank" rel="noreferrer" className="hover:text-accent">
              source ↗
            </a>
          ) : (
            <Link href={link.href} className="hover:text-accent">
              source
            </Link>
          )
        ) : (
          <span>{item.source}</span>
        )}
      </p>
    </li>
  );
}

function SectionCard({ section }: { section: WeeklySection }) {
  const meta = statusMeta(section.status);
  const items = section.items ?? [];
  return (
    <section
      className="ticks border border-rule bg-paper-2"
      data-section={section.key}
      data-status={section.status}
    >
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1 border-b border-rule-soft px-3 py-2">
        <h3 className="font-mono text-[12px] font-bold uppercase tracking-[0.12em] text-ink">
          {section.title}
        </h3>
        <span className="ml-auto">
          <Pill tone={meta.tone} title={meta.meaning}>
            {meta.word}
          </Pill>
        </span>
      </div>
      <p className="px-3 pt-2 font-mono text-[11px] text-ink-3">source: {section.source}</p>
      {section.status !== "ok" && section.reason ? (
        <p className="mx-3 mt-2 border-l-2 border-high px-2 text-[12px] text-ink-2" role="note">
          {section.reason}
        </p>
      ) : null}
      {items.length > 0 ? (
        <ul className="mt-2">
          {items.map((item) => (
            <ItemRow key={item.key || item.what} item={item} />
          ))}
        </ul>
      ) : (
        <p className="px-3 py-2 text-[12px] text-ink-3">
          {section.status === "ok" || section.status === "partial"
            ? "Nothing found in what could be read."
            : "Nothing shown, because nothing was read."}
        </p>
      )}
      <div className="h-2" />
    </section>
  );
}

function PageBlock({ page }: { page: WeeklyPage }) {
  const flashCount = flashes(page).length;
  return (
    <article className="flex flex-col gap-3" data-page={page.repo_id}>
      <header className="flex flex-wrap items-baseline gap-x-3">
        <h2 className="text-[16px] font-bold text-ink">{page.repo_full_name}</h2>
        <span className="font-mono text-[11px] text-ink-3">
          week of {page.week_of} · {newThisWeek(page)} new · {flashCount} flash
        </span>
        <Link
          href={weeklyHref(page.repo_id)}
          className="ml-auto font-mono text-[11px] text-ink-3 hover:text-accent print:hidden"
        >
          this application only
        </Link>
      </header>
      {page.sections.map((section) => (
        <SectionCard key={section.key} section={section} />
      ))}
    </article>
  );
}

export function WeeklyBriefingView({ briefing }: { briefing: WeeklyBriefing }) {
  return (
    <div className="flex flex-col gap-6">
      <header>
        <h1 className="text-[20px] font-bold text-ink">Weekly intelligence</h1>
        <p className="mt-1 max-w-prose text-[13px] text-ink-2">
          Week of {briefing.week_of}. What the outside world knows this week that matters to what
          each application ships. A flash is known exploited or critical, and shipped; it is also
          sent as a same-day DM.
        </p>
        <p className="mt-1 font-mono text-[11px] text-ink-3">
          <Link href="/briefing" className="hover:text-accent">
            daily briefing
          </Link>
          {" · "}
          <Link href={weeklyHref(null)} className="hover:text-accent">
            every application
          </Link>
        </p>
      </header>
      {briefing.pages.length === 0 ? (
        <p className="text-[13px] text-ink-2">No application is onboarded.</p>
      ) : (
        briefing.pages.map((page) => <PageBlock key={page.repo_id} page={page} />)
      )}
    </div>
  );
}
