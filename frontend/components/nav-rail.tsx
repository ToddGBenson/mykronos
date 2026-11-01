"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";

import { NAV } from "@/lib/nav";
import { activeHref } from "@/lib/nav-active";

/**
 * The nav rail, with "you are here" (TheHub #61135, P5).
 *
 * A client component only because the current path is a client fact; the
 * entries themselves stay pure data in `lib/nav.ts`. The current page gets
 * `aria-current="page"` and the accent bar, so a screen reader and a glance
 * get the same answer. Every link is at least 44px tall, and the group labels
 * are `ink-3` at full strength: the `opacity-70` they used to carry took them
 * below AA (P10).
 *
 * On a phone the rail folds behind a Menu button, which names the current
 * page; at full height it filled the first screen. From `md` up it is always
 * open. The open state is kept per path, so following a link closes it.
 */
export function NavRail() {
  const pathname = usePathname() ?? "/";
  const items = NAV.flatMap((group) => group.items);
  const current = activeHref(
    pathname,
    items.map((item) => item.href),
  );
  const currentLabel = items.find((item) => item.href === current)?.label;
  const [openFor, setOpenFor] = useState<string | null>(null);
  const open = openFor === pathname;

  return (
    <nav
      data-chrome
      aria-label="Sections"
      className="shrink-0 border-b border-rule bg-paper-2 md:w-48 md:border-b-0 md:border-r md:py-2"
    >
      <button
        type="button"
        aria-expanded={open}
        aria-controls="nav-sections"
        onClick={() => setOpenFor(open ? null : pathname)}
        className="flex min-h-11 w-full items-center justify-between gap-2 px-3 font-mono text-[13px] text-ink md:hidden"
      >
        <span>
          {open ? "Close menu" : "Menu"}
          {currentLabel ? <span className="text-ink-3">{` · ${currentLabel}`}</span> : null}
        </span>
        <span aria-hidden>{open ? "×" : "≡"}</span>
      </button>
      <div id="nav-sections" className={`${open ? "block" : "hidden"} pb-2 md:block md:pb-0`}>
        {NAV.map((group) => (
          <div key={group.section} className="mb-2">
            <p className="px-3 pb-1 pt-2 font-mono text-[11px] uppercase tracking-[0.13em] text-ink-3">
              {group.section}
            </p>
            {group.items.map((item) => {
              const here = item.href === current;
              return (
                <Link
                  key={item.label}
                  href={item.href}
                  aria-current={here ? "page" : undefined}
                  className={`flex min-h-11 items-center border-l-[3px] px-3 py-1.5 font-mono text-[13px] hover:bg-paper-3 ${
                    here
                      ? "border-accent bg-paper-3 font-semibold text-ink"
                      : "border-transparent text-ink-2 hover:border-accent"
                  }`}
                >
                  {item.label}
                </Link>
              );
            })}
          </div>
        ))}
      </div>
    </nav>
  );
}
