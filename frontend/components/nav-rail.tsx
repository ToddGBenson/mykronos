"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

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
 */
export function NavRail() {
  const pathname = usePathname() ?? "/";
  const current = activeHref(
    pathname,
    NAV.flatMap((group) => group.items.map((item) => item.href)),
  );

  return (
    <nav
      data-chrome
      aria-label="Sections"
      className="shrink-0 border-b border-rule bg-paper-2 py-2 md:w-48 md:border-b-0 md:border-r"
    >
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
    </nav>
  );
}
