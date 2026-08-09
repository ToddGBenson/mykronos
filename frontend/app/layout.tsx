import type { Metadata } from "next";
import Link from "next/link";

import "./globals.css";

export const metadata: Metadata = {
  title: "Mykronos",
  description:
    "Unified AppSec onboarding, scanning, risk-decision and dashboard platform.",
};

/**
 * The nav rail.
 *
 * It used to show unbuilt views disabled, labelled with the phase that would
 * deliver them — hiding them would have made the shipped slice look like the
 * whole design, and "where is the risk score?" deserved an answer rather than
 * a blank. As of Phase 7 there is nothing left to label, so the branch that
 * rendered those is gone rather than kept warm for a case that no longer
 * arises.
 */
const NAV: {
  section: string;
  items: { label: string; href: string }[];
}[] = [
  {
    section: "Views",
    items: [
      { label: "Portfolio", href: "/" },
      { label: "Triage queue", href: "/triage" },
      { label: "Decisions", href: "/decisions" },
      { label: "Remediation", href: "/triage" },
      { label: "Trends", href: "/trends" },
      { label: "Retros", href: "/retro" },
    ],
  },
  {
    section: "Manage",
    items: [
      { label: "Repositories", href: "/" },
      { label: "Oracle policy", href: "/decisions#policy" },
      { label: "Knowledge", href: "/retro" },
    ],
  },
];

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen antialiased">
        <div className="flex min-h-screen flex-col">
          <header className="flex flex-wrap items-center gap-4 border-b border-rule bg-paper-2 px-4 py-2.5">
            <Link href="/" className="font-mono text-xs font-bold tracking-[0.14em]">
              MYKRONOS
            </Link>
            <span className="font-mono text-[10px] text-ink-3">
              AppSec control plane
            </span>
            <span className="ml-auto border border-rule px-2 py-0.5 font-mono text-[9px] uppercase tracking-[0.1em] text-ink-3">
              Phase 7 · admin
            </span>
          </header>

          <div className="flex flex-1 flex-col md:flex-row">
            <nav
              aria-label="Sections"
              className="shrink-0 border-b border-rule bg-paper-2 py-2 md:w-44 md:border-b-0 md:border-r"
            >
              {NAV.map((group) => (
                <div key={group.section} className="mb-2">
                  <p className="px-3 pb-1 pt-2 font-mono text-[9px] uppercase tracking-[0.13em] text-ink-3 opacity-70">
                    {group.section}
                  </p>
                  {group.items.map((item) => (
                    <Link
                      key={item.label}
                      href={item.href}
                      className="block border-l-2 border-transparent px-3 py-1.5 font-mono text-[11px] text-ink-2 hover:border-accent hover:bg-paper-3"
                    >
                      {item.label}
                    </Link>
                  ))}
                </div>
              ))}
            </nav>

            <main className="min-w-0 flex-1 p-4 md:p-6">{children}</main>
          </div>
        </div>
      </body>
    </html>
  );
}
