import type { Metadata } from "next";
import Link from "next/link";

import "./globals.css";

export const metadata: Metadata = {
  title: "Mykronos",
  description:
    "Unified AppSec onboarding, scanning, risk-decision and dashboard platform.",
};

/**
 * The nav rail lists the whole product, not just what is built.
 *
 * Unbuilt views are shown disabled with the phase that delivers them, rather
 * than hidden. Hiding them would make the shipped slice look like the whole
 * design; labelling them makes the roadmap legible to anyone reading the
 * dashboard, and stops "where is the risk score?" being a mystery.
 */
const NAV: {
  section: string;
  items: { label: string; href?: string; phase?: string }[];
}[] = [
  {
    section: "Views",
    items: [
      { label: "Portfolio", href: "/" },
      { label: "Decisions", phase: "Phase 3" },
      { label: "Remediation", phase: "Phase 6" },
      { label: "Trends", phase: "Phase 7" },
      { label: "Retros", phase: "Phase 7" },
    ],
  },
  {
    section: "Manage",
    items: [
      { label: "Repositories", href: "/" },
      { label: "Oracle policy", phase: "Phase 3" },
      { label: "Knowledge", phase: "Phase 5" },
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
              Phase 2 · admin
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
                  {group.items.map((item) =>
                    item.href ? (
                      <Link
                        key={item.label}
                        href={item.href}
                        className="block border-l-2 border-transparent px-3 py-1.5 font-mono text-[11px] text-ink-2 hover:border-accent hover:bg-paper-3"
                      >
                        {item.label}
                      </Link>
                    ) : (
                      <span
                        key={item.label}
                        className="flex items-baseline justify-between px-3 py-1.5 font-mono text-[11px] text-ink-3 opacity-50"
                        title={`Arrives in ${item.phase}`}
                      >
                        {item.label}
                        <span className="text-[8px] tracking-wider">{item.phase}</span>
                      </span>
                    ),
                  )}
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
