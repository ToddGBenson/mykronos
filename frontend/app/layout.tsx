import type { Metadata } from "next";
import { headers } from "next/headers";
import { IBM_Plex_Mono, IBM_Plex_Sans } from "next/font/google";
import Link from "next/link";

import { Feedback } from "@/components/feedback";
import { ThemeToggle } from "@/components/theme-toggle";

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
      // Incident lookup lives here too: "what does the outside world think
      // matters" and "is it here" are two views of one question, and a KEV row
      // is exactly where the second one gets asked.
      { label: "Threat intelligence", href: "/threat-intel" },
      // Beside threat intelligence, not under a repository: the question it
      // answers is estate-wide by construction — how many distinct libraries
      // are we maintaining, and which are we carrying at several versions.
      { label: "Libraries", href: "/libraries" },
      // Beside the triage queue, not the portfolio: the queue is what to do
      // next, and this is the standing account of what is outstanding and
      // what was decided against — the two halves of the same job.
      {
        label: "Vulnerability management",
        href: "/vulnerability-management",
      },
      // Directly after it, because it is the same backlog asked a different
      // question. Vulnerability management reports what is outstanding;
      // this answers which of it is work *today* — and on the day it was
      // written the honest split was 109 free, 316 frozen, 0 auto-fixable.
      { label: "Remediate today", href: "/remediate" },
      { label: "Pull requests", href: "/pull-requests" },
      { label: "Decisions", href: "/decisions" },
      // "Remediation" and "Remediate today" sat adjacent, four characters
      // apart, leading to different pages with different jobs. One is a
      // worklist and one is a library, so they are now named that way: the
      // difference has to be legible before the click, not after it.
      { label: "Remediation library", href: "/remediation" },
      { label: "Trends", href: "/trends" },
      { label: "Retros", href: "/retro" },
    ],
  },
];

/**
 * The "Manage" section is gone, and its absence is the fix.
 *
 * It held three items and no destinations of its own: "Repositories" pointed
 * at `/` (Portfolio), "Knowledge" pointed at `/retro` (Retros), and "Risk
 * decision policy" pointed at an anchor inside Decisions. Thirteen labels led
 * to ten places.
 *
 * A sidebar is a map. When two labels lead to one location the map is wrong,
 * the active-state highlight cannot be correct for both, and a reader building
 * a model of the product quietly gets a worse one. Deleting the aliases is
 * honest; the pages they pointed at all remain reachable under their real
 * names, one line above.
 */

/**
 * Two faces, doing two different jobs (Direction C).
 *
 * The markup has always split identifiers from prose — `font-mono` on a
 * package name, nothing on a paragraph — but nothing declared a sans, so the
 * prose half fell through to whatever `system-ui` resolved to and the two read
 * as one voice. `libc6 2.41-12+deb13u3` beside "no fixed version has been
 * published" made the reader separate them by meaning rather than by sight.
 *
 * Self-hosted through `next/font` rather than linked from a CDN: this platform
 * runs on a LAN and is read during incidents, and a typeface that needs the
 * internet is one that disappears exactly when it is most needed.
 */
const sans = IBM_Plex_Sans({
  subsets: ["latin"],
  weight: ["400", "500", "600"],
  variable: "--font-plex-sans",
  display: "swap",
});

const mono = IBM_Plex_Mono({
  subsets: ["latin"],
  weight: ["400", "500", "600"],
  variable: "--font-plex-mono",
  display: "swap",
});

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  // The nonce `proxy.ts` minted for this request. The theme script below is
  // inline by necessity — it has to run before the first paint — and inline
  // scripts are exactly what the CSP blocks, so it carries the nonce rather
  // than the policy carrying `'unsafe-inline'`.
  const nonce = (await headers()).get("x-nonce") ?? undefined;

  return (
    <html
      lang="en"
      className={`${sans.variable} ${mono.variable}`}
      // The script below sets `data-theme` before React sees the document, so
      // the server's markup and the client's disagree by design. Without this,
      // that is a hydration error rather than the point.
      suppressHydrationWarning
    >
      <head>
        {/*
          Applied before the first paint, which is the whole reason it is
          inline and synchronous: deferring to an effect would render the wrong
          ground and then correct it, and a page that flashes white on a dark
          screen at 3am is worse than one that took a millisecond longer.

          Absent or unreadable storage falls through to no attribute at all,
          which is the `system` default — so a private window or blocked site
          data degrades to following the OS rather than to a broken page.
        */}
        <script
          nonce={nonce}
          dangerouslySetInnerHTML={{
            __html:
              '(function(){try{var t=localStorage.getItem("theme");' +
              'if(t==="light"||t==="dark")document.documentElement.setAttribute("data-theme",t)}' +
              "catch(e){}})()",
          }}
        />
      </head>
      <body className="min-h-screen antialiased">
        <div className="flex min-h-screen flex-col">
          <header className="flex flex-wrap items-center gap-4 border-b border-rule bg-paper-2 px-4 py-2.5">
            <Link href="/" className="font-mono text-xs font-bold tracking-[0.14em]">
              MYKRONOS
            </Link>
            <span className="font-mono text-[12px] text-ink-3">
              AppSec control plane
            </span>
            <div className="ml-auto flex items-center gap-3">
              <Feedback />
              <ThemeToggle />
              {/* "Phase 7 · admin" used to sit here — the project's internal
                  delivery phase, in the corner every interface uses for
                  identity. It told the reader nothing they could act on and
                  implied the product was a roadmap they were watching rather
                  than a tool they were using. The role is the half that was
                  ever about them, so the role is what stayed. */}
              <span
                className="border border-rule px-2 py-0.5 font-mono text-[11px] uppercase tracking-[0.1em] text-ink-3"
                title="Your role. Admin can enable capabilities, dispatch scans, and record dispositions."
              >
                admin
              </span>
            </div>
          </header>

          <div className="flex flex-1 flex-col md:flex-row">
            <nav
              aria-label="Sections"
              className="shrink-0 border-b border-rule bg-paper-2 py-2 md:w-44 md:border-b-0 md:border-r"
            >
              {NAV.map((group) => (
                <div key={group.section} className="mb-2">
                  <p className="px-3 pb-1 pt-2 font-mono text-[11px] uppercase tracking-[0.13em] text-ink-3 opacity-70">
                    {group.section}
                  </p>
                  {group.items.map((item) => (
                    <Link
                      key={item.label}
                      href={item.href}
                      className="block border-l-2 border-transparent px-3 py-1.5 font-mono text-[13px] text-ink-2 hover:border-accent hover:bg-paper-3"
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
