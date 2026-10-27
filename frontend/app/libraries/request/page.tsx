import Link from "next/link";

import { LibraryRequestForm } from "@/components/library-request-form";

export const dynamic = "force-dynamic";

export const metadata = { title: "Request a library — Mykronos" };

/**
 * Request a library (TheHub #60895).
 *
 * The one-click link in a pull request's `library-allowlist` check lands
 * here with the ecosystem, name and version filled in. Submitting vets the
 * package and opens its approval; the vetting report is shown at once.
 */
export default async function RequestLibraryPage({
  searchParams,
}: {
  searchParams: Promise<{ ecosystem?: string; name?: string; version?: string }>;
}) {
  const { ecosystem, name, version } = await searchParams;

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap items-baseline gap-3">
        <h1 className="text-xl font-bold tracking-tight">Request a library</h1>
        <Link href="/libraries" className="font-mono text-[13px] text-ink-3 hover:text-accent">
          back to Libraries
        </Link>
      </div>
      <p className="max-w-prose text-[14px] leading-relaxed text-ink-2">
        The platform vets the package itself — known vulnerabilities, license, release
        history, OpenSSF Scorecard, transitive weight, and typosquat and new-package
        checks — and opens an approval request. A flagged report needs a person to
        approve it. Nothing is allowed until it is approved.
      </p>
      <LibraryRequestForm
        initial={{ ecosystem: ecosystem ?? "npm", name: name ?? "", version: version ?? "" }}
      />
    </div>
  );
}
