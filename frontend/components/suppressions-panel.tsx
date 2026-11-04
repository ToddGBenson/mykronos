import { ErrorPanel } from "@/components/primitives";
import { SuppressionsTable } from "@/components/suppressions";
import { getRepoSuppressions } from "@/lib/server";

/** The Risk management tab's "Suppressed in the repository" section (TheHub #60963). */
export async function SuppressionsPanel({ repoId }: { repoId: string }) {
  const result = await getRepoSuppressions(repoId);
  return (
    <section aria-labelledby="suppressions-heading" className="flex flex-col gap-2">
      <h2 id="suppressions-heading" className="font-mono text-[12px] font-bold uppercase tracking-[0.1em] text-ink-2">
        Suppressed in the repository
      </h2>
      <p className="max-w-prose text-[14px] leading-relaxed text-ink-3">
        Results the repository silenced itself, with a pragma or a scanner config
        entry, as its newest scans reported them. They are not findings and are not
        the platform&rsquo;s decisions. An expired one is also reported on its lane.
      </p>
      {result.ok ? (
        <SuppressionsTable data={result.data} />
      ) : (
        <ErrorPanel title="Suppressions unavailable" detail={result.error} />
      )}
    </section>
  );
}
