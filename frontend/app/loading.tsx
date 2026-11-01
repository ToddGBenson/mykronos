/**
 * What every route shows while its server component waits on the backend
 * (TheHub #61143, P9).
 *
 * Every page here is dynamic and reads live data, so a slow backend used to
 * leave the main column blank with no sign that anything was happening. This
 * is the root segment's `loading.tsx`, so it covers every route below the
 * layout; the nav rail stays usable while it shows. The skeleton is the
 * common shape of a page here: a title, a row of stat tiles, a table.
 */
export default function Loading() {
  return (
    <div role="status" aria-busy="true" aria-live="polite" className="flex flex-col gap-4">
      <span className="sr-only">Loading this page</span>
      <div aria-hidden="true" className="flex animate-pulse flex-col gap-4">
        <div className="h-7 w-64 max-w-full bg-paper-3" />
        <div className="grid grid-cols-2 gap-2 lg:grid-cols-4">
          {[0, 1, 2, 3].map((tile) => (
            <div key={tile} className="h-20 border border-rule bg-paper-2" />
          ))}
        </div>
        <div className="flex flex-col gap-1.5 border border-rule bg-paper-2 p-3">
          {[0, 1, 2, 3, 4, 5].map((row) => (
            <div key={row} className="h-4 bg-paper-3" style={{ width: `${92 - row * 9}%` }} />
          ))}
        </div>
      </div>
      <p className="font-mono text-[12px] text-ink-3">Loading this page from the backend…</p>
    </div>
  );
}
