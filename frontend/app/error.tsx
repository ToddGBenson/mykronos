"use client";

/**
 * What a route shows when its page throws (TheHub #61143, P9).
 *
 * The root segment's `error.tsx`, so it catches every route below the layout
 * and leaves the header and nav rail standing: the reader can retry, or go
 * somewhere else, without reloading the whole app. Pages here already turn a
 * backend refusal into an `ErrorPanel`; this is for what they did not expect.
 *
 * The error's message is never shown. Next replaces a server error's message
 * in production, and a client one may carry something that should not be on
 * screen. Its `digest` is the reference that matches the server's log line,
 * so that is what is shown.
 */
export default function RouteError({
  error,
  retry,
}: {
  error: unknown;
  retry: () => void;
}) {
  const digest =
    error instanceof Error && "digest" in error && typeof error.digest === "string"
      ? error.digest
      : null;
  return (
    <div role="alert" className="flex max-w-prose flex-col gap-3 border border-critical bg-critical-wash p-4">
      <h1 className="text-ink">This page could not load</h1>
      <p className="text-[14px] text-ink-2">
        Something failed while this page was being put together. The rest of the dashboard still
        works. Try again; if it keeps failing, MyKronos Health shows whether a backend job or
        dependency is down.
      </p>
      {digest ? (
        <p className="font-mono text-[12px] text-ink-3">
          reference {digest}: the same id is in the frontend server&rsquo;s log
        </p>
      ) : null}
      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          onClick={() => retry()}
          className="min-h-11 border border-accent bg-accent px-4 text-[13px] font-semibold text-paper"
        >
          Try again
        </button>
        <a
          href="/platform-health"
          className="inline-flex min-h-11 items-center border border-accent px-4 text-[13px] font-semibold text-accent"
        >
          Open MyKronos Health
        </a>
      </div>
    </div>
  );
}
