"use client";

import "./globals.css";

/**
 * The boundary for the root layout itself (TheHub #61143, P9).
 *
 * `error.tsx` cannot catch the layout above it, so a layout that throws used
 * to leave Next's own error screen. This one replaces the whole document,
 * which is why it renders `<html>` and `<body>`. As in `error.tsx`, the
 * message is never shown, only the digest that matches the server log.
 */
export default function GlobalError({
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
    <html lang="en">
      <body className="min-h-screen bg-paper p-6 text-ink antialiased">
        <main role="alert" className="flex max-w-prose flex-col gap-3">
          <p className="font-mono text-xs font-bold tracking-[0.14em]">MYKRONOS</p>
          <h1>MyKronos could not load</h1>
          <p className="text-[14px] text-ink-2">
            The dashboard&rsquo;s own frame failed to render, so no page could be shown. Try again;
            if it keeps failing, the frontend server&rsquo;s log has the reason.
          </p>
          {digest ? (
            <p className="font-mono text-[12px] text-ink-3">reference {digest}</p>
          ) : null}
          <div>
            <button
              type="button"
              onClick={() => retry()}
              className="min-h-11 border border-accent bg-accent px-4 text-[13px] font-semibold text-paper"
            >
              Try again
            </button>
          </div>
        </main>
      </body>
    </html>
  );
}
