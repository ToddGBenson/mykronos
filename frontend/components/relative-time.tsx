"use client";

import { useEffect, useState } from "react";

/**
 * "4m ago", computed on the client.
 *
 * Deliberately not a server component. `Date.now()` during a server render
 * bakes the elapsed time into the HTML at render time: it never updates, it
 * is wrong the moment the response is cached, and it differs between the
 * server render and any client re-render. React's purity lint is right to
 * refuse it.
 *
 * So the server emits the absolute timestamp — correct and cacheable — and
 * the client swaps in the relative form after mount. The first client render
 * matches the server's exactly, so there is no hydration mismatch, and the
 * absolute value stays in the tooltip where precision is actually wanted.
 */
export function RelativeTime({ value }: { value: string | null | undefined }) {
  const [relative, setRelative] = useState<string | null>(null);

  // Timestamps from the lake are naive UTC (spec 01 §6); mark them as such
  // rather than letting the browser read them as local time.
  const iso = value ? (value.endsWith("Z") ? value : `${value}Z`) : null;

  useEffect(() => {
    if (!iso) return;

    const format = () => {
      const seconds = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
      const [amount, unit] =
        seconds < 90
          ? [Math.round(seconds), "s"]
          : seconds < 5400
            ? [Math.round(seconds / 60), "m"]
            : seconds < 172800
              ? [Math.round(seconds / 3600), "h"]
              : [Math.round(seconds / 86400), "d"];
      setRelative(`${amount}${unit} ago`);
    };

    format();
    // A dashboard left open on a wall should not quietly freeze at "2m ago".
    const timer = setInterval(format, 30_000);
    return () => clearInterval(timer);
  }, [iso]);

  if (!iso) return <span className="text-ink-3">never</span>;

  const absolute = new Date(iso);
  return (
    <time dateTime={absolute.toISOString()} title={absolute.toISOString()} className="tabular">
      {relative ?? absolute.toISOString().slice(0, 16).replace("T", " ")}
    </time>
  );
}
