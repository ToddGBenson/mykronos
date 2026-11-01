"use client";

import { useEffect, useState } from "react";

import { countdown, utcMs } from "@/lib/agents";

/**
 * "lapses in 3h", computed on the client for the reason `relative-time.tsx`
 * gives: a server render must not read the clock. The first render shows the
 * absolute time, which matches the server's HTML, and the countdown replaces
 * it after mount. Under two hours left it turns the warning colour.
 */
export function AgentCountdown({ expiresAt }: { expiresAt: string }) {
  const [now, setNow] = useState<number | null>(null);

  useEffect(() => {
    const tick = () => setNow(Date.now());
    tick();
    const id = setInterval(tick, 60_000);
    return () => clearInterval(id);
  }, []);

  const iso = new Date(utcMs(expiresAt)).toISOString();
  if (now === null) {
    return (
      <time dateTime={iso} className="font-mono text-[12px] text-ink-3">
        {iso.slice(0, 16).replace("T", " ")} UTC
      </time>
    );
  }
  const left = utcMs(expiresAt) - now;
  const tone = left <= 0 ? "text-ink-3" : left < 2 * 3_600_000 ? "text-high font-bold" : "text-ink-2";
  return (
    <time dateTime={iso} title={`${iso.slice(0, 16).replace("T", " ")} UTC`} className={`font-mono text-[12px] ${tone}`}>
      {countdown(expiresAt, now)}
    </time>
  );
}
