"use client";

/**
 * Report a bug, or ask for something.
 *
 * **A link, not a write, and that is the design decision.** The GitHub client
 * can create issues, and using it here would have been fewer moving parts —
 * but the issue would be filed by the App. An open-source feedback loop where
 * every report arrives from `mykronos-platform[bot]` with no author loses the
 * two things that make it a loop: who asked, and somebody to follow up with.
 * A pre-filled `issues/new` URL puts the report under the reporter's own
 * account, needs no token, and adds no server-side write path.
 *
 * The context is filled in because the details people forget are the ones
 * maintainers need: which page, which release, and what the browser was.
 * Everything else is left to them — a template that pre-writes the complaint
 * gets a template back.
 */

import { usePathname } from "next/navigation";

/** The platform's own repository, not anything on the estate it watches. */
const PLATFORM_REPO = "ToddGBenson/mykronos";

function issueUrl(kind: "bug" | "feature", page: string): string {
  const body =
    kind === "bug"
      ? [
          "### What happened",
          "",
          "",
          "### What you expected instead",
          "",
          "",
          "### Steps",
          "",
          "1. ",
          "",
          "---",
          "",
          `Page: \`${page}\``,
          `Release: \`${process.env.NEXT_PUBLIC_VERSION ?? "0.1.0"}\``,
          "",
          "<sub>Opened from the Mykronos console. Please remove anything",
          "sensitive before submitting — this becomes a public issue.</sub>",
        ].join("\n")
      : [
          "### What you are trying to do",
          "",
          "",
          "### What would make that easier",
          "",
          "",
          "### How you work around it today",
          "",
          "",
          "---",
          "",
          `Page: \`${page}\``,
          "",
          "<sub>Opened from the Mykronos console.</sub>",
        ].join("\n");

  // No `title`. Pre-filling it blank is the same as omitting it, and
  // pre-filling it with a guess produces issues titled "Bug report".
  const params = new URLSearchParams({ body, labels: kind });
  return `https://github.com/${PLATFORM_REPO}/issues/new?${params.toString()}`;
}

export function Feedback() {
  const pathname = usePathname();

  return (
    <span className="inline-flex items-center gap-px" role="group" aria-label="Feedback">
      {(["bug", "feature"] as const).map((kind) => (
        <a
          key={kind}
          href={issueUrl(kind, pathname)}
          target="_blank"
          rel="noreferrer"
          title={
            kind === "bug"
              ? "Open a GitHub issue about something that is wrong. It opens under your own account, pre-filled with this page and release."
              : "Ask for something. It opens under your own account."
          }
          className="tap border border-rule px-1.5 py-0.5 font-mono text-[11px] lowercase tracking-[0.08em] text-ink-3 hover:border-accent hover:text-accent"
        >
          {kind === "bug" ? "report a bug" : "request"}
        </a>
      ))}
    </span>
  );
}
