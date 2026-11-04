import type { components } from "@/lib/api-types";

type FixPullRequest = components["schemas"]["FixPullRequestOut"];

/**
 * A fix waiting for review (TheHub #60915): the open dependency-bot pull
 * requests that bump this finding's package to its fixed version or above.
 * Shown first under "What to do about it", because merging one is cheaper
 * than any other answer on the page, and an accept-risk path beside an open
 * fix is the mistake this exists to stop.
 *
 * Nothing renders when GitHub answered and none is open. When GitHub could
 * not be asked, the page says so rather than implying there is none.
 */
export function FixPullRequests({ prs, unread }: { prs: FixPullRequest[]; unread: boolean }) {
  if (prs.length === 0) {
    if (!unread) return null;
    return (
      <p className="mb-2 text-[13px] text-ink-3">
        Open dependency pull requests could not be read from GitHub, so a fix waiting for
        review may exist.
      </p>
    );
  }
  return (
    <div className="mb-2 border-l-2 border-accent bg-accent-wash px-2 py-1.5">
      <p className="text-[14px] font-semibold text-ink">
        A pull request that would fix this is open: review it
      </p>
      <ul className="mt-0.5 flex flex-col gap-0.5">
        {prs.map((pr) => (
          <li key={`${pr.repo_full_name}#${pr.number}`} className="text-[13px] text-ink-2">
            <a href={pr.url} className="font-mono text-accent underline-offset-2 hover:underline">
              {pr.repo_full_name}#{pr.number}
            </a>{" "}
            bumps {pr.package} to {pr.to_version}: {pr.title}
          </li>
        ))}
      </ul>
    </div>
  );
}
