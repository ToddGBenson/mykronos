import Link from "next/link";

import { EmptyState, Pill, Section } from "@/components/primitives";
import type { PoTrace, PoTraceView } from "@/lib/po-console";

/**
 * One story's delivery chain: commit, pull request, scan, deploy (spec 35
 * §8.5). A commit is shown only when its `Stories:` trailer credits the story
 * (D-139), and the first missing link is always named.
 */

const LINKS = [
  { id: "commit", label: "commit" },
  { id: "pr", label: "pull request" },
  { id: "scan", label: "scan" },
  { id: "deploy", label: "deploy" },
] as const;

function Chain({ trace }: { trace: PoTrace }) {
  return (
    <ol className="flex flex-wrap items-baseline gap-1.5 px-3 py-2">
      {LINKS.map((link, index) => (
        <li key={link.id} className="flex items-baseline gap-1.5">
          <Pill tone={trace.links[link.id] ? "pass" : "muted"}>{link.label}</Pill>
          {index < LINKS.length - 1 ? (
            <span aria-hidden="true" className="text-ink-3">
              →
            </span>
          ) : null}
        </li>
      ))}
    </ol>
  );
}

function TraceBody({ trace }: { trace: PoTrace }) {
  return (
    <div className="flex flex-col gap-3">
      <Section
        title={`#${trace.story.id} ${trace.story.title}`}
        detail={`${trace.story.bucket} · ${trace.story.gate}`}
        aside={
          trace.first_missing ? (
            <Pill tone="warn">{trace.first_missing}</Pill>
          ) : (
            <Pill tone="pass">every link recorded</Pill>
          )
        }
      >
        <Chain trace={trace} />
        <p className="border-t border-rule-soft px-3 py-1.5 text-[12px] text-ink-2">
          Commits are the ones whose <span className="font-mono">Stories:</span> trailer names
          this story
          {trace.commits_read !== null
            ? `, from ${trace.commits_read} commit(s) read on the default branch since it was created`
            : ""}
          .
          {trace.prose_mentions
            ? ` ${trace.prose_mentions} more mention it in prose without crediting it, and are not shown as delivering it.`
            : ""}
        </p>
        {trace.github_error ? (
          <p className="border-t border-rule-soft px-3 py-1.5 text-[12px] text-critical">
            {trace.github_error}
          </p>
        ) : null}
        {trace.deploys_error ? (
          <p className="border-t border-rule-soft px-3 py-1.5 text-[12px] text-high">
            TheHub&rsquo;s deploy list could not be read: {trace.deploys_error}
          </p>
        ) : null}
      </Section>
      {trace.commits.map((commit) => (
        <Section
          key={commit.sha}
          title={commit.sha.slice(0, 10)}
          detail={commit.subject}
          aside={
            commit.missing ? (
              <Pill tone="warn">{commit.missing}</Pill>
            ) : (
              <Pill tone="pass">delivered</Pill>
            )
          }
        >
          <div className="flex flex-col gap-1 px-3 py-2 text-[12px] text-ink-2">
            <span>
              <a href={commit.url} rel="noreferrer" className="font-mono hover:text-accent">
                commit on GitHub
              </a>
              {commit.committed_at ? (
                <span className="font-mono text-[11px] text-ink-3">
                  {" "}
                  · {commit.committed_at.slice(0, 10)}
                </span>
              ) : null}
            </span>
            <span>
              Pull requests:{" "}
              {commit.prs.length === 0
                ? "none recorded"
                : commit.prs.map((pr) => (
                    <a
                      key={pr.number}
                      href={pr.url}
                      rel="noreferrer"
                      title={`from ${pr.source}`}
                      className="mr-2 font-mono hover:text-accent"
                    >
                      #{pr.number}
                    </a>
                  ))}
            </span>
            <span>
              Scans:{" "}
              {commit.scans.length === 0
                ? "none recorded"
                : commit.scans.map((scan, index) =>
                    scan.run_url ? (
                      <a
                        key={index}
                        href={scan.run_url}
                        rel="noreferrer"
                        className="mr-2 font-mono hover:text-accent"
                      >
                        {scan.capability} {scan.status} ({scan.of})
                      </a>
                    ) : (
                      <span key={index} className="mr-2 font-mono">
                        {scan.capability} {scan.status} ({scan.of})
                      </span>
                    ),
                  )}
            </span>
            <span>
              Deploys:{" "}
              {commit.running ? <Pill tone="pass">running now</Pill> : null}{" "}
              {commit.deploys.length === 0 && !commit.running
                ? "none recorded"
                : commit.deploys.map((deploy, index) => (
                    <span key={index} className="mr-2 font-mono" title={deploy.source}>
                      {String(deploy.id ?? "?")} {deploy.status}
                    </span>
                  ))}
            </span>
          </div>
        </Section>
      ))}
    </div>
  );
}

export function TraceView({ repoId, data }: { repoId: string; data: PoTraceView }) {
  if (!data.hub.connected) {
    return (
      <EmptyState
        title="TheHub is not connected"
        detail="A trace starts from a TheHub story, so there is nothing to start from."
      />
    );
  }
  return (
    <div className="flex flex-col gap-3">
      <nav aria-label="Stories to trace" className="flex flex-wrap gap-1">
        {data.stories.map((story) => (
          <Link
            key={story.id}
            href={`/repos/${repoId}?tab=product-owner&view=trace&story=${story.id}`}
            title={story.title}
            className={`border px-1.5 py-0.5 font-mono text-[11px] ${
              data.trace?.story.id === story.id
                ? "border-accent font-bold text-ink"
                : "border-rule text-ink-3 hover:text-accent"
            }`}
          >
            #{story.id}
          </Link>
        ))}
      </nav>
      {data.trace ? (
        <TraceBody trace={data.trace} />
      ) : (
        <EmptyState
          title="Choose a story"
          detail="Pick a sprint or recently closed story above to see the chain that delivered it."
        />
      )}
    </div>
  );
}
