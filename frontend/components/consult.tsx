import Link from "next/link";

import { Label, Section } from "@/components/primitives";
import type { components } from "@/lib/api-types";

type Consult = components["schemas"]["ConsultOut"];
type Answer = components["schemas"]["ConsultAnswerOut"];
type Unanswerable = components["schemas"]["ConsultUnanswerableOut"];

function AnswerBlock({ repoId, answer }: { repoId: string; answer: Answer }) {
  return (
    <div className="border-t border-rule-soft px-3 py-3">
      <p className="text-[13px] font-semibold text-ink">{answer.question}</p>
      <p className="mt-1 max-w-prose text-[14px] leading-relaxed text-ink-2">
        {answer.answer}
      </p>

      {answer.evidence.map((line) => (
        <p key={line} className="mt-1 max-w-prose text-[12px] text-ink-3">
          {line}
        </p>
      ))}

      {/* Every answer points at the tab it came from. An answer with no
          source is a claim; a link is what makes it falsifiable. */}
      {answer.tab ? (
        <Link
          href={`/repos/${repoId}?tab=${answer.tab}`}
          className="mt-1.5 inline-block font-mono text-[12px] text-accent underline decoration-dotted underline-offset-2"
        >
          check it on {answer.tab} &rarr;
        </Link>
      ) : null}
    </div>
  );
}

function CannotAnswer({ item }: { item: Unanswerable }) {
  return (
    <div className="border-t border-rule-soft px-3 py-2.5">
      <p className="text-[13px] text-ink-2">{item.question}</p>
      <p className="mt-1 max-w-prose text-[12px] text-ink-3">{item.why}</p>
    </div>
  );
}

/**
 * Consult the Champion.
 *
 * **Not a chat box, and the difference is the point.** There is no model here
 * and no free-text input. It answers the questions somebody actually arrives
 * with, from records, and each answer links to the tab where it can be
 * checked.
 *
 * The second half — the questions it *cannot* answer — is not an apology. The
 * failure mode of an assistant is not saying "I do not know"; it is answering
 * anyway, and a reader who knows the boundary can trust what is inside it.
 *
 * It cannot act. Everything above is a read.
 */
export function Consult({ repoId, data }: { repoId: string; data: Consult }) {
  return (
    <div className="flex flex-col gap-4">
      <Section
        title="What this platform knows"
        detail="answered from records, with somewhere to check each one"
      >
        {data.answers.map((answer) => (
          <AnswerBlock key={answer.key} repoId={repoId} answer={answer} />
        ))}
      </Section>

      <Section
        title="What it cannot tell you"
        detail="named rather than guessed at"
      >
        {data.cannot_answer.map((item) => (
          <CannotAnswer key={item.question} item={item} />
        ))}
      </Section>

      <div className="border border-rule bg-paper-2 px-3 py-2.5">
        <Label>How this works</Label>
        <p className="mt-1 max-w-prose text-[12px] text-ink-2">{data.note}</p>
      </div>
    </div>
  );
}
