import { Consult } from "@/components/consult";
import { ExecutiveReport } from "@/components/executive-report";
import { ErrorPanel } from "@/components/primitives";
import { reportAnswers } from "@/lib/report";
import type { ConsultView, ExecutiveSummary } from "@/lib/server";

/**
 * The Report tab (TheHub #60885): the executive summary, then the consult
 * answers it does not already give, then everything neither can answer.
 *
 * One document, and it prints as one: `data-print-report` is here rather than
 * on the summary, so the print rules in `globals.css` (no navigation, light
 * palette, rows kept whole) cover the whole tab, and the "check it on" links,
 * which mean nothing on paper, are hidden in print.
 *
 * Either half failing costs that half: a reader who came for the summary still
 * gets it when the consult read fails, and the other way round.
 */
export function Report({
  repoId,
  executive,
  executiveError,
  consult,
  consultError,
}: {
  repoId: string;
  executive: ExecutiveSummary | null;
  executiveError: string | null;
  consult: ConsultView | null;
  consultError: string | null;
}) {
  return (
    <div data-print-report className="flex flex-col gap-4">
      {executive ? (
        <ExecutiveReport data={executive} gaps={consult === null} />
      ) : (
        <ErrorPanel title="Executive summary unavailable" detail={executiveError ?? ""} />
      )}
      {consult ? (
        <Consult
          repoId={repoId}
          data={consult}
          answers={reportAnswers(consult.answers)}
          gaps={executive?.gaps ?? []}
        />
      ) : (
        <ErrorPanel title="Consult unavailable" detail={consultError ?? ""} />
      )}
    </div>
  );
}
