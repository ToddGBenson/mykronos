import { BriefingView } from "@/components/briefing";
import { ErrorPanel } from "@/components/primitives";
import type { BriefingProduct } from "@/lib/briefing";
import { getDailyBriefing, getPortfolio } from "@/lib/server";

export const dynamic = "force-dynamic";

export const metadata = { title: "Briefing — Mykronos" };

/**
 * The morning briefing (TheHub #60864, epic #60858): the page the 07:00 Slack
 * DM links to. Overall by default; `?repo_id=` is one product's.
 *
 * Every section carries its source, how old it is and a status, and the
 * lines say what changed, so what, and whether it is a merge, a decision or
 * a story. Whatever the API returns is rendered, so sections that B3 (TheHub
 * #60861) fills appear here as soon as it serves them.
 */
export default async function BriefingPage({
  searchParams,
}: {
  searchParams: Promise<{ repo_id?: string }>;
}) {
  const { repo_id: repoId } = await searchParams;
  const [briefing, portfolio] = await Promise.all([
    getDailyBriefing(repoId ?? null),
    getPortfolio(),
  ]);

  if (!briefing.ok) {
    return <ErrorPanel title="Briefing unavailable" detail={briefing.error} />;
  }

  // The switcher and the repository links need the onboarding ids. Without
  // the portfolio the briefing still renders, with names instead of links.
  const products: BriefingProduct[] = portfolio.ok
    ? portfolio.data.repos.map((row) => ({
        repoId: row.repo_id,
        repoFullName: row.repo_full_name,
      }))
    : [];

  return (
    <BriefingView
      briefing={briefing.data}
      products={products}
      selectedRepoId={repoId ?? null}
    />
  );
}
