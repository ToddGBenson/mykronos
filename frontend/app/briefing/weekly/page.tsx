import { ErrorPanel } from "@/components/primitives";
import { WeeklyBriefingView } from "@/components/weekly-briefing";
import { getWeeklyBriefing } from "@/lib/server";

export const dynamic = "force-dynamic";

export const metadata = { title: "Weekly intelligence — Mykronos" };

/**
 * The Monday intelligence page (TheHub #60865, B7): one page per
 * application, or one application's with `?repo_id=`. The flash DM links
 * here.
 */
export default async function WeeklyBriefingPage({
  searchParams,
}: {
  searchParams: Promise<{ repo_id?: string }>;
}) {
  const { repo_id: repoId } = await searchParams;
  const briefing = await getWeeklyBriefing(repoId ?? null);
  if (!briefing.ok) {
    return <ErrorPanel title="Weekly briefing unavailable" detail={briefing.error} />;
  }
  return <WeeklyBriefingView briefing={briefing.data} />;
}
