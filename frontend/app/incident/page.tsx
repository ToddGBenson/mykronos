import { redirect } from "next/navigation";

/**
 * Incident lookup moved into Threat intelligence.
 *
 * They were two views of one question — what the outside world thinks matters,
 * and whether it is here — and keeping them apart meant reading a CVE on one
 * page and retyping it into another.
 *
 * This redirect is not tidiness. A lookup URL is the thing somebody pastes
 * into an incident channel, and those links outlive the page they were made
 * on; a 404 during an incident is the worst possible time to discover an
 * information-architecture change. The query is carried across, so an old
 * link lands on the same answer.
 */
export default async function IncidentPage({
  searchParams,
}: {
  searchParams: Promise<{ q?: string }>;
}) {
  const { q } = await searchParams;
  const query = (q ?? "").trim();
  redirect(query ? `/threat-intel?q=${encodeURIComponent(query)}` : "/threat-intel");
}
