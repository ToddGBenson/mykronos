/**
 * Server-side reads for the finding page's decision panel (TheHub #61140).
 *
 * Kept out of `server.ts` so this story's reads do not collide with the other
 * pages being rebuilt alongside it. Same contract: data or a reason.
 */

import "server-only";

import { backendClient } from "./api";

export type DeclaredControl = { control_id: string; description: string; kind: string };

/**
 * The repository's declared controls, the only kind of compensating control
 * the acceptance API takes (#60902). An empty list on failure: the form
 * still works without one, and says none is declared.
 */
export async function getDeclaredControls(repoId: string): Promise<DeclaredControl[]> {
  try {
    const { data } = await backendClient().GET("/api/dashboard/repos/{repo_id}/controls", {
      params: { path: { repo_id: repoId } },
      cache: "no-store",
    });
    return (data?.controls ?? []).map((c) => ({
      control_id: c.control_id,
      description: c.description,
      kind: c.kind,
    }));
  } catch {
    return [];
  }
}
