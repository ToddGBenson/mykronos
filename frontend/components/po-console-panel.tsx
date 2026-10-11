import type { ReactNode } from "react";

import { ApprovalsView, DeliveryView, RetroView, RolesView } from "@/components/po-console";
import { FleetView } from "@/components/po-fleet";
import { TraceView } from "@/components/po-trace";
import { ErrorPanel } from "@/components/primitives";
import {
  getPoApprovals,
  getPoDelivery,
  getPoFleet,
  getPoRetro,
  getPoRoles,
  getPoTrace,
  windowDays,
} from "@/lib/po-console";

/** The query-string parameters the phase 2 views read. */
export type PoConsoleQuery = { days?: string; story?: string };

/**
 * The rendered phase 2 view for `view`, or undefined for a phase 1 view
 * (spec 35 §8). Fetched beside the phase 1 read, which still supplies the
 * console's header.
 */
export async function poConsoleView(
  repoId: string,
  view: string,
  query: PoConsoleQuery,
): Promise<ReactNode | undefined> {
  if (view === "delivery") {
    const result = await getPoDelivery(repoId, windowDays(query.days, 30, 180));
    return result.ok ? (
      <DeliveryView repoId={repoId} data={result.data} />
    ) : (
      <ErrorPanel title="Delivery unavailable" detail={result.error} />
    );
  }
  if (view === "approvals") {
    const result = await getPoApprovals(repoId);
    return result.ok ? (
      <ApprovalsView repoId={repoId} data={result.data} />
    ) : (
      <ErrorPanel title="Approvals unavailable" detail={result.error} />
    );
  }
  if (view === "roles") {
    const result = await getPoRoles(repoId);
    return result.ok ? (
      <RolesView data={result.data} />
    ) : (
      <ErrorPanel title="Roles & agents unavailable" detail={result.error} />
    );
  }
  if (view === "retro") {
    const result = await getPoRetro(repoId, windowDays(query.days, 14, 90));
    return result.ok ? (
      <RetroView repoId={repoId} data={result.data} />
    ) : (
      <ErrorPanel title="Retro unavailable" detail={result.error} />
    );
  }
  if (view === "trace") {
    const id = Number(query.story);
    const result = await getPoTrace(repoId, Number.isInteger(id) && id > 0 ? id : undefined);
    return result.ok ? (
      <TraceView repoId={repoId} data={result.data} />
    ) : (
      <ErrorPanel title="Delivery trace unavailable" detail={result.error} />
    );
  }
  if (view === "fleet") {
    const result = await getPoFleet(repoId, windowDays(query.days, 7, 90));
    return result.ok ? (
      <FleetView repoId={repoId} data={result.data} />
    ) : (
      <ErrorPanel title="Agent fleet unavailable" detail={result.error} />
    );
  }
  return undefined;
}
