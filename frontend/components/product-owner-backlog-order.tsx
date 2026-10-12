"use client";

import { useState, type ReactNode } from "react";

/**
 * The Backlog view's two orders (spec 35 §7.4): the Product Owner's manual rank,
 * and a suggested order by the Oracle risk points each story removes. Switching
 * is local to this page and writes nothing; the rank controls are shown only in
 * the manual order, so the suggested one can never be stored by accident.
 */
export function BacklogOrder({
  manual,
  byRisk,
  manualRows,
  riskRows,
  statement,
}: {
  manual: number[];
  byRisk: number[];
  manualRows: Record<string, ReactNode>;
  riskRows: Record<string, ReactNode>;
  statement: string;
}) {
  const [order, setOrder] = useState<"manual" | "risk">("manual");
  const ids = order === "manual" ? manual : byRisk;
  const rows = order === "manual" ? manualRows : riskRows;
  const tab = (id: "manual" | "risk", label: string) => (
    <button
      type="button"
      onClick={() => setOrder(id)}
      aria-pressed={order === id}
      className={`border px-2 py-0.5 font-mono text-[11px] ${
        order === id ? "border-accent font-bold text-ink" : "border-rule text-ink-3 hover:text-accent"
      }`}
    >
      {label}
    </button>
  );
  return (
    <div className="flex flex-col">
      <div className="flex flex-wrap items-baseline gap-1.5 px-3 py-1.5">
        {tab("manual", "manual rank")}
        {tab("risk", "by risk removed")}
        {order === "risk" ? (
          <span className="w-full text-[12px] text-ink-3">
            {statement} A suggestion: the manual rank is unchanged.
          </span>
        ) : null}
      </div>
      {ids.map((id) => (
        <div key={id}>{rows[String(id)]}</div>
      ))}
    </div>
  );
}
