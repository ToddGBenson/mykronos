"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  useEffect,
  useId,
  useRef,
  useState,
  useTransition,
  type ReactNode,
} from "react";

import {
  BUILTIN_VIEWS,
  SORTS,
  activeFilterCount,
  clearAll,
  findingsHref,
  isCurrentView,
  loadSavedViews,
  pillValue,
  setValues,
  storeSavedViews,
  valuesOf,
  viewPatch,
  viewQueryString,
  withSavedView,
  type FilterKey,
  type FindingsQuery,
  type FindingsView,
  type MultiKey,
} from "@/lib/findings-filters";

/**
 * The Findings tab's filter row (option C): one line of pills, each saying
 * what it is set to, each opening a small dialog to change it.
 *
 * Client-side only for the popovers. Every change is a navigation to a new
 * URL, and the server renders the filtered list from it — so a view is still
 * a link, still survives a refresh, and nothing here is the source of truth.
 */

export type PillOption = { value: string; label: string; count?: number };

export type PillDef =
  | {
      kind: "multi";
      key: MultiKey;
      label: string;
      options: PillOption[];
      /** What the pill reads when nothing is chosen. */
      anyLabel?: string;
      hint?: string;
    }
  | { kind: "text"; key: "rule_id" | "path"; label: string; placeholder: string; hint?: string }
  | { kind: "age"; label: string }
  | { kind: "intel"; label: string }
  | { kind: "toggle"; key: "fixable"; label: string; onLabel: string; hint?: string };

const pillId = (def: PillDef) =>
  def.kind === "age" ? "age" : def.kind === "intel" ? "intel" : def.key;

/** The URL keys a pill owns, for "is it set" and "clear it". */
function keysOf(def: PillDef): FilterKey[] {
  if (def.kind === "age") return ["older_than_days", "newer_than_days"];
  if (def.kind === "intel") return ["kev_only", "min_epss"];
  return [def.key];
}

function isSet(def: PillDef, query: FindingsQuery): boolean {
  if (def.kind === "multi" && def.key === "status") {
    const values = valuesOf(query, "status");
    return values.length > 0 && !(values.length === 1 && values[0] === "open");
  }
  return keysOf(def).some((key) => Boolean(query[key]));
}

const EPSS_STEPS = ["0.1", "0.3", "0.5", "0.7", "0.9"];

function describe(def: PillDef, query: FindingsQuery): string {
  switch (def.kind) {
    case "multi": {
      const labels = new Map(def.options.map((option) => [option.value, option.label]));
      const values = valuesOf(query, def.key);
      if (!values.length) return def.anyLabel ?? "any";
      return pillValue(values, (value) => labels.get(value) ?? value);
    }
    case "text":
      return query[def.key] ? `“${query[def.key]}”` : "any";
    case "toggle":
      return query[def.key] === "1" ? def.onLabel : "any";
    case "age":
      if (query.older_than_days) return `older than ${query.older_than_days}d`;
      if (query.newer_than_days) return `last ${query.newer_than_days}d`;
      return "any";
    case "intel": {
      const parts = [
        query.kev_only === "1" ? "KEV" : "",
        query.min_epss ? `EPSS ≥ ${Math.round(Number(query.min_epss) * 100)}%` : "",
      ].filter(Boolean);
      return parts.length ? parts.join(" + ") : "any";
    }
  }
}

export function FindingsFilterBar({
  repoId,
  query,
  primary,
  secondary,
}: {
  repoId: string;
  query: FindingsQuery;
  /** Always shown: Status, Severity, Scan type, Exposure, Due. */
  primary: PillDef[];
  /** Behind "+ Add filter", shown while set or once added. */
  secondary: PillDef[];
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [open, setOpen] = useState<string | null>(null);
  const [added, setAdded] = useState<string[]>([]);
  const triggers = useRef(new Map<string, HTMLButtonElement | null>());

  const go = (patch: Partial<FindingsQuery>) => {
    setOpen(null);
    startTransition(() => router.push(findingsHref(repoId, query, patch), { scroll: false }));
  };

  /** Close and hand focus back to the control that opened it. */
  const close = (id: string) => {
    setOpen(null);
    triggers.current.get(id)?.focus();
  };

  const visibleSecondary = secondary.filter(
    (def) => isSet(def, query) || added.includes(pillId(def)),
  );
  const addable = secondary.filter((def) => !visibleSecondary.includes(def));
  const count = activeFilterCount(query);

  const pill = (def: PillDef) => {
    const id = pillId(def);
    const active = isSet(def, query);
    const expanded = open === id;
    const popoverId = `findings-filter-${id}`;
    return (
      <div key={id} className="relative">
        <span
          className={`inline-flex items-stretch border ${
            active || expanded ? "border-accent" : "border-rule"
          } ${active ? "bg-accent-wash" : "bg-paper"}`}
        >
          <button
            type="button"
            ref={(node) => {
              triggers.current.set(id, node);
            }}
            aria-haspopup="dialog"
            aria-expanded={expanded}
            aria-controls={expanded ? popoverId : undefined}
            onClick={() => setOpen(expanded ? null : id)}
            className="inline-flex items-center gap-1.5 px-2.5 py-1 text-[12.5px] text-ink hover:bg-paper-2 focus-visible:outline-2 focus-visible:outline-accent"
          >
            <span className="text-ink-2">{def.label}</span>
            <span className="max-w-[16rem] truncate font-semibold">{describe(def, query)}</span>
            <svg
              width="10"
              height="10"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2.5"
              aria-hidden
              className="text-ink-3"
            >
              <path d="M6 9l6 6 6-6" />
            </svg>
          </button>
          {active ? (
            <Link
              href={findingsHref(
                repoId,
                query,
                Object.fromEntries([
                  ...keysOf(def).map((key) => [key, undefined]),
                  ["group", undefined],
                  ["finding", undefined],
                ]),
              )}
              scroll={false}
              aria-label={`Clear the ${def.label} filter`}
              title={`Clear ${def.label}`}
              className="flex items-center border-l border-accent/40 px-1.5 text-[12px] text-accent hover:bg-accent hover:text-paper"
            >
              ✕
            </Link>
          ) : null}
        </span>
        {expanded ? (
          <Popover id={popoverId} label={`${def.label} filter`} onClose={() => close(id)}>
            <PillEditor def={def} query={query} onApply={go} />
          </Popover>
        ) : null}
      </div>
    );
  };

  return (
    <div
      className={`flex flex-wrap items-center gap-2 ${pending ? "opacity-70" : ""}`}
      aria-busy={pending}
    >
      {primary.map(pill)}
      {visibleSecondary.map(pill)}

      {addable.length ? (
        <div className="relative">
          <button
            type="button"
            ref={(node) => {
              triggers.current.set("__add", node);
            }}
            aria-haspopup="dialog"
            aria-expanded={open === "__add"}
            onClick={() => setOpen(open === "__add" ? null : "__add")}
            className="border border-dashed border-rule px-2.5 py-1 text-[12.5px] text-accent hover:border-accent focus-visible:outline-2 focus-visible:outline-accent"
          >
            + Add filter
          </button>
          {open === "__add" ? (
            <Popover id="findings-filter-add" label="Add a filter" onClose={() => close("__add")}>
              <ul className="flex flex-col">
                {addable.map((def) => (
                  <li key={pillId(def)}>
                    <button
                      type="button"
                      onClick={() => {
                        const id = pillId(def);
                        setAdded((current) => [...current, id]);
                        setOpen(id);
                      }}
                      className="flex w-full flex-col items-start px-2 py-1.5 text-left text-[12.5px] text-ink hover:bg-paper-2 focus-visible:bg-paper-2 focus-visible:outline-none"
                    >
                      <span>{def.label}</span>
                      {"hint" in def && def.hint ? (
                        <span className="text-[11px] text-ink-3">{def.hint}</span>
                      ) : null}
                    </button>
                  </li>
                ))}
              </ul>
            </Popover>
          ) : null}
        </div>
      ) : null}

      {count > 0 ? (
        <Link
          href={findingsHref(repoId, query, clearAll())}
          scroll={false}
          className="px-1 text-[12px] text-accent underline decoration-dotted underline-offset-2 hover:text-ink"
        >
          Clear all ({count})
        </Link>
      ) : null}

      <span className="hidden grow sm:block" />

      <label className="flex items-center gap-1.5 text-[12px] text-ink-2">
        Sort
        <select
          value={query.sort ?? ""}
          onChange={(event) => go({ sort: event.target.value || undefined })}
          className="border border-rule bg-paper px-1.5 py-1 text-[12px] text-ink focus:border-accent focus:outline-none"
        >
          {SORTS.map((entry) => (
            <option key={entry.value} value={entry.value}>
              {entry.label}
            </option>
          ))}
        </select>
      </label>

      <ViewsMenu
        repoId={repoId}
        query={query}
        open={open === "__views"}
        onToggle={() => setOpen(open === "__views" ? null : "__views")}
        onClose={() => close("__views")}
        triggerRef={(node) => {
          triggers.current.set("__views", node);
        }}
      />
    </div>
  );
}

/**
 * A labelled, non-modal dialog under its pill. Escape closes it and focus
 * goes back to the pill; so does a click anywhere outside. Focus moves inside
 * on open, to the first field.
 */
function Popover({
  id,
  label,
  onClose,
  align = "left",
  children,
}: {
  id: string;
  label: string;
  onClose: () => void;
  align?: "left" | "right";
  children: ReactNode;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const closeRef = useRef(onClose);
  useEffect(() => {
    closeRef.current = onClose;
  });

  useEffect(() => {
    const node = ref.current;
    node
      ?.querySelector<HTMLElement>("input, select, button, [href], [tabindex]:not([tabindex='-1'])")
      ?.focus();
    const onPointer = (event: PointerEvent) => {
      const trigger = node?.parentElement;
      if (trigger && !trigger.contains(event.target as Node)) closeRef.current();
    };
    // On the document, so Escape closes it whether focus is inside the
    // dialog or still on the pill that opened it.
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.stopPropagation();
        closeRef.current();
      }
    };
    document.addEventListener("pointerdown", onPointer);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("pointerdown", onPointer);
      document.removeEventListener("keydown", onKey);
    };
  }, []);

  return (
    <div
      ref={ref}
      id={id}
      role="dialog"
      aria-label={label}
      className={`absolute top-[calc(100%+6px)] z-20 flex w-[min(18rem,calc(100vw-2rem))] flex-col gap-2 border border-rule bg-paper p-2.5 shadow-[0_8px_24px_rgba(18,23,21,0.12)] ${
        align === "right" ? "right-0" : "left-0"
      }`}
    >
      {children}
    </div>
  );
}

/** What goes inside a pill's dialog, by kind. A form, so Enter applies. */
function PillEditor({
  def,
  query,
  onApply,
}: {
  def: PillDef;
  query: FindingsQuery;
  onApply: (patch: Partial<FindingsQuery>) => void;
}) {
  switch (def.kind) {
    case "multi":
      return <MultiEditor def={def} query={query} onApply={onApply} />;
    case "text":
      return <TextEditor def={def} query={query} onApply={onApply} />;
    case "age":
      return <AgeEditor query={query} onApply={onApply} />;
    case "intel":
      return <IntelEditor query={query} onApply={onApply} />;
    case "toggle":
      return (
        <form
          className="flex flex-col gap-2"
          onSubmit={(event) => {
            event.preventDefault();
            const on = new FormData(event.currentTarget).get("on") === "1";
            onApply({ [def.key]: on ? "1" : undefined, group: undefined, finding: undefined });
          }}
        >
          <label className="flex min-h-6 items-center gap-2 text-[12.5px]">
            <input
              type="checkbox"
              name="on"
              value="1"
              defaultChecked={query[def.key] === "1"}
              className="accent-accent"
            />
            {def.onLabel}
          </label>
          {def.hint ? <p className="text-[11px] text-ink-3">{def.hint}</p> : null}
          <Footer />
        </form>
      );
  }
}

function Footer({ left }: { left?: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-2 border-t border-rule-soft pt-2">
      <span className="flex gap-3">{left}</span>
      <button
        type="submit"
        className="border border-accent bg-accent-wash px-2.5 py-1 text-[12px] text-accent hover:bg-accent hover:text-paper"
      >
        Apply
      </button>
    </div>
  );
}

const linkButton =
  "border-0 bg-transparent p-0 text-[12px] text-accent hover:underline focus-visible:underline";

function MultiEditor({
  def,
  query,
  onApply,
}: {
  def: Extract<PillDef, { kind: "multi" }>;
  query: FindingsQuery;
  onApply: (patch: Partial<FindingsQuery>) => void;
}) {
  const initial = valuesOf(query, def.key);
  const [chosen, setChosen] = useState<string[]>(
    def.key === "status" && initial.length === 0 ? ["open"] : initial,
  );
  const [needle, setNeedle] = useState("");
  const [last, setLast] = useState<string | undefined>(initial[0]);
  const listId = useId();

  // Values from the URL that no option names (an owner from a shared link,
  // say) stay listed, so applying never silently drops them.
  const options: PillOption[] = [
    ...def.options,
    ...initial
      .filter((value) => !def.options.some((option) => option.value === value))
      .map((value) => ({ value, label: value })),
  ];
  const shown = needle
    ? options.filter((option) =>
        `${option.label} ${option.value}`.toLowerCase().includes(needle.toLowerCase()),
      )
    : options;
  const lastLabel = options.find((option) => option.value === last)?.label;

  return (
    <form
      className="flex flex-col gap-2"
      onSubmit={(event) => {
        event.preventDefault();
        onApply(setValues(def.key, chosen));
      }}
    >
      {options.length > 6 ? (
        <input
          type="search"
          value={needle}
          onChange={(event) => setNeedle(event.target.value)}
          placeholder={`Find ${def.label.toLowerCase()}…`}
          aria-label={`Find ${def.label.toLowerCase()}`}
          aria-controls={listId}
          className="border border-rule bg-paper px-2 py-1 text-[12px] text-ink placeholder:text-ink-3 focus:border-accent focus:outline-none"
        />
      ) : null}
      <fieldset id={listId} className="flex max-h-64 flex-col overflow-y-auto">
        <legend className="sr-only">{def.label}</legend>
        {shown.length === 0 ? (
          <p className="py-1 text-[12px] text-ink-3">Nothing matches.</p>
        ) : (
          shown.map((option) => (
            <label
              key={option.value}
              className="flex min-h-6 items-center gap-2 px-0.5 text-[12.5px] hover:bg-paper-2"
            >
              <input
                type="checkbox"
                checked={chosen.includes(option.value)}
                onChange={() => {
                  setLast(option.value);
                  setChosen((current) =>
                    current.includes(option.value)
                      ? current.filter((value) => value !== option.value)
                      : [...current, option.value],
                  );
                }}
                className="accent-accent"
              />
              <span className="grow">{option.label}</span>
              {option.count !== undefined ? (
                <span
                  className={`font-mono text-[11.5px] ${
                    option.count === 0 ? "text-ink-3/60" : "text-ink-3"
                  }`}
                >
                  {option.count}
                </span>
              ) : null}
            </label>
          ))
        )}
      </fieldset>
      {def.hint ? <p className="text-[11px] text-ink-3">{def.hint}</p> : null}
      <Footer
        left={
          <>
            {last && lastLabel ? (
              <button
                type="button"
                className={linkButton}
                onClick={() => onApply(setValues(def.key, [last]))}
              >
                Only {lastLabel}
              </button>
            ) : null}
            {chosen.length ? (
              <button type="button" className={linkButton} onClick={() => setChosen([])}>
                None
              </button>
            ) : null}
          </>
        }
      />
    </form>
  );
}

function TextEditor({
  def,
  query,
  onApply,
}: {
  def: Extract<PillDef, { kind: "text" }>;
  query: FindingsQuery;
  onApply: (patch: Partial<FindingsQuery>) => void;
}) {
  return (
    <form
      className="flex flex-col gap-2"
      onSubmit={(event) => {
        event.preventDefault();
        const value = String(new FormData(event.currentTarget).get("value") ?? "").trim();
        onApply({ [def.key]: value || undefined, group: undefined, finding: undefined });
      }}
    >
      <input
        type="search"
        name="value"
        defaultValue={query[def.key] ?? ""}
        placeholder={def.placeholder}
        aria-label={def.label}
        maxLength={200}
        className="border border-rule bg-paper px-2 py-1 font-mono text-[12px] text-ink placeholder:text-ink-3 focus:border-accent focus:outline-none"
      />
      {def.hint ? <p className="text-[11px] text-ink-3">{def.hint}</p> : null}
      <Footer />
    </form>
  );
}

function AgeEditor({
  query,
  onApply,
}: {
  query: FindingsQuery;
  onApply: (patch: Partial<FindingsQuery>) => void;
}) {
  const [mode, setMode] = useState(query.newer_than_days ? "newer" : "older");
  const [days, setDays] = useState(query.older_than_days ?? query.newer_than_days ?? "30");
  const apply = (which: string, value: string) => {
    const n = value.trim();
    onApply({
      older_than_days: which === "older" && n ? n : undefined,
      newer_than_days: which === "newer" && n ? n : undefined,
      group: undefined,
      finding: undefined,
    });
  };
  return (
    <form
      className="flex flex-col gap-2"
      onSubmit={(event) => {
        event.preventDefault();
        apply(mode, days);
      }}
    >
      <fieldset className="flex flex-col gap-1 text-[12.5px]">
        <legend className="mb-1 text-[11px] text-ink-3">First seen</legend>
        <label className="flex items-center gap-2">
          <input
            type="radio"
            name="mode"
            checked={mode === "older"}
            onChange={() => setMode("older")}
            className="accent-accent"
          />
          more than … days ago
        </label>
        <label className="flex items-center gap-2">
          <input
            type="radio"
            name="mode"
            checked={mode === "newer"}
            onChange={() => setMode("newer")}
            className="accent-accent"
          />
          within the last … days
        </label>
      </fieldset>
      <label className="flex items-center gap-2 text-[12.5px]">
        Days
        <input
          type="number"
          min={0}
          max={3650}
          value={days}
          onChange={(event) => setDays(event.target.value)}
          className="w-20 border border-rule bg-paper px-2 py-1 font-mono text-[12px] focus:border-accent focus:outline-none"
        />
      </label>
      <div className="flex gap-1.5">
        {["7", "30", "90"].map((preset) => (
          <button
            key={preset}
            type="button"
            onClick={() => setDays(preset)}
            className={`border px-1.5 py-0.5 font-mono text-[11px] ${
              days === preset ? "border-accent text-accent" : "border-rule text-ink-3"
            }`}
          >
            {preset}d
          </button>
        ))}
      </div>
      <Footer />
    </form>
  );
}

function IntelEditor({
  query,
  onApply,
}: {
  query: FindingsQuery;
  onApply: (patch: Partial<FindingsQuery>) => void;
}) {
  return (
    <form
      className="flex flex-col gap-2"
      onSubmit={(event) => {
        event.preventDefault();
        const data = new FormData(event.currentTarget);
        onApply({
          kev_only: data.get("kev") === "1" ? "1" : undefined,
          min_epss: String(data.get("epss") ?? "") || undefined,
          group: undefined,
          finding: undefined,
        });
      }}
    >
      {/* A fact and a probability, so two controls rather than one
          "exploitable" checkbox that would conflate them (spec 17 §3). */}
      <label className="flex min-h-6 items-center gap-2 text-[12.5px]">
        <input
          type="checkbox"
          name="kev"
          value="1"
          defaultChecked={query.kev_only === "1"}
          className="accent-accent"
        />
        Listed in CISA KEV
      </label>
      <label className="flex items-center gap-2 text-[12.5px]">
        EPSS at least
        <select
          name="epss"
          defaultValue={query.min_epss ?? ""}
          className="border border-rule bg-paper px-1.5 py-1 text-[12px] focus:border-accent focus:outline-none"
        >
          <option value="">any</option>
          {(EPSS_STEPS.includes(query.min_epss ?? "") || !query.min_epss
            ? EPSS_STEPS
            : [...EPSS_STEPS, query.min_epss]
          ).map((step) => (
            <option key={step} value={step}>
              {Math.round(Number(step) * 100)}%
            </option>
          ))}
        </select>
      </label>
      <p className="text-[11px] text-ink-3">
        Both together keep findings that are KEV-listed and over the EPSS line.
      </p>
      <Footer />
    </form>
  );
}

/**
 * Built-in views and the ones saved in this browser. A view is a set of
 * filters, applied in place of whatever is on (the sort is kept). Saved views
 * live in localStorage, and every read and write survives it being absent:
 * without it the built-ins still work and saving says it could not.
 */
function ViewsMenu({
  repoId,
  query,
  open,
  onToggle,
  onClose,
  triggerRef,
}: {
  repoId: string;
  query: FindingsQuery;
  open: boolean;
  onToggle: () => void;
  onClose: () => void;
  triggerRef: (node: HTMLButtonElement | null) => void;
}) {
  const [saved, setSaved] = useState<FindingsView[]>([]);
  const [note, setNote] = useState<string | null>(null);
  const current = viewQueryString(query);

  const storage = (): Storage | null => {
    try {
      return window.localStorage;
    } catch {
      return null;
    }
  };

  const viewLink = (view: FindingsView, removable: boolean) => {
    const on = isCurrentView(query, view.query);
    return (
      <li key={view.id} className="flex items-center gap-1">
        <Link
          href={findingsHref(repoId, query, viewPatch(view.query))}
          scroll={false}
          onClick={onClose}
          aria-current={on ? "true" : undefined}
          className={`grow px-2 py-1 text-[12.5px] hover:bg-paper-2 ${
            on ? "font-semibold text-accent" : "text-ink"
          }`}
        >
          {view.label}
        </Link>
        {removable ? (
          <button
            type="button"
            aria-label={`Delete the saved view ${view.label}`}
            onClick={() => {
              const next = saved.filter((entry) => entry.id !== view.id);
              setSaved(next);
              if (!storeSavedViews(storage(), next)) setNote("Could not update saved views.");
            }}
            className="px-1.5 text-[12px] text-ink-3 hover:text-critical"
          >
            ✕
          </button>
        ) : null}
      </li>
    );
  };

  return (
    <div className="relative">
      <button
        type="button"
        ref={triggerRef}
        aria-haspopup="dialog"
        aria-expanded={open}
        onClick={() => {
          if (!open) {
            setSaved(loadSavedViews(storage()));
            setNote(null);
          }
          onToggle();
        }}
        className="border border-rule bg-paper px-2.5 py-1 text-[12px] text-ink hover:border-accent focus-visible:outline-2 focus-visible:outline-accent"
      >
        Views ▾
      </button>
      {open ? (
        <Popover id="findings-views" label="Views" onClose={onClose} align="right">
          <div>
            <span className="px-2 font-mono text-[10.5px] uppercase tracking-[0.06em] text-ink-3">
              Built in
            </span>
            <ul className="mt-1 flex flex-col">
              {BUILTIN_VIEWS.map((view) => viewLink(view, false))}
            </ul>
          </div>
          <div className="border-t border-rule-soft pt-2">
            <span className="px-2 font-mono text-[10.5px] uppercase tracking-[0.06em] text-ink-3">
              Saved in this browser
            </span>
            {saved.length ? (
              <ul className="mt-1 flex flex-col">{saved.map((view) => viewLink(view, true))}</ul>
            ) : (
              <p className="px-2 py-1 text-[12px] text-ink-3">None yet.</p>
            )}
          </div>
          <form
            className="flex flex-col gap-1.5 border-t border-rule-soft pt-2"
            onSubmit={(event) => {
              event.preventDefault();
              const form = event.currentTarget;
              const name = String(new FormData(form).get("name") ?? "").trim();
              if (!name) return;
              const next = withSavedView(saved, name, current);
              setSaved(next);
              setNote(
                storeSavedViews(storage(), next)
                  ? `Saved “${name}”.`
                  : "This browser would not store it; the view lasts until you leave.",
              );
              form.reset();
            }}
          >
            <label className="flex flex-col gap-1 text-[12px] text-ink-2">
              Save current filters as a view
              <input
                name="name"
                required
                maxLength={60}
                placeholder="e.g. Payments, high+"
                className="border border-rule bg-paper px-2 py-1 text-[12px] text-ink placeholder:text-ink-3 focus:border-accent focus:outline-none"
              />
            </label>
            <button
              type="submit"
              className="self-end border border-accent bg-accent-wash px-2.5 py-1 text-[12px] text-accent hover:bg-accent hover:text-paper"
            >
              Save view
            </button>
            {note ? (
              <p role="status" className="text-[11px] text-ink-3">
                {note}
              </p>
            ) : null}
          </form>
        </Popover>
      ) : null}
    </div>
  );
}
