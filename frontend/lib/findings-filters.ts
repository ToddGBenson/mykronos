/**
 * The Findings tab's filter state: what is in the URL, what each pill says,
 * and the link every click goes to (option C, filter pills + clickable
 * summary).
 *
 * **The URL is the state.** Every filter is a query parameter, so a filtered
 * view survives a refresh, renders on the server, and is a link somebody can
 * send. Nothing here holds state of its own: each function takes the query
 * and returns a query or an href.
 *
 * **Several values, one parameter.** A multi-select filter is stored
 * comma-separated (`severity=critical,high`). Reading also accepts a repeated
 * parameter (`severity=critical&severity=high`, which Next hands over as an
 * array) and the single value every older link carries, so no link anybody
 * saved stops working.
 *
 * Pure — no React, no `window` — so the vitest suite runs it directly.
 */

export type FindingsQuery = {
  tab?: string;
  severity?: string;
  capability?: string;
  status?: string;
  /** Free-text, matched against rule_id and title (spec 17 §3). */
  rule_id?: string;
  /** "1" when set — CISA KEV-listed CVEs only (spec 17 §3, #20). */
  kev_only?: string;
  /** EPSS threshold as a string, e.g. "0.5" (spec 17 §3, #20). */
  min_epss?: string;
  /** classify()'s classification, plus toxic_combination (spec 18 §5.1). */
  triage?: string;
  /** "1" when set — only groups Patchwork produced a fix for (spec 19 §3.2). */
  fixable?: string;
  /** A CODEOWNERS handle or team, or one of two queues: `unresolved` (the
   *  platform could not work it out) and `unclaimed` (nobody has taken it by
   *  name — it has an owner only because the repository does). */
  owner?: string;
  /** overdue | due_soon | on_track | no_target (spec 24 §2.4). */
  due?: string;
  /** A stored effective severity (TheHub #60828). */
  effective?: string;
  /** down | up | unchanged | not_rescorable (TheHub #60828). */
  rescored?: string;
  /** `none` (no declared surface places it) or a declared surface's id. */
  component?: string;
  /** internet | internal | local | unknown | unplaced: where the placing
   *  surface sits. */
  exposure?: string;
  /** File path or package: a glob with `*`/`?`, otherwise a substring. */
  path?: string;
  /** First seen at least N days ago. */
  older_than_days?: string;
  /** First seen within the last N days. */
  newer_than_days?: string;
  /** How the rows are ordered; absent is the backend's worst-first. */
  sort?: string;
  /** Which deduplicated row is open. */
  group?: string;
  /** Which occurrence inside that row is open. */
  finding?: string;
};

export type FilterKey = Exclude<keyof FindingsQuery, "tab" | "sort" | "group" | "finding">;

/** Filters that take several values. */
export const MULTI_KEYS = [
  "status",
  "severity",
  "capability",
  "exposure",
  "due",
  "effective",
  "component",
  "owner",
  "triage",
  "rescored",
] as const satisfies readonly FilterKey[];

export type MultiKey = (typeof MULTI_KEYS)[number];

/** Every filter parameter, in the order a link writes them. */
export const FILTER_KEYS: readonly FilterKey[] = [
  ...MULTI_KEYS,
  "rule_id",
  "path",
  "kev_only",
  "min_epss",
  "fixable",
  "older_than_days",
  "newer_than_days",
];

const ALL_KEYS: readonly (keyof FindingsQuery)[] = [
  "tab",
  ...FILTER_KEYS,
  "sort",
  "group",
  "finding",
];

/** Changing a filter clears the selection: the row that was open is routinely
 *  not in the new list, and a detail pane describing something the table no
 *  longer shows is worse than an empty one. */
export const CLEAR_SELECTION = { group: undefined, finding: undefined } as const;

export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

export const STATUS_LABELS: Record<string, string> = {
  open: "open",
  accepted_risk: "accepted risk",
  false_positive: "false positive",
  fixed: "fixed",
  suppressed: "suppressed",
  superseded: "superseded",
  // Open when its capability lost the grant that lets it report (B-047).
  stranded: "stranded",
};

export const EXPOSURE_LABELS: Record<string, string> = {
  internet: "internet-facing",
  internal: "internal",
  local: "local only",
  unknown: "declared, exposure unknown",
  unplaced: "not placed",
};

export const DUE_LABELS: Record<string, string> = {
  overdue: "overdue",
  due_soon: "due soon",
  on_track: "on track",
  no_target: "no target",
};

export const TRIAGE_LABELS: Record<string, string> = {
  toxic_combination: "toxic combo",
  true_positive: "true positive",
  likely_false_positive: "likely false positive",
  needs_human_judgment: "needs judgment",
};

export const RESCORED_LABELS: Record<string, string> = {
  down: "rescored down (verified)",
  up: "rescored up",
  unchanged: "unchanged",
  not_rescorable: "not rescorable",
};

export const OWNER_QUEUE_LABELS: Record<string, string> = {
  unclaimed: "unclaimed (nobody by name)",
  unresolved: "unresolved (no owner found)",
};

/** Every value a parameter carries: comma-separated, repeated, or single.
 *  Blanks are dropped and duplicates collapse, first occurrence kept. */
export function readValues(raw: unknown): string[] {
  const items = Array.isArray(raw) ? raw : raw === undefined || raw === null ? [] : [raw];
  const out: string[] = [];
  for (const item of items) {
    for (const part of String(item).split(",")) {
      const value = part.trim();
      if (value && !out.includes(value)) out.push(value);
    }
  }
  return out;
}

/**
 * The query as the tab works with it: each multi-value filter one
 * comma-joined string, every other key its first value. Accepts what Next
 * passes as `searchParams` (strings, or arrays for a repeated key).
 */
export function normalizeQuery(raw: Record<string, unknown>): FindingsQuery {
  const out: FindingsQuery = {};
  for (const key of ALL_KEYS) {
    const value = raw[key];
    if (value === undefined || value === null) continue;
    if ((MULTI_KEYS as readonly string[]).includes(key)) {
      const values = readValues(value);
      if (values.length) out[key] = values.join(",");
    } else {
      const first = Array.isArray(value) ? value[0] : value;
      if (first !== undefined && first !== null && String(first) !== "") {
        out[key] = String(first);
      }
    }
  }
  return out;
}

/** The values currently applied for one filter. */
export function valuesOf(query: FindingsQuery, key: FilterKey): string[] {
  return readValues(query[key]);
}

/** A patch that sets one filter to these values (none removes it). `status`
 *  set to exactly `open` is removed too: open is the default, and every link
 *  into the tab already means it. */
export function setValues(key: FilterKey, values: readonly string[]): Partial<FindingsQuery> {
  const clean = readValues([...values]);
  if (key === "status" && clean.length === 1 && clean[0] === "open") {
    return { status: undefined, ...CLEAR_SELECTION };
  }
  return { [key]: clean.length ? clean.join(",") : undefined, ...CLEAR_SELECTION };
}

/** A patch that adds the value if absent and removes it if present. */
export function toggleValue(
  query: FindingsQuery,
  key: FilterKey,
  value: string,
): Partial<FindingsQuery> {
  const current = valuesOf(query, key);
  const next = current.includes(value)
    ? current.filter((entry) => entry !== value)
    : [...current, value];
  return setValues(key, next);
}

/** The link for the query with `patch` applied. `tab=findings` is always
 *  written (spec 17 §2.4): a link that dropped it would bounce the reader to
 *  the default tab. Keys are written in a fixed order so equal views are
 *  equal links. */
export function findingsHref(
  repoId: string,
  query: FindingsQuery,
  patch: Partial<FindingsQuery> = {},
): string {
  const merged: FindingsQuery = { ...query, ...patch };
  const next = new URLSearchParams();
  next.set("tab", "findings");
  for (const key of ALL_KEYS) {
    if (key === "tab") continue;
    const value = merged[key];
    if (value) next.set(key, value);
  }
  return `/repos/${repoId}?${next.toString()}`;
}

/** A patch removing every filter. The sort order is a preference, not a
 *  filter, and stays. */
export function clearAll(): Partial<FindingsQuery> {
  const patch: Partial<FindingsQuery> = { ...CLEAR_SELECTION };
  for (const key of FILTER_KEYS) patch[key] = undefined;
  return patch;
}

/** Whether anything narrows the list beyond the status it shows. */
export function hasNarrowingFilters(query: FindingsQuery): boolean {
  return FILTER_KEYS.some((key) => key !== "status" && Boolean(query[key]));
}

/** How many filters are applied, status included when it is not the
 *  default. Drives "Clear all". */
export function activeFilterCount(query: FindingsQuery): number {
  return FILTER_KEYS.filter((key) => {
    if (key === "older_than_days" || key === "newer_than_days") return false;
    if (key === "kev_only" || key === "min_epss") return false;
    return Boolean(query[key]);
  }).length +
    (query.older_than_days || query.newer_than_days ? 1 : 0) +
    (query.kev_only || query.min_epss ? 1 : 0);
}

/** What a pill says it is set to: `any` when unset, the labels when one or
 *  two are on, and "first +N" beyond that so a row of pills stays one row. */
export function pillValue(values: readonly string[], label: (value: string) => string): string {
  if (values.length === 0) return "any";
  if (values.length <= 2) return values.map(label).join(", ");
  return `${label(values[0])} +${values.length - 1}`;
}

/** The query-string form of the filters only (no tab, selection or sort),
 *  for saving as a view. */
export function viewQueryString(query: FindingsQuery): string {
  const out = new URLSearchParams();
  for (const key of FILTER_KEYS) {
    const value = query[key];
    if (value) out.set(key, value);
  }
  return out.toString();
}

/** The filters a view's query string sets, every other filter cleared, so a
 *  view is a destination rather than an addition to whatever was on. */
export function viewPatch(queryString: string): Partial<FindingsQuery> {
  const parsed = new URLSearchParams(queryString);
  const raw: Record<string, unknown> = {};
  for (const key of FILTER_KEYS) {
    const all = parsed.getAll(key);
    if (all.length) raw[key] = all;
  }
  return { ...clearAll(), ...normalizeQuery(raw) };
}

/** Whether the current filters are exactly this view's. */
export function isCurrentView(query: FindingsQuery, queryString: string): boolean {
  return canonical({ ...query, ...viewPatch(queryString) }) === canonical(query);
}

/** The filters with each value list sorted, so order never decides equality. */
function canonical(query: FindingsQuery): string {
  return FILTER_KEYS.map((key) => `${key}=${readValues(query[key]).sort().join(",")}`).join("&");
}

export type FindingsView = { id: string; label: string; query: string };

/** Named starting points: the questions this tab is opened to answer. */
export const BUILTIN_VIEWS: readonly FindingsView[] = [
  { id: "all-open", label: "All open", query: "" },
  {
    id: "internet-high",
    label: "Internet-facing high+",
    query: "exposure=internet&severity=critical,high",
  },
  { id: "overdue", label: "Overdue", query: "due=overdue" },
  { id: "kev-epss", label: "KEV & EPSS ≥ 50%", query: "kev_only=1&min_epss=0.5" },
  { id: "kev", label: "Known exploited (KEV)", query: "kev_only=1" },
  { id: "unclaimed", label: "Unclaimed", query: "owner=unclaimed" },
  { id: "fixable", label: "Fixable now", query: "fixable=1" },
  { id: "toxic", label: "Toxic combinations", query: "triage=toxic_combination" },
];

/** Where saved views live. Per browser, by design: a view is a convenience,
 *  and the URL it stands for is the shareable thing. */
export const SAVED_VIEWS_KEY = "mykronos.findings.views.v1";

type StorageLike = Pick<Storage, "getItem" | "setItem">;

/** Saved views, or none — never a throw. Storage can be absent, blocked, or
 *  hold something another version wrote. */
export function loadSavedViews(storage: StorageLike | null | undefined): FindingsView[] {
  if (!storage) return [];
  try {
    const parsed: unknown = JSON.parse(storage.getItem(SAVED_VIEWS_KEY) ?? "[]");
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (entry): entry is FindingsView =>
        typeof entry === "object" &&
        entry !== null &&
        typeof (entry as FindingsView).id === "string" &&
        typeof (entry as FindingsView).label === "string" &&
        typeof (entry as FindingsView).query === "string",
    );
  } catch {
    return [];
  }
}

/** Store the list; false when storage refused it (the caller says so). */
export function storeSavedViews(
  storage: StorageLike | null | undefined,
  views: readonly FindingsView[],
): boolean {
  if (!storage) return false;
  try {
    storage.setItem(SAVED_VIEWS_KEY, JSON.stringify(views));
    return true;
  } catch {
    return false;
  }
}

/** The list with this view added, replacing one of the same name. */
export function withSavedView(
  views: readonly FindingsView[],
  label: string,
  query: string,
): FindingsView[] {
  const name = label.trim();
  if (!name) return [...views];
  const rest = views.filter((view) => view.label !== name);
  return [...rest, { id: `saved-${Date.now().toString(36)}`, label: name, query }];
}

export const SORTS = [
  { value: "", label: "Worst first" },
  { value: "newest", label: "Newest first" },
  { value: "oldest", label: "Oldest first" },
  { value: "occurrences", label: "Most occurrences" },
  { value: "due", label: "Due soonest" },
] as const;

type Sortable = {
  severity: string;
  occurrences: number;
  age_days?: number | null;
  due_at?: string | null;
};

const SEVERITY_RANK: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/**
 * The rows in the order asked for. Done on the server render, over the rows
 * the backend returned: absent keeps the backend's own worst-first order, and
 * every other order breaks ties by it, so equal rows never reshuffle.
 */
export function sortGroups<T extends Sortable>(groups: readonly T[], sort: string | undefined): T[] {
  const indexed = groups.map((group, index) => ({ group, index }));
  const bySeverity = (a: T, b: T) =>
    (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9);
  const age = (group: T) => group.age_days ?? -1;
  const due = (group: T) =>
    group.due_at ? new Date(group.due_at).getTime() : Number.POSITIVE_INFINITY;
  const compare: ((a: T, b: T) => number) | undefined = {
    newest: (a: T, b: T) => age(a) - age(b),
    oldest: (a: T, b: T) => age(b) - age(a),
    occurrences: (a: T, b: T) => b.occurrences - a.occurrences,
    due: (a: T, b: T) => due(a) - due(b),
  }[sort ?? ""];
  if (!compare) return [...groups];
  return indexed
    .sort((a, b) => compare(a.group, b.group) || bySeverity(a.group, b.group) || a.index - b.index)
    .map((entry) => entry.group);
}

/** The open-findings API's parameters for this query. Multi-value filters go
 *  as arrays (sent as repeated parameters); absent is "no filter". */
export function findingsApiQuery(query: FindingsQuery) {
  const list = (key: FilterKey) => {
    const values = valuesOf(query, key);
    return values.length ? values : undefined;
  };
  const days = (value: string | undefined) => {
    if (!value) return undefined;
    const parsed = Number.parseInt(value, 10);
    return Number.isFinite(parsed) && parsed >= 0 ? parsed : undefined;
  };
  const epss = query.min_epss ? Number(query.min_epss) : undefined;
  return {
    severity: list("severity"),
    capability: list("capability"),
    finding_status: list("status"),
    rule_id: query.rule_id || undefined,
    kev_only: query.kev_only === "1",
    min_epss: epss !== undefined && Number.isFinite(epss) ? epss : undefined,
    triage: list("triage"),
    fixable: query.fixable === "1" ? true : undefined,
    due: list("due"),
    owner: list("owner"),
    effective: list("effective"),
    rescored: list("rescored"),
    component: list("component"),
    exposure: list("exposure"),
    path: query.path || undefined,
    older_than_days: days(query.older_than_days),
    newer_than_days: days(query.newer_than_days),
  };
}

/**
 * The export links' parameters (TheHub #60762). The export takes one
 * severity, one capability, one status and the rule text; a filter it cannot
 * carry — a second severity, or any of the tab's other filters — is named in
 * `unexported` so the links say the file does not match rather than imply it.
 */
export function exportQuery(query: FindingsQuery): {
  params: URLSearchParams;
  unexported: string[];
} {
  const params = new URLSearchParams();
  const unexported: string[] = [];
  const single = (key: "severity" | "capability", name: string) => {
    const values = valuesOf(query, key);
    if (values.length === 1) params.set(key, values[0]);
    else if (values.length > 1) unexported.push(`more than one ${name}`);
  };
  single("severity", "severity");
  single("capability", "scan type");
  // Status defaults to open, as the tab does.
  const statuses = valuesOf(query, "status");
  params.set("finding_status", statuses.length === 1 ? statuses[0] : "open");
  if (statuses.length > 1) unexported.push("more than one status");
  if (query.rule_id) params.set("rule_id", query.rule_id);
  const names: [FilterKey, string][] = [
    ["kev_only", "KEV"],
    ["min_epss", "EPSS"],
    ["triage", "triage"],
    ["fixable", "fixable"],
    ["owner", "owner"],
    ["due", "due"],
    ["effective", "effective severity"],
    ["rescored", "rescoring"],
    ["component", "component"],
    ["exposure", "exposure"],
    ["path", "path"],
    ["older_than_days", "age"],
    ["newer_than_days", "age"],
  ];
  for (const [key, name] of names) {
    if (query[key] && !unexported.includes(name)) unexported.push(name);
  }
  return { params, unexported };
}
