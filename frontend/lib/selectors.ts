/**
 * Surface selectors on the Threat Model tab (TheHub #60825).
 *
 * A surface's selectors say where it is, so a finding can be placed inside it:
 * path globs for code, image repositories for containers, `host:port` and
 * hostnames for the network and DAST. The backend validates and normalises
 * them; this only moves them between a comma-separated input and the lists
 * the API takes, and says them back in one line.
 */

export const SELECTOR_KINDS = ["paths", "images", "addresses", "hostnames"] as const;
export type SelectorKind = (typeof SELECTOR_KINDS)[number];
export type Selectors = Record<SelectorKind, string[]>;

export const SELECTOR_LABELS: Record<SelectorKind, string> = {
  paths: "paths",
  images: "images",
  addresses: "host:port",
  hostnames: "hostnames",
};

export const SELECTOR_PLACEHOLDERS: Record<SelectorKind, string> = {
  paths: "backend/**, frontend/app/",
  images: "acme/api, postgres",
  addresses: "10.0.0.5:5433, *:22",
  hostnames: "app.example.net, *.example.net",
};

/** `"a, b ,,c"` -> `["a", "b", "c"]`, order kept, duplicates dropped. */
export function splitList(text: string): string[] {
  const out: string[] = [];
  for (const part of text.split(",")) {
    const value = part.trim();
    if (value && !out.includes(value)) out.push(value);
  }
  return out;
}

/** The request body's `selectors`, or `undefined` when nothing was typed. */
export function selectorsFromInputs(
  inputs: Partial<Record<SelectorKind, string>>,
): Selectors | undefined {
  const out = {} as Selectors;
  let any = false;
  for (const kind of SELECTOR_KINDS) {
    out[kind] = splitList(inputs[kind] ?? "");
    if (out[kind].length) any = true;
  }
  return any ? out : undefined;
}

/** How many selectors a surface carries, all kinds together. */
export function selectorCount(selectors: Partial<Selectors> | null | undefined): number {
  if (!selectors) return 0;
  return SELECTOR_KINDS.reduce((sum, kind) => sum + (selectors[kind]?.length ?? 0), 0);
}

/**
 * One chip per selector, labelled with its kind. Empty is shown by the caller
 * as "not located", which is the honest reading: a surface with no selectors
 * matches no finding.
 */
export function selectorChips(
  selectors: Partial<Selectors> | null | undefined,
): { kind: SelectorKind; value: string }[] {
  if (!selectors) return [];
  return SELECTOR_KINDS.flatMap((kind) =>
    (selectors[kind] ?? []).map((value) => ({ kind, value })),
  );
}

/** `CR:H IR:– AR:L`, or empty when nothing is overridden. */
export function requirementsLabel(row: {
  cr?: string | null;
  ir?: string | null;
  ar?: string | null;
}): string {
  if (!row.cr && !row.ir && !row.ar) return "";
  return [
    `CR:${row.cr ?? "–"}`,
    `IR:${row.ir ?? "–"}`,
    `AR:${row.ar ?? "–"}`,
  ].join(" ");
}
