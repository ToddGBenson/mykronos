import { FilterSelect } from "@/components/filter-select";

/**
 * One toolbar, on every page that filters or looks something up.
 *
 * Before this, each page invented its own: the triage queue had chips on three
 * rows and a GET form on a fourth, the findings tab had two more rows of
 * chips, incident lookup had a bare search box, and the shapes did not match
 * each other. Somebody who learned one page learned only that page.
 *
 * **The URL stays the state, and that is what makes one component possible.**
 * Every control here writes to the query string — the search box through a
 * plain GET form, the dropdowns through `FilterSelect`'s router push — so a
 * filtered view is a link, and the toolbar needs no state of its own to be
 * consistent across pages that share nothing else.
 *
 * The search form carries the active filters as hidden inputs. Without them a
 * GET submit replaces the whole query string, so typing a search term would
 * silently clear the severity somebody had already chosen — the bug this
 * component exists to make impossible rather than to fix once per page.
 */
export function Toolbar({
  search,
  filters = [],
  preserve = {},
  action,
}: {
  /** The lookup box, where a page has one. */
  search?: {
    name: string;
    value?: string;
    placeholder: string;
    /** The accessible name, and the submit button's text. */
    label: string;
    /** Where the form posts. Defaults to the current path. */
    action?: string;
  };
  filters?: {
    label: string;
    name: string;
    value: string | undefined;
    options: readonly { value: string; label: string; hint?: string }[];
    anyLabel?: string;
    clears?: readonly string[];
  }[];
  /** Query parameters the search form must not drop when it submits. */
  preserve?: Record<string, string | undefined>;
  /** A link or button pinned to the right — "portfolio view", and the like. */
  action?: React.ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-y border-rule py-2">
      {search ? (
        <form method="GET" action={search.action} className="flex items-center gap-1.5">
          {Object.entries(preserve).map(([key, value]) =>
            value ? <input key={key} type="hidden" name={key} value={value} /> : null,
          )}
          <input
            type="search"
            name={search.name}
            defaultValue={search.value ?? ""}
            placeholder={search.placeholder}
            aria-label={search.label}
            className="min-w-[16rem] border border-rule bg-paper px-2 py-1 font-mono text-[12px] text-ink placeholder:text-ink-3 focus:border-accent focus:outline-none"
          />
          <button
            type="submit"
            className="border border-accent px-2 py-1 font-mono text-[12px] text-accent hover:bg-accent-wash"
          >
            {search.label}
          </button>
        </form>
      ) : null}

      {filters.map((filter) => (
        <FilterSelect key={filter.name} {...filter} />
      ))}

      {action ? <div className="ml-auto">{action}</div> : null}
    </div>
  );
}
