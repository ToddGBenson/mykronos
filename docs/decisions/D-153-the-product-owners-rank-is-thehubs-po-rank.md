## D-153 — The Product Owner's rank is TheHub's `po_rank`

**2026-10-11.** **Status:** Implemented (B-068, TheHub #60566). Supersedes
the rank paragraph of D-133.

**The decision.** The Product Owner tab reads a story's rank from TheHub's
`dev_stories.po_rank` (TheHub migration 329) and writes it with
`PATCH /api/dev/stories/{id}` carrying `{"po_rank": n}` and nothing else.
MyKronos's `po_backlog_rank` table is copied across once by
`python -m mykronos.backfill_po_rank` and then dropped, through a new
`RETIRED_TABLES` list beside D-052's `RETIRED_COLUMNS`. The story now has one
rank, in the one place its other facts live, which is what D-133 is for.

**The rank write is the third Hub write, and the PATCH is narrow on our
side.** ADR 0093 (TheHub) allows MyKronos a bucket move, the autonomy switch
and the rank. A PATCH to a story could edit its title, and TheHub cannot yet
refuse that: the Hub token is its admin token. So `HubClient.set_rank` takes a
story id and a rank and builds the body itself. No caller can pass another
field through it.

**One PATCH per changed position, and the first refusal stops the rest.** The
order is computed as before, from the stories and ranks TheHub returns now, and
the whole visible order is stored. Only the positions that differ from TheHub's
are sent. A refusal is shown in TheHub's words and not retried (a 5xx is
reported as "TheHub failed", and its body is not passed on). Stories written
before the refusal keep their new rank. The `po.rank` audit row records the
outcome (`ranked`, `unchanged`, `refused`, `unreachable`) and the story ids
written, so a half-applied move can be read back. A press that moves nothing,
such as "up" on the top story, writes nothing. Before, it wrote the whole order.

**One rank per story, not per repository.** `po_backlog_rank` was keyed by
(repository, story) and `po_rank` is keyed by story. A story belongs to two
repositories only when one counts untagged stories and the story also carries
the other's tag. The backfill reports such a story and does not choose between
the two ranks. Each repository's tab writes positions from 1 for its own
backlog, so Mission Control's cross-repository `order=po_rank` view
interleaves repositories by position. It does not show one global priority.
Nothing in phase 1 asks for a global priority.

**The backfill never overwrites.** A story already holding a `po_rank` in
TheHub is left alone and reported, because the tab may have ranked it since. A
story TheHub no longer has (404) is skipped and reported. `--dry-run` makes
the same reads and writes nothing. On 2026-10-11 production's
`po_backlog_rank` held 0 rows, so the copy is a formality there.

**The drop is a named list, not inference.** This is D-052's reasoning applied
to tables. "Drop every table the models do not declare" would destroy data on
the first rollback, so a table goes only when it is named. The drop runs at
start-up through `create_all`, so the backfill has to run against the database
before an image carrying the drop starts. The backfill reads the table with
plain SQL and never calls `create_all`. That keeps it usable after the model
is deleted.

**Rejected.**
- *Keep `po_backlog_rank` as a cache of the Hub's rank.* That keeps two copies
  of one fact, which B-068 exists to remove.
- *A bulk rank endpoint in TheHub.* It would mean a second TheHub change and a
  new write shape for ADR 0093. N small PATCHes are fine for one operator's
  backlog.
- *Resolve two-repository conflicts by taking the lower rank.* That makes the
  Product Owner's decision for them, silently.
