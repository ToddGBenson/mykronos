# Decisions, one file each

From D-137 on, every implementation decision the specs do not settle is its own
file here (D-149). [`../DECISIONS.md`](../DECISIONS.md) holds D-001 to D-136 as
they were written, and the generated index of this directory.

**To record one:**

1. Take the next free number: one past the highest in `../DECISIONS.md` and
   here, together.
2. Write `D-nnn-<slug>.md`, where the slug is lowercase words joined by hyphens.
   The file holds one `## D-nnn — Title` heading, a `**Status:**` line, then the
   decision and why, in the log's usual format. Relative links are from this
   directory: `../../specs/…`, `../approvals.md`.
3. Run `python scripts/decisions_index.py` and commit the file together with
   the updated index.

A decision is superseded by a new file, never edited. `backend/tests/test_decisions_log.py`
fails on a number used twice (across the log and here), a heading whose number
is not the filename's, an index that does not match this directory, and an
entry with no reasoning in it.
