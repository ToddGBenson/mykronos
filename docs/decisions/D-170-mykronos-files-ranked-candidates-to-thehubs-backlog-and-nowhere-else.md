## D-170 — MyKronos files ranked next-sprint candidates to TheHub's backlog, and nowhere else

**2026-10-21.** **Status:** Decided, implemented
**Story:** TheHub #60862 (epic #60858, briefing B4) · Refs D-153, TheHub ADR 0093, [spec 35](../../specs/35-product-owner-tab.md)

**The rule.** The daily `briefing-signal-filing` job creates TheHub stories
through `POST /api/dev/stories`, and only these:

- in the **backlog** bucket. `HubClient.create_story` refuses any other bucket
  before TheHub is asked. A story created in the sprint would arm autonomous
  dispatch, which `pull_into_sprint`'s ordering exists to prevent (spec 35);
- tagged `briefing-signal` and `briefing-signal:<key>`, with the key in
  `source_ref` and the detail, where the key is a hash of the repository and
  the fix or lane, stable from day to day;
- at most `sprint_signal.FILE_LIMIT` (3) a day, highest score first, each with
  the score's factors, three options and a recommendation.

It never edits, moves or closes a story. The other writes stay what D-153 and
TheHub ADR 0093 allow: the bucket move, the autonomy switch and the rank.

**Why the backlog.** On Todd's board the backlog holds what needs his
decision. A ranked candidate is a proposal: pull it into a sprint, leave it, or
accept the risk. Filing it there puts it where he decides, and filing it
nowhere else keeps the decision his.

**Why no duplicates is the job's own check.** TheHub has no uniqueness on a
story's title or tags, so the job reads every bucket fresh before it files
(not the briefing's few-minutes cache) and files nothing whose key is on a
story in any bucket, including `done`, nor anything the briefing's own matcher
(`daily_briefing.on_board`: the fix id in the story, or the title) says is a
story already. A person who renames a filed story or removes the
`briefing-signal` tag does not cause a second one while the key tag or the
key in the detail survives.

**When TheHub is not connected** the job records `skipped` with the reason in
`job_runs`, so MyKronos Health shows it, and the page still ranks.
