## D-153 — A GitHub-Issues backlog is read only; its sprint is the `ready` label, and its gate comes from the project when the App can read it, otherwise from labels

**2026-10-11.** **Status:** Decided in the build (B-072, TheHub #60570), implemented
**Spec:** [35 §9](../../specs/35-product-owner-tab.md#9-a-github-issues-backlog-b-072) ·
TheHub ADR 0093 keeps the write rules

**Context.** keel's work items are GitHub issues, not TheHub stories (keel
`docs/15-tracking.md`). Its gate is a Projects single-select field `Gate`
(`G0 intake` … `G5 released`), its `ready` label marks a G1-approved story
the unattended sprint runner may take, and its sprint is `./keel sprint`
(`docs/16-sprint-automation.md`). Phase 1 refused any `backlog.source` but
`thehub`, so keel's tab showed its process and no backlog. B-072 asked for a
read-only adapter, and four things it left open had to be settled to build one.

**Decisions.**

1. **Read only, and the writes are refused rather than hidden.** Pull into
   sprint, back to backlog and rank answer `409` with one sentence: this
   backlog is GitHub Issues, which the tab reads only; keel's sprint is
   `./keel sprint`. Each refusal is audit-logged with
   `outcome=refused_read_only_source`, and TheHub is never asked. *Why:* the
   tab's writes are TheHub's bucket move and MyKronos's rank, and neither
   means anything for an issue. A label write from here would be a second
   way into keel's sprint that its own runner and gate records know nothing
   about. TheHub ADR 0093 owns what a write is; this changes none of it.
2. **The Sprint view is the issues carrying any of the manifest's
   `sprint_labels` (default `[ready]`).** Open ones are placed on the spine by gate; ones closed
   in the last 14 days show as done, so sprint progress has a numerator. A
   closed issue that never carried the label is history and is not shown.
   *Why:* keel has two: `ready` is exactly the set `./keel sprint
   --unattended` takes, and `sprint` is the label the supervised `./keel
   sprint` puts on the issue it opens (`scripts/sprint.sh`). Together they are
   the nearest thing keel has to "committed". A milestone or an assignee would
   be a convention keel does not use.
3. **Gate source: the project when it is named and readable, otherwise the
   `gate:G<n>` labels, never a mix.** With a readable project, an issue not on
   the board has no gate rather than a label's. When the project cannot be
   read the tab says so, with the reason, under the header. *Why:* showing
   some gates from the board and some from labels would present two sources
   as one. And "could not read the board" must not look like "no gates".
4. **Evidence the issue does not show is *unavailable*, not failed.**
   `sized` reads a `size:` label, `detail_500` the body length and `sprint`
   the label. `acceptance_criteria` and `threat_model` live in the body and
   in gate-record comments, which the adapter does not parse. *Why:* phase 1
   already treats unseen evidence as "could not see" (`threat_model`), and
   parsing free text into a pass would claim a check that never ran.

**The permission finding (measured 2026-10-11, installation 152755402).**
The live installation holds `checks`, `contents`, `pull_requests`, `secrets`
and `workflows` at write, plus `actions`, `administration` and `metadata` at
read. It holds **no `issues` permission**, although `REQUIRED_PERMISSIONS`
lists `issues: write`. Listing keel's issues still answers 200, because keel
is public and GitHub serves public issues without the permission. If keel
goes private, the read fails, and the tab says the App needs `issues: read`
instead of showing an empty backlog. There is **no Projects permission**: the
App's GraphQL view of `ToddGBenson` and of `keel` returns zero Projects.
As GitHub documents App permissions, `organization_projects` covers boards
an organisation owns, and none covers a board owned by a user account, which
keel's would be. Whether keel's board exists at all could not be checked: the
operator's `gh` token lacks `read:project`. Either way the label fallback is
the path keel will take, and its manifest should name no `project` until that
changes.

**Not decided here:** switching keel's manifest to `github_issues`. That is
keel's change, by its own pull request.
