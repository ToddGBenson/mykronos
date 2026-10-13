## D-161 — The GitHub App holds `issues: read` and writes no issues; its permission set is pinned to its call sites

**2026-10-12.** **Status:** Decided by the Product Owner (option B, TheHub #60725), implemented
**Spec:** follows [D-133](../DECISIONS.md) and [D-156](D-156-a-github-issues-backlog-is-read-only-and-its-sprint-is-its-label.md)

**The problem.** `REQUIRED_PERMISSIONS` listed `issues: write` and
`actions: write`. On 2026-10-11 (#60570) the registered App held no `issues`
permission and only `actions: read`. The code claimed writes the App could not
make, and the App lacked the one read the PO tab needs on a private repository.
The operator chose to shrink the code before granting anything.

**The inventory (measured 2026-10-12, live MyKronos database).**

| Write | Callers | Live? |
|---|---|---|
| `create_issue`, `update_issue`, `comment_on_issue`, `close_issue` (`issues: write`) | `groom.open_or_update_story` and `groom.sync_story_dispositions`. They are reached from the Groom buttons (`POST /api/triage/.../groom`) and from the `routing` job. | **No.** `routing` is off (`MYKRONOS_ROUTING_ENABLED=false`, last run 2026-09-18). The last groom was also 2026-09-18 (186 issues, 184 on mykronos and 2 on keel). The App has no `issues` permission, so every click since then got a 403. D-133 moved work items to TheHub. |
| `delete_actions_secret` (`secrets: write`) | none | **No.** It is dead code. `put_actions_secret` still earns `secrets: write`. |
| `dispatch_workflow` (`actions: write`) | Scan now (`POST /api/repos/{id}/scan`), the stalled-lanes panel, and the `fix-verification` job | **Yes.** `keel` and `binnacle` are active and `scanned_by=github_actions`. |
| `set_workflow_state` (`actions: write`) | the workflow switches (`PUT /api/repos/{id}/workflows/{cap}/enable\|disable`) and `mykronos workflows --enable/--disable` | **Yes**, for the same two repositories. |
| contents, workflows, pull_requests, secrets and checks writes | the installer, resync, Patchwork, the PO tab, rotation, Oracle, ingest, and the PR stamps | **Yes.** These were already granted and are unchanged. |

**The decision.**
- Issue writes are retired.
  - The four methods are removed from `GitHubClient`, the fake and the REST
    client. So are `groom.py`, the `routing` job, and its two settings and
    compose variable.
  - The two groom routes stay and answer **410 Gone** with the reason. The
    agent work queue (spec 36) still names the combination route, and a reason
    is a better answer than a 404.
  - The frontend Groom buttons and their proxies are removed. The
    `groomed_stories` table stays as history.
- `delete_actions_secret` is removed.
- `issues` drops to `read`, which `po_issues` spends. `actions` **stays
  `write`**: it has live callers on two onboarded repositories, which is the
  condition #60725's option B named for keeping it.
- `METHOD_PERMISSIONS` in `github/client.py` maps every client method to what
  it spends. `tests/test_github_permissions.py` fails on each of these:
  - a method that is not declared;
  - a REST write verb not declared at `write`;
  - a declared write that is not required;
  - a required permission no method spends.

  It also pins the literal set.

**What the operator must grant afterwards.** Two changes on the App, and
nothing else:
- `Issues: Read-only`, which is new.
- `Actions: Read and write`, up from read.

Then accept the request on the installation. These are the only differences
between what the App holds and `REQUIRED_PERMISSIONS` plus
`OPTIONAL_PERMISSIONS`.

**Rejected.**
- *Retiring Actions dispatch as well, to reach `issues: read` alone.* That
  would remove Scan now and the pause switch for keel and binnacle, which is a
  product change. Nothing has decided against those features. If the operator
  does decide it, it is a follow-up story, and this test makes it visible.
- *Keeping grooming and filing into TheHub instead.* That is a new integration,
  and D-133 already says MyKronos reads and moves TheHub stories. It does not
  author them.
