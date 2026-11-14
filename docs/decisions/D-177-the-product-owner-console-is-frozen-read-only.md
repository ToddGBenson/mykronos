## D-177 — The Product Owner console is frozen read-only; MyKronos holds DevSecOps facts, the Hub holds operations

**2026-11-13.** **Status:** Decided, implemented (TheHub #61588)
**Story:** TheHub #61588

**The decision (operator, 2026-11-13).** "If it is not a devsecops feature,
function, etc, it would not belong in mykronos. Hub specific items, such as
incidents, do not belong in mykronos for now." In short: MyKronos is
DevSecOps only, and operations mostly live in the Hub.

**What is frozen.** The Product Owner console's story and sprint writes. The
backend answers `410 Gone` with "Frozen read-only since 2026-11-13: stories and
sprints live in the Hub" on four routes under
`/api/dashboard/repos/{repo_id}/product-owner/`: `stories/{id}/pull`,
`stories/{id}/return`, `rank` and `template`. The GET routes stay. Nothing
else called these four routes, so the routes themselves are frozen, not only
the buttons. The page drops the pull-into-sprint, back-to-backlog and rank
up/down buttons and the starter-template picker, and shows the sentence in
their place. Approval decisions (`.../approvals/{id}/decision`) are not
stories or sprints, are shared with the Approvals page, and are untouched.

**What else this freezes, as read-only feeds for now.** Other MyKronos
operations surfaces fall under the same decision: the Health page's jobs and
credentials sections, the Today run sheet, and the deployment probe page. They
stay as they are, read-only feeds, and take no new features. The next-sprint
signals also stay as feeds.

**Why a switch, not a deletion.** `product_owner.WRITES_FROZEN` is `True` and
nothing sets it at runtime. The write paths and their tests stay, so reversing
the decision is one line and not a rebuild; the older tests run with it off
(`tests/conftest.py`), and `tests/test_po_console_frozen.py` runs with it on.
