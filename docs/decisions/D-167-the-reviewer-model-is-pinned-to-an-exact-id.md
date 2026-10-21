## D-167 — The independent reviewer runs a pinned model, claude-opus-5-5

**2026-10-21.** **Status:** Decided, implemented
**Story:** TheHub #60866 (option A) · Refs D-047, D-149, [spec 34 §4.3](../../specs/34-duties-delegation-and-independent-approval.md)

**The rule.** The platform-started independent reviewer runs `claude-opus-5-5`,
an exact model id, pinned on 2026-10-21. Every place this repository
configures its own model names it: the `reviewer_model` default in
`backend/mykronos/config.py`, the fallback in `approvals/reviewer.py`, the
compose default in `deploy/mykronos/docker-compose.yml`, `backend/.env.example`
and the default family in `scripts/enable-agent-reviewer.ps1`. Upgrading it is
a reviewed change: one pull request that moves every one of those lines at
once and says why. `backend/tests/test_ai_checks.py`
(`TestThisRepositorysOwnModelIsPinned`) fails on a family alias in any of
them, and on any two of them disagreeing.

**Why pin.** The reviewer runs in `shadow` before it runs `live`, and the
shadow-agreement numbers (how often its verdict matched the person's) are the
evidence for trusting it with a duty. Those numbers describe one model. The
previous default, `claude-opus-5`, was the family alias, so the model behind it
could change without a commit, and agreement measured last month would then be
quoted for a model that never earned it. Numbers are only comparable against a
fixed model.

**Why `check_ai` needed `EXACT_IDS`.** Our own `ai` lane flagged the alias,
which is how this was found. But its `PINNED` rule only recognises a date or a
version separator, and Anthropic's current ids carry neither: `claude-opus-5-5`
is complete as published, and a date appended to it is an error. Shape cannot
separate the two cases either, because `claude-sonnet-4-5` is an alias of a
dated snapshot and looks the same. So `scripts/check_ai.py` names each undated
exact id in `EXACT_IDS`, one reviewed line at a time. Adding the next one
belongs in the same pull request as moving to it.

**What the operator does when this merges.** The family a delegation trusts is
the model string, compared exactly (`engine.py`). A delegation granted to
`claude-opus-5` does not cover a reviewer running `claude-opus-5-5`, so a `live`
reviewer is refused by its preflight and the request waits for a person. That
is the safe direction, but it is a stop. If `backend/.env` sets
`MYKRONOS_REVIEWER_MODEL`, it overrides this default and must be changed by
hand. Then run `scripts/enable-agent-reviewer.ps1` again to propose a
delegation for the new family. Shadow numbers gathered under `claude-opus-5`
are not carried over.
