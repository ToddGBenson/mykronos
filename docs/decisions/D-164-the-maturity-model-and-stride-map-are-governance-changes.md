## D-164 — The maturity model and the STRIDE map are `governance` changes: a person approves every edit

**2026-10-17.** **Status:** Implemented in this change (#60755). A person confirms or reverses it when approving the pull request, which is itself `governance`.
**Spec:** applies [spec 34 §6.1](../../specs/34-duties-delegation-and-independent-approval.md) · relates to [spec 10 §2.3](../../specs/10-jded-dashboard.md), [spec 28 §2](../../specs/28-threat-model-resolution.md), [`../approvals.md`](../approvals.md)

**The problem.** `approval-policy-v1.yaml`'s `governance` class matched
`*-policy-v1.yaml`, plus `agent-playbooks-v1.yaml` since #805.
`maturity-model-v1.yaml` and `stride-map-v1.yaml` are reviewed data files at
the repository root, but their names do not end in `-policy-v1.yaml`, so they
fell to the default class, `production`. A delegated agent may approve a
`production` change. Found by the handbook fact-check on 2026-10-12.

**Decision.** Both files are listed by name in the `governance` class, with a
test case each in `tests/test_pull_request_review.py`.

**Why.**
- Each file states that it is reviewed as policy. The maturity model says it is
  "versioned and reviewed in a pull request for the same reason the Oracle
  policy is", because it "decides what teams are told to aim at". The STRIDE
  map says it is a file "for the same reason `oracle-policy-v1.yaml` and
  `maturity-model-v1.yaml` are files": a judgement that should not be
  "changed in a commit nobody reviews as policy". The Oracle policy is
  `governance`. Leaving these two at `production` contradicted their own
  stated reason for existing as files.
- The platform reviewer's instructions for `pull_request_merge` already say a
  change to "governance ... policy is not routine whatever its label says;
  reject it here so a person decides". A reviewer shown one of these files had
  to guess whether that sentence applied. Listing them removes the guess.
- Each file changes what the platform reports. The maturity model sets the
  criteria a repository is scored against. The STRIDE map decides which threat
  category a finding counts toward. An agent whose work those numbers describe
  should not approve the change that redefines them.
- The cost is small. Under `single_operator` the `governance` tier is one
  person and a one-hour cooling-off. These files change rarely.

**Rejected.**
- *Leave both at `production`.* Neither file grants authority or gates a
  merge, and spec 34 §6.1 names only approval policy, Oracle policy, CI and
  branch protection as `governance`. Rejected because the files claim the same
  review as the Oracle policy, and the reviewer instructions already treat
  policy edits as a person's call.
- *Only the maturity model.* The STRIDE map is a taxonomy, and its effect is
  limited to the threat-model tab. Rejected because it gives the same reason as
  the maturity model for being a reviewed file, and splitting them would need
  a line between "policy" and "taxonomy" that nothing else in the repository
  draws.
- *Rename them to `*-policy-v1.yaml`.* This would change two settings
  defaults, their environment overrides, and every reference in specs and code,
  only to fit a glob. An explicit entry says the same thing.
