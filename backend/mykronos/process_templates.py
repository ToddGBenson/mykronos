"""Starter `.sdlc/process.yaml` manifests for a repository that declares none
(spec 35 §7.2, B-069, D-141).

Three shapes the estate already runs: keel's six gates, TheHub's eight story
gates, and a lightweight four-step process. Each is a valid version-1 manifest
(a test parses every one), with the repository's default tag substituted, and
each says at the top that it is a starter to be edited. It arrives as a draft
pull request, so nothing here becomes a repository's declared process until a
person has read it and merged it.

Templates declare no `branch_controls` and no `enforced_by`. A starter that
claimed controls nobody has checked would be a declaration written to fail the
drift check (§7.1) on its first render.
"""

from __future__ import annotations

from dataclasses import dataclass

#: Substituted with the repository's `repo:<name>` tag. Not a format string:
#: the manifests contain YAML flow mappings with braces.
TAG = "__TAG__"

_HEADER = """\
# A STARTER process manifest, opened by MyKronos as a draft pull request
# (spec 35 §7.2). Edit it until it describes how this repository is actually
# run, then mark the pull request ready and merge it. Until then the Product
# Owner tab keeps saying this repository declares no process.
#
# Every checklist item without an `evidence` key is manual: shown, never passed
# or failed. Keys MyKronos can check: acceptance_criteria, detail_500, sized,
# threat_model, sprint.
"""

_KEEL = (
    _HEADER
    + """version: 1
name: keel-style (G0-G5)
spine_map:
  G0: idea
  G1: ready
  G2: building
  G3: building
  G4: verifying
  G5: shipping
gates:
  - id: G0
    name: Idea
    recommends: Product Owner
    approves: Product Owner
    story_gates: [intake]
    checklist:
      - id: problem
        text: The problem is written down, with evidence
  - id: G1
    name: Ready
    recommends: Product Owner
    approves: Delivery Lead
    story_gates: [clarified, designed]
    checklist:
      - id: ac-binary
        text: Acceptance criteria are binary and observable
        evidence: acceptance_criteria
      - id: sized
        text: Sized
        evidence: sized
  - id: G2
    name: Committed
    recommends: Delivery Lead
    approves: Delivery Lead
    story_gates: [ready]
    checklist:
      - id: in-sprint
        text: Pulled into the sprint
        evidence: sprint
  - id: G3
    name: Built
    recommends: Developer
    approves: Reviewer
    story_gates: [in_progress]
    checklist:
      - id: pr
        text: A pull request with tests, reviewed by someone other than the author
  - id: G4
    name: Verified
    recommends: Reviewer
    approves: Delivery Lead
    story_gates: [tested]
    checklist:
      - id: checks
        text: Required checks pass on the merged commit
  - id: G5
    name: Released
    recommends: Delivery Lead
    approves: Product Owner
    story_gates: [deployed, verified]
    checklist:
      - id: released
        text: Released, and the release verified
backlog:
  source: thehub
  tag: __TAG__
  include_untagged: false
delivery:
  summary: PR to main, required checks, human merge, release after merge
  steps: [pr, checks, human-merge, release]
"""
)

_THEHUB = (
    _HEADER
    + """version: 1
name: TheHub-style (8 story gates)
spine_map:
  intake: idea
  clarified: ready
  designed: ready
  ready: ready
  in_progress: building
  tested: verifying
  deployed: shipping
  verified: done
gates:
  - id: intake
    name: Intake
    story_gates: [intake]
    checklist:
      - id: has-ac
        text: At least one acceptance criterion
        evidence: acceptance_criteria
  - id: clarified
    name: Clarified
    story_gates: [clarified]
    checklist:
      - id: detail
        text: Detail of at least 500 characters
        evidence: detail_500
  - id: designed
    name: Designed
    story_gates: [designed]
    checklist:
      - id: sized
        text: Sized
        evidence: sized
      - id: threat-model
        text: Threat model recorded where the change touches a sensitive path
        evidence: threat_model
  - id: ready
    name: Ready (in sprint)
    story_gates: [ready]
    checklist:
      - id: in-sprint
        text: Pulled into the sprint
        evidence: sprint
  - id: in_progress
    name: In progress
    story_gates: [in_progress]
    checklist:
      - id: failing-test
        text: A failing test first, then the code until it is green
  - id: tested
    name: Tested
    story_gates: [tested]
    checklist:
      - id: suite
        text: The full suite and the security scan pass
  - id: deployed
    name: Deployed
    story_gates: [deployed]
    checklist:
      - id: smoke
        text: Deployed through the pipeline, smoke test green
  - id: verified
    name: Verified
    story_gates: [verified]
    checklist:
      - id: observed
        text: The change is observed working in production
backlog:
  source: thehub
  tag: __TAG__
  include_untagged: false
delivery:
  summary: Commit through the pipeline, gated deploy, smoke test
  steps: [commit, pipeline, deploy, smoke-test]
"""
)

_LIGHTWEIGHT = (
    _HEADER
    + """version: 1
name: lightweight (Idea, Ready, Building, Done)
spine_map:
  idea: idea
  ready: ready
  building: building
  done: done
gates:
  - id: idea
    name: Idea
    story_gates: [intake]
  - id: ready
    name: Ready
    story_gates: [clarified, designed, ready]
    checklist:
      - id: ac
        text: Acceptance criteria exist
        evidence: acceptance_criteria
  - id: building
    name: Building
    story_gates: [in_progress, tested]
  - id: done
    name: Done
    story_gates: [deployed, verified]
backlog:
  source: thehub
  tag: __TAG__
  include_untagged: false
"""
)


@dataclass(frozen=True)
class Template:
    id: str
    label: str
    summary: str
    body: str

    def render(self, tag: str) -> str:
        return self.body.replace(TAG, tag)


TEMPLATES: dict[str, Template] = {
    t.id: t
    for t in (
        Template(
            id="keel",
            label="keel-style",
            summary="Six gates, G0 to G5, each with a recommender and an approver.",
            body=_KEEL,
        ),
        Template(
            id="thehub",
            label="TheHub-style",
            summary="TheHub's eight story gates, one manifest gate each.",
            body=_THEHUB,
        ),
        Template(
            id="lightweight",
            label="lightweight",
            summary="Idea, Ready, Building, Done. One checked item.",
            body=_LIGHTWEIGHT,
        ),
    )
}
