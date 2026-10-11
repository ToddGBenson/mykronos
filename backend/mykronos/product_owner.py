"""The Product Owner tab: a repository's declared process, backlog and sprint
(spec 35, D-132 - D-135).

Three things live here, and none of them owns a story:

- **The manifest** (`.sdlc/process.yaml`, D-132). Parsed strictly: an unknown
  key is an error, so a typo is reported rather than silently ignored, and an
  invalid manifest is shown as invalid with the reason. The tab never falls
  back to a default and presents it as the repository's declared process.
- **Gate checks.** A checklist item that names an evidence key is checked
  against the Hub story; one that names none is *manual* -- neither passed nor
  failed, because nothing here can see whether a person did it.
- **The Hub client.** TheHub's `dev_stories` is the system of record (D-133).
  This module reads stories and asks the Hub to move them. It never edits a
  story's content.

The sprint pull's order is the safety property of the whole module and is
written once, in `pull_into_sprint`: autonomy is switched off first, and the
story is moved only if that succeeded. A sprint move arms autonomous dispatch
in TheHub, so the order the other way round would leave a window where a story
is in the sprint with autonomy armed.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

import httpx2
import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from mykronos.github.client import FileChange, GitHubClient, PullRequest
from mykronos.process_templates import Template

logger = logging.getLogger(__name__)

MANIFEST_PATH = ".sdlc/process.yaml"

#: The shared spine (D-134). Every repository's own gates map onto it, which
#: is what makes two repositories comparable and gives one with no manifest a
#: default.
SPINE: tuple[str, ...] = ("idea", "ready", "building", "verifying", "shipping", "done")
SpineStep = Literal["idea", "ready", "building", "verifying", "shipping", "done"]

#: TheHub's own gates (`schemas/dev_story.py` GATES), in order.
HUB_GATES: tuple[str, ...] = (
    "intake",
    "clarified",
    "designed",
    "ready",
    "in_progress",
    "tested",
    "deployed",
    "verified",
)

#: Where a Hub gate sits on the spine when no manifest says otherwise.
DEFAULT_SPINE_MAP: dict[str, str] = {
    "intake": "idea",
    "clarified": "ready",
    "designed": "ready",
    "ready": "ready",
    "in_progress": "building",
    "tested": "verifying",
    "deployed": "shipping",
    "verified": "done",
}

#: Phase-1 evidence keys (spec 35 §2.2).
EvidenceKey = Literal["acceptance_criteria", "detail_500", "sized", "threat_model", "sprint"]

#: Definition-of-Done evidence keys (spec 35 §7.3): exit criteria, checked
#: against commits, scans and deploys rather than against the story text.
DodEvidenceKey = Literal["commit", "scan_passed", "deployed"]

#: A path inside the repository: relative, no traversal, no scheme. Rendered as
#: a link, so a `javascript:` or absolute URL must never get through. A leading
#: dot is allowed (`.env.example`, `.github/CODEOWNERS`); a `..` segment is not.
_SAFE_PATH = re.compile(r"^[A-Za-z0-9_.][A-Za-z0-9_./-]*$")


# --------------------------------------------------------------------------
# The manifest
# --------------------------------------------------------------------------


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _repo_path(value: str | None) -> str | None:
    if value is None:
        return None
    if not _SAFE_PATH.match(value) or ".." in value.split("/"):
        raise ValueError("must be a relative path inside the repository")
    return value


class ChecklistItem(_Strict):
    id: str = Field(min_length=1, max_length=64)
    text: str = Field(min_length=1, max_length=500)
    #: Omitted means manual: shown, never passed or failed.
    evidence: EvidenceKey | None = None


#: A setting name in a dotenv, YAML or JSON file: letters, digits, `_`, and
#: `.` for a dotted YAML path. Nothing that could be read as a pattern.
_SWITCH_KEY = r"^[A-Za-z_][A-Za-z0-9_.-]*$"


class Switch(_Strict):
    """The setting that turns a gate on (spec 35 §7.1). Read from the
    repository at the default branch, never from a running process."""

    file: str = Field(min_length=1, max_length=512)
    key: str = Field(min_length=1, max_length=128, pattern=_SWITCH_KEY)

    @field_validator("file")
    @classmethod
    def _file_in_repo(cls, value: str) -> str:
        return _repo_path(value) or value


class Gate(_Strict):
    id: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=128)
    recommends: str = Field(default="", max_length=128)
    approves: str = Field(default="", max_length=128)
    doc: str | None = Field(default=None, max_length=512)
    #: TheHub `dev_stories.gate` values this gate covers.
    story_gates: list[str] = Field(default_factory=list)
    checklist: list[ChecklistItem] = Field(default_factory=list)
    #: What switches this gate on, where the gate is enforced by a flag. Drift
    #: when the declared gate's switch reads off (B-070).
    enforced_by: Switch | None = None

    @field_validator("doc")
    @classmethod
    def _doc_in_repo(cls, value: str | None) -> str | None:
        return _repo_path(value)

    @field_validator("story_gates")
    @classmethod
    def _known_story_gates(cls, value: list[str]) -> list[str]:
        unknown = [gate for gate in value if gate not in HUB_GATES]
        if unknown:
            raise ValueError(
                f"{', '.join(unknown)} not a TheHub gate; expected one of {', '.join(HUB_GATES)}"
            )
        return value


class Backlog(_Strict):
    #: Phase 1 reads TheHub only. A keel GitHub-Issues adapter is B-072.
    source: Literal["thehub"]
    tag: str = Field(min_length=1, max_length=128)
    include_untagged: bool = False


class Delivery(_Strict):
    summary: str = Field(default="", max_length=1000)
    steps: list[str] = Field(default_factory=list)


class PolicyItem(_Strict):
    id: str = Field(min_length=1, max_length=64)
    text: str = Field(min_length=1, max_length=500)
    met: bool


class DocLink(_Strict):
    label: str = Field(min_length=1, max_length=128)
    path: str = Field(min_length=1, max_length=512)

    @field_validator("path")
    @classmethod
    def _path_in_repo(cls, value: str) -> str:
        return _repo_path(value) or value


class DodItem(_Strict):
    id: str = Field(min_length=1, max_length=64)
    text: str = Field(min_length=1, max_length=500)
    #: Omitted means manual. An unknown key is a validation error, never
    #: quietly manual: a typo would otherwise make an exit criterion vanish.
    evidence: DodEvidenceKey | None = None


class BranchControls(_Strict):
    """What the default branch is declared to enforce (spec 35 §7.1).

    Each is optional: an omitted key declares nothing, so it cannot drift.
    Only `true` is a declaration worth checking -- `false` says the control is
    not part of this process, and a branch that enforces more than declared
    has not drifted in any direction that needs a person.
    """

    required_review: bool | None = None
    required_checks: bool | None = None
    codeowner_review: bool | None = None
    enforced_for_admins: bool | None = None
    signed_commits: bool | None = None
    force_push_blocked: bool | None = None
    #: Who fixes a branch-control drift: whoever can change branch protection.
    owner: str = Field(default="Repository admins", min_length=1, max_length=128)


class ProcessManifest(_Strict):
    """`.sdlc/process.yaml`, version 1 (spec 35 §2)."""

    version: Literal[1]
    name: str = Field(min_length=1, max_length=128)
    spine_map: dict[str, SpineStep] = Field(default_factory=dict)
    gates: list[Gate] = Field(default_factory=list)
    backlog: Backlog
    delivery: Delivery | None = None
    automation_policy: list[PolicyItem] = Field(default_factory=list)
    docs: list[DocLink] = Field(default_factory=list)
    branch_controls: BranchControls | None = None
    definition_of_done: list[DodItem] = Field(default_factory=list)


ManifestStateName = Literal["valid", "invalid", "absent", "unreadable"]


@dataclass
class ManifestState:
    """What the default branch says, including that it says nothing."""

    state: ManifestStateName
    manifest: ProcessManifest | None = None
    error: str | None = None

    @property
    def spine_is_default(self) -> bool:
        return self.manifest is None


def _describe(exc: ValidationError) -> str:
    """The reason a person can act on: where, and what was wrong. Bounded,
    because a manifest with forty typos needs the first few, not a page."""
    parts = []
    for error in exc.errors()[:5]:
        location = ".".join(str(part) for part in error.get("loc", ())) or "(top level)"
        message = str(error.get("msg", "invalid"))
        if error.get("type") == "extra_forbidden":
            message = "unknown key"
        parts.append(f"{location}: {message}")
    more = len(exc.errors()) - 5
    if more > 0:
        parts.append(f"and {more} more")
    return "; ".join(parts)


def parse_manifest(text: str | None) -> ManifestState:
    """Parse a manifest, or report exactly why it cannot be used."""
    if text is None:
        return ManifestState(state="absent")
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" at line {mark.line + 1}" if mark is not None else ""
        return ManifestState(state="invalid", error=f"Not valid YAML{where}.")
    if not isinstance(document, dict):
        return ManifestState(state="invalid", error="The manifest must be a YAML mapping.")
    try:
        return ManifestState(state="valid", manifest=ProcessManifest.model_validate(document))
    except ValidationError as exc:
        return ManifestState(state="invalid", error=_describe(exc))


# --------------------------------------------------------------------------
# Stories against the process
# --------------------------------------------------------------------------


def default_tag(repo_full_name: str) -> str:
    """`owner/name` -> `repo:name`, the tag D-133 assigns a repository."""
    return f"repo:{repo_full_name.rsplit('/', 1)[-1].lower()}"


def belongs(story: dict[str, Any], tag: str, include_untagged: bool) -> bool:
    """Whether a Hub story is this repository's (D-133).

    By its `repo:<name>` tag; and, when the manifest says untagged stories
    count, also every story carrying no `repo:` tag at all (TheHub's own).
    """
    tags = [str(t).lower() for t in story.get("tags") or []]
    if tag.lower() in tags:
        return True
    return include_untagged and not any(t.startswith("repo:") for t in tags)


def gate_for(story: dict[str, Any], manifest: ProcessManifest | None) -> Gate | None:
    """The manifest gate covering the story's current Hub gate, if any."""
    if manifest is None:
        return None
    hub_gate = str(story.get("gate") or "intake")
    for gate in manifest.gates:
        if hub_gate in gate.story_gates:
            return gate
    return None


def spine_step(story: dict[str, Any], manifest: ProcessManifest | None) -> str:
    """Where a story is on the shared spine."""
    if story.get("bucket") == "done":
        return "done"
    gate = gate_for(story, manifest)
    if gate is not None and manifest is not None and gate.id in manifest.spine_map:
        return manifest.spine_map[gate.id]
    return DEFAULT_SPINE_MAP.get(str(story.get("gate") or "intake"), "idea")


CheckStatus = Literal["passed", "failed", "manual", "unavailable"]


def check_evidence(evidence: str | None, story: dict[str, Any]) -> CheckStatus:
    """One checklist item against one Hub story (spec 35 §2.2)."""
    if evidence is None:
        return "manual"
    if evidence == "acceptance_criteria":
        return "passed" if len(story.get("acceptance_criteria") or []) >= 1 else "failed"
    if evidence == "detail_500":
        return "passed" if len(story.get("detail") or "") >= 500 else "failed"
    if evidence == "sized":
        return "passed" if story.get("size") else "failed"
    if evidence == "sprint":
        return "passed" if story.get("bucket") == "sprint" else "failed"
    if evidence == "threat_model":
        # TheHub's story response does not carry `inception_draft` today.
        # Absent is "could not see", not "has none" -- reporting it as failed
        # would claim a gap the evidence does not show.
        if "inception_draft" not in story:
            return "unavailable"
        draft = story.get("inception_draft")
        return "passed" if isinstance(draft, dict) and "threat_model_md" in draft else "failed"
    return "manual"


@dataclass
class CheckItemResult:
    id: str
    text: str
    evidence: str | None
    status: CheckStatus


@dataclass
class GateCheck:
    gate_id: str | None
    gate_name: str | None
    items: list[CheckItemResult] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for item in self.items if item.status == "passed")

    @property
    def failed(self) -> int:
        return sum(1 for item in self.items if item.status == "failed")

    @property
    def manual(self) -> int:
        return sum(1 for item in self.items if item.status == "manual")

    @property
    def unavailable(self) -> int:
        return sum(1 for item in self.items if item.status == "unavailable")

    @property
    def total(self) -> int:
        """Items that can be checked. Manual and unavailable ones are counted
        separately, so `passed / total` never reads a manual item as a miss."""
        return self.passed + self.failed


def check_story(story: dict[str, Any], manifest: ProcessManifest | None) -> GateCheck:
    gate = gate_for(story, manifest)
    if gate is None:
        return GateCheck(gate_id=None, gate_name=None)
    return GateCheck(
        gate_id=gate.id,
        gate_name=gate.name,
        items=[
            CheckItemResult(
                id=item.id,
                text=item.text,
                evidence=item.evidence,
                status=check_evidence(item.evidence, story),
            )
            for item in gate.checklist
        ],
    )


@dataclass
class DoneEvidence:
    """What MyKronos can see of a story's exit (spec 35 §7.3).

    `commits` is None when TheHub could not say, which makes every evidence
    item unavailable rather than failed. `scanned` is None when the lake could
    not be read, for the same reason.
    """

    commits: list[str] | None
    #: Commits TheHub records a `success` deploy run of.
    deployed: list[str] = field(default_factory=list)
    #: Commits with a `success` scan run in the lake.
    scanned: list[str] | None = None
    #: The repository's probed running revision (#361), if any.
    deployed_revision: str | None = None


#: The shortest SHA prefix accepted as naming a commit. TheHub sends twelve
#: characters, scanners send seven or forty.
MIN_SHA = 7


def same_commit(a: str | None, b: str | None) -> bool:
    a, b = (a or "").strip().lower(), (b or "").strip().lower()
    if len(a) < MIN_SHA or len(b) < MIN_SHA:
        return False
    return a.startswith(b) or b.startswith(a)


def evidence_from_deploys(
    deploys: list[dict[str, Any]] | None,
) -> tuple[list[str] | None, list[str]]:
    """(commits naming the story, commits deployed) from TheHub's
    `/api/dev/stories/{id}/deploys`, which it builds from `Stories:` trailers."""
    if deploys is None:
        return None, []
    commits: list[str] = []
    deployed: list[str] = []
    for row in deploys:
        sha = str(row.get("sha") or "")
        if len(sha) < MIN_SHA:
            continue
        if sha not in commits:
            commits.append(sha)
        if row.get("final_status") == "success" and sha not in deployed:
            deployed.append(sha)
    return commits, deployed


def check_dod_evidence(evidence: str | None, done: DoneEvidence) -> CheckStatus:
    """One Definition-of-Done item against what was seen of the story."""
    if evidence is None:
        return "manual"
    if done.commits is None:
        return "unavailable"
    if evidence == "commit":
        return "passed" if done.commits else "failed"
    if evidence == "scan_passed":
        if not done.commits:
            return "failed"
        if done.scanned is None:
            return "unavailable"
        hit = any(same_commit(c, s) for c in done.commits for s in done.scanned)
        return "passed" if hit else "failed"
    if evidence == "deployed":
        hit = any(same_commit(c, d) for c in done.commits for d in done.deployed) or any(
            same_commit(c, done.deployed_revision) for c in done.commits
        )
        return "passed" if hit else "failed"
    return "manual"


def is_done(story: dict[str, Any], manifest: ProcessManifest | None) -> bool:
    """A done-equivalent gate: the story sits on the spine's last step."""
    return spine_step(story, manifest) == "done"


def check_dod(manifest: ProcessManifest | None, done: DoneEvidence) -> GateCheck | None:
    """The manifest's Definition of Done against one story, or None when the
    manifest declares none."""
    if manifest is None or not manifest.definition_of_done:
        return None
    return GateCheck(
        gate_id="definition_of_done",
        gate_name="Definition of Done",
        items=[
            CheckItemResult(
                id=item.id,
                text=item.text,
                evidence=item.evidence,
                status=check_dod_evidence(item.evidence, done),
            )
            for item in manifest.definition_of_done
        ],
    )


def _gate_index(story: dict[str, Any]) -> int:
    gate = str(story.get("gate") or "intake")
    return HUB_GATES.index(gate) if gate in HUB_GATES else -1


def _created(story: dict[str, Any]) -> str:
    return str(story.get("created_at") or story.get("updated_at") or "")


def order_backlog(stories: list[dict[str, Any]], ranks: dict[int, int]) -> list[dict[str, Any]]:
    """Ranked stories in the Product Owner's order, then unranked ones by gate
    (furthest along first) and age (oldest first) -- spec 35 §3."""
    ranked = sorted(
        (s for s in stories if int(s["id"]) in ranks),
        key=lambda s: (ranks[int(s["id"])], int(s["id"])),
    )
    unranked = sorted(
        (s for s in stories if int(s["id"]) not in ranks),
        key=lambda s: (-_gate_index(s), _created(s), int(s["id"])),
    )
    return ranked + unranked


def moved(order: list[int], story_id: int, direction: Literal["up", "down"]) -> list[int]:
    """`order` with one story moved a place. Unchanged at either end."""
    if story_id not in order:
        return list(order)
    result = list(order)
    index = result.index(story_id)
    target = index - 1 if direction == "up" else index + 1
    if 0 <= target < len(result):
        result[index], result[target] = result[target], result[index]
    return result


# --------------------------------------------------------------------------
# Declared versus observed (B-070, spec 35 §7.1, D-136)
# --------------------------------------------------------------------------

#: A `branch_controls` declaration -> (the governance control that observes
#: it, the observed states that satisfy it, what the declaration says).
#: `required_review` is satisfied by one approval (`partial`): the manifest
#: declares that review is required, not how many reviewers.
DECLARED_CONTROLS: dict[str, tuple[str, frozenset[str], str]] = {
    "required_review": (
        "approving_reviews_required",
        frozenset({"on", "partial"}),
        "an approving review is required",
    ),
    "required_checks": (
        "required_status_checks",
        frozenset({"on"}),
        "a status check must pass before a merge",
    ),
    "codeowner_review": (
        "codeowner_review_required",
        frozenset({"on"}),
        "a CODEOWNERS review is required",
    ),
    "enforced_for_admins": (
        "enforced_for_admins",
        frozenset({"on"}),
        "administrators are bound by the rules",
    ),
    "signed_commits": (
        "signed_commits_required",
        frozenset({"on"}),
        "commits must be signed",
    ),
    "force_push_blocked": (
        "force_push_blocked",
        frozenset({"on"}),
        "force pushes are blocked",
    ),
}

ObservationStatus = Literal["consistent", "drift", "unobserved"]

_ON = frozenset({"true", "1", "yes", "on"})
_OFF = frozenset({"false", "0", "no", "off"})


@dataclass
class Observation:
    """One declaration beside what MyKronos can see of it.

    `declared` and `observed` are kept as two fields and rendered as two, so
    "the manifest says required" and "branch protection says none" are never
    collapsed into a single word that hides which side is which.
    """

    id: str
    #: branch_control | gate_switch
    kind: str
    subject: str
    declared: str
    observed: str
    status: ObservationStatus
    owner: str
    detail: str = ""


def branch_control_observations(
    manifest: ProcessManifest | None,
    branch: str,
    control_states: dict[str, str] | None,
    *,
    unobserved_reason: str = "",
) -> list[Observation]:
    """Each `branch_controls: true` declaration against the stored governance
    reading. `control_states` is None when there is no current reading, which
    makes every declaration unobserved rather than consistent."""
    if manifest is None or manifest.branch_controls is None:
        return []
    declared = manifest.branch_controls
    out: list[Observation] = []
    for name, (control_key, satisfied, says) in DECLARED_CONTROLS.items():
        if getattr(declared, name) is not True:
            continue
        state = None if control_states is None else control_states.get(control_key)
        if state is None or state == "unknown":
            status: ObservationStatus = "unobserved"
            observed = "not observed"
            detail = unobserved_reason or f"{control_key} could not be read."
        elif state in satisfied:
            status, observed, detail = "consistent", f"{control_key}: {state}", ""
        else:
            status = "drift"
            observed = f"{control_key}: {state}"
            detail = (
                f"The manifest declares that {says} on {branch}; branch protection on "
                f"{branch} reports {control_key} as {state}."
            )
        out.append(
            Observation(
                id=f"branch:{name}",
                kind="branch_control",
                subject=f"{name} on {branch}",
                declared=f"{name}: true",
                observed=observed,
                status=status,
                owner=declared.owner,
                detail=detail,
            )
        )
    return out


def switch_files(manifest: ProcessManifest | None) -> list[str]:
    """The distinct files the declared gate switches live in."""
    if manifest is None:
        return []
    return sorted({g.enforced_by.file for g in manifest.gates if g.enforced_by is not None})


def read_switch(text: str | None, path: str, key: str) -> str | None:
    """The raw value of `key` in a file, or None if it is not there.

    `.yaml`, `.yml` and `.json` are read as YAML (JSON is YAML) with `key` as
    a dotted path. Anything else is read as dotenv: the last `KEY=value` line
    wins, as it does for every dotenv loader, and a trailing comment or quotes
    around the value are stripped.
    """
    if text is None:
        return None
    if path.endswith((".yaml", ".yml", ".json")):
        try:
            node: Any = yaml.safe_load(text)
        except yaml.YAMLError:
            return None
        for part in key.split("."):
            if not isinstance(node, dict) or part not in node:
                return None
            node = node[part]
        if isinstance(node, bool):
            return "true" if node else "false"
        return None if node is None or isinstance(node, dict | list) else str(node)
    value: str | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, _, rest = line.partition("=")
        if name.strip() != key:
            continue
        rest = rest.strip()
        if len(rest) >= 2 and rest[0] in "'\"" and rest[-1] == rest[0]:
            rest = rest[1:-1]
        else:
            rest = rest.split(" #", 1)[0].strip()
        value = rest
    return value


def gate_switch_observations(
    manifest: ProcessManifest | None, files: dict[str, str | None]
) -> list[Observation]:
    """Each declared gate against the switch that is meant to enforce it.

    `files` maps a path to its text, or to None when it is absent or could
    not be read -- either way the switch is unobserved, never "off".
    """
    if manifest is None:
        return []
    fallback_owner = (
        manifest.branch_controls.owner if manifest.branch_controls else "Repository admins"
    )
    out: list[Observation] = []
    for gate in manifest.gates:
        switch = gate.enforced_by
        if switch is None:
            continue
        raw = read_switch(files.get(switch.file), switch.file, switch.key)
        where = f"{switch.key} in {switch.file}"
        value = (raw or "").strip().lower()
        status: ObservationStatus
        if raw is None:
            status, observed = "unobserved", "not observed"
            detail = (
                f"{switch.file} is not on the default branch."
                if files.get(switch.file) is None
                else f"{switch.key} is not set in {switch.file}."
            )
        elif value in _ON:
            status, observed, detail = "consistent", f"{where} = {raw}", ""
        elif value in _OFF or value == "":
            status = "drift"
            observed = f"{where} = {raw or '(empty)'}"
            detail = (
                f"The manifest declares gate {gate.id} ({gate.name}); its switch "
                f"{switch.key} is off in {switch.file}."
            )
        else:
            status, observed = "unobserved", f"{where} = {raw}"
            detail = f"{raw!r} is neither on nor off."
        out.append(
            Observation(
                id=f"gate:{gate.id}",
                kind="gate_switch",
                subject=f"gate {gate.id} ({gate.name})",
                declared=f"gate {gate.id} enforced by {switch.key}",
                observed=observed,
                status=status,
                owner=gate.approves or fallback_owner,
                detail=detail,
            )
        )
    return out


# --------------------------------------------------------------------------
# A template pull request (B-069, spec 35 §7.2, D-137)
# --------------------------------------------------------------------------

#: Its own prefix, so `find_open_pull_request` never mistakes a workflow
#: install pull request (`mykronos/install-...`) for a manifest one, or the
#: other way round.
TEMPLATE_BRANCH_PREFIX = "mykronos/sdlc-process-"


@dataclass
class TemplatePullRequest:
    pull_request: PullRequest
    branch: str
    #: False when an open template pull request was returned instead.
    created: bool


def template_pr_body(template: Template, tag: str) -> str:
    return "\n".join(
        [
            "This pull request was opened by **Mykronos** from the Product Owner tab.",
            "",
            f"It adds a starter `{MANIFEST_PATH}` ({template.label}): {template.summary}",
            "",
            "### Before you merge",
            "",
            "- It is a **draft** and a starting point. Edit the gates, approvers and",
            "  checklists until they describe how this repository is actually run.",
            f"- Stories are matched by the tag `{tag}` in TheHub.",
            "- Nothing is committed to the default branch. Until this merges, the tab",
            "  keeps saying the repository declares no process.",
            "",
            "Spec 35 §2 describes every key; an unknown key makes the manifest invalid.",
        ]
    )


async def open_template_pr(
    github: GitHubClient,
    repo_full_name: str,
    default_branch: str,
    template: Template,
    *,
    now: datetime,
) -> TemplatePullRequest:
    """Open a draft pull request adding the starter manifest.

    The Workflow Installer's path (`installer.apply`): reuse an open pull
    request rather than opening a second, otherwise branch from the default
    branch, commit, and open. One file, and never a commit to the default
    branch itself.
    """
    existing = await github.find_open_pull_request(repo_full_name, TEMPLATE_BRANCH_PREFIX)
    if existing is not None:
        return TemplatePullRequest(
            pull_request=existing, branch=existing.head_branch, created=False
        )
    tag = default_tag(repo_full_name)
    branch = f"{TEMPLATE_BRANCH_PREFIX}{now.strftime('%Y%m%dT%H%M%S')}"
    await github.create_branch(repo_full_name, branch, default_branch)
    await github.commit_files(
        repo_full_name,
        branch,
        f"Mykronos: add a starter {MANIFEST_PATH} ({template.label})",
        [FileChange(path=MANIFEST_PATH, content=template.render(tag))],
    )
    pull_request = await github.create_pull_request(
        repo_full_name,
        head=branch,
        base=default_branch,
        title=f"Mykronos: declare a development process ({template.label})",
        body=template_pr_body(template, tag),
        draft=True,
    )
    return TemplatePullRequest(pull_request=pull_request, branch=branch, created=True)


# --------------------------------------------------------------------------
# TheHub
# --------------------------------------------------------------------------


class HubUnavailableError(Exception):
    """TheHub could not be asked. The message is ours and safe to show."""


@dataclass
class HubResult:
    ok: bool
    status: int
    #: TheHub's own refusal text when it refused. The Hub writes these, so
    #: they are surfaced verbatim; a transport error never reaches here.
    detail: str | None = None
    body: Any = None


def refusal_text(body: Any, status_code: int) -> str:
    """TheHub's `detail`, as a sentence. It is a string for most refusals and
    a small object for the inception gate (`error`, `reason`,
    `missing_fields`)."""
    detail = body.get("detail") if isinstance(body, dict) else None
    if isinstance(detail, str) and detail.strip():
        text = detail.strip()
    elif isinstance(detail, dict):
        parts = [str(detail[key]) for key in ("error", "reason") if detail.get(key)]
        missing = detail.get("missing_fields")
        if isinstance(missing, list) and missing:
            parts.append("missing: " + ", ".join(str(m) for m in missing))
        text = "; ".join(parts) or f"TheHub refused (HTTP {status_code})."
    else:
        text = f"TheHub refused (HTTP {status_code})."
    return text[:500]


class HubClient:
    """A thin client for the three Hub calls spec 35 uses, and one read."""

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        timeout: float = 5.0,
        transport: httpx2.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._token = token
        self._timeout = timeout
        self._transport = transport

    @classmethod
    def from_settings(cls, settings: Any) -> HubClient | None:
        """None when either half is missing: the tab then says TheHub is not
        connected, rather than failing to ask."""
        url = str(getattr(settings, "hub_api_url", "") or "")
        token = str(getattr(settings, "hub_api_token", "") or "")
        if not url or not token:
            return None
        return cls(url, token)

    async def _request(
        self, method: str, path: str, *, json: Any = None, params: Any = None
    ) -> httpx2.Response:
        try:
            async with httpx2.AsyncClient(
                base_url=self.base_url,
                timeout=self._timeout,
                transport=self._transport,
                headers={"X-Hub-Token": self._token},
            ) as http:
                return await http.request(method, path, json=json, params=params)
        except httpx2.HTTPError as exc:
            # Logged by class only: the exception text can carry the URL, and
            # the client gets a sentence of ours, never the exception.
            logger.warning("TheHub request failed: %s %s (%s)", method, path, type(exc).__name__)
            raise HubUnavailableError("TheHub could not be reached.") from exc

    @staticmethod
    def _body(response: httpx2.Response) -> Any:
        try:
            return response.json()
        except ValueError:
            return None

    async def list_stories(self, bucket: str, limit: int = 500) -> list[dict[str, Any]]:
        response = await self._request(
            "GET", "/api/dev/stories", params={"bucket": bucket, "limit": limit}
        )
        if response.status_code != 200:
            raise HubUnavailableError(
                f"TheHub did not list the {bucket} (HTTP {response.status_code})."
            )
        body = self._body(response)
        if not isinstance(body, list):
            raise HubUnavailableError("TheHub's story list was not in the expected shape.")
        return [story for story in body if isinstance(story, dict) and "id" in story]

    async def get_story(self, story_id: int) -> dict[str, Any] | None:
        response = await self._request("GET", f"/api/dev/stories/{story_id}")
        if response.status_code == 404:
            return None
        if response.status_code != 200:
            raise HubUnavailableError(
                f"TheHub did not return the story (HTTP {response.status_code})."
            )
        body = self._body(response)
        return body if isinstance(body, dict) else None

    async def story_deploys(self, story_id: int) -> list[dict[str, Any]] | None:
        """The deploy runs TheHub attributes to a story by its commits'
        `Stories:` trailers. None when TheHub could not answer: "could not
        see" is never reported as "has none"."""
        try:
            response = await self._request("GET", f"/api/dev/stories/{story_id}/deploys")
        except HubUnavailableError:
            return None
        if response.status_code != 200:
            return None
        body = self._body(response)
        deploys = body.get("deploys") if isinstance(body, dict) else None
        if not isinstance(deploys, list):
            return None
        return [row for row in deploys if isinstance(row, dict)]

    async def _write(self, path: str, payload: dict[str, Any]) -> HubResult:
        response = await self._request("POST", path, json=payload)
        body = self._body(response)
        if 200 <= response.status_code < 300:
            return HubResult(ok=True, status=response.status_code, body=body)
        if response.status_code >= 500:
            # A 5xx is the Hub failing, not the Hub refusing; its body is not
            # an authored message and is not passed on.
            return HubResult(
                ok=False,
                status=response.status_code,
                detail=f"TheHub failed (HTTP {response.status_code}).",
            )
        return HubResult(
            ok=False, status=response.status_code, detail=refusal_text(body, response.status_code)
        )

    async def disable_autonomy(self, story_id: int) -> HubResult:
        return await self._write(
            f"/api/devops/autonomy/stories/{story_id}/toggle-autonomy",
            {"autonomy_disabled": True},
        )

    async def move(self, story_id: int, bucket: Literal["sprint", "backlog"]) -> HubResult:
        return await self._write(f"/api/dev/stories/{story_id}/move", {"bucket": bucket})


@dataclass
class PullOutcome:
    """What a sprint pull did. `autonomy_disabled` is true whenever the toggle
    succeeded, including when the move then failed -- the state the order of
    the two calls exists to guarantee."""

    moved: bool
    autonomy_disabled: bool
    #: `toggle` or `move`: which call refused, when one did.
    refused_at: str | None = None
    detail: str | None = None


async def pull_into_sprint(hub: HubClient, story_id: int) -> PullOutcome:
    """Autonomy off first; move second, and only if the first succeeded.

    A sprint move arms autonomous dispatch in TheHub. Doing this the other way
    round, or both at once, opens a window where a story sits in the sprint
    with autonomy armed. In this order a failure between the calls leaves it
    in the backlog with autonomy off, which is safe. Never retried: a Hub
    refusal is the Hub's rule, and asking again does not change it.
    """
    toggle = await hub.disable_autonomy(story_id)
    if not toggle.ok:
        return PullOutcome(
            moved=False, autonomy_disabled=False, refused_at="toggle", detail=toggle.detail
        )
    try:
        move = await hub.move(story_id, "sprint")
    except HubUnavailableError as exc:
        return PullOutcome(
            moved=False, autonomy_disabled=True, refused_at="move", detail=str(exc)
        )
    if not move.ok:
        return PullOutcome(
            moved=False, autonomy_disabled=True, refused_at="move", detail=move.detail
        )
    return PullOutcome(moved=True, autonomy_disabled=True)

