"""The Patchwork pipeline (spec 08 §2).

Six stages, run server-side. Every finding routed through it produces exactly
one `RemediationEvent` — including the ones where nothing happened, because
spec 08 §7 makes that a requirement and spec 01 §6 makes silence a bug. "We
looked at this and could not fix it" is a useful thing for a dashboard to be
able to say; a finding that simply never appears is not.

The hard constraint (spec 08 §3) is enforced structurally rather than by
permission: the GitHub client exposes no merge operation, so there is nothing
here that could merge even if it wanted to. `tests/test_patchwork.py` asserts
the method does not exist.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from typing import Any

from mykronos.github.client import FileChange, GitHubClient, GitHubError, PullRequest
from mykronos.knowledge.store import KnowledgeStore
from mykronos.lake.buffer import WriteAheadBuffer
from mykronos.lake.catalog import Catalog
from mykronos.patchwork import correlate, fixers, image_date
from mykronos.patchwork.regression_prompt import regression_prompt
from mykronos.patchwork.rejection import is_dampened, rejection_prompt
from mykronos.patchwork.stewardship import BRANCH_PREFIX, branches_off_limits
from mykronos.patchwork.triage import classify
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

STAGES = (
    "triaged",
    "correlated",
    "fix_generated",
    "pr_opened",
    "no_fix_available",
    "skipped_low_confidence",
    "queued",
    "superseded",
    # Preview only (spec 18 §7.2) — never written to `remediation_events`;
    # listed here anyway because it is a real `StageOutcome.stage` value and
    # this tuple is the vocabulary's one definition.
    "would_fix",
)

#: What Patchwork may write a patch for. Narrow by construction: each of
#: these points at a line in a file a deterministic fixer can change.
#: `atlas` is here because the three dependency-pinning fixers are registered
#: under it; without it they were never offered a finding (#727).
DEFAULT_SOURCE_CAPABILITIES = ("sast", "secrets", "containers", "iac", "atlas")

#: What toxic-combination detection may consider (spec 08 §5a). Wider, and
#: deliberately so - correlation is not fix generation. A DAST finding can be
#: half of a combination that matters enormously while being something
#: Patchwork will never patch, and using the fix-generation list for
#: correlation made that entire class undetectable.
DEFAULT_CORRELATION_CAPABILITIES = (
    "sast",
    "secrets",
    "containers",
    "iac",
    "dast",
    "atlas",
    "cloud",
    # Spec 14. A network finding is never patchable and is half of three of
    # the rules in `correlate`, which is exactly the case §5a exists for.
    "network",
)


def event_id(repo_full_name: str, finding_id: str) -> str:
    """Derived, not random (spec 08 §4)."""
    return hashlib.sha256(f"{repo_full_name}\x00{finding_id}".encode()).hexdigest()


@dataclass
class StageOutcome:
    finding_id: str
    stage: str
    classification: str
    rationale: str
    toxic_combination_id: str | None = None
    contributing: list[str] = field(default_factory=list)
    fix_pr_number: int | None = None
    fix_pr_url: str | None = None
    pr_status: str | None = None
    #: Which fixer produced this. Persisted since spec 25 §3.1 — the per-fixer
    #: efficacy scoreboard cannot be computed without it. Also set by a
    #: `preview_only` `_attempt_fix` call (spec 18 §7.2), which reports
    #: "auto remediation identified" without opening anything.
    fixer_name: str | None = None
    fix_confidence: float | None = None
    fix_files: dict[str, str] | None = None
    #: True when this outcome points at a pull request another finding's
    #: outcome already counted: bump-image-date opens one per image and date,
    #: and the draft budget is spent once for it, not once per CVE. Never
    #: persisted.
    shared_pr: bool = False

    def to_row(self, repo_full_name: str) -> dict[str, Any]:
        stamp = utcnow()
        return {
            "event_id": event_id(repo_full_name, self.finding_id),
            "repo_full_name": repo_full_name,
            "finding_id": self.finding_id,
            "toxic_combination_id": self.toxic_combination_id,
            "contributing_finding_ids": json.dumps(self.contributing),
            "pipeline_stage_reached": self.stage,
            "triage_classification": self.classification,
            "fix_pr_number": self.fix_pr_number,
            "fix_pr_url": self.fix_pr_url,
            "pr_status": self.pr_status,
            "rationale": self.rationale,
            # Spec 25 §3.1. The name, never the content: a per-fixer verified
            # rate is unanswerable without it, and a fixer that opens pull
            # requests nobody merges is indistinguishable from one that
            # silently removes real risk every week.
            "fixer_name": self.fixer_name,
            "created_at": stamp,
            "updated_at": stamp,
        }


@dataclass
class PipelineResult:
    outcomes: list[StageOutcome] = field(default_factory=list)
    prs_opened: int = 0
    queued: int = 0
    errors: list[str] = field(default_factory=list)

    def by_stage(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for outcome in self.outcomes:
            counts[outcome.stage] = counts.get(outcome.stage, 0) + 1
        return counts


@dataclass
class _ImageGroup:
    """One patched image's decision in one run, handed to each of its findings."""

    refusal: str | None = None
    stage: str = "no_fix_available"
    plan: image_date.ImageDatePlan | None = None
    pr: PullRequest | None = None
    preview: bool = False
    #: Whether a finding's outcome has already counted this pull request
    #: against the draft budget. True from the start for one that was open
    #: before this run.
    counted: bool = False

    def outcome_for(self, finding_id: str, triage_rationale: str) -> StageOutcome:
        name = image_date.FIXER_NAME
        plan = self.plan
        if self.refusal is not None or plan is None:
            return StageOutcome(
                finding_id=finding_id,
                stage=self.stage,
                classification="true_positive",
                rationale=f"{triage_rationale} {self.refusal}",
                fixer_name=name if plan is not None else None,
                fix_confidence=plan.fix.confidence if plan is not None else None,
            )
        new_tag = plan.new_image.path_tag
        if finding_id not in {str(f["finding_id"]) for f in plan.clears}:
            persists = finding_id in {str(f["finding_id"]) for f in plan.persists}
            return StageOutcome(
                finding_id=finding_id,
                stage="no_fix_available",
                classification="true_positive",
                rationale=(
                    f"{triage_rationale} "
                    + (
                        f"{new_tag} has been scanned and still carries this finding, "
                        "so moving to it would not clear it."
                        if persists
                        else f"Not in the open findings of {plan.image.path_tag}."
                    )
                ),
            )
        summary = f"{plan.fix.summary} ({name})."
        if self.preview:
            return StageOutcome(
                finding_id=finding_id,
                stage="would_fix",
                classification="true_positive",
                rationale=f"{triage_rationale} {summary}",
                fixer_name=name,
                fix_confidence=plan.fix.confidence,
                fix_files=dict(plan.fix.files),
            )
        assert self.pr is not None
        shared = self.counted
        self.counted = True
        return StageOutcome(
            finding_id=finding_id,
            stage="pr_opened",
            classification="true_positive",
            rationale=f"{triage_rationale} {summary}",
            fix_pr_number=self.pr.number,
            fix_pr_url=self.pr.url,
            pr_status="draft_open",
            fixer_name=name,
            fix_confidence=plan.fix.confidence,
            shared_pr=shared,
        )


class PatchworkPipeline:
    def __init__(
        self,
        catalog: Catalog,
        buffer: WriteAheadBuffer,
        store: KnowledgeStore | None = None,
        *,
        min_confidence: float = 0.7,
        max_open_draft_prs: int = 10,
        source_capabilities: tuple[str, ...] = DEFAULT_SOURCE_CAPABILITIES,
        correlation_capabilities: tuple[str, ...] = DEFAULT_CORRELATION_CAPABILITIES,
        auto_fix_min_severity: str = "high",
        image_registry: image_date.TagSource | None = None,
    ) -> None:
        self.catalog = catalog
        self.buffer = buffer
        self.store = store
        self.min_confidence = min_confidence
        self.max_open_draft_prs = max_open_draft_prs
        self.source_capabilities = source_capabilities
        self.correlation_capabilities = correlation_capabilities
        # The severity floor for the *unprompted* sweep (spec 19 §4.5).
        # `classify()` hardcoded "critical or high" before this was
        # configurable, so the default keeps every existing repo's behaviour.
        self.auto_fix_min_severity = auto_fix_min_severity
        # bump-image-date's one network read. None leaves every patched-image
        # finding with a stated reason, not a silent skip.
        self.image_registry = image_registry
        #: Per run: one decision per patched image, shared by its findings.
        self._image_groups: dict[image_date.PatchedImage, _ImageGroup] = {}

    # -- stage 1: ingest -------------------------------------------------

    def _candidates(
        self,
        repo_full_name: str,
        limit: int = 200,
        capability_set: tuple[str, ...] | None = None,
    ) -> list[dict[str, Any]]:
        capabilities = ", ".join(
            f"'{c}'" for c in (capability_set or self.source_capabilities)
        )
        columns = [
            "finding_id",
            "rule_id",
            "title",
            "severity",
            "capability",
            "file_path",
            "line_start",
            "line_end",
            "symbol",
            "package_name",
            "package_version",
            "raw_finding_json",
        ]
        rows = self.catalog.query(
            f"SELECT {', '.join(columns)} FROM findings "
            f"WHERE asset_id = ? AND status = 'open' "
            f"AND capability IN ({capabilities}) "
            "ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, finding_id "
            "LIMIT ?",
            [repo_full_name, limit],
        )
        findings = []
        for row in rows:
            record = dict(zip(columns, row, strict=True))
            raw = record.get("raw_finding_json")
            if isinstance(raw, str) and raw:
                try:
                    record["raw_finding_json"] = json.loads(raw)
                except json.JSONDecodeError:
                    record["raw_finding_json"] = {}
            findings.append(record)
        return findings

    # -- stage 2: triage -------------------------------------------------

    def _triage(self, finding: dict[str, Any], repo_full_name: str) -> tuple[str, str]:
        """Classify a finding, consulting the Knowledge Store (spec 08 §2).

        The rules live in `patchwork/triage.py` because the dashboard's
        open-findings view triages the same findings, and a platform that
        called a rule "likely false positive" on one page while generating a
        fix for it on another would be arguing with itself in public.
        """
        return classify(
            finding,
            repo_full_name,
            self.store,
            min_severity=self.auto_fix_min_severity,
        )

    # -- the run ---------------------------------------------------------

    async def run(
        self,
        repo_full_name: str,
        *,
        github: GitHubClient | None = None,
        default_branch: str = "main",
        open_prs: int = 0,
    ) -> PipelineResult:
        """Stages 1-6 for one repository (spec 08 §2).

        Wrapped so a failure anywhere still records where each finding got to.
        spec 08 §8 requires it: an agent pipeline that dies mid-run and leaves
        no trace is indistinguishable from one that decided to do nothing.
        """
        result = PipelineResult()
        self._image_groups = {}
        findings = self._candidates(repo_full_name)
        # Correlation looks wider than fix generation (spec 08 §5a). Fetched
        # separately rather than filtered down from one query, because the
        # per-query limit is a severity-ordered top-N: a single query would
        # let 200 SAST findings crowd out the one DAST finding that makes a
        # combination.
        correlation_pool = self._candidates(
            repo_full_name, capability_set=self.correlation_capabilities
        )
        if not findings and not correlation_pool:
            return result

        by_id = {str(f["finding_id"]): f for f in findings}

        # Branches a person has taken over. Checked before anything is
        # regenerated: spec 08 §3 makes the human_edited transition permanent,
        # and a bot that reverted somebody's commit would end this
        # capability's welcome the same afternoon.
        off_limits = branches_off_limits(self.catalog, repo_full_name)

        # Stage 3. Done before fix generation so a finding that is part of a
        # combination is never fixed in isolation — spec 08 §8's overlap case,
        # and the reason combinations are detected at all.
        combinations = correlate.detect(correlation_pool)
        claimed = {fid for combo in combinations for fid in combo.finding_ids}
        # The exception spec 19 §3.3 scopes to exactly one rule: a member
        # finding whose fix is correct whether or not the other half is ever
        # addressed. Removed from `claimed` so the normal fix path still sees
        # it; the combination event above still says needs_human_judgment,
        # because the *combination* still does.
        partial = {
            combo.partial_fix_finding_id
            for combo in combinations
            if combo.partial_fix_finding_id
        }
        claimed -= partial

        for combo in combinations:
            result.outcomes.append(
                StageOutcome(
                    # Keyed on the combination, not on any one finding: the
                    # event is about the set.
                    finding_id=combo.combination_id,
                    stage="correlated",
                    classification="needs_human_judgment",
                    rationale=combo.rationale,
                    toxic_combination_id=combo.combination_id,
                    contributing=sorted(combo.finding_ids),
                )
            )

        budget = max(0, self.max_open_draft_prs - open_prs)

        for finding_id, finding in by_id.items():
            if finding_id in off_limits:
                # Deliberately produces no event. The existing one already
                # says `human_edited`, and overwriting it with a fresh
                # assessment would lose the fact that a person is on this.
                continue

            if finding_id in claimed:
                # Already covered by a combination event. Generating a
                # separate fix would produce two draft PRs touching related
                # code, which is spec 08 §8's conflicting-PR case.
                continue

            classification, rationale = self._triage(finding, repo_full_name)

            if classification != "true_positive":
                result.outcomes.append(
                    StageOutcome(
                        finding_id=finding_id,
                        stage="triaged",
                        classification=classification,
                        rationale=rationale,
                    )
                )
                continue

            outcome = await self._attempt_fix(
                repo_full_name,
                finding,
                rationale,
                github=github,
                default_branch=default_branch,
                budget=budget,
                result=result,
            )
            result.outcomes.append(outcome)
            if outcome.stage == "pr_opened" and not outcome.shared_pr:
                budget -= 1
                result.prs_opened += 1
            elif outcome.stage == "queued":
                result.queued += 1

        if result.outcomes:
            self.buffer.append(
                "remediation_events",
                [outcome.to_row(repo_full_name) for outcome in result.outcomes],
            )
        return result

    async def run_one(
        self,
        repo_full_name: str,
        finding_id: str,
        *,
        github: GitHubClient | None,
        default_branch: str = "main",
        open_prs: int = 0,
        preview_only: bool = False,
    ) -> StageOutcome | None:
        """One finding, on request (spec 18 §7) — a person clicking a button
        on the finding they are looking at, rather than the scheduled sweep
        `run()` does across the whole repository.

        Every guardrail `run()` applies still applies: the off-limits check
        (a human-edited branch stays permanently untouched), the toxic-
        combination claim (a finding that is half of a combination is not
        fixed alone), the triage gate (`classify()`, the same rules the
        Findings tab renders), and the draft-PR budget. Nothing here is a
        second, looser path to a fix `run()` would have refused.

        `None` means no open finding with this id exists in this repository —
        the caller's job to turn into a 404, not this method's to invent a
        `StageOutcome` for.

        `preview_only=True` stops before any write reaches GitHub (see
        `_attempt_fix`) and, when a fix would be generated, writes no
        `RemediationEvent` either — a preview a person looks at and does not
        act on should leave no trace, the same reason a `GET` does not.
        """
        columns = [
            "finding_id",
            "rule_id",
            "title",
            "severity",
            "capability",
            "file_path",
            "line_start",
            "line_end",
            "symbol",
            "package_name",
            "package_version",
            "raw_finding_json",
        ]
        rows = self.catalog.query(
            f"SELECT {', '.join(columns)} FROM findings "
            "WHERE asset_id = ? AND finding_id = ? AND status = 'open'",
            [repo_full_name, finding_id],
        )
        if not rows:
            return None
        finding = dict(zip(columns, rows[0], strict=True))
        raw = finding.get("raw_finding_json")
        if isinstance(raw, str) and raw:
            try:
                finding["raw_finding_json"] = json.loads(raw)
            except json.JSONDecodeError:
                finding["raw_finding_json"] = {}

        def _record(outcome: StageOutcome) -> StageOutcome:
            if not preview_only:
                self.buffer.append("remediation_events", [outcome.to_row(repo_full_name)])
            return outcome

        off_limits = branches_off_limits(self.catalog, repo_full_name)
        if finding_id in off_limits:
            return _record(
                StageOutcome(
                    finding_id=finding_id,
                    stage="no_fix_available",
                    classification="true_positive",
                    rationale=(
                        "A person has already edited this fix's branch; "
                        "Patchwork does not touch it again (spec 08 §3)."
                    ),
                )
            )

        # Correlation pool is fetched the same way `run()` fetches it —
        # wider than fix generation, so a combination this finding belongs to
        # is found even though the source-capability list alone would not
        # have surfaced the other half.
        correlation_pool = self._candidates(
            repo_full_name, capability_set=self.correlation_capabilities
        )
        for combo in correlate.detect(correlation_pool):
            if finding_id in combo.finding_ids:
                return _record(
                    StageOutcome(
                        finding_id=combo.combination_id,
                        stage="correlated",
                        classification="needs_human_judgment",
                        rationale=combo.rationale,
                        toxic_combination_id=combo.combination_id,
                        contributing=sorted(combo.finding_ids),
                    )
                )

        classification, rationale = self._triage(finding, repo_full_name)
        if classification != "true_positive":
            return _record(
                StageOutcome(
                    finding_id=finding_id,
                    stage="triaged",
                    classification=classification,
                    rationale=rationale,
                )
            )

        budget = max(0, self.max_open_draft_prs - open_prs)
        self._image_groups = {}
        outcome = await self._attempt_fix(
            repo_full_name,
            finding,
            rationale,
            github=github,
            default_branch=default_branch,
            budget=budget,
            result=PipelineResult(),
            preview_only=preview_only,
        )
        return _record(outcome)

    async def _attempt_fix(
        self,
        repo_full_name: str,
        finding: dict[str, Any],
        triage_rationale: str,
        *,
        github: GitHubClient | None,
        default_branch: str,
        budget: int,
        result: PipelineResult,
        preview_only: bool = False,
    ) -> StageOutcome:
        finding_id = str(finding["finding_id"])
        path = str(finding.get("file_path") or "")

        # Before the budget and the file read: a container finding's
        # `file_path` is a path inside the image, not a file in this
        # repository, and one image's findings share one pull request.
        image = image_date.image_of_finding(finding)
        if image is not None:
            return await self._attempt_image_date_fix(
                repo_full_name,
                finding,
                image,
                triage_rationale,
                github=github,
                default_branch=default_branch,
                budget=budget,
                result=result,
                preview_only=preview_only,
            )
        if finding.get("capability") == "containers":
            # A vendor image, not one of our -p<date> derivatives. Its
            # `file_path` is a path inside the image (`usr/local/bin/gosu`) or
            # the image name, so reading it from the repository finds nothing,
            # and the branch below used to record that as "no longer exists
            # ... resolved already" for findings that were still open.
            return StageOutcome(
                finding_id=finding_id,
                stage="no_fix_available",
                classification="true_positive",
                rationale=(
                    f"{triage_rationale} No fix attempted: `{path or 'this image'}` is "
                    "inside a vendor image, not a file in this repository. It moves "
                    "when the image is rebuilt or repinned, which no deterministic "
                    "fixer does for an image without a -p<date> derivative."
                ),
            )

        if budget <= 0:
            return StageOutcome(
                finding_id=finding_id,
                stage="queued",
                classification="true_positive",
                rationale=(
                    f"{triage_rationale} Not attempted: this repository is at "
                    f"its limit of {self.max_open_draft_prs} open draft pull "
                    "requests. A repository that wakes up to forty of them "
                    "does not triage them, it turns the capability off."
                ),
            )

        if github is None or not path:
            return StageOutcome(
                finding_id=finding_id,
                stage="no_fix_available",
                classification="true_positive",
                rationale=(
                    f"{triage_rationale} No fix attempted: "
                    + ("the finding names no file." if not path else "GitHub is not reachable.")
                ),
            )

        try:
            content = await github.get_file(repo_full_name, path, default_branch)
        except GitHubError as exc:
            return StageOutcome(
                finding_id=finding_id,
                stage="no_fix_available",
                classification="true_positive",
                rationale=f"{triage_rationale} Could not read {path}: {exc}",
            )
        if content is None:
            # The finding names a file that is no longer there. Almost always
            # means somebody already dealt with it, which is worth recording
            # as its own outcome rather than as a failure.
            return StageOutcome(
                finding_id=finding_id,
                stage="superseded",
                classification="true_positive",
                rationale=(
                    f"{triage_rationale} `{path}` no longer exists on "
                    f"{default_branch}; the finding appears to have been "
                    "resolved already."
                ),
            )

        generated = fixers.generate(finding, content)
        if generated is None:
            # One sentence, because there is one path. This used to choose
            # between two phrasings on `fix_generator_url`, which read as
            # though a generator had been consulted and declined (D-096).
            reason = "No deterministic fixer matches this finding."
            return StageOutcome(
                finding_id=finding_id,
                stage="no_fix_available",
                classification="true_positive",
                rationale=f"{triage_rationale} {reason}",
            )

        fixer_name, fix = generated

        # Two people here have already said this fixer gets this rule wrong
        # (spec 25 §3.3). Offering it a third time is asking them to review
        # the same wrong diff again, which is how a fix pipeline gets muted.
        skip, rejections = is_dampened(
            self.catalog,
            repo_full_name=repo_full_name,
            rule_id=str(finding.get("rule_id") or ""),
            fixer_name=fixer_name,
        )
        if skip:
            return StageOutcome(
                finding_id=finding_id,
                stage="skipped_low_confidence",
                classification="true_positive",
                rationale=(
                    f"{triage_rationale} {fixer_name} produced a fix, but its "
                    f"fixes for this rule have been closed as wrong "
                    f"{rejections} time(s) in this repository. Not offered "
                    "again here until somebody merges one by hand."
                ),
                fixer_name=fixer_name,
                fix_confidence=fix.confidence,
            )

        if fix.confidence < self.min_confidence:
            return StageOutcome(
                finding_id=finding_id,
                stage="skipped_low_confidence",
                classification="true_positive",
                rationale=(
                    f"{triage_rationale} {fixer_name} produced a fix at "
                    f"confidence {fix.confidence:.2f}, below this "
                    f"repository's floor of {self.min_confidence:.2f}. A "
                    "possibly-wrong fix costs more review than no fix."
                ),
                fixer_name=fixer_name,
                fix_confidence=fix.confidence,
            )

        if preview_only:
            # "Auto remediation identified" (spec 18 §7.2), stopping short of
            # every write `_open_draft_pr` below would make: no branch, no
            # commit, no pull request. Safe to call repeatedly — the fixer
            # contract `render_pr_body` already advertises ("re-running
            # produces the same diff") is what makes that true.
            return StageOutcome(
                finding_id=finding_id,
                stage="would_fix",
                classification="true_positive",
                rationale=f"{triage_rationale} {fix.summary} ({fixer_name}).",
                fixer_name=fixer_name,
                fix_confidence=fix.confidence,
                fix_files=dict(fix.files),
            )

        try:
            pr = await self._open_draft_pr(
                github,
                repo_full_name,
                finding,
                fix,
                fixer_name,
                default_branch=default_branch,
            )
        except GitHubError as exc:
            result.errors.append(f"{finding_id}: {exc}")
            return StageOutcome(
                finding_id=finding_id,
                stage="fix_generated",
                classification="true_positive",
                rationale=(
                    f"{triage_rationale} {fixer_name} produced a fix, but the "
                    f"draft pull request could not be opened: {exc}. The fix "
                    "was not lost — the next run regenerates it deterministically."
                ),
            )

        return StageOutcome(
            finding_id=finding_id,
            stage="pr_opened",
            classification="true_positive",
            rationale=f"{triage_rationale} {fix.summary} ({fixer_name}).",
            fix_pr_number=pr.number,
            fix_pr_url=pr.url,
            pr_status="draft_open",
        )

    # -- bump-image-date ---------------------------------------------------

    async def _attempt_image_date_fix(
        self,
        repo_full_name: str,
        finding: dict[str, Any],
        image: image_date.PatchedImage,
        triage_rationale: str,
        *,
        github: GitHubClient | None,
        default_branch: str,
        budget: int,
        result: PipelineResult,
        preview_only: bool,
    ) -> StageOutcome:
        """One finding in a patched image, decided once for the whole image.

        The first finding of an image in a run makes the decision (and opens
        the pull request); the rest of that image's findings share it, so an
        image with forty CVEs yields one pull request, not forty.
        """
        finding_id = str(finding["finding_id"])
        name = image_date.FIXER_NAME
        skip, rejections = is_dampened(
            self.catalog,
            repo_full_name=repo_full_name,
            rule_id=str(finding.get("rule_id") or ""),
            fixer_name=name,
        )
        if skip:
            return StageOutcome(
                finding_id=finding_id,
                stage="skipped_low_confidence",
                classification="true_positive",
                rationale=(
                    f"{triage_rationale} {name}'s fixes for this rule have been "
                    f"closed as wrong {rejections} time(s) in this repository. Not "
                    "offered again here until somebody merges one by hand."
                ),
                fixer_name=name,
            )

        group = self._image_groups.get(image)
        if group is None:
            group = await self._image_group(
                repo_full_name,
                image,
                github=github,
                default_branch=default_branch,
                budget=budget,
                result=result,
                preview_only=preview_only,
            )
            self._image_groups[image] = group
        return group.outcome_for(finding_id, triage_rationale)

    async def _image_group(
        self,
        repo_full_name: str,
        image: image_date.PatchedImage,
        *,
        github: GitHubClient | None,
        default_branch: str,
        budget: int,
        result: PipelineResult,
        preview_only: bool,
    ) -> _ImageGroup:
        if budget <= 0 and not preview_only:
            return _ImageGroup(
                refusal=(
                    f"Not attempted: this repository is at its limit of "
                    f"{self.max_open_draft_prs} open draft pull requests."
                ),
                stage="queued",
            )
        if github is None:
            return _ImageGroup(refusal="No fix attempted: GitHub is not reachable.")
        if self.image_registry is None:
            return _ImageGroup(
                refusal=(
                    "No image registry is configured for Patchwork "
                    "(MYKRONOS_PATCHWORK_IMAGE_REGISTRY), so it cannot see whether "
                    "image-refresh has published a newer snapshot of "
                    f"{image.path}:{image.prefix}."
                )
            )
        tags = await self.image_registry.tags(image.path)
        if tags is None:
            return _ImageGroup(
                refusal=f"Could not list the registry's tags for {image.path}."
            )
        new = image_date.newer_date(image, tags)
        files: dict[str, str] = {}
        if new is not None:
            for path in image_date.CANDIDATE_COMPOSE_FILES:
                try:
                    content = await github.get_file(repo_full_name, path, default_branch)
                except GitHubError as exc:
                    return _ImageGroup(refusal=f"Could not read {path}: {exc}")
                if content is not None:
                    files[path] = content
        plan = image_date.propose(
            image,
            tags=tags,
            files=files,
            findings=self._open_image_findings(repo_full_name, image),
            observed_in_newer=(
                self._observed_in(repo_full_name, image.with_date(new)) if new else None
            ),
        )
        if isinstance(plan, str):
            return _ImageGroup(refusal=plan)

        off_limits = branches_off_limits(self.catalog, repo_full_name)
        if any(str(f["finding_id"]) in off_limits for f in plan.clears):
            return _ImageGroup(
                refusal=(
                    "A person has already edited this image's fix branch; "
                    "Patchwork does not touch it again (spec 08 §3)."
                )
            )
        if plan.fix.confidence < self.min_confidence:
            return _ImageGroup(
                refusal=(
                    f"{image_date.FIXER_NAME} produced a fix at confidence "
                    f"{plan.fix.confidence:.2f}, below this repository's floor of "
                    f"{self.min_confidence:.2f}: no scan of the new tag backs it."
                ),
                stage="skipped_low_confidence",
                plan=plan,
            )
        if preview_only:
            return _ImageGroup(plan=plan, preview=True)

        lead = next(f for f in plan.clears if str(f["finding_id"]) == plan.lead_finding_id)
        branch = f"{BRANCH_PREFIX}{plan.lead_finding_id[:12]}"
        try:
            # Re-running is the normal case: the image stays open until its
            # pull request merges, and a second draft for it is noise.
            existing = await github.find_open_pull_request(repo_full_name, branch)
            if existing is not None:
                return _ImageGroup(plan=plan, pr=existing, counted=True)
            pr = await self._open_draft_pr(
                github,
                repo_full_name,
                lead,
                plan.fix,
                image_date.FIXER_NAME,
                default_branch=default_branch,
                body=image_date.render_pr_body(plan),
            )
        except GitHubError as exc:
            result.errors.append(f"{image.reference}: {exc}")
            return _ImageGroup(
                refusal=(
                    f"{image_date.FIXER_NAME} produced a fix, but the draft pull "
                    f"request could not be opened: {exc}. The next run regenerates "
                    "it deterministically."
                ),
                stage="fix_generated",
                plan=plan,
            )
        return _ImageGroup(plan=plan, pr=pr)

    def _container_rows(
        self, repo_full_name: str, *, open_only: bool
    ) -> list[dict[str, Any]]:
        columns = [
            "finding_id",
            "rule_id",
            "title",
            "severity",
            "package_name",
            "package_version",
            "raw_finding_json",
        ]
        rows = self.catalog.query(
            f"SELECT {', '.join(columns)} FROM findings "
            "WHERE asset_id = ? AND capability = 'containers'"
            + (" AND status = 'open'" if open_only else ""),
            [repo_full_name],
        )
        records = []
        for row in rows:
            record = dict(zip(columns, row, strict=True))
            record["capability"] = "containers"
            raw = record.get("raw_finding_json")
            if isinstance(raw, str):
                try:
                    record["raw_finding_json"] = json.loads(raw) if raw else {}
                except json.JSONDecodeError:
                    record["raw_finding_json"] = {}
            records.append(record)
        return records

    def _open_image_findings(
        self, repo_full_name: str, image: image_date.PatchedImage
    ) -> list[dict[str, Any]]:
        """Every open finding in exactly this image: the pull request's list."""
        return [
            record
            for record in self._container_rows(repo_full_name, open_only=True)
            if image_date.image_of_finding(record) == image
        ]

    def _observed_in(
        self, repo_full_name: str, newer: image_date.PatchedImage
    ) -> set[tuple[str, str]] | None:
        """(rule_id, package) the lake holds for `newer`, or None if none at all.

        Any status: a pair once seen in the newer tag is not claimed as cleared
        by it. Matched on repository and tag, not host: the same registry is
        named by more than one address across this estate's lanes.
        """
        seen: set[tuple[str, str]] | None = None
        for record in self._container_rows(repo_full_name, open_only=False):
            found = image_date.image_of_finding(record)
            if found is None or found.path_tag != newer.path_tag:
                continue
            seen = seen or set()
            seen.add(
                (str(record.get("rule_id") or ""), str(record.get("package_name") or ""))
            )
        return seen

    async def _open_draft_pr(
        self,
        github: GitHubClient,
        repo_full_name: str,
        finding: dict[str, Any],
        fix: fixers.ProposedFix,
        fixer_name: str,
        *,
        default_branch: str,
        body: str | None = None,
    ) -> PullRequest:
        finding_id = str(finding["finding_id"])
        branch = f"{BRANCH_PREFIX}{finding_id[:12]}"

        await github.create_branch(repo_full_name, branch, default_branch)
        await github.commit_files(
            repo_full_name,
            branch,
            changes=[
                FileChange(path=path, content=body)
                for path, body in sorted(fix.files.items())
            ],
            message=(
                f"fix({finding.get('capability')}): {fix.summary}\n\n"
                f"Generated by Mykronos Patchwork ({fixer_name}) for finding "
                f"{finding_id}.\n\nThis is a draft. Nothing merges it "
                "automatically, and Patchwork cannot merge it at all."
            ),
        )
        return await github.create_pull_request(
            repo_full_name,
            head=branch,
            base=default_branch,
            title=f"[Mykronos] {fix.summary}",
            body=body if body is not None else render_pr_body(finding, fix, fixer_name),
            # Not a parameter a caller can vary. spec 08 §3 is a hard
            # constraint, so it is written here once rather than passed in
            # from somewhere that could get it wrong.
            draft=True,
        )


def render_pr_body(
    finding: dict[str, Any], fix: fixers.ProposedFix, fixer_name: str
) -> str:
    """What a reviewer reads (spec 08 §2, stage 5).

    Leads with what to check rather than with what was done. A reviewer's job
    on a machine-generated pull request is to find the thing the machine got
    wrong, and a description that opens by explaining how clever the fix is
    makes that harder.
    """
    lines = [
        f"## {fix.summary}",
        "",
        "**Draft, and it stays that way.** Mykronos opens this for review; it "
        "has no ability to merge — the client it uses exposes no merge "
        "operation at all (spec 08 §3).",
        "",
        "### Before you approve",
        "",
    ]
    lines += [f"- {note}" for note in fix.review_notes] or [
        "- Read the diff. This fixer supplied no specific review guidance, "
        "which is itself worth a second look."
    ]

    lines += [
        "",
        "### What this addresses",
        "",
        f"- **{finding.get('rule_id')}** — {finding.get('title')}",
        f"- Severity: {finding.get('severity')} · reported by "
        f"`{finding.get('capability')}`",
        f"- Location: `{finding.get('file_path')}`"
        + (f":{finding['line_start']}" if finding.get("line_start") else ""),
        "",
        "### Files changed",
        "",
    ]
    lines += [f"- `{path}`" for path in fix.touched]

    lines += [
        "",
        # Asked before the rejection block, because it is the question a
        # merger answers and the rejection block is the one a closer answers.
        regression_prompt(),
        "",
        rejection_prompt(),
        "",
        "---",
        "",
        f"<sub>Generated deterministically by `{fixer_name}` — no model was "
        "involved, and re-running produces the same diff. If you edit this "
        "branch, Patchwork stops touching it permanently (spec 08 §3).</sub>",
    ]
    return "\n".join(lines)
