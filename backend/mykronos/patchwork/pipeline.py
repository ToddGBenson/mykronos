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
from mykronos.patchwork import correlate, fixers
from mykronos.patchwork.stewardship import BRANCH_PREFIX, branches_off_limits
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
)

CLASSIFICATIONS = ("true_positive", "likely_false_positive", "needs_human_judgment")

#: What Patchwork may write a patch for. Narrow by construction: each of
#: these points at a line in a file a deterministic fixer can change.
DEFAULT_SOURCE_CAPABILITIES = ("sast", "secrets", "containers", "iac")

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
        fix_generator_url: str | None = None,
    ) -> None:
        self.catalog = catalog
        self.buffer = buffer
        self.store = store
        self.min_confidence = min_confidence
        self.max_open_draft_prs = max_open_draft_prs
        self.source_capabilities = source_capabilities
        self.correlation_capabilities = correlation_capabilities
        # Null disables LLM-assisted generation entirely (spec 08 §2). The
        # deterministic fixers are unaffected; they are the primary path.
        self.fix_generator_url = fix_generator_url

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

        The store is what stops the pipeline repeating a mistake somebody has
        already corrected: a rule this repository keeps dismissing should not
        get an auto-fix generated for it, however confident the fixer is.
        """
        rule_id = str(finding.get("rule_id") or "")

        if self.store is not None:
            for entry, confidence in self.store.active_entries():
                if (
                    entry.source_type == "finding_dismissal"
                    and entry.subject == rule_id
                    and entry.repo_full_name in (None, repo_full_name)
                    and entry.has_reason
                ):
                    return (
                        "likely_false_positive",
                        f"This repository has dismissed {rule_id} "
                        f"{entry.observations} time(s) with a written reason "
                        f"(confidence {confidence:.2f}): \"{entry.reasons[0]}\". "
                        "Patchwork does not generate fixes for findings the "
                        "team has already judged.",
                    )

        severity = str(finding.get("severity") or "")
        if severity in ("critical", "high"):
            return (
                "true_positive",
                f"A {severity} {finding.get('capability')} finding with no "
                "prior dismissal recorded for this rule.",
            )
        return (
            "needs_human_judgment",
            f"A {severity} finding. Patchwork only generates fixes for high "
            "and critical findings unprompted — a draft pull request for a low "
            "finding costs more review attention than the finding is worth.",
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
            if outcome.stage == "pr_opened":
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
    ) -> StageOutcome:
        finding_id = str(finding["finding_id"])
        path = str(finding.get("file_path") or "")

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
            reason = (
                "No deterministic fixer matches this finding, and no fix "
                "generator endpoint is configured for this deployment, so "
                "nothing was attempted."
                if self.fix_generator_url is None
                else "No deterministic fixer matches this finding."
            )
            return StageOutcome(
                finding_id=finding_id,
                stage="no_fix_available",
                classification="true_positive",
                rationale=f"{triage_rationale} {reason}",
            )

        fixer_name, fix = generated
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

    async def _open_draft_pr(
        self,
        github: GitHubClient,
        repo_full_name: str,
        finding: dict[str, Any],
        fix: fixers.ProposedFix,
        fixer_name: str,
        *,
        default_branch: str,
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
            body=render_pr_body(finding, fix, fixer_name),
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
        "---",
        "",
        f"<sub>Generated deterministically by `{fixer_name}` — no model was "
        "involved, and re-running produces the same diff. If you edit this "
        "branch, Patchwork stops touching it permanently (spec 08 §3).</sub>",
    ]
    return "\n".join(lines)
