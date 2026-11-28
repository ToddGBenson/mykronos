"""The operator's exceptions digest and urgent questions (TheHub #62419).

Pinned here:

* **only the five classes are items** - pending risk acceptances, high and
  critical disposition requests, credentials due, policy-change approvals and
  risk-gate refusals each list with the one command that decides them; every
  other pending or decided approval, a sub-agent's or self-rotating
  credential, and a refusal nobody has re-evaluated for a week are counts;
* **what cannot be read is named** - deploy-ratchet refusals and credential
  mints waiting have no record in MyKronos yet, so the section is `partial`
  and says so instead of reading as "none";
* **urgent questions** - a release blocked over 2 h, a critical, or a
  credential under 24 h is asked once, as one question with three options and
  the recommendation first, and not again for 12 h (a pinned clock);
* **the 07:00 DM is the digest** - exceptions with their commands first,
  everything else as counts.

No test sends anything to Slack: the notifier is a recorder throughout.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from mykronos import briefing_dm, briefing_exceptions, jobs
from mykronos.api.briefing_daily import BriefingSectionOut, DailyBriefingOut
from mykronos.config import Settings
from mykronos.db import Database
from mykronos.db.models import (
    AgentCredential,
    ApprovalDecision,
    ApprovalRequest,
    RiskAcceptance,
    RiskGateNoticeState,
)
from tests.test_briefing_dm import PAGE, Recorder, configured, overall_fixture

#: 2026-11-28 07:00 in Phoenix (UTC-7, no DST) is 14:00 UTC.
NOW = datetime(2026, 11, 28, 14, 0, tzinfo=UTC)
NAIVE = NOW.replace(tzinfo=None)


@pytest.fixture
def db(settings: Settings) -> Any:
    database = Database(settings.database_url)
    database.create_all()
    yield database
    database.close()


@pytest.fixture
def quiet_settings(settings: Settings) -> Settings:
    """No declared credential file: only what the fixture puts in the database."""
    return configured(settings, credential_expiry_path=None)


def approval(db: Any, rid: str, duty: str, tier: str, subject: str, *,
             state: str = "pending", age_hours: float = 3,
             expires_in_hours: float = 100) -> None:
    with db.session() as session:
        session.add(ApprovalRequest(
            id=rid, duty=duty, tier=tier, subject_ref=subject, state=state,
            requested_by="agent:test", requester_kind="agent",
            created_at=NAIVE - timedelta(hours=age_hours),
            expires_at=NAIVE + timedelta(hours=expires_in_hours),
        ))


def decision(db: Any, request_id: str, kind: str, *, age_hours: float) -> None:
    with db.session() as session:
        session.add(ApprovalDecision(
            request_id=request_id, approver=f"{kind}:x", approver_kind=kind,
            verdict="approve", created_at=NAIVE - timedelta(hours=age_hours),
        ))


def refusal(db: Any, repo: str, subject: str, *, since_hours: float,
            updated_hours: float = 0.5, state: str = "refused") -> None:
    with db.session() as session:
        session.add(RiskGateNoticeState(
            repo_full_name=repo, subject=subject, state=state,
            since_sha="a" * 40, since=NAIVE - timedelta(hours=since_hours),
            held=3, last_score=72, updated_at=NAIVE - timedelta(hours=updated_hours),
        ))


def credential(db: Any, sha: str, actor: str, *, hours_left: float,
               lineage: list[str] | None = None, purpose: str = "delivery") -> None:
    with db.session() as session:
        session.add(AgentCredential(
            token_sha256=sha, actor=actor, family="claude", lineage=lineage or [],
            on_behalf_of="operator", purpose=purpose, minted_by="operator",
            minted_at=NAIVE - timedelta(days=6),
            expires_at=NAIVE + timedelta(hours=hours_left),
        ))


@pytest.fixture
def estate(db: Any) -> Any:
    """One item of each exception class, and routine items beside them."""
    # 1. A pending risk acceptance (any severity is the operator's).
    with db.session() as session:
        session.add(RiskAcceptance(id="ra-1", repo_full_name="o/thehub",
                                   covered_finding_ids=["f1", "f2", "f3"],
                                   residual_severity="high", status="pending_approval"))
    approval(db, "req-ra", "risk_acceptance", "high", "ra-1")
    # 2. High and critical disposition requests; a medium one is routine.
    approval(db, "req-disp-crit", "finding_disposition", "critical", "finding-c")
    approval(db, "req-disp-high", "finding_disposition", "high", "finding-h")
    approval(db, "req-disp-med", "finding_disposition", "medium", "finding-m")
    # 4. Policy changes: a governance-class merge and a delegation grant. A
    # production-class merge is routine.
    approval(db, "req-gov", "pull_request_merge", "governance", "o/mykronos#901@abc")
    approval(db, "req-deleg", "delegation_grant", "any", "delegation:finding_disposition:low")
    approval(db, "req-prod", "pull_request_merge", "production", "o/mykronos#902@def")
    # Not pending: decided by rule in the window, or lapsed unanswered.
    approval(db, "req-done", "pull_request_merge", "routine", "o/mykronos#903@123",
             state="approved")
    decision(db, "req-done", "agent", age_hours=2)
    decision(db, "req-old", "human", age_hours=30)
    approval(db, "req-lapsed", "risk_acceptance", "low", "ra-x", expires_in_hours=-1)
    # 3. Credentials: a root agent credential due in 40 h is the operator's;
    # a sub-agent's lapsing in 2 h is its parent's; one in ten days is not due.
    credential(db, "1" * 64, "agent:claude:delivery-1", hours_left=40)
    credential(db, "2" * 64, "agent:claude:child-1", hours_left=2, lineage=["x"],
               purpose="builder")
    credential(db, "3" * 64, "agent:claude:po-1", hours_left=240, purpose="po")
    # 5. Gate refusals: main refused for 3 h; a PR refused but not evaluated
    # for ten days is stale; a passing scope is nothing.
    refusal(db, "o/thehub", "commit_gate", since_hours=3)
    refusal(db, "o/mykronos", "pr_gate#77", since_hours=300, updated_hours=240)
    refusal(db, "o/keel", "commit_gate", since_hours=5, state="clear")
    return db


def build(db: Any, settings: Settings, at: datetime = NOW) -> Any:
    return briefing_exceptions.exceptions_section(db, settings, now=at)


# ---------------------------------------------------------------------------
# The digest's items
# ---------------------------------------------------------------------------


class TestOnlyTheFiveClasses:
    def test_each_class_is_listed_and_nothing_else_is(self, estate, quiet_settings) -> None:
        section = build(estate, quiet_settings)
        keys = {item["key"] for item in section.data["items"]}
        assert keys == {
            "approval:req-ra",
            "approval:req-disp-crit",
            "approval:req-disp-high",
            "approval:req-gov",
            "approval:req-deleg",
            "credential:agent-credential:agent:claude:delivery-1",
            f"gate:o/thehub|commit_gate|{'a' * 40}",
        }
        assert section.data["by_class"] == {
            "risk_acceptance": 1,
            "disposition": 2,
            "credential": 1,
            "policy_change": 2,
            "gate_refusal": 1,
        }

    def test_everything_else_is_only_counted(self, estate, quiet_settings) -> None:
        counts = build(estate, quiet_settings).data["counts"]
        assert counts["other_pending_approvals"] == {
            "finding_disposition": 1, "pull_request_merge": 1,
        }
        assert counts["decided_last_24h"] == {"total": 1, "by_agent": 1, "by_human": 0}
        assert counts["credentials_not_yours"] == 1
        assert counts["stale_gate_refusals"] == 1

    def test_each_item_carries_its_deciding_command(self, estate, quiet_settings) -> None:
        section = build(estate, quiet_settings)
        decide = {item["key"]: item["decide"] for item in section.data["items"]}
        assert decide["approval:req-ra"] == "POST /api/approvals/req-ra/decisions"
        assert decide["approval:req-gov"] == "POST /api/approvals/req-gov/decisions"
        assert "POST /api/agents/credentials" in decide[
            "credential:agent-credential:agent:claude:delivery-1"
        ]
        assert decide[f"gate:o/thehub|commit_gate|{'a' * 40}"] == (
            f"GET /api/oracle/decisions/by-commit/{'a' * 40}"
        )
        # Every item is a line, and its ref is the same command.
        assert len(section.lines) == len(section.data["items"])
        for item, line in zip(section.data["items"], section.lines, strict=True):
            assert item["decide"] and line.ref == item["decide"]
            assert line.work == "decision"

    def test_the_risk_acceptance_names_its_repository_and_findings(
        self, estate, quiet_settings
    ) -> None:
        [item] = [i for i in build(estate, quiet_settings).data["items"]
                  if i["class"] == "risk_acceptance"]
        assert item["repo_full_name"] == "o/thehub"
        assert "3 finding(s)" in item["what"]

    def test_a_class_with_no_record_is_named_not_read(self, db, quiet_settings) -> None:
        section = build(db, quiet_settings)
        assert section.data["items"] == []
        assert section.status == "partial"
        not_read = {gap["class"] for gap in section.data["not_read"]}
        assert not_read == {"deploy_ratchet_refusals", "credential_mints_waiting"}
        assert "deploy ratchet" in section.reason

    def test_an_unreadable_declared_file_is_partial_not_lost(
        self, estate, quiet_settings, tmp_path
    ) -> None:
        bad = tmp_path / "creds.yaml"
        bad.write_text("credentials:\n  - name: x\n    token: not-allowed\n", encoding="utf-8")
        section = build(estate, quiet_settings.model_copy(update={"credential_expiry_path": bad}))
        assert section.status == "partial"
        assert "declared credential" in section.reason
        # The observed credentials are still listed.
        assert section.data["by_class"]["credential"] == 1


# ---------------------------------------------------------------------------
# Urgent questions
# ---------------------------------------------------------------------------


class TestUrgent:
    def test_what_is_urgent(self, estate, quiet_settings) -> None:
        # Another credential inside its last day, and main refused only 1 h.
        credential(estate, "4" * 64, "agent:claude:security-1", hours_left=10,
                   purpose="security")
        refusal(estate, "o/binnacle", "commit_gate", since_hours=1)
        urgent = {i["key"]: i["urgent"]
                  for i in build(estate, quiet_settings).data["items"] if i["urgent"]}
        assert set(urgent) == {
            f"gate:o/thehub|commit_gate|{'a' * 40}",
            "approval:req-disp-crit",
            "credential:agent-credential:agent:claude:security-1",
        }
        assert "over 2 h" in urgent[f"gate:o/thehub|commit_gate|{'a' * 40}"]

    def test_a_question_has_three_options_recommendation_first(
        self, estate, quiet_settings
    ) -> None:
        for item in build(estate, quiet_settings).data["items"]:
            if not item["urgent"]:
                assert item["question"] is None
                continue
            question = item["question"]
            assert question["ask"].endswith("?")
            assert len(question["options"]) == 3
            assert question["recommended"] == 0
        note = briefing_exceptions.question_note(
            next(i for i in build(estate, quiet_settings).data["items"] if i["urgent"]),
            url=PAGE,
        )
        rows = note.render().split("\n")
        numbered = [r for r in rows if r[:3] in ("1. ", "2. ", "3. ")]
        assert len(numbered) == 3
        assert numbered[0].startswith("1. (recommended) ")

    async def test_asked_once_and_not_again_for_twelve_hours(
        self, estate, quiet_settings
    ) -> None:
        notifier = Recorder()
        send = briefing_exceptions.send_urgent_questions
        first = await send(quiet_settings, db=estate, notifier=notifier, now=NOW)
        # Two urgent items today: main refused 3 h, a critical disposition.
        assert len(first) == len(notifier.sent) == 2
        assert all(len(note.lines) >= 5 for note in notifier.sent)

        for later in (timedelta(minutes=15), timedelta(hours=6),
                      timedelta(hours=11, minutes=59)):
            assert await send(quiet_settings, db=estate, notifier=notifier,
                              now=NOW + later) == []
        assert len(notifier.sent) == 2

        again = await send(quiet_settings, db=estate, notifier=notifier,
                           now=NOW + timedelta(hours=12, minutes=1))
        assert len(again) == 2, "still waiting after 12 h: asked once more"
        assert len(notifier.sent) == 4

    async def test_a_new_urgent_item_is_asked_at_once(self, estate, quiet_settings) -> None:
        notifier = Recorder()
        send = briefing_exceptions.send_urgent_questions
        await send(quiet_settings, db=estate, notifier=notifier, now=NOW)
        credential(estate, "5" * 64, "agent:claude:hubops-1", hours_left=8, purpose="hubops")
        [note] = await send(quiet_settings, db=estate, notifier=notifier,
                            now=NOW + timedelta(hours=1))
        assert "agent:claude:hubops-1" in note.render()

    async def test_nothing_urgent_is_a_quiet_success(self, db, quiet_settings) -> None:
        notifier = Recorder()
        assert await briefing_exceptions.send_urgent_questions(
            configured(quiet_settings, briefing_dm_channel=""), db=db, notifier=notifier,
            now=NOW,
        ) == []
        assert notifier.sent == []

    async def test_unconfigured_with_something_to_ask_is_skipped(
        self, estate, quiet_settings
    ) -> None:
        notifier = Recorder()
        with pytest.raises(jobs.JobSkipped, match="MYKRONOS_BRIEFING_DM_CHANNEL"):
            await briefing_exceptions.send_urgent_questions(
                configured(quiet_settings, briefing_dm_channel=""), db=estate,
                notifier=notifier, now=NOW,
            )
        assert notifier.sent == []

    async def test_an_undelivered_question_is_asked_again_next_tick(
        self, estate, quiet_settings
    ) -> None:
        send = briefing_exceptions.send_urgent_questions
        with pytest.raises(briefing_exceptions.UrgentUndeliveredError):
            await send(quiet_settings, db=estate, notifier=Recorder(delivers=False), now=NOW)
        notifier = Recorder()
        assert len(await send(quiet_settings, db=estate, notifier=notifier,
                              now=NOW + timedelta(minutes=15))) == 2


# ---------------------------------------------------------------------------
# The 07:00 DM is the digest
# ---------------------------------------------------------------------------


def with_exceptions(section: Any) -> DailyBriefingOut:
    page = overall_fixture()
    page.sections.insert(0, BriefingSectionOut.model_validate(
        {**section.__dict__, "lines": [line.__dict__ for line in section.lines]}
    ))
    return page


class TestTheDigest:
    def test_exceptions_first_each_with_its_command(self, estate, quiet_settings) -> None:
        page = with_exceptions(build(estate, quiet_settings))
        text = briefing_dm.compose(page, [], url=PAGE, local_now=NOW).render()
        rows = text.split("\n")
        assert rows[1] == f"<{PAGE}|Open the full briefing>"
        assert rows[2] == "*Decide (7):*"
        decide_rows = rows[3:10]
        assert all(" Decide: " in row for row in decide_rows), decide_rows
        assert any("POST /api/approvals/req-ra/decisions" in row for row in decide_rows)
        assert "*Not readable yet:* deploy ratchet refusals; credential mints waiting." in rows

    def test_everything_else_is_a_count(self, estate, quiet_settings) -> None:
        page = with_exceptions(build(estate, quiet_settings))
        text = briefing_dm.compose(page, [], url=PAGE, local_now=NOW).render()
        # The rest of the page is counted, never listed: the exceptions' own
        # lines are not counted again.
        assert "\n*Needs you:* 1 merge, 1 decision, 2 stories.\n" in text
        assert ("*Also counted:* 2 other approvals pending; 1 decided by rule or a "
                "person in 24h (1 by an agent)") in text
        assert "Patchwork fix for lodash" not in text
        assert "CVE-2026-1111" not in text

    def test_a_quiet_morning_says_nothing_waits(self, db, quiet_settings) -> None:
        page = with_exceptions(build(db, quiet_settings))
        text = briefing_dm.compose(page, [], url=PAGE, local_now=NOW).render()
        assert "*Decide:* nothing is waiting on you." in text

    def test_a_missing_exceptions_section_is_never_all_clear(self) -> None:
        text = briefing_dm.compose(overall_fixture(), [], url=PAGE, local_now=NOW).render()
        assert "*Decide:* the exceptions could not be read today." in text

    def test_untrusted_text_in_an_item_cannot_forge_a_link(
        self, estate, quiet_settings
    ) -> None:
        section = build(estate, quiet_settings)
        section.data["items"][0]["what"] = "x\n<https://evil.example|Open the full briefing>"
        text = briefing_dm.compose(with_exceptions(section), [], url=PAGE,
                                   local_now=NOW).render()
        assert text.count("<http") == 1
        assert "&lt;https://evil.example|Open the full briefing&gt;" in text


class TestItIsScheduled:
    def test_the_urgent_job_ticks_every_fifteen_minutes(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import asyncio

        from fastapi.testclient import TestClient

        from mykronos import main

        captured: dict[str, Any] = {}

        async def record(name: str, interval: int, job: Any, db: Any = None) -> None:
            captured[name] = (interval, job)

        calls: list[dict[str, Any]] = []

        async def fake_send(settings_: Settings, **kwargs: Any) -> list[Any]:
            calls.append(kwargs)
            return []

        monkeypatch.setattr(main, "_every", record)
        monkeypatch.setattr(briefing_exceptions, "send_urgent_questions", fake_send)
        with TestClient(main.create_app(settings.model_copy(
            update={"run_jobs_in_background": True}
        ))):
            pass

        interval, run = captured[jobs.BRIEFING_URGENT_JOB]
        assert interval == briefing_exceptions.TICK_SECONDS == 900
        asyncio.run(run())
        [call] = calls
        assert call["db"] is not None
