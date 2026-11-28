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
            updated_hours: float = 0.5, state: str = "refused", sha: str = "a" * 40) -> None:
    with db.session() as session:
        session.add(RiskGateNoticeState(
            repo_full_name=repo, subject=subject, state=state,
            since_sha=sha, since=NAIVE - timedelta(hours=since_hours),
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
        # The critical is still waiting after 12 h: asked once more. The
        # refused gate was asked for this commit already, so it is left to
        # the 07:00 digest (N1, below).
        assert len(again) == 1, "still waiting after 12 h: asked once more"
        assert "critical" in again[0].render()
        assert len(notifier.sent) == 3

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


# ---------------------------------------------------------------------------
# After review (PR #1238, Fable FIX BEFORE MERGE): B1-B4, N1-N4, N6
# ---------------------------------------------------------------------------


def _stub_gather(monkeypatch: pytest.MonkeyPatch) -> None:
    from mykronos import briefing_sources

    inputs = briefing_sources.OperationalInputs(
        paused_jobs=[], failing_jobs=[], blocked_jobs=[], workflow_blocked_jobs=[],
        unhealthy_jobs=[], tokens=[], toxic_combinations=[], toxic_coverage={},
        exposure=[], production_lag=[],
    )
    monkeypatch.setattr(briefing_sources, "gather", lambda *_args: inputs)


def _soon_credential(db: Any, actor: str = "agent:claude:delivery-9") -> None:
    """A root credential inside its last day, by the wall clock the route reads
    (the route has no clock of its own; 10 h sits well inside 48 h)."""
    from mykronos.schemas import utcnow

    with db.session() as session:
        session.add(AgentCredential(
            token_sha256="9" * 64, actor=actor, family="claude", lineage=[],
            on_behalf_of="operator", purpose="delivery", minted_by="operator",
            minted_at=utcnow() - timedelta(days=6),
            expires_at=utcnow() + timedelta(hours=10),
        ))


def _exceptions(body: dict[str, Any]) -> dict[str, Any]:
    return next(s for s in body["sections"] if s["key"] == "exceptions")


class TestB1AViewerReadsNoCredentialCalendar:
    """`GET /api/credentials/expiring` refuses a principal that may not write;
    the briefing route gives such a principal the count only."""

    def test_a_viewer_gets_the_count_and_no_credential(
        self, client, viewer_auth, admin_auth, monkeypatch
    ) -> None:
        _stub_gather(monkeypatch)
        _soon_credential(client.app.state.db)
        assert client.get("/api/credentials/expiring",
                          headers=viewer_auth).status_code == 403

        response = client.get("/api/briefing/daily", headers=viewer_auth)
        assert response.status_code == 200
        assert "agent:claude:delivery-9" not in response.text
        section = _exceptions(response.json())
        assert [i for i in section["data"]["items"] if i["class"] == "credential"] == []
        assert all("delivery-9" not in line["what"] for line in section["lines"])
        assert section["data"]["counts"]["credentials_withheld"] >= 1
        assert section["data"]["by_class"]["credential"] >= 1, "the count stays"

        admin = _exceptions(client.get("/api/briefing/daily", headers=admin_auth).json())
        assert any("agent:claude:delivery-9" in i["what"] for i in admin["data"]["items"])
        assert "credentials_withheld" not in admin["data"]["counts"]

    async def test_the_dm_reads_the_full_list_and_signal_filing_does_not(
        self, client, monkeypatch
    ) -> None:
        _stub_gather(monkeypatch)
        _soon_credential(client.app.state.db)
        dm = _exceptions((await briefing_dm.route_reader(
            client.app, lists_credentials=True)(None)).model_dump())
        assert any("agent:claude:delivery-9" in i["what"] for i in dm["data"]["items"])
        other = _exceptions((await briefing_dm.route_reader(
            client.app, actor=f"job:{jobs.SIGNAL_FILING_JOB}")(None)).model_dump())
        assert not any("delivery-9" in i["what"] for i in other["data"]["items"])

    def test_the_scheduled_dm_reads_the_full_list(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import asyncio

        from fastapi.testclient import TestClient

        from mykronos import main

        _stub_gather(monkeypatch)
        captured: dict[str, Any] = {}

        async def record(name: str, interval: int, job: Any, db: Any = None) -> None:
            captured[name] = job

        reads: list[Any] = []

        async def fake_dm(settings_: Settings, **kwargs: Any) -> None:
            reads.append(await kwargs["read"](None))

        monkeypatch.setattr(main, "_every", record)
        monkeypatch.setattr(briefing_dm, "send_briefing_dm", fake_dm)
        with TestClient(main.create_app(settings.model_copy(
            update={"run_jobs_in_background": True}
        ))) as test_client:
            _soon_credential(test_client.app.state.db)
            asyncio.run(captured[jobs.BRIEFING_DM_JOB]())
        [page] = reads
        section = _exceptions(page.model_dump())
        assert any("agent:claude:delivery-9" in i["what"] for i in section["data"]["items"])


class TestB2AnUnreadableSectionIsAsked:
    async def test_an_unavailable_section_is_an_urgent_question(
        self, estate, quiet_settings, monkeypatch
    ) -> None:
        def broken(*_args: Any) -> Any:
            raise RuntimeError("risk_gate_notice_states is locked")

        monkeypatch.setattr(briefing_exceptions, "_refusals", broken)
        notifier = Recorder()
        send = briefing_exceptions.send_urgent_questions
        with pytest.raises(briefing_exceptions.ExceptionsUnreadableError):
            await send(quiet_settings, db=estate, notifier=notifier, now=NOW)
        [note] = notifier.sent
        text = note.render()
        assert "cannot read" in text
        assert "1. (recommended) " in text
        # Still failing, never a success; asked once per 12 h like any other.
        with pytest.raises(briefing_exceptions.ExceptionsUnreadableError):
            await send(quiet_settings, db=estate, notifier=notifier,
                       now=NOW + timedelta(minutes=15))
        assert len(notifier.sent) == 1

    async def test_an_unreadable_declared_file_is_asked_too(
        self, db, quiet_settings, tmp_path
    ) -> None:
        bad = tmp_path / "creds.yaml"
        bad.write_text("credentials:\n  - name: x\n    token: not-allowed\n", encoding="utf-8")
        notifier = Recorder()
        await briefing_exceptions.send_urgent_questions(
            quiet_settings.model_copy(update={"credential_expiry_path": bad}), db=db,
            notifier=notifier, now=NOW,
        )
        [note] = notifier.sent
        assert "cannot read the declared credential file" in note.render()


def _flood(db: Any) -> None:
    """The reviewer's probe: 12 credentials in their last day, 15 refused
    non-PR scopes held over 2 h."""
    for n in range(12):
        credential(db, f"{n:064d}", f"agent:claude:role{n}-1", hours_left=5,
                   purpose=f"role{n}")
    for n in range(15):
        refusal(db, f"o/repo{n}", "commit_gate", since_hours=4, sha=f"{n:040d}")


class TestB3UrgentDmsAreCapped:
    async def test_three_per_tick_then_one_summary_line(self, db, quiet_settings) -> None:
        _flood(db)
        notifier = Recorder()
        sent = await briefing_exceptions.send_urgent_questions(
            quiet_settings, db=db, notifier=notifier, now=NOW)
        assert len(sent) == len(notifier.sent) == briefing_exceptions.URGENT_PER_TICK == 3
        assert "24 more" in sent[-1].lines[-1]
        assert all("more" not in note.lines[-1] for note in sent[:-1])

    async def test_and_capped_per_day(self, db, quiet_settings) -> None:
        _flood(db)
        notifier = Recorder()
        for tick in range(96):  # a day of 15-minute ticks, clock pinned
            await briefing_exceptions.send_urgent_questions(
                quiet_settings, db=db, notifier=notifier,
                now=NOW + timedelta(minutes=15 * tick))
        assert len(notifier.sent) == briefing_exceptions.URGENT_PER_DAY == 6


class TestB4TheDigestIsNeverCutSilently:
    def _full(self, db: Any, settings: Settings) -> str:
        for n in range(6):
            credential(db, f"{n:064d}", f"agent:claude:{'r' * 60}{n}-1", hours_left=30,
                       purpose=f"role{n}")
        for n in range(5):
            refusal(db, f"o/{'p' * 60}{n}", "commit_gate", since_hours=1, sha=f"{n:040d}")
        page = with_exceptions(build(db, settings))
        products = [briefing_dm.ProductRead(f"o/product{n}", error="x" * 300)
                    for n in range(3)]
        return briefing_dm.compose(page, products, url=PAGE, local_now=NOW).render()

    def test_not_read_and_products_survive_and_the_cut_is_said(
        self, db, quiet_settings
    ) -> None:
        from mykronos.notify import MAX_TEXT

        text = self._full(db, quiet_settings)
        assert len(text) <= MAX_TEXT
        rows = text.split("\n")
        assert rows[-1].startswith("*Products:*"), rows[-1]
        assert "*Not read:*" in rows
        assert any(row.startswith("*Left out to fit:*") for row in rows), rows
        assert any("more on the page" in row for row in rows)

    def test_a_short_digest_leaves_nothing_out(self, estate, quiet_settings) -> None:
        page = with_exceptions(build(estate, quiet_settings))
        text = briefing_dm.compose(page, [], url=PAGE, local_now=NOW).render()
        assert "Left out to fit" not in text
        assert "*Needs you:*" in text and "*Also counted:*" in text


class TestN1AStandingRefusalIsAskedOncePerCommit:
    async def test_asked_once_then_digest_only(self, db, quiet_settings) -> None:
        refusal(db, "o/thehub", "portfolio", since_hours=30)
        notifier = Recorder()
        send = briefing_exceptions.send_urgent_questions
        assert len(await send(quiet_settings, db=db, notifier=notifier, now=NOW)) == 1
        for later in (12.5, 24, 72):
            assert await send(quiet_settings, db=db, notifier=notifier,
                              now=NOW + timedelta(hours=later)) == []
        # Still in the digest.
        keys = [i["key"] for i in build(db, quiet_settings,
                                         NOW + timedelta(hours=72)).data["items"]]
        assert f"gate:o/thehub|portfolio|{'a' * 40}" in keys

    async def test_a_new_commit_is_asked_again(self, db, quiet_settings) -> None:
        refusal(db, "o/thehub", "portfolio", since_hours=30)
        notifier = Recorder()
        send = briefing_exceptions.send_urgent_questions
        await send(quiet_settings, db=db, notifier=notifier, now=NOW)
        refusal(db, "o/thehub", "commit_gate", since_hours=3, sha="b" * 40)
        [note] = await send(quiet_settings, db=db, notifier=notifier,
                            now=NOW + timedelta(hours=1))
        assert "bbbbbbbbbbbb" in note.render()


class TestN2CredentialWindowIsPlusMinus24h:
    def _urgent(self, db: Any, settings: Settings) -> dict[str, str]:
        return {i["key"]: i["urgent"] for i in build(db, settings).data["items"]
                if i["class"] == "credential"}

    def test_lapsed_over_a_day_is_digest_only(self, db, quiet_settings) -> None:
        credential(db, "1" * 64, "agent:claude:old-1", hours_left=-72, purpose="old")
        assert self._urgent(db, quiet_settings) == {
            "credential:agent-credential:agent:claude:old-1": ""
        }

    def test_lapsed_within_a_day_says_lapsed(self, db, quiet_settings) -> None:
        credential(db, "1" * 64, "agent:claude:gone-1", hours_left=-5, purpose="gone")
        credential(db, "2" * 64, "agent:claude:soon-1", hours_left=5, purpose="soon")
        urgent = self._urgent(db, quiet_settings)
        lapsed = urgent["credential:agent-credential:agent:claude:gone-1"]
        live = urgent["credential:agent-credential:agent:claude:soon-1"]
        assert "lapsed" in lapsed and "under 24 h" not in lapsed
        assert live and "lapsed" not in live


class TestN3TheAskIsRecordedBeforeItIsSent:
    async def test_a_failing_audit_write_sends_nothing(
        self, estate, quiet_settings, monkeypatch
    ) -> None:
        def no_audit(*_args: Any, **_kwargs: Any) -> Any:
            raise RuntimeError("audit_log is read-only")

        monkeypatch.setattr(estate, "audit", no_audit)
        notifier = Recorder()
        for tick in range(3):
            with pytest.raises(RuntimeError):
                await briefing_exceptions.send_urgent_questions(
                    quiet_settings, db=estate, notifier=notifier,
                    now=NOW + timedelta(minutes=15 * tick))
        assert notifier.sent == [], "nothing goes out that is not recorded"


class TestN4AskedIsBoundedByCreatedAt:
    async def test_an_old_row_is_not_read(self, estate, quiet_settings) -> None:
        from mykronos.db.models import AuditLogEntry

        # An ask written a month ago whose detail claims a recent time: the
        # window is the row's own `created_at`, so it does not count.
        with estate.session() as session:
            session.add(AuditLogEntry(
                actor="job:briefing-urgent", action=briefing_exceptions.ACTION,
                entity_type="briefing_exception", entity_id="approval:req-disp-crit",
                detail={"asked_at": (NAIVE - timedelta(hours=1)).isoformat()},
                created_at=NAIVE - timedelta(days=30),
            ))
        notifier = Recorder()
        await briefing_exceptions.send_urgent_questions(
            quiet_settings, db=estate, notifier=notifier, now=NOW)
        assert any("critical" in note.render() for note in notifier.sent)


class TestN6AQuestionEscapesHostileText:
    def test_question_note_cannot_ping_or_forge_a_link(self) -> None:
        hostile = "x <!channel> \n<https://evil.example|The briefing> & more"
        item = {
            "key": "k", "decide": hostile, "urgent": hostile,
            "question": {"ask": hostile + "?", "options": [hostile] * 3, "recommended": 0},
        }
        text = briefing_exceptions.question_note(item, url=PAGE).render()
        assert "<!channel>" not in text
        assert text.count("<http") == 1 and f"<{PAGE}|The briefing>" in text
        assert "&lt;https://evil.example|The briefing&gt;" in text
        assert "\\n" not in text and len(text.split("\n")) == 7
