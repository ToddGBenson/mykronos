"""Operator actions that check themselves (TheHub #60972).

The probe registry, its two probes against a stubbed GitHub, the
verification each operator action in "Needs you today" carries, and the
read-only line: the probe path never writes to GitHub or TheHub.
"""

from __future__ import annotations

import ast
import inspect
from datetime import timedelta
from typing import Any

import pytest

from mykronos import briefing_sources, daily_briefing, delivery_sources, operator_checks
from mykronos.delivery_sources import BoardRead, DeliveryInputs
from mykronos.github.client import FakeGitHubClient, GitHubError
from mykronos.github.factory import FakeGitHubClientFactory
from mykronos.operator_checks import (
    OBSERVED_DONE,
    OBSERVED_NOT_DONE,
    PROBE_ERROR,
    UNPROBED,
    Verification,
    required_checks_on_main,
    tag_ruleset_exists,
)
from mykronos.schemas import utcnow
from tests.conftest import INSTALLATION, REPO
from tests.po_support import FakeHub, attach_hub, story
from tests.po_support import onboard as onboard_row
from tests.test_daily_briefing import _everything_read, _get, _section

ALL_THREE = ["independent-review", "backend-tests", "secret-hygiene"]


@pytest.fixture(autouse=True)
def _fresh_cache() -> Any:
    delivery_sources.clear_cache()
    yield
    delivery_sources.clear_cache()


@pytest.fixture
def gathered(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(briefing_sources, "gather", lambda *_args: _everything_read())


class StubClient:
    """Answers branch protection and rulesets as told; records every call."""

    def __init__(
        self,
        protection: dict[str, Any] | None = None,
        rulesets: list[dict[str, Any]] | None = None,
        raises: GitHubError | None = None,
    ) -> None:
        self.protection = protection
        self.rulesets = rulesets or []
        self.raises = raises
        self.calls: list[str] = []

    async def get_branch_protection(self, repo: str, branch: str) -> dict[str, Any] | None:
        self.calls.append("get_branch_protection")
        if self.raises:
            raise self.raises
        return self.protection

    async def get_rulesets(self, repo: str) -> list[dict[str, Any]]:
        self.calls.append("get_rulesets")
        if self.raises:
            raise self.raises
        return [{k: v for k, v in r.items() if k not in ("conditions", "rules")}
                for r in self.rulesets]

    async def get_ruleset(self, repo: str, ruleset_id: int) -> dict[str, Any]:
        self.calls.append("get_ruleset")
        return next(r for r in self.rulesets if r["id"] == ruleset_id)


def _protection(contexts: list[str]) -> dict[str, Any]:
    return {
        "required_status_checks": {
            "strict": False,
            "contexts": contexts,
            "checks": [{"context": c, "app_id": None} for c in contexts],
        }
    }


def _tag_ruleset(
    include: list[str], rules: list[str], *, enforcement: str = "active", rid: int = 7
) -> dict[str, Any]:
    return {
        "id": rid,
        "name": "release tags",
        "target": "tag",
        "enforcement": enforcement,
        "conditions": {"ref_name": {"include": include, "exclude": []}},
        "rules": [{"type": t} for t in rules],
    }


# ---------------------------------------------------------------------------
# The registry
# ---------------------------------------------------------------------------


class TestRegistry:
    def test_ships_exactly_two_probes_mapped_to_their_stories(self) -> None:
        assert set(operator_checks.REGISTRY) == {60931, 60810}
        assert operator_checks.REGISTRY[60931].name == "required_checks_on_main"
        assert operator_checks.REGISTRY[60810].name == "tag_ruleset_exists"
        assert {p.repo for p in operator_checks.REGISTRY.values()} == {"ToddGBenson/mykronos"}

    def test_evidence_is_required_except_when_unprobed(self) -> None:
        assert Verification(UNPROBED).evidence == ""
        with pytest.raises(ValueError):
            Verification(OBSERVED_DONE)
        with pytest.raises(ValueError):
            Verification("guessed", "x")


# ---------------------------------------------------------------------------
# required_checks_on_main
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestRequiredChecksOnMain:
    async def test_all_three_required_is_observed_done(self) -> None:
        probe = required_checks_on_main(REPO, ["backend-tests"])
        v = await probe.check(StubClient(_protection(ALL_THREE)))
        assert v.verification == OBSERVED_DONE
        assert "backend-tests" in v.evidence and "secret-hygiene" in v.evidence

    async def test_no_contexts_is_observed_not_done(self) -> None:
        v = await required_checks_on_main(REPO, ["backend-tests"]).check(
            StubClient(_protection([]))
        )
        assert v.verification == OBSERVED_NOT_DONE
        assert "does not require backend-tests" in v.evidence

    async def test_the_other_two_without_backend_tests_is_not_done(self) -> None:
        v = await required_checks_on_main(REPO, ["backend-tests"]).check(
            StubClient(_protection(["independent-review", "secret-hygiene"]))
        )
        assert v.verification == OBSERVED_NOT_DONE

    async def test_unprotected_main_is_not_done(self) -> None:
        v = await required_checks_on_main(REPO, ["backend-tests"]).check(StubClient(None))
        assert v.verification == OBSERVED_NOT_DONE
        assert "no branch protection" in v.evidence

    async def test_a_403_is_probe_error_never_done(self) -> None:
        refused = GitHubError("Resource not accessible by integration: secret-ish", status=403)
        v = await required_checks_on_main(REPO, ["backend-tests"]).check(
            StubClient(raises=refused)
        )
        assert v.verification == PROBE_ERROR
        assert "403" in v.evidence and "administration: read" in v.evidence
        # GitHub's own response text is never echoed.
        assert "secret-ish" not in v.evidence


# ---------------------------------------------------------------------------
# tag_ruleset_exists
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestTagRulesetExists:
    async def test_no_rulesets_is_not_done(self) -> None:
        v = await tag_ruleset_exists(REPO, "v*").check(StubClient(rulesets=[]))
        assert v.verification == OBSERVED_NOT_DONE
        assert "none targets v*" in v.evidence

    async def test_an_active_v_ruleset_restricting_update_and_deletion_is_done(self) -> None:
        client = StubClient(rulesets=[_tag_ruleset(["refs/tags/v*"], ["update", "deletion"])])
        v = await tag_ruleset_exists(REPO, "v*").check(client)
        assert v.verification == OBSERVED_DONE
        assert "release tags" in v.evidence
        # The listing has no conditions, so the single read was made.
        assert client.calls == ["get_rulesets", "get_ruleset"]

    async def test_a_ruleset_that_only_restricts_deletion_is_not_done(self) -> None:
        client = StubClient(rulesets=[_tag_ruleset(["refs/tags/v*"], ["deletion"])])
        v = await tag_ruleset_exists(REPO, "v*").check(client)
        assert v.verification == OBSERVED_NOT_DONE
        assert "deletion" in v.evidence

    async def test_an_evaluate_only_or_other_pattern_ruleset_is_not_done(self) -> None:
        client = StubClient(
            rulesets=[
                _tag_ruleset(["refs/tags/v*"], ["update", "deletion"], enforcement="evaluate"),
                _tag_ruleset(["refs/tags/release-*"], ["update", "deletion"], rid=8),
            ]
        )
        v = await tag_ruleset_exists(REPO, "v*").check(client)
        assert v.verification == OBSERVED_NOT_DONE

    async def test_a_403_is_probe_error(self) -> None:
        v = await tag_ruleset_exists(REPO, "v*").check(
            StubClient(raises=GitHubError("nope", status=403))
        )
        assert v.verification == PROBE_ERROR and "403" in v.evidence


# ---------------------------------------------------------------------------
# verify: installations and failures
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestVerify:
    async def test_a_repository_with_no_installation_is_probe_error(self) -> None:
        registry = {1: required_checks_on_main(REPO, ["backend-tests"])}
        out = await operator_checks.verify(FakeGitHubClientFactory(), {}, registry)
        assert out[1].verification == PROBE_ERROR
        assert "not onboarded" in out[1].evidence

    async def test_no_factory_is_probe_error(self) -> None:
        registry = {1: required_checks_on_main(REPO, ["backend-tests"])}
        out = await operator_checks.verify(None, {REPO: INSTALLATION}, registry)
        assert out[1].verification == PROBE_ERROR

    async def test_a_probe_that_blows_up_is_probe_error(self) -> None:
        class Broken:
            async def get_branch_protection(self, *_a: Any) -> Any:
                raise RuntimeError("boom with a token in it")

        class Factory:
            def for_installation(self, _i: int) -> Any:
                return Broken()

        registry = {1: required_checks_on_main(REPO, ["backend-tests"])}
        out = await operator_checks.verify(Factory(), {REPO: INSTALLATION}, registry)
        assert out[1].verification == PROBE_ERROR
        assert "token" not in out[1].evidence

    async def test_for_story(self) -> None:
        checks = {60931: Verification(OBSERVED_DONE, "seen", "required_checks_on_main")}
        assert operator_checks.for_story(60931, checks, "why").verification == OBSERVED_DONE
        assert operator_checks.for_story(99, checks, "why").verification == UNPROBED
        # Registered but not run: an error that says why, never done.
        missing = operator_checks.for_story(60810, checks, "not run")
        assert missing.verification == PROBE_ERROR and missing.evidence == "not run"


# ---------------------------------------------------------------------------
# Needs you today
# ---------------------------------------------------------------------------


def _board(*stories: dict[str, Any]) -> BoardRead:
    return BoardRead(stories={"icebox": list(stories)}, as_of=utcnow())


class TestNeedsYou:
    def _section(self, checks: dict[int, Verification] | None) -> daily_briefing.Section:
        delivery = DeliveryInputs(
            board=_board(
                story(id=60931, bucket="icebox", title="OPERATOR ACTION: backend-tests required"),
                story(id=60810, bucket="icebox", title="OPERATOR ACTION: protect v* tags"),
                story(id=60940, bucket="icebox", title="OPERATOR ACTION: something unprobed"),
            ),
            board_error="",
            operator_checks=checks,
            operator_checks_error="Not checked.",
        )
        return daily_briefing.needs_you_section(delivery, now=utcnow())

    def test_done_is_not_a_line_and_carries_its_evidence(self) -> None:
        section = self._section(
            {
                60931: Verification(OBSERVED_DONE, "main requires backend-tests.", "p"),
                60810: Verification(OBSERVED_NOT_DONE, "no v* ruleset.", "q"),
            }
        )
        whats = {line.what: line for line in section.lines}
        assert "OPERATOR ACTION: backend-tests required" not in whats
        not_done = whats["OPERATOR ACTION: protect v* tags"]
        assert not_done.verification == OBSERVED_NOT_DONE
        assert "no v* ruleset." in not_done.so_what
        assert whats["OPERATOR ACTION: something unprobed"].verification == UNPROBED

        actions = {a["id"]: a for a in section.data["board"]["operator_actions"]}
        assert actions[60931]["verification"] == OBSERVED_DONE
        assert actions[60931]["evidence"] == "main requires backend-tests."
        assert actions[60810]["evidence"] == "no v* ruleset."
        assert actions[60940]["verification"] == UNPROBED
        assert "evidence" not in actions[60940]
        assert section.data["board"]["operator_actions_done"] == 1

    def test_probe_error_says_could_not_check_and_is_never_done(self) -> None:
        section = self._section(None)
        whats = {line.what: line for line in section.lines}
        for title in ("OPERATOR ACTION: backend-tests required",
                      "OPERATOR ACTION: protect v* tags"):
            line = whats[title]
            assert line.verification == PROBE_ERROR
            assert line.so_what.startswith("could not check: Not checked.")
        assert section.data["board"]["operator_actions_done"] == 0

    def test_done_is_left_out_of_the_needs_you_count(self) -> None:
        from mykronos import briefing_dm

        done = self._section(
            {60931: Verification(OBSERVED_DONE, "e", "p"),
             60810: Verification(OBSERVED_DONE, "e", "q")}
        )
        open_ = self._section(None)
        assert briefing_dm.work_counts([done])["story"] == 1
        assert briefing_dm.work_counts([open_])["story"] == 3


# ---------------------------------------------------------------------------
# Through the API, against the fake GitHub
# ---------------------------------------------------------------------------


class TestThroughTheApi:
    def test_each_action_carries_its_verification(
        self, client, admin_auth, github: FakeGitHubClient, gathered, monkeypatch
    ) -> None:
        onboard_row(client)
        github.repos[REPO].branch_protection["main"] = _protection(ALL_THREE)
        monkeypatch.setattr(
            operator_checks,
            "REGISTRY",
            {
                20: required_checks_on_main(REPO, ["backend-tests"]),
                21: tag_ruleset_exists(REPO, "v*"),
                22: required_checks_on_main("example-org/not-onboarded", ["x"]),
            },
        )
        hub = FakeHub(
            [
                story(id=20, bucket="icebox", title="OPERATOR ACTION: require backend-tests",
                      created_at=(utcnow() - timedelta(days=3)).isoformat()),
                story(id=21, bucket="icebox", title="OPERATOR ACTION: protect tags"),
                story(id=22, bucket="icebox", title="OPERATOR ACTION: elsewhere"),
                story(id=23, bucket="icebox", title="OPERATOR ACTION: unprobed"),
            ]
        )
        attach_hub(client, hub)

        body = _get(client, admin_auth)
        section = _section(body, "needs_you_today")
        actions = {a["id"]: a for a in section["data"]["board"]["operator_actions"]}

        assert {i: a["verification"] for i, a in actions.items()} == {
            20: OBSERVED_DONE, 21: OBSERVED_NOT_DONE, 22: PROBE_ERROR, 23: UNPROBED,
        }
        for i in (20, 21, 22):
            assert actions[i]["evidence"]
        lines = {line["what"]: line for line in section["lines"]}
        assert "OPERATOR ACTION: require backend-tests" not in lines
        assert lines["OPERATOR ACTION: protect tags"]["verification"] == OBSERVED_NOT_DONE
        assert lines["OPERATOR ACTION: elsewhere"]["so_what"].startswith("could not check:")
        assert lines["OPERATOR ACTION: unprobed"]["verification"] == UNPROBED
        # Every other line carries no verification.
        assert all(
            line["verification"] == ""
            for s in body["sections"] for line in s["lines"]
            if not line["what"].startswith("OPERATOR ACTION:")
        )

        # Read-only: GitHub was only read, TheHub only listed.
        assert github.calls and all(name.startswith(("get_", "list_", "installation"))
                                    for name, _ in github.calls)
        assert {method for method, _path, _body in hub.calls} == {"GET"}

    def test_probes_are_cached_with_the_pull_requests(
        self, client, admin_auth, github: FakeGitHubClient, gathered, monkeypatch
    ) -> None:
        onboard_row(client)
        monkeypatch.setattr(
            operator_checks, "REGISTRY", {20: required_checks_on_main(REPO, ["backend-tests"])}
        )
        attach_hub(client, FakeHub([]))
        _get(client, admin_auth)
        asked = [c for c in github.calls if c[0] == "get_branch_protection"]
        _get(client, admin_auth)
        assert [c for c in github.calls if c[0] == "get_branch_protection"] == asked
        assert len(asked) == 1


# ---------------------------------------------------------------------------
# No write in the probe path
# ---------------------------------------------------------------------------


_WRITE_VERBS = ("POST", "PATCH", "PUT", "DELETE")
_WRITE_PREFIXES = ("create_", "update_", "put_", "set_", "close_", "dispatch_", "commit_",
                   "delete_", "patch_", "post_")


def _attribute_calls(source: str) -> set[str]:
    return {
        node.func.attr
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }


class TestReadOnly:
    def test_the_probe_module_names_no_write_verb_or_write_call(self) -> None:
        source = inspect.getsource(operator_checks)
        code = "\n".join(
            line for line in source.splitlines() if not line.lstrip().startswith("#")
        )
        for verb in _WRITE_VERBS:
            assert f'"{verb}"' not in code and f"'{verb}'" not in code, verb
        called = _attribute_calls(source)
        assert not {c for c in called if c.startswith(_WRITE_PREFIXES)}, called
        github_reads = {c for c in called if c.startswith("get_")}
        assert github_reads == {"get_branch_protection", "get_rulesets", "get_ruleset"}

    def test_the_gather_step_makes_no_write_call(self) -> None:
        source = inspect.getsource(delivery_sources.operator_checks)
        assert not {c for c in _attribute_calls(source) if c.startswith(_WRITE_PREFIXES)}
        for verb in _WRITE_VERBS:
            assert f'"{verb}"' not in source

    @pytest.mark.asyncio
    async def test_running_every_registered_probe_only_reads(self) -> None:
        fake = FakeGitHubClient()
        fake.add_repo("ToddGBenson/mykronos")
        fake.repos["ToddGBenson/mykronos"].branch_protection["main"] = _protection(ALL_THREE)
        fake.repos["ToddGBenson/mykronos"].rulesets.append(
            _tag_ruleset(["refs/tags/v*"], ["update", "deletion"])
        )
        out = await operator_checks.verify(
            FakeGitHubClientFactory(fake), {"ToddGBenson/mykronos": INSTALLATION}
        )
        assert {v.verification for v in out.values()} == {OBSERVED_DONE}
        assert {name for name, _ in fake.calls} <= {
            "get_branch_protection", "get_rulesets", "get_ruleset"
        }


@pytest.mark.asyncio
async def test_rest_get_ruleset_reads_the_single_ruleset(monkeypatch) -> None:
    from mykronos.github.client import RestGitHubClient

    seen: list[tuple[str, str]] = []

    async def fake_json(self: Any, method: str, path: str, **_kwargs: Any) -> Any:
        seen.append((method, path))
        return _tag_ruleset(["refs/tags/v*"], ["update"])

    client = RestGitHubClient.__new__(RestGitHubClient)
    monkeypatch.setattr(RestGitHubClient, "_json", fake_json)
    ruleset = await client.get_ruleset("o/r", 7)
    assert seen == [("GET", "/repos/o/r/rulesets/7")]
    assert ruleset["conditions"]["ref_name"]["include"] == ["refs/tags/v*"]
