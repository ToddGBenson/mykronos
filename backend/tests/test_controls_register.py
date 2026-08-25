"""The controls register and three honest states (spec 28 §3, §4).

A threat model is made of four things — assets, entry points, trust
boundaries, mitigations — and this platform had one. It could say what was
found and not what stops it, which gets worse as scanning improves: the tab
can only ever grow more red, and a team that spends a quarter adding controls
sees no change at all.

The test to read first is `test_an_unscanned_category_is_never_reported_as
_clean`. A STRIDE category with no findings because DAST has never run
rendered identically to one with no findings because the code is clean, and
that is an absence of looking presented as good news.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient

from mykronos import controls
from mykronos.dashboard import STRIDE_BY_CAPABILITY, STRIDE_CATEGORIES
from mykronos.db.models import RepoControl
from mykronos.schemas import utcnow
from tests.conftest import REPO, finding_payload, post_findings, post_scan
from tests.test_onboarding import onboard


def a_control(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "stride": "spoofing",
        "kind": "authentication",
        "description": "Every route behind the session middleware.",
        "evidence_ref": "app/middleware/auth.py",
    }
    payload.update(overrides)
    return payload


class TestDeclaring:
    def _repo_id(self, client: TestClient, admin_auth: dict[str, str]) -> str:
        return client.get("/api/dashboard/portfolio", headers=admin_auth).json()[
            "repos"
        ][0]["repo_id"]

    def test_an_admin_can_declare_one(
        self, client: TestClient, admin_auth
    ) -> None:
        onboard(client, admin_auth)

        r = client.post(
            f"/api/dashboard/repos/{self._repo_id(client, admin_auth)}/controls",
            json=a_control(),
            headers=admin_auth,
        )

        assert r.status_code == 200
        assert r.json()["kind"] == "authentication"
        assert r.json()["evidence"] == "referenced"

    def test_a_control_without_evidence_is_the_weaker_claim_not_a_refusal(
        self, client: TestClient, admin_auth
    ) -> None:
        """Requiring a reference would mean the register only ever holds the
        controls somebody had time to document."""
        onboard(client, admin_auth)

        r = client.post(
            f"/api/dashboard/repos/{self._repo_id(client, admin_auth)}/controls",
            json=a_control(evidence_ref=""),
            headers=admin_auth,
        )

        assert r.status_code == 200
        assert r.json()["evidence"] == "asserted"

    def test_a_viewer_cannot_declare(
        self, client: TestClient, admin_auth, viewer_auth
    ) -> None:
        onboard(client, admin_auth)

        r = client.post(
            f"/api/dashboard/repos/{self._repo_id(client, admin_auth)}/controls",
            json=a_control(),
            headers=viewer_auth,
        )

        assert r.status_code == 403

    def test_an_invented_stride_category_is_refused(
        self, client: TestClient, admin_auth
    ) -> None:
        onboard(client, admin_auth)

        r = client.post(
            f"/api/dashboard/repos/{self._repo_id(client, admin_auth)}/controls",
            json=a_control(stride="telepathy"),
            headers=admin_auth,
        )

        assert r.status_code == 422

    def test_an_invented_kind_is_refused(
        self, client: TestClient, admin_auth
    ) -> None:
        """A free-text kind would make two teams' registers incomparable
        inside a quarter, and "how many repositories declare an authentication
        control" is the question this table exists to answer."""
        onboard(client, admin_auth)

        r = client.post(
            f"/api/dashboard/repos/{self._repo_id(client, admin_auth)}/controls",
            json=a_control(kind="vibes"),
            headers=admin_auth,
        )

        assert r.status_code == 422

    def test_the_declarer_cannot_choose_what_verifies_it(
        self, client: TestClient, admin_auth
    ) -> None:
        """`verified_by_capability` is a property of the kind, not a choice. A
        control naming a capability that cannot see it would look checked and
        be nothing of the kind — so the field is not on the request model at
        all, and sending it is a 422."""
        onboard(client, admin_auth)

        r = client.post(
            f"/api/dashboard/repos/{self._repo_id(client, admin_auth)}/controls",
            json={**a_control(), "verified_by_capability": "atlas"},
            headers=admin_auth,
        )

        assert r.status_code == 422

    def test_it_is_derived_from_the_kind(
        self, client: TestClient, admin_auth
    ) -> None:
        onboard(client, admin_auth)

        r = client.post(
            f"/api/dashboard/repos/{self._repo_id(client, admin_auth)}/controls",
            json=a_control(kind="secrets_management", stride="information_disclosure"),
            headers=admin_auth,
        )

        assert r.json()["verified_by_capability"] == "secrets"

    def test_a_kind_nothing_can_check_says_so(
        self, client: TestClient, admin_auth
    ) -> None:
        """Stated rather than left implied: a control nothing can contradict
        is not a verified control, and the tab must not let it look like
        one."""
        onboard(client, admin_auth)

        r = client.post(
            f"/api/dashboard/repos/{self._repo_id(client, admin_auth)}/controls",
            json=a_control(kind="logging", stride="repudiation"),
            headers=admin_auth,
        )

        assert r.json()["checkable"] is False


class TestFreshness:
    def test_declaring_counts_as_confirming(self, client: TestClient) -> None:
        """Left null the row would read as stale from the moment it was
        written, which is the opposite of what happened."""
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            control = controls.declare(
                session, repo_full_name=REPO, stride="spoofing", kind="authentication"
            )

            assert controls.as_dict(control)["stale"] is False

    def test_a_control_nobody_has_reread_goes_stale(self, client: TestClient) -> None:
        """A mitigation nobody has checked since last quarter is a belief, and
        the tab should say which of the two it is showing."""
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            control = controls.declare(
                session, repo_full_name=REPO, stride="spoofing", kind="authentication"
            )
            control.last_verified_at = utcnow() - timedelta(days=120)

            assert controls.as_dict(control)["stale"] is True

    def test_confirming_makes_it_fresh_again(
        self, client: TestClient, admin_auth
    ) -> None:
        onboard(client, admin_auth)
        repo_id = client.get("/api/dashboard/portfolio", headers=admin_auth).json()[
            "repos"
        ][0]["repo_id"]
        control_id = client.post(
            f"/api/dashboard/repos/{repo_id}/controls",
            json=a_control(),
            headers=admin_auth,
        ).json()["control_id"]
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            session.get(RepoControl, control_id).last_verified_at = utcnow() - timedelta(
                days=120
            )

        r = client.post(
            f"/api/dashboard/repos/{repo_id}/controls/{control_id}/confirm",
            headers=admin_auth,
        )

        assert r.json()["stale"] is False

    def test_confirming_someone_elses_control_is_404(
        self, client: TestClient, admin_auth
    ) -> None:
        onboard(client, admin_auth)
        repo_id = client.get("/api/dashboard/portfolio", headers=admin_auth).json()[
            "repos"
        ][0]["repo_id"]
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            other = controls.declare(
                session, repo_full_name="acme/other", stride="spoofing",
                kind="authentication",
            )
            other_id = other.id

        r = client.post(
            f"/api/dashboard/repos/{repo_id}/controls/{other_id}/confirm",
            headers=admin_auth,
        )

        assert r.status_code == 404


class TestWithdrawing:
    def test_it_is_deleted_not_flagged(self, client: TestClient, admin_auth) -> None:
        """A control is a claim about the present. A withdrawn one is not
        evidence of anything — nobody needs to know somebody once believed
        authentication was enforced — and the audit entry records who removed
        it, which is the part that matters."""
        onboard(client, admin_auth)
        repo_id = client.get("/api/dashboard/portfolio", headers=admin_auth).json()[
            "repos"
        ][0]["repo_id"]
        control_id = client.post(
            f"/api/dashboard/repos/{repo_id}/controls",
            json=a_control(),
            headers=admin_auth,
        ).json()["control_id"]

        r = client.delete(
            f"/api/dashboard/repos/{repo_id}/controls/{control_id}", headers=admin_auth
        )

        assert r.status_code == 204
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            assert session.get(RepoControl, control_id) is None

    def test_offboarding_takes_the_register_with_it(
        self, client: TestClient, admin_auth
    ) -> None:
        """Historical lake rows are the audit trail and stay. A declared
        control is a claim about the present, and a repository nobody scans
        any more has no present worth claiming things about."""
        onboard(client, admin_auth)
        repo_id = client.get("/api/dashboard/portfolio", headers=admin_auth).json()[
            "repos"
        ][0]["repo_id"]
        client.post(
            f"/api/dashboard/repos/{repo_id}/controls",
            json=a_control(),
            headers=admin_auth,
        )

        client.delete(f"/api/repos/{repo_id}", headers=admin_auth)

        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            assert controls.for_repo(session, REPO) == []


class TestTheFourStates:
    def _states(
        self,
        findings: dict[str, int] | None = None,
        declared: list[RepoControl] | None = None,
        scanned: set[str] | None = None,
    ) -> dict[str, dict[str, Any]]:
        rows = controls.category_states(
            categories=STRIDE_CATEGORIES,
            findings_by_category=findings or {},
            controls=declared or [],
            scanned_capabilities=scanned if scanned is not None else {"sast", "dast"},
            stride_by_capability=STRIDE_BY_CAPABILITY,
        )
        return {row["stride"]: row for row in rows}

    def test_an_unscanned_category_is_never_reported_as_clean(self) -> None:
        """The bug this closes. A category with no findings because nothing
        ever looked rendered identically to one with no findings because the
        code is clean — an absence of looking presented as good news."""
        states = self._states(scanned=set())

        assert {s["state"] for s in states.values()} == {"unscanned"}

    def test_unscanned_wins_over_everything(self) -> None:
        """Checked first on purpose: whatever else is true of a category
        nothing has ever looked at, `clean` is not it."""
        states = self._states(findings={"tampering": 0}, scanned=set())

        assert states["tampering"]["state"] == "unscanned"

    def test_it_names_what_would_have_to_run(self) -> None:
        reason = self._states(scanned=set())["denial_of_service"]["reason"]

        assert "network" in reason

    def test_scanned_and_empty_and_undeclared_is_unmitigated(self) -> None:
        assert self._states()["tampering"]["state"] == "unmitigated"

    def test_scanned_and_empty_with_a_control_is_mitigated(
        self, client: TestClient
    ) -> None:
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            declared = [
                controls.declare(
                    session, repo_full_name=REPO, stride="tampering",
                    kind="input_validation",
                )
            ]
            state = self._states(declared=declared)["tampering"]

        assert state["state"] == "mitigated"
        assert "somebody asserted it" in state["reason"]

    def test_findings_open_beats_a_declared_control(
        self, client: TestClient
    ) -> None:
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            declared = [
                controls.declare(
                    session, repo_full_name=REPO, stride="tampering",
                    kind="input_validation",
                )
            ]
            state = self._states(findings={"tampering": 3}, declared=declared)[
                "tampering"
            ]

        assert state["state"] == "findings_open"

    def test_a_control_with_findings_under_it_is_flagged_not_resolved(
        self, client: TestClient
    ) -> None:
        """The platform has no basis to decide whether the control is wrong,
        bypassed, or narrower than its description. All three are worth
        somebody's attention, so both facts are shown."""
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            declared = [
                controls.declare(
                    session, repo_full_name=REPO, stride="spoofing",
                    kind="authentication",
                )
            ]
            state = self._states(findings={"spoofing": 2}, declared=declared)["spoofing"]

        assert state["contradicted"] is True
        assert "bypassed" in state["reason"]

    def test_a_clean_category_is_not_contradicted(self, client: TestClient) -> None:
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            declared = [
                controls.declare(
                    session, repo_full_name=REPO, stride="spoofing",
                    kind="authentication",
                )
            ]

            assert self._states(declared=declared)["spoofing"]["contradicted"] is False


class TestTheTab:
    def _model(self, client: TestClient, admin_auth: dict[str, str]) -> dict[str, Any]:
        repo_id = client.get("/api/dashboard/portfolio", headers=admin_auth).json()[
            "repos"
        ][0]["repo_id"]
        return client.get(
            f"/api/dashboard/repos/{repo_id}/threat-model", headers=admin_auth
        ).json()

    def test_a_repository_nothing_has_scanned_says_so_once(
        self, client: TestClient, admin_auth
    ) -> None:
        """Rather than rendering six identical empty sections. It is one fact
        about the repository, not six about its categories."""
        onboard(client, admin_auth)

        assert self._model(client, admin_auth)["nothing_scanned"] is True

    def test_a_scanned_repository_is_not_flagged_that_way(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        onboard(client, admin_auth)
        post_scan(client, auth)
        run_compaction()

        assert self._model(client, admin_auth)["nothing_scanned"] is False

    def test_the_declared_control_rides_on_the_category(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        onboard(client, admin_auth)
        post_scan(client, auth)
        run_compaction()
        repo_id = client.get("/api/dashboard/portfolio", headers=admin_auth).json()[
            "repos"
        ][0]["repo_id"]
        client.post(
            f"/api/dashboard/repos/{repo_id}/controls",
            json=a_control(stride="tampering", kind="input_validation"),
            headers=admin_auth,
        )

        by_stride = {c["stride"]: c for c in self._model(client, admin_auth)["categories"]}

        assert by_stride["tampering"]["state"] == "mitigated"
        assert by_stride["tampering"]["controls"][0]["kind"] == "input_validation"

    def test_a_control_over_open_findings_reads_as_a_contradiction(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        """A DAST authentication control on a repository whose SAST is
        reporting tampering findings underneath it."""
        onboard(client, admin_auth)
        post_scan(client, auth)
        post_findings(client, auth, [finding_payload(rule_id="sqli", symbol="q")])
        run_compaction()
        repo_id = client.get("/api/dashboard/portfolio", headers=admin_auth).json()[
            "repos"
        ][0]["repo_id"]
        client.post(
            f"/api/dashboard/repos/{repo_id}/controls",
            json=a_control(stride="tampering", kind="input_validation"),
            headers=admin_auth,
        )

        by_stride = {c["stride"]: c for c in self._model(client, admin_auth)["categories"]}

        assert by_stride["tampering"]["contradicted"] is True

    def test_the_register_is_additive(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        """spec 28 §5: a repository that declares nothing loses nothing."""
        onboard(client, admin_auth)
        post_scan(client, auth)
        post_findings(client, auth, [finding_payload(rule_id="sqli", symbol="q")])
        run_compaction()

        model = self._model(client, admin_auth)
        placed = [f for c in model["categories"] for f in c["findings"]]

        assert placed
        assert all(c["controls"] == [] for c in model["categories"])


class TestModuleGuards:
    def test_every_kind_names_a_real_capability_or_none(self) -> None:
        """A kind mapped to a capability that does not exist would let a
        control look checkable by something that cannot see it."""
        from mykronos.schemas import Capability

        known = {c.value for c in Capability}
        for kind in controls.CONTROL_KINDS:
            mapped = controls.CONTRADICTED_BY.get(kind, "")
            assert mapped == "" or mapped in known

    def test_every_kind_has_an_entry(self) -> None:
        """A kind absent from the map silently becomes uncheckable, which is
        a different claim from deliberately uncheckable."""
        assert set(controls.CONTROL_KINDS) == set(controls.CONTRADICTED_BY)

    def test_declaring_an_unknown_kind_is_refused_at_the_module(self) -> None:
        with pytest.raises(controls.ControlError, match="not a control kind"):
            controls.declare(
                None,  # type: ignore[arg-type]
                repo_full_name=REPO,
                stride="spoofing",
                kind="vibes",
            )
