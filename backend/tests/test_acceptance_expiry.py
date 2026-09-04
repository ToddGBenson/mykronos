"""Acceptances that expire, and the one premise a scan can contradict
(spec 24 §3).

The platform is carrying 243 acceptances that each said no vendor fix exists.
That claim stops being true the day a vendor ships one, and until now nothing
re-checked it. These tests pin both halves of the fix: a review date the sweep
enforces, and an automatic re-open for the single reason code where machine
evidence can disprove the premise.
"""

from __future__ import annotations

from datetime import date, timedelta
from typing import Any

from fastapi.testclient import TestClient

from mykronos.jobs import sweep_acceptances
from mykronos.lake.catalog import Catalog
from mykronos.schemas import utcnow
from tests.conftest import (
    dependency_finding,
    finding_payload,
    post_findings,
    post_scan,
)


def today() -> date:
    """UTC, not local.

    The lake stores naive UTC (spec 01 §6) and the endpoint validates against
    `utcnow()`, so a test using `today()` on a machine behind UTC asks to
    accept until a date the server has already passed — a silent 422 that
    makes an expiry test pass without ever creating an acceptance. It did.
    """
    return utcnow().date()


def accept(
    client: TestClient,
    admin_auth: dict[str, str],
    finding_id: str,
    **body: Any,
) -> Any:
    payload: dict[str, Any] = {
        "status": "accepted_risk",
        "reason": "no upstream patch",
        "accepted_reason_code": "no_vendor_fix",
    }
    payload.update(body)
    return client.patch(
        f"/api/dashboard/findings/{finding_id}/status", json=payload, headers=admin_auth
    )


def seed(client: TestClient, auth: dict[str, str], run_compaction: Any, **overrides: Any) -> None:
    post_scan(client, auth)
    post_findings(client, auth, [finding_payload(**overrides)])
    run_compaction()


def only_finding(catalog: Catalog) -> str:
    return str(catalog.query("SELECT finding_id FROM findings")[0][0])


def state(catalog: Catalog) -> tuple[Any, Any, Any]:
    row = catalog.query(
        "SELECT status, accepted_until, accepted_reason_code FROM findings"
    )[0]
    return (row[0], row[1], row[2])


class TestTheDispositionContract:
    def test_a_reason_code_is_required(
        self,
        client: TestClient,
        auth: dict[str, str],
        admin_auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        seed(client, auth, run_compaction)
        response = accept(
            client,
            admin_auth,
            only_finding(catalog),
            accepted_reason_code=None,
            accepted_until=(today() + timedelta(days=30)).isoformat(),
        )
        assert response.status_code == 422
        assert "accepted_reason_code" in response.json()["detail"]

    def test_a_date_or_an_explicit_indefinite_is_required(
        self,
        client: TestClient,
        auth: dict[str, str],
        admin_auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        seed(client, auth, run_compaction)
        response = accept(client, admin_auth, only_finding(catalog))
        assert response.status_code == 422
        assert "indefinite" in response.json()["detail"]

    def test_indefinite_is_allowed_when_stated(
        self,
        client: TestClient,
        auth: dict[str, str],
        admin_auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        seed(client, auth, run_compaction)
        response = accept(client, admin_auth, only_finding(catalog), indefinite=True)
        assert response.status_code == 200
        assert state(catalog) == ("accepted_risk", None, "no_vendor_fix")

    def test_a_past_date_is_refused(
        self,
        client: TestClient,
        auth: dict[str, str],
        admin_auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        """The next sweep would expire it immediately, which is a confusing
        way to learn you typed the wrong year."""
        seed(client, auth, run_compaction)
        response = accept(
            client,
            admin_auth,
            only_finding(catalog),
            accepted_until=(today() - timedelta(days=1)).isoformat(),
        )
        assert response.status_code == 422
        assert "not in the future" in response.json()["detail"]

    def test_the_fields_do_not_apply_to_other_dispositions(
        self,
        client: TestClient,
        auth: dict[str, str],
        admin_auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        seed(client, auth, run_compaction)
        response = client.patch(
            f"/api/dashboard/findings/{only_finding(catalog)}/status",
            json={
                "status": "false_positive",
                "reason": "test fixture",
                "accepted_reason_code": "other",
            },
            headers=admin_auth,
        )
        assert response.status_code == 422

    def test_an_unknown_reason_code_is_refused(
        self,
        client: TestClient,
        auth: dict[str, str],
        admin_auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        seed(client, auth, run_compaction)
        response = accept(
            client,
            admin_auth,
            only_finding(catalog),
            accepted_reason_code="because_i_said_so",
            indefinite=True,
        )
        assert response.status_code == 422


class TestExpiry:
    def _accept_until(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        catalog: Catalog,
        when: date,
    ) -> None:
        response = accept(
            client,
            admin_auth,
            only_finding(catalog),
            accepted_until=when.isoformat(),
        )
        assert response.status_code == 200, response.text

    def test_an_acceptance_past_its_date_reopens(
        self,
        client: TestClient,
        auth: dict[str, str],
        admin_auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        seed(client, auth, run_compaction)
        self._accept_until(client, admin_auth, catalog, today() + timedelta(days=30))

        result = sweep_acceptances(catalog, today=today() + timedelta(days=31))

        assert result.expired == 1
        assert state(catalog)[0] == "open"

    def test_an_acceptance_inside_its_window_is_left_alone(
        self,
        client: TestClient,
        auth: dict[str, str],
        admin_auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        seed(client, auth, run_compaction)
        self._accept_until(client, admin_auth, catalog, today() + timedelta(days=30))

        result = sweep_acceptances(catalog, today=today())

        assert result.expired == 0
        assert result.still_accepted == 1
        assert state(catalog)[0] == "accepted_risk"

    def test_an_indefinite_acceptance_never_expires(
        self,
        client: TestClient,
        auth: dict[str, str],
        admin_auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        seed(client, auth, run_compaction)
        assert accept(
            client, admin_auth, only_finding(catalog), indefinite=True
        ).status_code == 200

        result = sweep_acceptances(catalog, today=today() + timedelta(days=3650))

        assert result.expired == 0
        assert state(catalog)[0] == "accepted_risk"

    def test_expiry_preserves_first_seen(
        self,
        client: TestClient,
        auth: dict[str, str],
        admin_auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        """spec 24 §3.2: an acceptance that ran out is not a new discovery.
        Resetting the clock would hand every ageing finding a way to look
        young — and age drives the due date, the Oracle term and MTTF."""
        seed(client, auth, run_compaction)
        before = catalog.query("SELECT first_seen_at FROM findings")[0][0]
        self._accept_until(client, admin_auth, catalog, today() + timedelta(days=1))

        sweep_acceptances(catalog, today=today() + timedelta(days=2))

        assert catalog.query("SELECT first_seen_at FROM findings")[0][0] == before

    def test_expiry_clears_the_paperwork(
        self,
        client: TestClient,
        auth: dict[str, str],
        admin_auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        """An open row must not carry a review date, or the next sweep would
        expire it again and the UI would show a decision that has lapsed."""
        seed(client, auth, run_compaction)
        self._accept_until(client, admin_auth, catalog, today() + timedelta(days=1))

        sweep_acceptances(catalog, today=today() + timedelta(days=2))

        assert state(catalog) == ("open", None, None)

    def test_a_second_sweep_changes_nothing(
        self,
        client: TestClient,
        auth: dict[str, str],
        admin_auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        seed(client, auth, run_compaction)
        self._accept_until(client, admin_auth, catalog, today() + timedelta(days=1))
        later = today() + timedelta(days=2)

        assert sweep_acceptances(catalog, today=later).expired == 1
        assert sweep_acceptances(catalog, today=later).expired == 0


class TestAFixShipping:
    def _accept_dependency(
        self,
        client: TestClient,
        auth: dict[str, str],
        admin_auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
        reason_code: str = "no_vendor_fix",
    ) -> str:
        post_scan(client, auth)
        post_findings(client, auth, [dependency_finding()])
        run_compaction()
        finding_id = only_finding(catalog)
        response = accept(
            client,
            admin_auth,
            finding_id,
            accepted_reason_code=reason_code,
            indefinite=True,
        )
        assert response.status_code == 200, response.text
        return finding_id

    def _report_a_fix(
        self, client: TestClient, auth: dict[str, str], run_compaction: Any
    ) -> None:
        post_findings(
            client,
            auth,
            [dependency_finding(raw_finding_json={"fixed_version": "2.0.7"})],
            scan_run_id="run-2",
        )
        run_compaction()

    def test_no_vendor_fix_reopens_when_a_version_ships(
        self,
        client: TestClient,
        auth: dict[str, str],
        admin_auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        self._accept_dependency(client, auth, admin_auth, catalog, run_compaction)
        self._report_a_fix(client, auth, run_compaction)

        result = sweep_acceptances(catalog, today=today())

        assert result.reopened_by_fix == 1
        assert state(catalog)[0] == "open"

    def test_no_fix_reported_leaves_it_accepted(
        self,
        client: TestClient,
        auth: dict[str, str],
        admin_auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        self._accept_dependency(client, auth, admin_auth, catalog, run_compaction)

        result = sweep_acceptances(catalog, today=today())

        assert result.reopened_by_fix == 0
        assert state(catalog)[0] == "accepted_risk"

    def test_other_reason_codes_are_never_reopened_by_a_scan(
        self,
        client: TestClient,
        auth: dict[str, str],
        admin_auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        """A compensating control may have been removed and no scanner can
        see that; re-opening on machine evidence would be inventing a
        verdict about a decision a person made."""
        self._accept_dependency(
            client,
            auth,
            admin_auth,
            catalog,
            run_compaction,
            reason_code="compensating_control",
        )
        self._report_a_fix(client, auth, run_compaction)

        result = sweep_acceptances(catalog, today=today())

        assert result.reopened_by_fix == 0
        assert state(catalog)[0] == "accepted_risk"

    def test_reopening_preserves_first_seen(
        self,
        client: TestClient,
        auth: dict[str, str],
        admin_auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        self._accept_dependency(client, auth, admin_auth, catalog, run_compaction)
        before = catalog.query("SELECT first_seen_at FROM findings")[0][0]
        self._report_a_fix(client, auth, run_compaction)

        sweep_acceptances(catalog, today=today())

        assert catalog.query("SELECT first_seen_at FROM findings")[0][0] == before


class TestTheSweepIsSafe:
    def test_an_empty_lake_is_not_an_error(self, catalog: Catalog) -> None:
        assert sweep_acceptances(catalog).expired == 0

    def test_open_findings_are_untouched(
        self,
        client: TestClient,
        auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        seed(client, auth, run_compaction)

        result = sweep_acceptances(catalog, today=today() + timedelta(days=3650))

        assert (result.expired, result.reopened_by_fix, result.still_accepted) == (0, 0, 0)
        assert state(catalog)[0] == "open"
