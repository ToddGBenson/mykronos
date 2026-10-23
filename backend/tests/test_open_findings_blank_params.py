"""Blank and malformed filter values on `open-findings` (TheHub #60964).

A scanner, a bookmarked form or a hand-edited link sends every filter with
nothing in it (`?capability=&severity=&min_epss=`). That must mean "no
filter", exactly as leaving the parameter out does. A value that is present
and wrong is a 422 that names the field, and never a 500.

No error body repeats what was sent: the caller already has it, and an error
page that reflects the request is the thing an application-error-disclosure
check flags.

Uses `outstanding` (seven open findings).
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.test_dashboard import outstanding  # noqa: F401  (fixture)

URL = "/api/dashboard/repos/{}/open-findings"

#: Every query parameter the route takes.
PARAMS = (
    "capability",
    "severity",
    "finding_status",
    "rule_id",
    "kev_only",
    "min_epss",
    "triage",
    "fixable",
    "due",
    "owner",
    "effective",
    "rescored",
    "component",
    "exposure",
    "path",
    "older_than_days",
    "newer_than_days",
    "limit",
)

#: Recognisable, so an echo of it anywhere in a response body is unmistakable.
MARK = "zqx7731"

#: A malformed value for each parameter. Free-text parameters are malformed
#: only by length, so theirs is over the limit.
MALFORMED: dict[str, Any] = {
    "capability": f"sast,{MARK}",
    "severity": MARK,
    "finding_status": MARK,
    "rule_id": MARK * 30,
    "kev_only": MARK,
    "min_epss": f"{MARK}.5",
    "triage": MARK,
    "fixable": MARK,
    "due": MARK,
    "owner": MARK * 40,
    "effective": MARK,
    "rescored": MARK,
    "component": MARK * 10,
    "exposure": MARK,
    "path": MARK * 40,
    "older_than_days": f"7{MARK}",
    "newer_than_days": f"7{MARK}",
    "limit": f"4{MARK}",
}


def _baseline(client: TestClient, auth: dict[str, str], repo_id: str) -> Any:
    response = client.get(URL.format(repo_id), headers=auth)
    assert response.status_code == 200, response.text
    return response.json()


def test_every_parameter_has_a_malformed_case() -> None:
    assert set(MALFORMED) == set(PARAMS)


class TestBlankIsUnset:
    def test_every_filter_present_and_blank_is_no_filter(
        self, client: TestClient, admin_auth: dict[str, str], outstanding  # noqa: F811
    ) -> None:
        response = client.get(
            URL.format(outstanding), params={p: "" for p in PARAMS}, headers=admin_auth
        )

        assert response.status_code == 200, response.text
        page = response.json()
        base = _baseline(client, admin_auth, outstanding)
        assert page["matching"] == base["matching"] == 7
        assert page["finding_status"] == "open"
        assert page["groups"] == base["groups"]

    @pytest.mark.parametrize("param", PARAMS)
    @pytest.mark.parametrize("blank", ["", "  "])
    def test_each_blank_parameter_is_no_filter(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        outstanding,  # noqa: F811
        param: str,
        blank: str,
    ) -> None:
        response = client.get(
            URL.format(outstanding), params={param: blank}, headers=admin_auth
        )

        assert response.status_code == 200, (param, response.status_code, response.text)
        assert response.json()["matching"] == 7, param

    def test_a_set_flag_still_filters(
        self, client: TestClient, admin_auth: dict[str, str], outstanding  # noqa: F811
    ) -> None:
        """Blank is unset; it is not a way to switch a real value off."""
        response = client.get(
            URL.format(outstanding),
            params={"kev_only": "true", "limit": "1"},
            headers=admin_auth,
        )
        assert response.status_code == 200, response.text
        assert response.json()["limit"] == 1


class TestMalformedIs422:
    @pytest.mark.parametrize("param", PARAMS)
    def test_a_malformed_value_is_a_field_level_422_that_does_not_echo_it(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        outstanding,  # noqa: F811
        param: str,
    ) -> None:
        response = client.get(
            URL.format(outstanding), params={param: MALFORMED[param]}, headers=admin_auth
        )

        assert response.status_code == 422, (param, response.status_code, response.text)
        detail = response.json()["detail"]
        assert any(error["loc"][:2] == ["query", param] for error in detail), detail
        assert all(error.get("msg") for error in detail), detail
        assert MARK not in response.text, response.text

    def test_too_many_owners_is_a_422(
        self, client: TestClient, admin_auth: dict[str, str], outstanding  # noqa: F811
    ) -> None:
        owners = ",".join(f"{MARK}-{n}" for n in range(21))
        response = client.get(
            URL.format(outstanding), params={"owner": owners}, headers=admin_auth
        )
        assert response.status_code == 422, response.text
        assert MARK not in response.text, response.text
