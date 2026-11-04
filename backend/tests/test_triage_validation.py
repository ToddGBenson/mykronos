"""Triage T5: safe validation against the demo environment (TheHub #60892).

Epic #60879 decided that validation is evidence plus safe tests on the demo
only, never production. These tests pin the two halves of that:

- **Validation never targets production.** Every refusal is checked by
  recording what the HTTP transport was asked to send: a refused validation
  sends nothing, and an allowed one sends exactly one safe request, to the
  demo origin, whatever host the finding was recorded against.
- **Results are recorded with evidence.** The verdict (validated,
  not_validated, inconclusive) is stored with the request that was sent and
  the response that came back, and listed on the finding.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx2
import pytest
from fastapi.testclient import TestClient

from mykronos import validation
from tests.conftest import REPO, issue_token, post_findings, post_scan

DEMO = "https://demo.example.test:8443"
PROD = "https://prod.example.test"
EVIDENCE = "X-Powered-By: Express"


class Recorder:
    """An HTTP transport that answers from a table and remembers every request."""

    def __init__(self, answer: Any = None) -> None:
        self.sent: list[httpx2.Request] = []
        self._answer = answer or (lambda request: httpx2.Response(200, text="ok"))

    def handler(self, request: httpx2.Request) -> httpx2.Response:
        self.sent.append(request)
        result = self._answer(request)
        if isinstance(result, Exception):
            raise result
        return result

    @property
    def transport(self) -> httpx2.MockTransport:
        return httpx2.MockTransport(self.handler)

    def origins(self) -> set[str]:
        return {validation.origin_of(str(r.url)) or "" for r in self.sent}


def _dast(uri: str, *, method: str = "GET", evidence: str = EVIDENCE, env: str = "demo"):
    return {
        "finding_id": "f" * 64,
        "repo_full_name": REPO,
        "capability": "dast",
        "rule_id": "ZAP-10037",
        "symbol": env,
        "status": "open",
        "raw_finding_json": {
            "alertRef": "10037",
            "instance": {"uri": uri, "method": method, "evidence": evidence},
        },
    }


def _policy(demo: str = DEMO, production: tuple[str, ...] = (PROD,)) -> validation.TargetPolicy:
    return validation.TargetPolicy(demo_origin=demo, production_origins=production)


def _run(
    finding: dict[str, Any], recorder: Recorder, policy: validation.TargetPolicy | None = None
):
    plan = validation.replay_plan(finding, policy or _policy())
    return asyncio.run(validation.replay(plan, policy or _policy(), transport=recorder.transport))


# --------------------------------------------------------------------------
# Never production
# --------------------------------------------------------------------------


class TestNeverProduction:
    def test_a_finding_recorded_against_production_is_replayed_at_the_demo(self) -> None:
        recorder = Recorder(lambda r: httpx2.Response(200, headers={"X-Powered-By": "Express"}))

        result = _run(_dast(f"{PROD}/api/orders?id=7", env="prod"), recorder)

        assert [str(r.url) for r in recorder.sent] == [f"{DEMO}/api/orders?id=7"]
        assert recorder.origins() == {DEMO}
        assert result.request["url"] == f"{DEMO}/api/orders?id=7"

    def test_nothing_is_sent_when_no_demo_is_configured(self) -> None:
        with pytest.raises(validation.RefusedError) as refused:
            validation.replay_plan(_dast(f"{DEMO}/a"), _policy(demo=""))
        assert refused.value.code == "not_configured"

    def test_a_demo_origin_that_is_a_production_origin_is_refused(self) -> None:
        with pytest.raises(validation.RefusedError) as refused:
            validation.replay_plan(_dast(f"{PROD}/a"), _policy(demo=PROD))
        assert refused.value.code == "demo_is_production"

    def test_production_is_matched_by_origin_not_spelling(self) -> None:
        """Case, a trailing slash and the scheme's default port do not make a
        production origin into a different one."""
        policy = _policy(demo="HTTPS://Prod.Example.Test:443/", production=(PROD,))
        with pytest.raises(validation.RefusedError) as refused:
            validation.replay_plan(_dast(f"{PROD}/a"), policy)
        assert refused.value.code == "demo_is_production"

    def test_a_demo_origin_seen_serving_production_is_refused(self) -> None:
        """A prod-lane finding recorded at the configured demo origin means
        the 'demo' is production, whatever the configuration says."""
        with pytest.raises(validation.RefusedError) as refused:
            validation.replay_plan(_dast(f"{DEMO}/a", env="prod"), _policy(production=()))
        assert refused.value.code == "demo_is_production"

    @pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
    def test_only_safe_methods_are_replayed(self, method: str) -> None:
        with pytest.raises(validation.RefusedError) as refused:
            validation.replay_plan(_dast(f"{DEMO}/a", method=method), _policy())
        assert refused.value.code == "unsafe_method"

    def test_a_redirect_to_production_is_recorded_not_followed(self) -> None:
        recorder = Recorder(
            lambda r: httpx2.Response(302, headers={"Location": f"{PROD}/login"})
        )

        result = _run(_dast(f"{DEMO}/a"), recorder)

        assert recorder.origins() == {DEMO}
        assert len(recorder.sent) == 1
        assert result.response["status"] == 302
        assert result.verdict == validation.INCONCLUSIVE

    def test_the_client_refuses_any_request_off_the_demo_origin(self) -> None:
        """Defence in depth: even a plan built by hand cannot leave the demo."""
        recorder = Recorder()
        plan = validation.ReplayPlan(
            method="GET", url=f"{PROD}/a", evidence=EVIDENCE, recorded_uri=f"{PROD}/a"
        )

        with pytest.raises(validation.RefusedError) as refused:
            asyncio.run(validation.replay(plan, _policy(), transport=recorder.transport))

        assert refused.value.code == "production"
        assert recorder.sent == []

    def test_a_path_cannot_smuggle_another_host(self) -> None:
        recorder = Recorder()

        _run(_dast(f"{PROD}//evil.example.test/a"), recorder)

        assert recorder.origins() == {DEMO}

    def test_a_finding_with_no_recorded_request_is_not_replayed(self) -> None:
        finding = _dast(f"{DEMO}/a")
        finding["raw_finding_json"] = {"alertRef": "10037"}
        with pytest.raises(validation.RefusedError) as refused:
            validation.replay_plan(finding, _policy())
        assert refused.value.code == "no_replay"

    def test_a_non_dast_finding_is_not_replayed(self) -> None:
        finding = _dast(f"{DEMO}/a")
        finding["capability"] = "sast"
        with pytest.raises(validation.RefusedError) as refused:
            validation.replay_plan(finding, _policy())
        assert refused.value.code == "no_replay"

    def test_no_credentials_are_sent(self) -> None:
        recorder = Recorder()

        _run(_dast(f"{DEMO}/a"), recorder)

        [sent] = recorder.sent
        assert "authorization" not in sent.headers
        assert "cookie" not in sent.headers


class TestNucleiResults:
    def test_a_result_against_production_is_refused(self) -> None:
        with pytest.raises(validation.RefusedError) as refused:
            validation.check_nuclei(
                _policy(), target_url=f"{PROD}/a", template_tags=["exposure"]
            )
        assert refused.value.code == "production"

    def test_a_result_off_the_demo_is_refused(self) -> None:
        with pytest.raises(validation.RefusedError) as refused:
            validation.check_nuclei(
                _policy(), target_url="https://other.example.test/a", template_tags=[]
            )
        assert refused.value.code == "not_demo"

    @pytest.mark.parametrize("tag", ["intrusive", "dos", "fuzz", "bruteforce", "Intrusive"])
    def test_a_destructive_template_is_refused(self, tag: str) -> None:
        with pytest.raises(validation.RefusedError) as refused:
            validation.check_nuclei(_policy(), target_url=f"{DEMO}/a", template_tags=[tag])
        assert refused.value.code == "unsafe_template"

    def test_a_safe_template_on_the_demo_is_accepted(self) -> None:
        assert validation.check_nuclei(
            _policy(), target_url=f"{DEMO}/a", template_tags=["exposure", "misconfig"]
        ) == DEMO


# --------------------------------------------------------------------------
# The verdict and its evidence
# --------------------------------------------------------------------------


class TestVerdict:
    def test_evidence_present_is_validated(self) -> None:
        recorder = Recorder(lambda r: httpx2.Response(200, headers={"X-Powered-By": "Express"}))
        result = _run(_dast(f"{DEMO}/a"), recorder)
        assert result.verdict == validation.VALIDATED
        assert "X-Powered-By: Express" in result.reason

    def test_evidence_in_the_body_is_validated(self) -> None:
        recorder = Recorder(lambda r: httpx2.Response(200, text="<p>X-Powered-By: Express</p>"))
        assert _run(_dast(f"{DEMO}/a"), recorder).verdict == validation.VALIDATED

    def test_evidence_absent_is_not_validated(self) -> None:
        recorder = Recorder(lambda r: httpx2.Response(200, text="nothing here"))
        result = _run(_dast(f"{DEMO}/a"), recorder)
        assert result.verdict == validation.NOT_VALIDATED

    def test_a_server_error_is_inconclusive(self) -> None:
        recorder = Recorder(lambda r: httpx2.Response(503, text="down"))
        assert _run(_dast(f"{DEMO}/a"), recorder).verdict == validation.INCONCLUSIVE

    def test_an_unreachable_demo_is_inconclusive_with_the_error(self) -> None:
        recorder = Recorder(lambda r: httpx2.ConnectError("refused", request=r))
        result = _run(_dast(f"{DEMO}/a"), recorder)
        assert result.verdict == validation.INCONCLUSIVE
        assert result.response["error"]

    def test_nothing_recorded_to_look_for_is_inconclusive(self) -> None:
        recorder = Recorder()
        result = _run(_dast(f"{DEMO}/a", evidence=""), recorder)
        assert result.verdict == validation.INCONCLUSIVE

    def test_the_response_is_kept_bounded_and_cookies_redacted(self) -> None:
        recorder = Recorder(
            lambda r: httpx2.Response(
                200,
                headers={"Set-Cookie": "session=abc123", "X-Powered-By": "Express"},
                text="x" * (validation.BODY_KEPT_BYTES * 3),
            )
        )
        result = _run(_dast(f"{DEMO}/a"), recorder)
        assert len(result.response["body"]) <= validation.BODY_KEPT_BYTES
        assert result.response["body_truncated"] is True
        assert result.response["headers"]["set-cookie"] == validation.REDACTED
        assert "abc123" not in str(result.response)


# --------------------------------------------------------------------------
# The API
# --------------------------------------------------------------------------


@pytest.fixture
def dast_finding(client: TestClient, run_compaction, catalog) -> str:
    token = issue_token(client, REPO, "dast")
    auth = {"Authorization": f"Bearer {token}"}
    scan = "22222222-2222-2222-2222-222222222222"
    response = post_scan(
        client, auth, scan_run_id=scan, capability="dast", tool_name="zap-demo", pr_number=None
    )
    assert response.status_code in (200, 201), response.text
    response = post_findings(
        client,
        auth,
        [
            {
                "rule_id": "ZAP-10037",
                "title": "Server leaks X-Powered-By at GET /api/orders",
                "severity": "low",
                "file_path": "/api/orders",
                "code_snippet": "GET /api/orders",
                "symbol": "demo",
                "raw_finding_json": {
                    "alertRef": "10037",
                    "instance": {
                        "uri": f"{PROD}/api/orders?id=7",
                        "method": "GET",
                        "evidence": EVIDENCE,
                    },
                },
            }
        ],
        scan_run_id=scan,
        capability="dast",
    )
    assert response.status_code in (200, 201, 202), response.text
    run_compaction()
    [(finding_id,)] = catalog.query(
        "SELECT finding_id FROM findings WHERE rule_id = ?", ["ZAP-10037"]
    )
    return str(finding_id)


@pytest.fixture
def demo(client: TestClient):
    settings = client.app.state.settings  # type: ignore[attr-defined]
    settings.validation_demo_origin = DEMO
    settings.validation_production_origins = [PROD]
    recorder = Recorder(lambda r: httpx2.Response(200, headers={"X-Powered-By": "Express"}))
    client.app.state.validation_transport = recorder.transport  # type: ignore[attr-defined]
    return recorder


class TestApi:
    def test_a_replay_is_recorded_with_its_request_and_response(
        self, client: TestClient, admin_auth: dict[str, str], dast_finding: str, demo: Recorder
    ) -> None:
        response = client.post(
            f"/api/dashboard/findings/{dast_finding}/validations", json={}, headers=admin_auth
        )

        assert response.status_code == 201, response.text
        got = response.json()
        assert got["verdict"] == "validated"
        assert got["source"] == "zap_replay"
        assert got["environment"] == "demo"
        assert got["target_origin"] == DEMO
        assert got["request"]["method"] == "GET"
        assert got["request"]["url"] == f"{DEMO}/api/orders?id=7"
        assert got["response"]["status"] == 200
        assert demo.origins() == {DEMO}

        listed = client.get(
            f"/api/dashboard/findings/{dast_finding}/validations", headers=admin_auth
        )
        assert listed.status_code == 200, listed.text
        [entry] = listed.json()["validations"]
        assert entry["id"] == got["id"]
        assert entry["request"]["url"] == f"{DEMO}/api/orders?id=7"
        assert entry["response"]["headers"]["x-powered-by"] == "Express"

    def test_validation_does_not_change_the_finding(
        self, client: TestClient, admin_auth: dict[str, str], dast_finding: str, demo: Recorder
    ) -> None:
        client.post(
            f"/api/dashboard/findings/{dast_finding}/validations", json={}, headers=admin_auth
        )
        row = client.app.state.catalog  # type: ignore[attr-defined]
        [(status,)] = row.query(
            "SELECT status FROM findings WHERE finding_id = ?", [dast_finding]
        )
        assert status == "open"

    def test_a_refusal_sends_nothing_and_records_nothing(
        self, client: TestClient, admin_auth: dict[str, str], dast_finding: str, demo: Recorder
    ) -> None:
        client.app.state.settings.validation_demo_origin = PROD  # type: ignore[attr-defined]

        response = client.post(
            f"/api/dashboard/findings/{dast_finding}/validations", json={}, headers=admin_auth
        )

        assert response.status_code == 422, response.text
        assert response.json()["detail"]["code"] == "demo_is_production"
        assert demo.sent == []
        listed = client.get(
            f"/api/dashboard/findings/{dast_finding}/validations", headers=admin_auth
        )
        assert listed.json()["validations"] == []

    def test_unconfigured_is_refused(
        self, client: TestClient, admin_auth: dict[str, str], dast_finding: str
    ) -> None:
        response = client.post(
            f"/api/dashboard/findings/{dast_finding}/validations", json={}, headers=admin_auth
        )
        assert response.status_code == 422, response.text
        assert response.json()["detail"]["code"] == "not_configured"

    def test_a_nuclei_result_is_recorded_on_the_demo_only(
        self, client: TestClient, admin_auth: dict[str, str], dast_finding: str, demo: Recorder
    ) -> None:
        body = {
            "template_id": "tech-detect",
            "template_tags": ["tech", "exposure"],
            "target_url": f"{DEMO}/api/orders",
            "outcome": "matched",
            "request": "GET /api/orders HTTP/1.1\r\nHost: demo",
            "response": "HTTP/1.1 200 OK\r\nX-Powered-By: Express",
        }
        response = client.post(
            f"/api/dashboard/findings/{dast_finding}/validations/nuclei",
            json=body,
            headers=admin_auth,
        )
        assert response.status_code == 201, response.text
        got = response.json()
        assert got["verdict"] == "validated"
        assert got["source"] == "nuclei"
        assert got["template_id"] == "tech-detect"
        assert got["request"]["raw"].startswith("GET /api/orders")
        assert "X-Powered-By" in got["response"]["raw"]

        refused = client.post(
            f"/api/dashboard/findings/{dast_finding}/validations/nuclei",
            json={**body, "target_url": f"{PROD}/api/orders"},
            headers=admin_auth,
        )
        assert refused.status_code == 422, refused.text
        assert refused.json()["detail"]["code"] == "production"
        listed = client.get(
            f"/api/dashboard/findings/{dast_finding}/validations", headers=admin_auth
        )
        assert len(listed.json()["validations"]) == 1

    def test_a_viewer_can_read_but_not_validate(
        self,
        client: TestClient,
        viewer_auth: dict[str, str],
        dast_finding: str,
        demo: Recorder,
    ) -> None:
        response = client.post(
            f"/api/dashboard/findings/{dast_finding}/validations", json={}, headers=viewer_auth
        )
        assert response.status_code == 403, response.text
        assert demo.sent == []
        listed = client.get(
            f"/api/dashboard/findings/{dast_finding}/validations", headers=viewer_auth
        )
        assert listed.status_code == 200

    def test_an_unknown_finding_is_404(
        self, client: TestClient, admin_auth: dict[str, str], demo: Recorder
    ) -> None:
        response = client.post(
            "/api/dashboard/findings/nope/validations", json={}, headers=admin_auth
        )
        assert response.status_code == 404
        assert demo.sent == []
