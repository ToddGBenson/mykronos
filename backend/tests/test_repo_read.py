"""Repo read tokens: read-only, one repository, counts only.

A service that wants a number about its own repository had two credentials to
choose from: its ingestion token, which writes findings, and the viewer token,
which reads every repository. These tests pin the three properties that make a
read token narrower than both: it reads only the repository it was minted for,
it is accepted by no other route, and only a person can mint or revoke it.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from mykronos.auth import hash_token
from mykronos.config import Settings
from mykronos.db.models import AuditLogEntry, RepoReadToken
from mykronos.gate import TOKEN_HEADER
from mykronos.main import create_app
from mykronos.schemas import utcnow
from tests.conftest import (
    ADMIN_TOKEN,
    REPO,
    VIEWER_TOKEN,
    WEBHOOK_SECRET,
    dependency_finding,
    issue_token,
    post_findings,
    post_scan,
)

OTHER = "example-org/other-service"
SUMMARY = "/api/repo-read/posture-summary"


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _mint(client: TestClient, auth: dict[str, str], repo: str = REPO, **body: Any):
    return client.post(
        "/api/repo-read/tokens", json={"repo_full_name": repo, **body}, headers=auth
    )


def _read_token(client: TestClient, admin_auth: dict[str, str], repo: str = REPO) -> str:
    response = _mint(client, admin_auth, repo)
    assert response.status_code == 201, response.text
    return str(response.json()["token"])


def _seed(client: TestClient, repo: str, capability: str, severities: list[str], run: str):
    ingest = _bearer(issue_token(client, repo, capability))
    post_scan(
        client,
        ingest,
        scan_run_id=run,
        repo_full_name=repo,
        capability=capability,
        tool_name="trivy",
        pr_number=None,
        triggered_by="push",
    )
    response = post_findings(
        client,
        ingest,
        [
            dependency_finding(rule_id=f"CVE-2026-{i:04d}", severity=s, package_name=f"p{i}")
            for i, s in enumerate(severities)
        ],
        scan_run_id=run,
        capability=capability,
    )
    assert response.status_code == 200, response.text


class TestTheSummary:
    def test_counts_open_findings_for_the_tokens_repo_only(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction
    ) -> None:
        _seed(client, REPO, "atlas", ["critical", "high", "high", "low"], "run-atlas")
        _seed(client, OTHER, "atlas", ["critical", "critical"], "run-other")
        run_compaction()

        response = client.get(SUMMARY, headers=_bearer(_read_token(client, admin_auth)))

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["repo_full_name"] == REPO
        atlas = body["capabilities"]["atlas"]
        assert atlas["open_by_severity"] == {
            "info": 0, "low": 1, "medium": 0, "high": 2, "critical": 1
        }
        assert atlas["open_total"] == 4
        assert atlas["last_successful_scan_at"] is not None

    def test_a_capability_that_never_scanned_says_so(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction
    ) -> None:
        """A zero with no scan behind it measured nothing; the null says which."""
        _seed(client, REPO, "atlas", ["high"], "run-atlas")
        run_compaction()

        body = client.get(SUMMARY, headers=_bearer(_read_token(client, admin_auth))).json()

        assert body["capabilities"]["containers"]["open_total"] == 0
        assert body["capabilities"]["containers"]["last_successful_scan_at"] is None

    def test_quality_stages_are_not_reported(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        body = client.get(SUMMARY, headers=_bearer(_read_token(client, admin_auth))).json()
        assert {"unit", "functional", "qa"}.isdisjoint(body["capabilities"])
        assert {"atlas", "containers"} <= set(body["capabilities"])

    def test_it_carries_no_finding_detail(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction
    ) -> None:
        _seed(client, REPO, "atlas", ["high"], "run-atlas")
        run_compaction()
        text = client.get(SUMMARY, headers=_bearer(_read_token(client, admin_auth))).text
        assert "CVE-2026" not in text
        assert "p0" not in text


class TestOnlyAReadTokenOpensIt:
    @pytest.mark.parametrize(
        "headers",
        [
            {},
            {"Authorization": "Bearer mkr_not-a-real-token"},
            {"Authorization": f"Bearer {ADMIN_TOKEN}"},
            {"Authorization": f"Bearer {VIEWER_TOKEN}"},
        ],
        ids=["none", "unknown", "admin", "viewer"],
    )
    def test_anything_else_is_refused(self, client: TestClient, headers) -> None:
        assert client.get(SUMMARY, headers=headers).status_code == 401

    def test_an_ingestion_token_is_refused(self, client: TestClient) -> None:
        ingest = issue_token(client, REPO, "atlas")
        assert client.get(SUMMARY, headers=_bearer(ingest)).status_code == 401

    def test_a_revoked_token_is_refused(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        minted = _mint(client, admin_auth).json()
        revoked = client.post(
            f"/api/repo-read/tokens/{minted['token_id']}/revoke", headers=admin_auth
        )
        assert revoked.status_code == 200, revoked.text
        assert client.get(SUMMARY, headers=_bearer(minted["token"])).status_code == 401

    def test_an_expired_token_is_refused(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        token = _read_token(client, admin_auth)
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            row = session.get(RepoReadToken, hash_token(token))
            row.expires_at = utcnow() - timedelta(seconds=1)
        assert client.get(SUMMARY, headers=_bearer(token)).status_code == 401


class TestItOpensNothingElse:
    @pytest.mark.parametrize(
        "path",
        [
            "/api/agents/whoami",
            "/api/dashboard/portfolio",
            "/api/repos",
            "/api/repo-read/tokens",
            "/api/ingest/health",
        ],
    )
    def test_it_is_refused_on_every_other_read(
        self, client: TestClient, admin_auth: dict[str, str], path: str
    ) -> None:
        token = _read_token(client, admin_auth)
        assert client.get(path, headers=_bearer(token)).status_code in (401, 403)

    def test_it_cannot_write_findings(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        token = _read_token(client, admin_auth)
        response = post_findings(client, _bearer(token), [dependency_finding()], capability="atlas")
        assert response.status_code == 401

    def test_it_cannot_mint_another(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        token = _read_token(client, admin_auth)
        assert _mint(client, _bearer(token)).status_code == 401


class TestOnlyAPersonMints:
    def test_a_person_mints_and_only_the_hash_is_stored(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        minted = _mint(client, admin_auth, label="TheHub self-assessment").json()
        assert minted["token"].startswith("mkr_")
        assert minted["repo_full_name"] == REPO
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            rows = list(session.execute(select(RepoReadToken)).scalars())
            audit = list(
                session.execute(
                    select(AuditLogEntry).where(AuditLogEntry.action == "repo_read_token.minted")
                ).scalars()
            )
        assert len(rows) == 1 and rows[0].token_sha256 == hash_token(minted["token"])
        assert all(minted["token"] not in (r.token_sha256 + r.label) for r in rows)
        assert len(audit) == 1

    def test_a_viewer_cannot_mint(self, client: TestClient, viewer_auth: dict[str, str]) -> None:
        assert _mint(client, viewer_auth).status_code == 403

    def test_an_agent_cannot_mint(self, client: TestClient, admin_auth: dict[str, str]) -> None:
        agent = client.post(
            "/api/agents/credentials", json={"family": "claude-opus-5.5"}, headers=admin_auth
        ).json()["token"]
        assert _mint(client, _bearer(agent)).status_code == 403

    def test_a_repo_must_be_owner_slash_name(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        assert _mint(client, admin_auth, repo="not-a-repo").status_code == 422

    def test_listing_shows_metadata_never_the_token(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        minted = _mint(client, admin_auth).json()
        listed = client.get("/api/repo-read/tokens", headers=admin_auth)
        assert listed.status_code == 200
        assert [r["token_id"] for r in listed.json()] == [minted["token_id"]]
        assert minted["token"] not in listed.text
        assert hash_token(minted["token"]) not in listed.text


class TestThePerimeterGate:
    @pytest.fixture
    def gated(self, tmp_path):
        settings = Settings(
            datalake_dir=tmp_path / "datalake",
            database_url=f"sqlite:///{(tmp_path / 'g.db').as_posix()}",
            run_compaction_in_background=False,
            run_jobs_in_background=False,
            admin_token=ADMIN_TOKEN,
            viewer_token=VIEWER_TOKEN,
            github_webhook_secret=WEBHOOK_SECRET,
            gate_token="gate-value",
        )
        with TestClient(create_app(settings)) as client:
            yield client

    def test_the_summary_authenticates_itself(self, gated: TestClient) -> None:
        minted = gated.post(
            "/api/repo-read/tokens",
            json={"repo_full_name": REPO},
            headers={TOKEN_HEADER: "gate-value", "Authorization": f"Bearer {ADMIN_TOKEN}"},
        )
        assert minted.status_code == 201, minted.text
        assert gated.get(SUMMARY, headers=_bearer(minted.json()["token"])).status_code == 200

    def test_minting_stays_behind_the_gate(self, gated: TestClient) -> None:
        response = gated.post(
            "/api/repo-read/tokens",
            json={"repo_full_name": REPO},
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "Not authorised for this host."
