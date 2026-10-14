"""The ingestion API under a hostile caller — specs/05-datalake.md §4, §6, §7.

Every CI lane writes here with a per-repo token, so this is the surface a
compromised runner reaches first. `test_ingest_api.py` pins the contract for
an honest caller; this file pins what a dishonest one cannot do:

1. A token for repo A writes nothing to repo B, whatever the body claims
   (§4 "Is bound to exactly one `repo_full_name`. This is the isolation
   boundary.").
2. `/raw` is not a write primitive onto the host, and refuses oversized
   uploads at the configured ceiling (§7, `max_raw_output_bytes`).
3. A malformed body is a 4xx, never a 500 (§4 "reject (`422`) with a clear
   error rather than partially ingesting malformed data").
4. Capability grants are enforced on every capability-scoped route (D-009).
5. A revoked token, an immediately rotated one, and a superseded one past its
   overlap are refused on the very next request (§4, §9).
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from mykronos.auth import TokenRegistry
from mykronos.config import Settings
from mykronos.github import FakeGitHubClient
from mykronos.github.factory import FakeGitHubClientFactory
from mykronos.main import create_app
from mykronos.notify import Notification
from tests.conftest import (
    CAPABILITY,
    REPO,
    finding_payload,
    issue_token,
    post_findings,
    post_scan,
    scan_run_payload,
)

#: The repository the attacker's token does not belong to.
VICTIM = "example-org/ledger-core"
VICTIM_RUN = "22222222-2222-2222-2222-222222222222"


class RecordingNotifier:
    """Captures what would have gone to Slack, so attribution can be read."""

    enabled = True

    def __init__(self) -> None:
        self.sent: list[Notification] = []

    async def send(self, note: Notification) -> bool:
        self.sent.append(note)
        return True


@pytest.fixture
def client(settings: Settings, github: FakeGitHubClient) -> Iterator[TestClient]:
    """The shared client, but a server-side exception is a 500 rather than a
    re-raise — "never a 500" has to be observable as a status code."""
    with TestClient(create_app(settings), raise_server_exceptions=False) as test_client:
        test_client.app.state.github_factory = FakeGitHubClientFactory(github)  # type: ignore[attr-defined]
        test_client.app.state.notifier = RecordingNotifier()  # type: ignore[attr-defined]
        yield test_client


@pytest.fixture
def victim_auth(client: TestClient) -> dict[str, str]:
    return {"Authorization": f"Bearer {issue_token(client, VICTIM, CAPABILITY)}"}


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# --------------------------------------------------------------------------
# 1. The repository comes from the token
# --------------------------------------------------------------------------


class TestCrossRepoWrites:
    def test_scan_run_naming_another_repo_is_refused_and_writes_nothing(
        self, client: TestClient, auth: dict[str, str], buffer
    ) -> None:
        response = post_scan(client, auth, repo_full_name=VICTIM, scan_run_id=VICTIM_RUN)

        assert response.status_code == 403
        assert buffer.count_sealed() == 0

    def test_a_findings_batch_has_no_field_to_name_another_repo(
        self, client: TestClient, auth: dict[str, str], buffer
    ) -> None:
        """extra='forbid' at both levels: smuggling the field in is a 422,
        not a silently ignored key that a reviewer might read as honoured."""
        on_batch = client.post(
            "/api/ingest/findings",
            json={
                "scan_run_id": "run-1",
                "capability": CAPABILITY,
                "repo_full_name": VICTIM,
                "findings": [],
            },
            headers=auth,
        )
        on_finding = post_findings(client, auth, [finding_payload(repo_full_name=VICTIM)])

        assert on_batch.status_code == 422
        assert on_finding.status_code == 422
        assert "repo_full_name" in on_batch.text and "repo_full_name" in on_finding.text
        assert buffer.count_sealed() == 0

    def test_findings_against_another_repos_scan_run_stay_the_tokens_own(
        self,
        client: TestClient,
        auth: dict[str, str],
        victim_auth: dict[str, str],
        catalog,
        run_compaction,
    ) -> None:
        """Knowing a victim's scan_run_id does not let you file into its repo."""
        assert post_scan(client, victim_auth, repo_full_name=VICTIM, scan_run_id=VICTIM_RUN)
        post_findings(client, auth, [finding_payload()], scan_run_id=VICTIM_RUN)
        run_compaction()

        assert catalog.query("SELECT DISTINCT repo_full_name FROM findings") == [(REPO,)]

    def test_a_scan_run_id_cannot_be_taken_over_by_another_repos_token(
        self,
        client: TestClient,
        auth: dict[str, str],
        victim_auth: dict[str, str],
        catalog,
        run_compaction,
    ) -> None:
        """D-002 makes `/scan-run` an upsert on `scan_run_id`, and the client
        chooses that id. Run ids are printed in CI logs, so a token for A that
        re-posts B's id under A's own name must not re-attribute B's run to
        A, or finalise it as failed: that is writing to B's data (§4)."""
        assert (
            post_scan(
                client, victim_auth, repo_full_name=VICTIM, scan_run_id=VICTIM_RUN
            ).status_code
            == 200
        )
        run_compaction()

        hijack = post_scan(
            client,
            auth,
            scan_run_id=VICTIM_RUN,
            scan_status="failure",
            completed_at=scan_run_payload()["started_at"],
        )
        run_compaction()

        assert hijack.status_code in (403, 409), hijack.text
        assert catalog.query(
            "SELECT repo_full_name, scan_status FROM scan_runs WHERE scan_run_id = ?",
            [VICTIM_RUN],
        ) == [(VICTIM, "success")]

    def test_the_victims_own_finalising_post_still_upserts(
        self,
        client: TestClient,
        victim_auth: dict[str, str],
        catalog,
        run_compaction,
    ) -> None:
        """The guard above must not break D-002 for the run's own repo."""
        post_scan(client, victim_auth, repo_full_name=VICTIM, scan_run_id=VICTIM_RUN)
        run_compaction()
        final = post_scan(
            client,
            victim_auth,
            repo_full_name=VICTIM,
            scan_run_id=VICTIM_RUN,
            scan_status="failure",
            completed_at=scan_run_payload()["started_at"],
        )
        run_compaction()

        assert final.status_code == 200
        assert catalog.query(
            "SELECT repo_full_name, scan_status FROM scan_runs WHERE scan_run_id = ?",
            [VICTIM_RUN],
        ) == [(VICTIM, "failure")]

    def test_raw_output_lands_under_the_tokens_repo_whatever_the_query_says(
        self, client: TestClient, auth: dict[str, str], settings: Settings
    ) -> None:
        response = client.post(
            "/api/ingest/raw",
            params={
                "scan_run_id": "run-1",
                "capability": CAPABILITY,
                "filename": "out.sarif",
                "repo_full_name": VICTIM,
                "owner": "example-org",
                "name": "ledger-core",
            },
            content=b"{}",
            headers=auth,
        )

        assert response.status_code == 200
        assert response.json()["raw_output_ref"].startswith("raw/example-org/payments-api/")
        assert not (settings.raw_dir / "example-org" / "ledger-core").exists()

    def test_lane_failure_cannot_name_another_repo(
        self, client: TestClient, auth: dict[str, str]
    ) -> None:
        notifier = client.app.state.notifier  # type: ignore[attr-defined]

        smuggled = client.post(
            "/api/ingest/lane-failure",
            json={"lane": "publish", "repo_full_name": VICTIM},
            headers=auth,
        )
        honest = client.post("/api/ingest/lane-failure", json={"lane": "publish"}, headers=auth)

        assert smuggled.status_code == 422
        assert "repo_full_name" in smuggled.text
        assert honest.status_code == 200
        assert [n.repo_full_name for n in notifier.sent] == [REPO]

    def test_a_check_run_for_another_repo_is_refused(
        self, client: TestClient, auth: dict[str, str], github: FakeGitHubClient
    ) -> None:
        response = client.post(
            "/api/ingest/check-runs",
            json={
                "repo_full_name": VICTIM,
                "commit_sha": "a" * 40,
                "job": "unit",
                "phase": "start",
            },
            headers=auth,
        )

        assert response.status_code == 403
        assert "scoped to" in response.json()["detail"]

    @pytest.mark.parametrize(
        ("path", "capability", "body"),
        [
            (
                "/api/ingest/aegis",
                "aegis",
                {"pr_number": 1, "commit_sha": "abc", "author_login": "someone"},
            ),
            ("/api/ingest/atlas", "atlas", {"commit_sha": "abc", "ecosystems": []}),
            (
                "/api/ingest/reachability",
                "sast",
                {"commit_sha": "abc", "language": "python", "orphaned_paths": []},
            ),
            ("/api/ingest/netassess", "network", {"run_key": "2026-10-14"}),
        ],
    )
    def test_capability_payloads_have_no_field_to_name_another_repo(
        self, client: TestClient, path: str, capability: str, body: dict[str, Any], buffer
    ) -> None:
        headers = _bearer(issue_token(client, REPO, capability))

        response = client.post(path, json={**body, "repo_full_name": VICTIM}, headers=headers)

        assert response.status_code == 422, response.text
        assert "repo_full_name" in response.text, "refused for some other reason"
        assert buffer.count_sealed() == 0


# --------------------------------------------------------------------------
# 2. /raw is not a write primitive onto the host
# --------------------------------------------------------------------------


def _post_raw(
    client: TestClient, auth: dict[str, str], body: bytes, **params: str
) -> Any:
    query = {"scan_run_id": "run-1", "capability": CAPABILITY, "filename": "out.sarif"}
    query.update(params)
    return client.post("/api/ingest/raw", params=query, content=body, headers=auth)


def _files_under(root: Path) -> set[Path]:
    return {p for p in root.rglob("*") if p.is_file()}


class TestRawArchiveAbuse:
    @pytest.mark.parametrize(
        "filename",
        [
            "../../evil.txt",
            "../../../../../../../../tmp/evil.txt",
            "/etc/evil.txt",
            "..\\..\\evil.txt",
            "C:\\Windows\\evil.txt",
            "\\\\server\\share\\evil.txt",
            "..%2F..%2Fevil.txt",
            "%2e%2e%2f%2e%2e%2fevil.txt",
            "..%252F..%252Fevil.txt",
            "sub/../../evil.txt",
            "evil.txt\x00.sarif",
            "\x00",
            "..",
            ".",
            "",
            "./",
            "...",
        ],
    )
    def test_a_hostile_filename_lands_in_the_run_directory_or_is_refused(
        self,
        client: TestClient,
        auth: dict[str, str],
        settings: Settings,
        tmp_path: Path,
        filename: str,
    ) -> None:
        before = _files_under(tmp_path)
        run_dir = (settings.raw_dir / "example-org" / "payments-api" / "run-1").resolve()

        response = _post_raw(client, auth, b"payload", filename=filename)

        assert response.status_code < 500, response.text
        written = _files_under(tmp_path) - before
        if response.status_code == 200:
            ref = response.json()["raw_output_ref"]
            stored = (settings.datalake_dir / ref).resolve()
            assert stored.parent == run_dir, ref
            assert stored.read_bytes() == b"payload"
            # Nothing but the archive copy (and the buffer, which /raw does
            # not touch) may have appeared anywhere under the test root.
            assert {p.resolve() for p in written} == {stored}
        else:
            assert 400 <= response.status_code < 500
            assert written == set()

    @pytest.mark.parametrize("scan_run_id", ["../../..", "/etc", "..\\..", "x\x00y", "%2e%2e"])
    def test_a_hostile_scan_run_id_stays_inside_the_repos_archive(
        self, client: TestClient, auth: dict[str, str], settings: Settings, scan_run_id: str
    ) -> None:
        response = _post_raw(client, auth, b"x", scan_run_id=scan_run_id)

        assert response.status_code < 500, response.text
        if response.status_code == 200:
            stored = (settings.datalake_dir / response.json()["raw_output_ref"]).resolve()
            repo_dir = (settings.raw_dir / "example-org" / "payments-api").resolve()
            assert stored.parent.parent == repo_dir

    def test_the_ceiling_is_inclusive_and_one_byte_over_is_413_with_nothing_written(
        self, settings: Settings, github: FakeGitHubClient, tmp_path: Path
    ) -> None:
        settings.max_raw_output_bytes = 1024
        with TestClient(create_app(settings), raise_server_exceptions=False) as client:
            client.app.state.github_factory = FakeGitHubClientFactory(github)  # type: ignore[attr-defined]
            headers = _bearer(issue_token(client, REPO, CAPABILITY))

            at_limit = _post_raw(client, headers, b"a" * 1024, filename="ok.sarif")
            before = _files_under(tmp_path)
            over = _post_raw(client, headers, b"a" * 1025, filename="big.sarif")

        assert at_limit.status_code == 200
        assert over.status_code == 413
        assert _files_under(tmp_path) - before == set()
        run_dir = settings.raw_dir / "example-org" / "payments-api" / "run-1"
        assert not (run_dir / "big.sarif").exists()

    def test_the_default_ceiling_exists(self) -> None:
        """A limit of "unbounded" would be a finding in itself (§7 bounds
        local disk usage). Pinned so it cannot quietly become 0-means-off."""
        default = Settings.model_fields["max_raw_output_bytes"].default
        assert isinstance(default, int)
        assert 0 < default <= 100 * 1024 * 1024


# --------------------------------------------------------------------------
# 3. Malformed bodies are a 4xx, never a 500
# --------------------------------------------------------------------------


_MALFORMED_JSON: list[bytes] = [
    b"",
    b"{",
    b"not json",
    b"null",
    b"[]",
    b'"a string"',
    b"42",
    b"\xff\xfe\x00{",
    b'{"scan_run_id": "run-1", "capability": "sast", "findings": {}}',
    b'{"scan_run_id": "run-1", "capability": "sast", "findings": [null]}',
    b'{"scan_run_id": "run-1", "capability": "sast", "findings": [[]]}',
    b'{"scan_run_id": "run-1", "capability": "sast", "findings": "x"}',
    b'{"scan_run_id": "", "capability": "sast", "findings": []}',
    b'{"scan_run_id": "run-1", "capability": "../../etc", "findings": []}',
    # A SARIF document posted to the wrong endpoint: well-formed JSON of the
    # wrong shape, which is the realistic way a lane gets this wrong.
    b'{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "x"}}, "results": []}]}',
    # JUnit XML, likewise.
    b'<?xml version="1.0"?><testsuite name="x"><testcase name="y"/></testsuite>',
    b"[" * 100_000 + b"]" * 100_000,
]


class TestMalformedBodies:
    @pytest.mark.parametrize("path", ["/api/ingest/findings", "/api/ingest/scan-run"])
    @pytest.mark.parametrize("body", _MALFORMED_JSON, ids=lambda b: repr(b[:24]))
    def test_a_malformed_body_is_4xx(
        self, client: TestClient, auth: dict[str, str], buffer, path: str, body: bytes
    ) -> None:
        response = client.post(
            path, content=body, headers={**auth, "Content-Type": "application/json"}
        )

        assert 400 <= response.status_code < 500, (response.status_code, response.text[:200])
        assert buffer.count_sealed() == 0

    @pytest.mark.parametrize(
        "overrides",
        [
            {"cvss_score": "NaN"},
            {"line_start": -1},
            # The lake column is INTEGER: a value it cannot hold was accepted
            # with a 200 and stored as NULL, a partial ingest by another name.
            {"line_start": 10**40},
            {"line_end": 2**31},
            {"port": 2**31},
            {"severity": "CRITICAL!"},
            {"title": ""},
            {"rule_id": "x" * 10_000},
            {"raw_finding_json": "not an object"},
            {"cwe_ids": "CWE-89"},
        ],
        ids=lambda o: next(iter(o)),
    )
    def test_a_malformed_finding_is_4xx(
        self, client: TestClient, auth: dict[str, str], overrides: dict[str, Any]
    ) -> None:
        response = post_findings(client, auth, [finding_payload(**overrides)])

        assert 400 <= response.status_code < 500, (response.status_code, response.text[:200])

    @pytest.mark.parametrize("literal", [b"1e400", b"-1e400", b"NaN", b"Infinity"])
    def test_a_non_finite_cvss_score_is_4xx(
        self, client: TestClient, auth: dict[str, str], buffer, literal: bytes
    ) -> None:
        """Python's json accepts these; the lake and every reader of it do not.
        Sent as raw bytes because no compliant client library will encode them."""
        body = (
            b'{"scan_run_id": "run-1", "capability": "sast", "findings": [{'
            b'"rule_id": "R", "title": "t", "severity": "low", "cvss_score": '
            + literal
            + b"}]}"
        )

        response = client.post(
            "/api/ingest/findings",
            content=body,
            headers={**auth, "Content-Type": "application/json"},
        )

        assert 400 <= response.status_code < 500, (response.status_code, response.text[:200])
        assert buffer.count_sealed() == 0

    def test_a_scan_run_count_the_lake_cannot_hold_is_4xx(
        self, client: TestClient, auth: dict[str, str]
    ) -> None:
        assert post_scan(client, auth, finding_count=2**31).status_code == 422
        assert post_scan(client, auth, pr_number=2**31).status_code == 422

    def test_a_deeply_nested_raw_finding_is_not_a_500(
        self, client: TestClient, auth: dict[str, str]
    ) -> None:
        """`raw_finding_json` is the tool's record verbatim; a tool (or an
        attacker) controls its depth. Accepting it is fine, crashing is not."""
        depth = 5_000
        nested = '{"a":' * depth + "1" + "}" * depth
        body = (
            '{"scan_run_id": "run-1", "capability": "sast", "findings": [{'
            '"rule_id": "R", "title": "t", "severity": "low", '
            f'"raw_finding_json": {nested}}}]}}'
        ).encode()

        response = client.post(
            "/api/ingest/findings",
            content=body,
            headers={**auth, "Content-Type": "application/json"},
        )

        assert response.status_code < 500, response.text[:200]

    @pytest.mark.parametrize(
        "body",
        [
            b'{"runs": [',
            b"<testsuite><testcase",
            b"\x00\xff\xfe binary garbage",
            b"",
        ],
    )
    def test_malformed_raw_output_is_archived_verbatim_not_parsed(
        self, client: TestClient, auth: dict[str, str], settings: Settings, body: bytes
    ) -> None:
        """/raw is the dispute-resolution copy: the server must store what the
        tool said, broken or not, and must not choke trying to read it."""
        response = _post_raw(client, auth, body)

        assert response.status_code == 200, response.text
        stored = settings.datalake_dir / response.json()["raw_output_ref"]
        assert stored.read_bytes() == body


# --------------------------------------------------------------------------
# 4. Capability grants are enforced on every capability-scoped route
# --------------------------------------------------------------------------


class TestCapabilityGrants:
    @pytest.mark.parametrize(
        ("path", "body"),
        [
            ("/api/ingest/findings", {"scan_run_id": "r", "capability": "secrets", "findings": []}),
            ("/api/ingest/scan-run", scan_run_payload(capability="secrets")),
            (
                "/api/ingest/aegis",
                {"pr_number": 1, "commit_sha": "abc", "author_login": "someone"},
            ),
            ("/api/ingest/atlas", {"commit_sha": "abc", "ecosystems": []}),
            ("/api/ingest/netassess", {"run_key": "2026-10-14"}),
            ("/api/ingest/patchwork", None),
        ],
    )
    def test_an_ungranted_capability_is_403_and_writes_nothing(
        self,
        client: TestClient,
        auth: dict[str, str],
        buffer,
        path: str,
        body: dict[str, Any] | None,
    ) -> None:
        """`auth` holds `sast` only."""
        response = client.post(path, json=body, headers=auth)

        assert response.status_code == 403, response.text
        assert buffer.count_sealed() == 0

    def test_reachability_needs_sast(self, client: TestClient, buffer) -> None:
        headers = _bearer(issue_token(client, REPO, "secrets"))

        response = client.post(
            "/api/ingest/reachability",
            json={"commit_sha": "abc", "language": "python", "orphaned_paths": []},
            headers=headers,
        )

        assert response.status_code == 403

    def test_raw_needs_the_capability_it_archives_for(
        self, client: TestClient, auth: dict[str, str], settings: Settings
    ) -> None:
        response = _post_raw(client, auth, b"x", capability="secrets")

        assert response.status_code == 403
        assert not settings.raw_dir.exists() or _files_under(settings.raw_dir) == set()

    def test_another_repos_grant_does_not_leak_onto_this_token(
        self, client: TestClient, auth: dict[str, str]
    ) -> None:
        """Grants are keyed by repository. Granting `secrets` to the victim
        must not let A's token write `secrets`."""
        issue_token(client, VICTIM, "secrets")

        response = post_findings(client, auth, [], capability="secrets")

        assert response.status_code == 403

    def test_an_unknown_capability_is_422_not_a_new_grant(
        self, client: TestClient, auth: dict[str, str]
    ) -> None:
        response = post_findings(client, auth, [], capability="admin")

        assert response.status_code == 422


# --------------------------------------------------------------------------
# 5. Revoked and rotated tokens stop at once
# --------------------------------------------------------------------------


class TestRevocationAndRotation:
    _ROUTES: list[tuple[str, str, Any]] = [
        ("POST", "/api/ingest/scan-run", scan_run_payload()),
        (
            "POST",
            "/api/ingest/findings",
            {"scan_run_id": "r", "capability": CAPABILITY, "findings": []},
        ),
        ("POST", "/api/ingest/lane-failure", {"lane": "publish"}),
        ("GET", "/api/ingest/health", None),
    ]

    def _all_refused(self, client: TestClient, headers: dict[str, str]) -> list[int]:
        codes = [
            client.request(method, path, json=body, headers=headers).status_code
            for method, path, body in self._ROUTES
        ]
        codes.append(_post_raw(client, headers, b"x").status_code)
        return codes

    def test_offboarding_refuses_every_route_on_the_next_request(
        self, client: TestClient, auth: dict[str, str]
    ) -> None:
        assert post_scan(client, auth).status_code == 200

        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            TokenRegistry(session).revoke_repo(REPO)

        assert self._all_refused(client, auth) == [401] * (len(self._ROUTES) + 1)

    def test_an_immediate_rotation_refuses_the_old_token_and_accepts_the_new(
        self, client: TestClient, auth: dict[str, str]
    ) -> None:
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            new = TokenRegistry(session).rotate(REPO, immediate=True)

        assert self._all_refused(client, auth) == [401] * (len(self._ROUTES) + 1)
        assert post_scan(client, _bearer(new)).status_code == 200

    def test_every_earlier_value_dies_with_an_immediate_rotation(
        self, client: TestClient, auth: dict[str, str]
    ) -> None:
        """The leaked value had already been superseded by a scheduled
        rotation; containment must still reach it (D-043 follow-up)."""
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            middle = TokenRegistry(session).rotate(REPO)
        assert post_scan(client, auth).status_code == 200  # inside overlap

        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            newest = TokenRegistry(session).rotate(REPO, immediate=True)

        assert post_scan(client, auth).status_code == 401
        assert post_scan(client, _bearer(middle)).status_code == 401
        assert post_scan(client, _bearer(newest)).status_code == 200

    def test_a_superseded_token_is_refused_once_its_overlap_has_passed(
        self, client: TestClient, auth: dict[str, str]
    ) -> None:
        """§9: "an overlap that never expires is not a rotation"."""
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            TokenRegistry(session, overlap_hours=0).rotate(REPO)

        assert post_scan(client, auth).status_code == 401

    def test_revoking_one_repo_leaves_another_repos_token_working(
        self, client: TestClient, auth: dict[str, str], victim_auth: dict[str, str]
    ) -> None:
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            TokenRegistry(session).revoke_repo(VICTIM)

        assert post_scan(client, victim_auth, repo_full_name=VICTIM).status_code == 401
        assert post_scan(client, auth).status_code == 200

    @pytest.mark.parametrize(
        "header",
        [
            "Bearer ",
            "Bearer",
            "Basic dXNlcjpwYXNz",
            "bearer " + "x" * 10_000,
            "Bearer \x7f",
        ],
    )
    def test_a_malformed_authorization_header_is_401_not_500(
        self, client: TestClient, header: str
    ) -> None:
        response = client.post(
            "/api/ingest/scan-run", json=scan_run_payload(), headers={"Authorization": header}
        )

        assert response.status_code in (401, 403), response.text
