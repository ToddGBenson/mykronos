"""Spec 12 §8's acceptance criteria, as tests rather than as a memo.

A security review that produces a document is true on the day it is written.
These are five claims the platform makes about itself, and each one here fails
the build if it stops being true — which is the only version of a review that
survives the next six months of changes.

Each test names the criterion it enforces and, where the criterion exists
because of a specific hazard, the hazard.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from mykronos.auth import TokenRegistry
from mykronos.db.models import AuditLogEntry
from mykronos.installer import DEFAULT_SECRET_NAME
from tests.conftest import REPO, issue_token, post_scan
from tests.test_onboarding import onboard

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"

#: Real GitHub credential prefixes. `ghp_` personal access tokens are the
#: thing spec 12 §2 exists to keep out of this system entirely.
CREDENTIAL_SHAPES = re.compile(
    r"\b(ghp_[A-Za-z0-9]{16,}"
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|ghs_[A-Za-z0-9]{16,}"
    r"|gho_[A-Za-z0-9]{16,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----)"
)

SOURCE_GLOBS = ("**/*.py", "**/*.yaml", "**/*.yml", "**/*.json", "**/*.j2", "**/*.md")
SKIP_DIRS = {".venv", "node_modules", ".git", "__pycache__", ".next", "datalake"}


def _source_files() -> list[Path]:
    files: list[Path] = []
    for pattern in SOURCE_GLOBS:
        for path in ROOT.glob(pattern):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            files.append(path)
    return files


class TestNoCredentialsInTheTree:
    """spec 12 §8: no PAT-shaped credential in the codebase, schema, or
    default configuration — including test fixtures."""

    def test_no_credential_shaped_string_anywhere(self) -> None:
        offenders = []
        for path in _source_files():
            try:
                body = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            # This file necessarily contains the patterns it searches for.
            if path.name == Path(__file__).name:
                continue
            for match in CREDENTIAL_SHAPES.finditer(body):
                line = body[: match.start()].count("\n") + 1
                offenders.append(f"{path.relative_to(ROOT)}:{line}")

        assert offenders == [], (
            "Credential-shaped strings found: " + ", ".join(offenders)
        )

    def test_the_env_example_has_no_real_values(self) -> None:
        """spec 12 §8: documented placeholders, never a working secret."""
        example = BACKEND / ".env.example"

        assert example.exists(), "backend/.env.example is missing"
        body = example.read_text(encoding="utf-8")
        assert not CREDENTIAL_SHAPES.search(body)

    def test_env_files_are_ignored_by_git(self) -> None:
        """The file that holds the real values must never be committable."""
        ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")

        assert ".env" in ignore
        assert "!.env.example" in ignore, (
            "`.env.*` is ignored but the example is not re-included, so the "
            "documented placeholders cannot be committed either."
        )

    def test_no_default_setting_holds_a_credential(self, monkeypatch) -> None:
        """An unconfigured deployment must hold nothing worth stealing."""
        import os

        from mykronos.config import Settings

        # `_env_file=None` silences the dotenv file but NOT the process
        # environment, which pydantic-settings always reads. In CI the
        # pipeline's shared env anchor exports MYKRONOS_GATE_TOKEN to every
        # task, so this test failed there and only there -- reporting a
        # credential default that does not exist in the tree. The claim under
        # test is about the CODE, so the ambient prefix is scrubbed first.

        for var in list(os.environ):
            if var.startswith("MYKRONOS_"):
                monkeypatch.delenv(var)

        settings = Settings(_env_file=None)  # type: ignore[call-arg]

        for name in (
            "admin_token",
            "viewer_token",
            "gate_token",
            "github_webhook_secret",
            "github_app_id",
        ):
            assert getattr(settings, name) == "", (
                f"Settings.{name} has a non-empty default. Every credential "
                "must be absent until an operator supplies it."
            )
        assert settings.github_app_private_key_path is None


class TestTheSecretsApiIsNarrow:
    """spec 12 §8, and the reason it is a criterion: `secrets: write` grants
    the ability to overwrite *any* named secret in an onboarded repository
    (§6.1). Nothing in the grant stops a future change doing that by
    accident, so the narrowness has to be asserted."""

    def test_only_one_secret_name_is_ever_written(self) -> None:
        call_sites = []
        for path in (BACKEND / "mykronos").rglob("*.py"):
            body = path.read_text(encoding="utf-8")
            for match in re.finditer(
                r"put_actions_secret\((.{0,200})", body, re.DOTALL
            ):
                # Skip the definitions themselves. The slice ends at the
                # name, so it holds "async def " rather than the full
                # signature — matching on the trailing "def " is what
                # actually distinguishes a definition from a call.
                if body[max(0, match.start() - 12): match.start()].rstrip().endswith("def"):
                    continue
                call_sites.append((path.relative_to(BACKEND), match.group(1)))

        assert call_sites, "No call sites found — has the API moved?"
        for path, snippet in call_sites:
            assert "secret_name" in snippet or DEFAULT_SECRET_NAME in snippet, (
                f"{path} writes an Actions secret whose name is not the one "
                "Mykronos owns. `secrets: write` can overwrite any secret in "
                "the repository, so the name must never be caller-supplied."
            )

    @pytest.mark.anyio
    async def test_the_installer_touches_only_its_own_secret(
        self, client, admin_auth, github
    ) -> None:
        """The behavioural half of the same claim."""
        repo_id = onboard(client, admin_auth).json()["id"]
        github.repos[REPO].secrets["CUSTOMER_DEPLOY_KEY"] = "not ours"

        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast"]},
            headers=admin_auth,
        )

        written = [
            name for _, name in
            [(c[0], c[1].split(":", 1)[-1]) for c in github.calls
             if c[0] == "put_actions_secret"]
        ]
        assert written == [DEFAULT_SECRET_NAME] or written == []
        assert github.repos[REPO].secrets["CUSTOMER_DEPLOY_KEY"] == "not ours"

    def test_the_client_cannot_read_a_secret_back(self) -> None:
        """spec 12 §6: Mykronos never reads a repo secret's value, and GitHub
        makes that structural. The interface should not even offer it."""
        from mykronos.github.client import GitHubClient

        readers = [
            name
            for name in dir(GitHubClient)
            if "secret" in name.lower() and name.startswith("get")
        ]
        assert readers == []


class TestRevocationIsImmediateAndLocal:
    """spec 12 §8: revoking one repo's capability stops that repo/capability
    pair writing, immediately, without touching any other repo."""

    def test_revoking_a_grant_stops_writes_at_once(self, client, admin_auth) -> None:
        onboard(client, admin_auth)
        token = issue_token(client, REPO, "sast")
        auth = {"Authorization": f"Bearer {token}"}

        assert post_scan(client, auth).status_code == 200

        with client.app.state.db.session() as session:
            TokenRegistry(session).revoke_grant(REPO, "sast")

        # Same token, same request, one moment later.
        assert post_scan(client, auth, scan_run_id="after").status_code == 403

    def test_revoking_one_capability_leaves_the_others(
        self, client, admin_auth
    ) -> None:
        onboard(client, admin_auth)
        token = issue_token(client, REPO, "sast", "secrets")
        auth = {"Authorization": f"Bearer {token}"}

        with client.app.state.db.session() as session:
            TokenRegistry(session).revoke_grant(REPO, "sast")

        assert post_scan(client, auth, capability="sast").status_code == 403
        assert (
            post_scan(
                client, auth, capability="secrets", scan_run_id="s2", tool_name="gitleaks"
            ).status_code
            == 200
        )

    def test_revoking_one_repo_leaves_another(self, client, admin_auth) -> None:
        onboard(client, admin_auth)
        mine = {"Authorization": f"Bearer {issue_token(client, REPO, 'sast')}"}
        theirs_token = issue_token(client, "example-org/ledger-core", "sast")
        theirs = {"Authorization": f"Bearer {theirs_token}"}

        with client.app.state.db.session() as session:
            TokenRegistry(session).revoke_repo(REPO)

        assert post_scan(client, mine).status_code == 401
        assert (
            post_scan(
                client,
                theirs,
                repo_full_name="example-org/ledger-core",
                scan_run_id="other",
            ).status_code
            == 200
        )

    def test_a_revoked_token_cannot_be_distinguished_from_a_wrong_one(
        self, client, admin_auth
    ) -> None:
        """A caller learns only that this token does not work now — not
        whether it ever did."""
        onboard(client, admin_auth)
        token = issue_token(client, REPO, "sast")
        with client.app.state.db.session() as session:
            TokenRegistry(session).revoke_repo(REPO)

        revoked = post_scan(client, {"Authorization": f"Bearer {token}"})
        nonsense = post_scan(client, {"Authorization": "Bearer never-existed"})

        assert revoked.status_code == nonsense.status_code == 401
        assert revoked.json() == nonsense.json()


class TestEveryPrivilegedActionIsLogged:
    """spec 12 §8: an audit entry for every RiskDecision override and every
    capability enable/disable."""

    def _actions(self, client) -> list[str]:
        with client.app.state.db.session() as session:
            return [row.action for row in session.query(AuditLogEntry).all()]

    def test_enabling_a_capability_is_logged(self, client, admin_auth) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]

        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast"]},
            headers=admin_auth,
        )

        assert any("capabilit" in a for a in self._actions(client))

    def test_disabling_a_capability_is_logged(self, client, admin_auth) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]
        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast"]},
            headers=admin_auth,
        )
        before = len(self._actions(client))

        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": []},
            headers=admin_auth,
        )

        assert len(self._actions(client)) > before

    def test_an_override_is_logged(
        self, client, admin_auth, run_compaction, catalog
    ) -> None:
        from tests.conftest import finding_payload, post_findings

        onboard(client, admin_auth)
        auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'sast', 'oracle')}"}
        post_scan(client, auth)
        post_findings(client, auth, [finding_payload()])
        run_compaction()

        decision_id = client.post(
            "/api/oracle/evaluate",
            json={"decision_type": "pr_gate", "commit_sha": "abc", "pr_number": 1},
            headers=auth,
        ).json()["decision_id"]
        run_compaction()

        client.post(
            f"/api/oracle/decisions/{decision_id}/override",
            json={"reason": "vendored fixture"},
            headers=admin_auth,
        )

        assert "oracle.override" in self._actions(client)

    def test_the_log_records_who_and_why(
        self, client, admin_auth, run_compaction
    ) -> None:
        """An audit entry with no actor and no reason records that something
        happened, which is the least useful thing an audit log can say."""
        from tests.conftest import finding_payload, post_findings

        onboard(client, admin_auth)
        auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'sast', 'oracle')}"}
        post_scan(client, auth)
        post_findings(client, auth, [finding_payload()])
        run_compaction()
        decision_id = client.post(
            "/api/oracle/evaluate",
            json={"decision_type": "pr_gate", "commit_sha": "abc", "pr_number": 1},
            headers=auth,
        ).json()["decision_id"]
        run_compaction()
        client.post(
            f"/api/oracle/decisions/{decision_id}/override",
            json={"reason": "the finding is in a vendored fixture"},
            headers=admin_auth,
        )

        with client.app.state.db.session() as session:
            entry = (
                session.query(AuditLogEntry)
                .filter(AuditLogEntry.action == "oracle.override")
                .one()
            )

        assert entry.actor
        assert "vendored fixture" in str(entry.detail)


class TestTheAdminApiFailsClosed:
    """Not in §8's list, but the property the rest of it rests on: an
    unconfigured deployment must be unusable rather than open."""

    def test_no_admin_token_means_503_not_200(self, tmp_path) -> None:
        from fastapi.testclient import TestClient

        from mykronos.config import Settings
        from mykronos.main import create_app

        settings = Settings(
            datalake_dir=tmp_path / "lake",
            database_url=f"sqlite:///{(tmp_path / 'x.db').as_posix()}",
            run_compaction_in_background=False,
            run_jobs_in_background=False,
            admin_token="",
            viewer_token="",
            gate_token="",
        )

        with TestClient(create_app(settings)) as client:
            response = client.get("/api/dashboard/portfolio")

        assert response.status_code == 503
        assert "no token configured" in response.json()["detail"].lower()

    def test_no_webhook_secret_means_rejection_not_trust(self, tmp_path) -> None:
        """Without it there is no way to tell GitHub from anyone who found
        the URL, and this endpoint can flip repos to active."""
        from fastapi.testclient import TestClient

        from mykronos.config import Settings
        from mykronos.main import create_app

        settings = Settings(
            datalake_dir=tmp_path / "lake",
            database_url=f"sqlite:///{(tmp_path / 'y.db').as_posix()}",
            run_compaction_in_background=False,
            run_jobs_in_background=False,
            admin_token="a",
            github_webhook_secret="",
            gate_token="",
        )

        with TestClient(create_app(settings)) as client:
            response = client.post("/webhooks/github", json={"action": "created"})

        assert response.status_code == 503
