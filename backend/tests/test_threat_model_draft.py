"""A threat model drafted from MyKronos's evidence, landing as pull requests
(TheHub #60899 and #60900, epic #60881).

The acceptance criteria, each a test that reads as its statement:

- M1: a draft validates against the strict schema; every element cites
  evidence.
- M2: a draft arrives as a pull request; drift opens a pull request.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient
from sqlalchemy import select

from mykronos import threat_model_draft as tmd
from mykronos import threat_model_pr as tpr
from mykronos.db.models import AuditLogEntry, PublicEndpoint
from mykronos.github import FakeGitHubClient
from mykronos.github.client import GitHubError
from mykronos.threat_model_manifest import MANIFEST_PATH, parse_manifest
from tests.conftest import REPO, issue_token, post_findings, post_scan
from tests.test_onboarding import onboard

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 10, 22, 12, 0, 0)

COMPOSE = """\
services:
  backend:
    image: localhost:5000/shop-backend:abc123
    build:
      context: backend
      dockerfile: Dockerfile
    ports:
      - "127.0.0.1:8000:8000"
  demo:
    image: shop-demo:latest
    ports:
      - "8002:8002"
  db:
    image: postgres:16
"""


def _bundle(**overrides: Any) -> tmd.EvidenceBundle:
    values: dict[str, Any] = {
        "repo_full_name": REPO,
        "endpoints": [
            {
                "url": "https://shop.example.net/",
                "label": "shop",
                "last_status": "gated",
                "last_probed_at": NOW,
            }
        ],
        "findings": [
            {
                "finding_id": "f-xss",
                "capability": "dast",
                "rule_id": "40012",
                "title": "Cross Site Scripting (Reflected)",
                "severity": "high",
                "file_path": "/search",
                "raw_finding_json": json.dumps(
                    {"instance": {"uri": "https://shop.example.net/search?q=1"}}
                ),
                "cwe_ids_json": json.dumps(["CWE-79"]),
            },
            {
                "finding_id": "f-sqli",
                "capability": "sast",
                "rule_id": "py/sql-injection",
                "title": "SQL injection",
                "severity": "critical",
                "file_path": "backend/app/orders.py",
                "raw_finding_json": "{}",
                "cwe_ids_json": json.dumps(["CWE-89"]),
            },
            {
                "finding_id": "f-os",
                "capability": "containers",
                "rule_id": "CVE-2026-0001",
                "title": "openssl flaw",
                "severity": "medium",
                "file_path": "shop-backend",
                "raw_finding_json": json.dumps({"image": "localhost:5000/shop-backend:abc123"}),
                "cwe_ids_json": None,
            },
            {
                "finding_id": "f-orphan",
                "capability": "containers",
                "rule_id": "CVE-2026-0002",
                "title": "busybox flaw",
                "severity": "low",
                "file_path": "orphan-tool",
                "raw_finding_json": json.dumps({"image": "orphan-tool:1.0"}),
                "cwe_ids_json": None,
            },
        ],
        "observations": [
            {
                "subject": "shop.example.net",
                "assertion": "anonymous_401",
                "state": "pass",
                "vantage": "internet",
                "tool": "exposure-probe",
                "collected_at": NOW,
                "raw_ref": "",
            },
            {
                "subject": "shop.example.net",
                "assertion": "header_csp",
                "state": "fail",
                "vantage": "internet",
                "tool": "exposure-probe",
                "collected_at": NOW,
                "raw_ref": "",
            },
            {
                "subject": "10.0.0.5:8002",
                "assertion": "port_published",
                "state": "pass",
                "vantage": "lan",
                "tool": "nmap",
                "collected_at": NOW,
                "raw_ref": "",
            },
            {
                "subject": "10.0.0.5:8000",
                "assertion": "bound_loopback",
                "state": "pass",
                "vantage": "host",
                "tool": "host-collector",
                "collected_at": NOW,
                "raw_ref": "",
            },
        ],
        "sbom": [{"ecosystem": "pypi", "components": 41, "observed_at": NOW}],
        "tree": [
            "README.md",
            "docker-compose.yml",
            "backend/Dockerfile",
            "backend/pyproject.toml",
            "backend/app/orders.py",
            "node_modules/x/package.json",
        ],
        "compose": {"docker-compose.yml": COMPOSE},
    }
    values.update(overrides)
    return tmd.EvidenceBundle(**values)


def _ids(draft: tmd.Draft, section: str) -> list[str]:
    return [e.id for e in draft.elements if e.section == section]


# --------------------------------------------------------------------------
# M1: drafting
# --------------------------------------------------------------------------


class TestDraft:
    def test_a_draft_validates_against_the_strict_schema(self) -> None:
        draft = tmd.draft(_bundle(), now=NOW)

        state = parse_manifest(draft.render())

        assert state.state == "valid", state.error
        assert state.manifest is not None
        # And the model built directly is the same strict schema.
        assert draft.manifest().model_dump() == state.manifest.model_dump()
        for section in ("assets", "entry_points", "trust_boundaries", "controls"):
            assert getattr(state.manifest, section), f"{section} is empty"

    def test_every_element_cites_evidence(self) -> None:
        draft = tmd.draft(_bundle(), now=NOW)

        assert draft.elements
        for element in draft.elements:
            assert element.evidence, element.id
            ref = element.body["evidence_ref"]
            assert tmd.citable(ref), (element.id, ref)
            assert ref in {e.ref for e in element.evidence}, element.id
            # The rendered file carries the evidence beside the element.
            assert "# evidence (" in tmd.render_element(element)

    def test_entry_points_come_from_endpoints_dast_and_compose(self) -> None:
        draft = tmd.draft(_bundle(), now=NOW)
        entries = {e.id: e for e in draft.section("entry_points")}

        web = entries["ep-shop.example.net"]
        assert web.body["exposure"] == "internet"
        assert web.body["selectors"] == {"hostnames": ["shop.example.net"]}
        assert {e.source for e in web.evidence} == {"exposure", "dast"}
        assert any("/search" in e.detail for e in web.evidence)

        loopback = entries["ep-backend-8000"]
        assert loopback.body["exposure"] == "local"
        assert loopback.body["evidence_ref"] == "docker-compose.yml"
        lan = entries["ep-demo-8002"]
        assert lan.body["exposure"] == "internal"
        assert lan.body["selectors"]["addresses"] == ["*:8002"]
        assert any(e.source == "observation" for e in lan.evidence)

    def test_boundaries_come_from_exposure(self) -> None:
        draft = tmd.draft(_bundle(), now=NOW)
        boundaries = {e.id: e for e in draft.section("trust_boundaries")}

        assert boundaries["tb-internet-edge"].body["selectors"] == {
            "hostnames": ["shop.example.net"]
        }
        # Only the port published on every interface crosses the host edge.
        assert boundaries["tb-host-network"].body["selectors"] == {"addresses": ["*:8002"]}

    def test_assets_come_from_images_sbom_and_iac(self) -> None:
        draft = tmd.draft(_bundle(), now=NOW)
        assets = {e.id: e for e in draft.section("assets")}

        backend = assets["img-shop-backend"]
        assert backend.body["selectors"] == {"images": ["shop-backend"]}
        # The image's own Dockerfile is the citation, and the containers lane
        # is evidence beside it.
        assert backend.body["evidence_ref"] == "backend/Dockerfile"
        assert {e.source for e in backend.evidence} == {"compose", "containers"}
        assert "img-postgres" in assets

        deps = assets["deps-pypi"]
        assert deps.body["selectors"] == {"paths": ["backend/pyproject.toml"]}
        assert any("41 pypi" in e.detail for e in deps.evidence)

        iac = assets["iac-definitions"]
        assert iac.body["selectors"]["paths"] == ["backend/Dockerfile", "docker-compose.yml"]

    def test_controls_are_observations_that_hold(self) -> None:
        draft = tmd.draft(_bundle(), now=NOW)
        controls = {e.id: e.body for e in draft.section("controls")}

        gate = controls["ctl-anonymous_401-ep-shop.example.net"]
        assert gate["kind"] == "perimeter_gate"
        assert gate["applies_to"] == "ep-shop.example.net"
        assert gate["evidence_ref"] == "https://shop.example.net/"
        segmentation = controls["ctl-bound_loopback-ep-backend-8000"]
        assert segmentation["kind"] == "network_segmentation"
        assert segmentation["applies_to"] == "ep-backend-8000"
        # A header that failed is not a control.
        assert not any(c["kind"] == "security_headers" for c in controls.values())

    def test_findings_map_cwe_to_stride_and_land_in_elements(self) -> None:
        draft = tmd.draft(_bundle(), now=NOW)
        by_weakness = {t.weakness: t for t in draft.threats}

        xss = by_weakness["CWE-79"]
        assert xss.resolution == "cwe"
        assert set(xss.stride) == {"tampering", "spoofing"}
        assert xss.element_id == "ep-shop.example.net"

        sqli = by_weakness["CWE-89"]
        assert set(sqli.stride) == {"tampering", "information_disclosure"}
        assert sqli.element_id is None
        assert sqli.ref == "backend/app/orders.py"
        rendered = draft.render()
        assert "CWE-89" in rendered.split("# Threats no drafted element covers")[1]
        # A threat in an element is rendered above that element.
        web = draft.element("ep-shop.example.net")
        assert web is not None
        assert "# threat (" in tmd.render_element(web, draft)

        container = next(t for t in draft.threats if t.capability == "containers")
        assert container.resolution == "capability"

    def test_a_candidate_with_nothing_citable_is_not_drafted(self) -> None:
        draft = tmd.draft(_bundle(), now=NOW)

        assert "img-orphan-tool" not in _ids(draft, "assets")
        labels = [label for label, _ in draft.uncited]
        assert "container image library/orphan-tool" in labels or any(
            "orphan-tool" in label for label in labels
        )
        assert "orphan-tool" in draft.render().split("Seen but not drafted")[1]

    def test_a_source_that_could_not_be_read_is_named(self) -> None:
        draft = tmd.draft(_bundle(tree=None, compose=None), now=NOW)

        assert draft.unread == ["tree", "compose"]
        assert "Not read while drafting" in draft.render()
        assert parse_manifest(draft.render()).state == "valid"

    def test_an_empty_bundle_drafts_a_valid_empty_file(self) -> None:
        draft = tmd.draft(tmd.EvidenceBundle(repo_full_name=REPO), now=NOW)

        state = parse_manifest(draft.render())
        assert state.state == "valid", state.error
        assert draft.elements == []

    def test_compose_ports(self) -> None:
        text = """\
services:
  a:
    ports: ["127.0.0.1:5432:5432", "8080:80", "9000", "${PORT}:80", "[::1]:7000:7000/tcp"]
  b:
    ports:
      - target: 443
        published: "8443"
        host_ip: 0.0.0.0
"""
        found = [(p.service, p.host_ip, p.host_port) for p in tmd.compose_ports("c.yml", text)]

        assert found == [
            ("a", "127.0.0.1", 5432),
            ("a", "", 8080),
            ("a", "::1", 7000),
            ("b", "0.0.0.0", 8443),
        ]


# --------------------------------------------------------------------------
# M2: pull requests
# --------------------------------------------------------------------------


def _github(manifest: str | None = None) -> FakeGitHubClient:
    github = FakeGitHubClient()
    files = {"README.md": "# shop"}
    if manifest is not None:
        files[MANIFEST_PATH] = manifest
    github.add_repo(REPO, files=files)
    return github


def _propose(github: FakeGitHubClient, draft: tmd.Draft) -> tpr.Proposal:
    return asyncio.run(tpr.propose(github, REPO, "main", draft, now=NOW))


def _branch_file(github: FakeGitHubClient, proposal: tpr.Proposal) -> str:
    assert proposal.pull_request is not None
    return github.repos[REPO].branches[proposal.pull_request.head_branch][MANIFEST_PATH]


DECLARED = """\
# Declared by the team. This comment must survive a drift PR.
version: 1

assets:
  - id: orders-db
    name: Orders database
    exposure: local
    evidence_ref: docker-compose.yml
    selectors:
      images: ["postgres"]

entry_points:
  - id: public-shop
    name: The shop
    exposure: internet
    evidence_ref: https://shop.example.net/
    selectors:
      hostnames: ["shop.example.net"]

# Controls a person reviewed.
controls:
  - id: gate
    kind: perimeter_gate
    evidence_ref: frontend/proxy.ts
    applies_to: public-shop
"""


# Every line break YAML recognises (1.1 adds NEL, LS and PS to CR and LF), and
# the C0/C1 controls a YAML reader refuses outright.
_YAML_BREAKS = ["\r", "\n", "\x85", chr(0x2028), chr(0x2029)]
_YAML_UNSAFE = (
    [chr(c) for c in range(0x20) if c != 0x0A]
    + [chr(c) for c in range(0x7F, 0xA0)]
    + [chr(0x2028), chr(0x2029), chr(0xFEFF)]
)


class TestCommentInjection:
    """#1008 review: record text rendered into `#` comments must not be able
    to end the comment and add keys to the committed file."""

    @pytest.mark.parametrize("brk", _YAML_BREAKS)
    def test_one_line_strips_every_yaml_line_break(self, brk: str) -> None:
        flat = tmd._one_line(f"title{brk}injected: 1")

        assert yaml.safe_load(f"a: 1\n# c {flat}\n") == {"a": 1}

    def test_one_line_strips_c0_and_c1_controls(self) -> None:
        flat = tmd._one_line("a" + "".join(_YAML_UNSAFE) + "b")

        assert not any(ch in flat for ch in _YAML_UNSAFE)
        assert flat.startswith("a") and flat.endswith("b")

    @pytest.mark.parametrize("brk", ["\x85", chr(0x2028), chr(0x2029), "\r"])
    def test_crafted_records_cannot_add_keys_to_the_draft(self, brk: str) -> None:
        payload = f"{brk}injected: 1{brk}"
        bundle = _bundle()
        assert bundle.endpoints is not None and bundle.findings is not None
        # An endpoint URL is both the evidence detail and its unsanitised ref.
        bundle.endpoints.append(
            {
                "url": f"https://shop.example.net/x{payload}",
                "label": "crafted",
                "last_status": "gated",
                "last_probed_at": NOW,
            }
        )
        bundle.findings.append(
            {
                "finding_id": "f-crafted",
                "capability": "dast",
                "rule_id": "10020",
                "title": f"Crafted title{payload}",
                "severity": "medium",
                "file_path": "/crafted",
                "raw_finding_json": json.dumps(
                    {"instance": {"uri": f"https://shop.example.net/crafted{payload}"}}
                ),
                "cwe_ids_json": json.dumps(["CWE-79"]),
            }
        )
        text = tmd.draft(bundle, now=NOW).render()

        assert not any(ch in text for ch in _YAML_UNSAFE)
        loaded = yaml.safe_load(text)
        assert "injected" not in loaded
        assert parse_manifest(text).state == "valid"
        # The crafted values are still shown, flattened onto their comment line.
        assert any(
            line.lstrip().startswith("#") and "injected: 1" in line
            for line in text.split("\n")
        )


class TestPullRequests:
    def test_a_draft_arrives_as_a_pr(self) -> None:
        github = _github()
        draft = tmd.draft(_bundle(), now=NOW)

        proposal = _propose(github, draft)

        assert proposal.state == "opened", proposal.reason
        assert proposal.pull_request is not None
        assert proposal.pull_request.head_branch.startswith(tpr.BRANCH_PREFIX)
        assert "draft .sdlc/threat-model.yaml" in proposal.pull_request.title
        content = _branch_file(github, proposal)
        assert content == draft.render()
        assert parse_manifest(content).state == "valid"
        # The default branch is untouched: the file arrives only by merge.
        assert MANIFEST_PATH not in github.repos[REPO].branches["main"]
        body = github.pull_request_bodies[proposal.pull_request.number]
        for element in draft.elements:
            assert f"`{element.id}`" in body
        assert "| Element | Section | Evidence |" in body

    def test_drift_opens_a_pr_that_adds_only_what_is_not_covered(self) -> None:
        github = _github(DECLARED)
        draft = tmd.draft(_bundle(), now=NOW)

        proposal = _propose(github, draft)

        assert proposal.state == "opened", proposal.reason
        assert proposal.pull_request is not None
        assert "drift" in proposal.pull_request.title
        content = _branch_file(github, proposal)
        state = parse_manifest(content)
        assert state.state == "valid", state.error
        assert state.manifest is not None
        ids = {item.id for _, item in state.manifest.surfaces()}
        # Declared rows stay, untouched, and the comments a person wrote too.
        assert content.startswith(DECLARED.split("\n\n", 1)[0])
        assert "# Controls a person reviewed." in content
        declared = parse_manifest(DECLARED).manifest
        assert declared is not None
        for item in declared.entry_points:
            assert item in state.manifest.entry_points
        # The covered host and image are not proposed again.
        assert "ep-shop.example.net" not in ids
        assert "img-postgres" not in ids
        # What moved on is.
        assert {"ep-backend-8000", "ep-demo-8002", "img-shop-backend"} <= ids
        # The drafted gate is covered by the declared one on the same surface;
        # the loopback control is new, and points at the added entry point.
        controls = {c.id: c for c in state.manifest.controls}
        assert "ctl-anonymous_401-ep-shop.example.net" not in controls
        assert controls["ctl-bound_loopback-ep-backend-8000"].applies_to == "ep-backend-8000"
        body = github.pull_request_bodies[proposal.pull_request.number]
        assert "Nothing already declared is changed or removed" in body
        assert "`ep-demo-8002`" in body and "`ep-shop.example.net`" not in body

    def test_a_drifted_control_points_at_the_declared_surface(self) -> None:
        github = _github(DECLARED.replace("kind: perimeter_gate", "kind: waf"))
        draft = tmd.draft(_bundle(), now=NOW)

        content = _branch_file(github, _propose(github, draft))

        state = parse_manifest(content)
        assert state.state == "valid", state.error
        assert state.manifest is not None
        gate = next(c for c in state.manifest.controls if c.kind == "perimeter_gate")
        assert gate.applies_to == "public-shop"

    def test_no_drift_opens_nothing(self) -> None:
        draft = tmd.draft(_bundle(), now=NOW)
        github = _github(draft.render())

        proposal = _propose(github, draft)

        assert proposal.state == "no_drift"
        assert github.repos[REPO].pull_requests == []

    def test_an_invalid_declared_file_proposes_nothing(self) -> None:
        github = _github("version: 1\nassets:\n  - id: x\n    nmae: typo\n")

        proposal = _propose(github, tmd.draft(_bundle(), now=NOW))

        assert proposal.state == "invalid"
        assert github.repos[REPO].pull_requests == []

    def test_new_drift_updates_the_open_pr_rather_than_opening_another(self) -> None:
        github = _github(DECLARED)
        first = _propose(github, tmd.draft(_bundle(), now=NOW))
        assert first.state == "opened"

        again = _propose(github, tmd.draft(_bundle(), now=NOW))
        assert again.state == "unchanged"

        more = _bundle()
        assert more.endpoints is not None
        more.endpoints.append(
            {"url": "https://admin.example.net/", "last_status": "open", "label": ""}
        )
        later = _propose(github, tmd.draft(more, now=NOW))

        assert later.state == "updated"
        assert len(github.repos[REPO].pull_requests) == 1
        assert "ep-admin.example.net" in _branch_file(github, first)

    def test_drift_merges_into_this_repositorys_own_threat_model(self) -> None:
        declared = (ROOT / MANIFEST_PATH).read_text(encoding="utf-8")
        assert parse_manifest(declared).state == "valid"
        github = _github(declared)
        bundle = _bundle(
            endpoints=[
                {"url": "https://brand-new.example.net/", "last_status": "open", "label": ""}
            ]
        )

        proposal = _propose(github, tmd.draft(bundle, now=NOW))

        assert proposal.state == "opened", proposal.reason
        content = _branch_file(github, proposal)
        state = parse_manifest(content)
        assert state.state == "valid", state.error
        assert content.startswith(declared.rstrip("\n").split("\nversion: 1", 1)[0])
        assert "ep-brand-new.example.net" in content


# --------------------------------------------------------------------------
# API
# --------------------------------------------------------------------------


def _repo_id(client: TestClient, admin_auth: dict[str, str]) -> str:
    return client.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"][0][
        "repo_id"
    ]


def _seed(client: TestClient, admin_auth: dict[str, str]) -> str:
    onboard(client, admin_auth, scanned_by="concourse")
    token = issue_token(client, REPO, "dast")
    auth = {"Authorization": f"Bearer {token}"}
    scan_id = "22222222-2222-2222-2222-222222222222"
    assert post_scan(
        client, auth, scan_run_id=scan_id, capability="dast", tool_name="zap", pr_number=None,
        triggered_by="schedule",
    ).status_code in (200, 201)
    r = post_findings(
        client,
        auth,
        [
            {
                "rule_id": "40012",
                "title": "Cross Site Scripting (Reflected)",
                "severity": "high",
                "file_path": "/search",
                "raw_finding_json": {
                    "instance": {"uri": "https://shop.example.net/search"},
                    "cweid": "79",
                },
            }
        ],
        scan_run_id=scan_id,
        capability="dast",
    )
    assert r.status_code in (200, 201, 202), r.text
    client.app.state.catalog  # noqa: B018 - the app's lake
    from mykronos.lake import compact

    compact(client.app.state.catalog, client.app.state.buffer)
    with client.app.state.db.session() as session:
        session.add(
            PublicEndpoint(url="https://shop.example.net/", repo_full_name=REPO, label="shop")
        )
    return _repo_id(client, admin_auth)


class TestApi:
    def test_the_draft_route_drafts_from_the_stores(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        repo_id = _seed(client, admin_auth)

        r = client.get(f"/api/dashboard/repos/{repo_id}/threat-model/draft", headers=admin_auth)

        assert r.status_code == 200, r.text
        out = r.json()
        assert parse_manifest(out["yaml"]).state == "valid"
        web = next(e for e in out["elements"] if e["id"] == "ep-shop.example.net")
        assert web["body"]["exposure"] == "internet"
        assert {e["source"] for e in web["evidence"]} == {"exposure", "dast"}
        assert out["unread"] == []

    def test_proposing_opens_a_pr_and_is_audited(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient
    ) -> None:
        repo_id = _seed(client, admin_auth)

        r = client.post(
            f"/api/dashboard/repos/{repo_id}/threat-model/draft/pull-request",
            headers=admin_auth,
        )

        assert r.status_code == 200, r.text
        out = r.json()
        assert out["state"] == "opened", out
        assert out["added"]["entry_points"] >= 1
        pr = github.repos[REPO].pull_requests[-1]
        assert pr.head_branch.startswith(tpr.BRANCH_PREFIX)
        assert parse_manifest(github.repos[REPO].branches[pr.head_branch][MANIFEST_PATH]).state == (
            "valid"
        )
        with client.app.state.db.session() as session:
            audit = session.scalars(
                select(AuditLogEntry).where(AuditLogEntry.action == "threat_model.propose")
            ).all()
        assert len(audit) == 1

    def test_a_viewer_cannot_propose(
        self, client: TestClient, admin_auth: dict[str, str], viewer_auth: dict[str, str]
    ) -> None:
        repo_id = _seed(client, admin_auth)

        r = client.post(
            f"/api/dashboard/repos/{repo_id}/threat-model/draft/pull-request",
            headers=viewer_auth,
        )

        assert r.status_code == 403


# --------------------------------------------------------------------------
# Rework of #1008 after review
# --------------------------------------------------------------------------

#: Every call that writes to the target repository.
_WRITES = {"create_branch", "commit_files", "create_pull_request", "update_pull_request"}


def _writes(github: FakeGitHubClient) -> list[tuple[str, str]]:
    return [c for c in github.calls if c[0] in _WRITES]


class TestVisibility:
    """[High] Threat and evidence detail is written only to a repository
    GitHub says is private. Public, internal, unreported or unreadable
    visibility writes nothing: no branch, no file, no body."""

    @pytest.mark.parametrize("visibility", ["public", "internal", None])
    def test_a_repository_not_known_private_gets_nothing_written(
        self, visibility: str | None
    ) -> None:
        github = _github()
        github.repos[REPO].visibility = visibility  # type: ignore[attr-defined]

        proposal = _propose(github, tmd.draft(_bundle(), now=NOW))

        assert proposal.state == "refused", proposal
        assert _writes(github) == []
        assert github.pull_request_bodies == {}
        assert list(github.repos[REPO].branches) == ["main"]
        # The reason names no host, address or finding.
        assert "example.net" not in proposal.reason

    def test_unreadable_visibility_writes_nothing(self) -> None:
        github = _github()

        async def broken(repo_full_name: str) -> dict[str, Any]:
            raise GitHubError("boom", status=502)

        github.get_repo = broken  # type: ignore[method-assign]

        proposal = _propose(github, tmd.draft(_bundle(), now=NOW))

        assert proposal.state == "refused"
        assert _writes(github) == []

    def test_a_repository_made_public_keeps_its_open_proposal_unchanged(self) -> None:
        github = _github(DECLARED)
        first = _propose(github, tmd.draft(_bundle(), now=NOW))
        assert first.state == "opened", first.reason
        held = _branch_file(github, first)
        github.repos[REPO].visibility = "public"  # type: ignore[attr-defined]
        github.calls.clear()
        more = _bundle()
        assert more.endpoints is not None
        more.endpoints.append(
            {"url": "https://admin.example.net/", "last_status": "open", "label": ""}
        )

        later = _propose(github, tmd.draft(more, now=NOW))

        assert later.state == "refused"
        assert _writes(github) == []
        assert _branch_file(github, first) == held

    def test_the_route_refuses_a_public_repository(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient
    ) -> None:
        repo_id = _seed(client, admin_auth)
        github.repos[REPO].visibility = "public"  # type: ignore[attr-defined]
        github.calls.clear()

        r = client.post(
            f"/api/dashboard/repos/{repo_id}/threat-model/draft/pull-request",
            headers=admin_auth,
        )

        assert r.status_code == 200, r.text
        assert r.json()["state"] == "refused"
        assert _writes(github) == []
        assert github.repos[REPO].pull_requests == []


class TestReviewerEdits:
    """[Medium] A person's edits on the proposal branch are never overwritten
    by a later run."""

    def test_reviewer_edits_on_the_branch_are_kept(self) -> None:
        github = _github(DECLARED)
        first = _propose(github, tmd.draft(_bundle(), now=NOW))
        assert first.state == "opened", first.reason
        assert first.pull_request is not None
        branch = first.pull_request.head_branch
        edited = _branch_file(github, first) + "# Reviewed: the demo port is retired." + chr(10)
        github.repos[REPO].branches[branch][MANIFEST_PATH] = edited
        github.calls.clear()
        more = _bundle()
        assert more.endpoints is not None
        more.endpoints.append(
            {"url": "https://admin.example.net/", "last_status": "open", "label": ""}
        )

        later = _propose(github, tmd.draft(more, now=NOW))

        assert later.state == "kept", later
        assert github.repos[REPO].branches[branch][MANIFEST_PATH] == edited
        assert [c for c in github.calls if c[0] == "commit_files"] == []

    def test_an_unedited_proposal_is_still_updated(self) -> None:
        github = _github(DECLARED)
        first = _propose(github, tmd.draft(_bundle(), now=NOW))
        assert first.state == "opened", first.reason
        more = _bundle()
        assert more.endpoints is not None
        more.endpoints.append(
            {"url": "https://admin.example.net/", "last_status": "open", "label": ""}
        )

        later = _propose(github, tmd.draft(more, now=NOW))

        assert later.state == "updated", later
        assert "ep-admin.example.net" in _branch_file(github, first)


class _Rows:
    def __init__(self, rows: list[Any]) -> None:
        self.rows = rows

    def __enter__(self) -> _Rows:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def scalars(self, _query: Any) -> list[Any]:
        return self.rows


class TestSweep:
    """[Low] A repository with no GitHub installation is skipped, never handed
    to `for_installation(None)`."""

    def test_no_installation_is_skipped_not_passed_as_none(self) -> None:
        from types import SimpleNamespace

        row = SimpleNamespace(
            github_repo_full_name=REPO, default_branch="main", github_installation_id=None
        )
        db = SimpleNamespace(session=lambda: _Rows([row]))
        asked: list[Any] = []

        class Factory:
            def for_installation(self, installation_id: int) -> FakeGitHubClient:
                asked.append(installation_id)
                if installation_id is None:
                    raise TypeError("installation_id is None")
                return _github()

        result = asyncio.run(tpr.sweep(db, None, Factory()))

        assert asked == []
        assert [p.state for p in result.proposals] == ["unreadable"]
