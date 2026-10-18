"""Which declared surface a finding is in (TheHub #60825).

Every finding below is what a real adapter produced from a real report shape
(the fixtures the adapter tests already hold), not a hand-built dict: the
selector matcher is only right if it reads the field each adapter actually
writes, and the way to know that is to run the adapter.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from mykronos.adapters import atlas_grype
from mykronos.adapters.base import ScanContext
from mykronos.adapters.containers_trivy import normalize as trivy_normalize
from mykronos.adapters.dast_zap import normalize as zap_normalize
from mykronos.adapters.network_nmap import normalize as nmap_normalize
from mykronos.adapters.sast_codeql import normalize as codeql_normalize
from mykronos.surface_match import (
    SelectorError,
    glob_match,
    matches,
    normalize_selectors,
    surface_for,
    validate_requirement,
)
from tests.test_adapters import sarif
from tests.test_adapters_phase2 import zap_report
from tests.test_network_adapter import NMAP

DATA = Path(__file__).parent / "data"


@dataclass
class S:
    """A surface: what `surface_for` needs of one, and nothing else."""

    name: str
    selectors: dict[str, Any] = field(default_factory=dict)
    kind: str = "asset"
    id: str = ""

    def __post_init__(self) -> None:
        self.id = self.id or self.name
        self.selectors = normalize_selectors(self.selectors)


def ctx(capability: str, tool: str = "t", workspace: Path | None = None) -> ScanContext:
    return ScanContext(
        repo_full_name="example-org/payments-api",
        capability=capability,
        tool_name=tool,
        tool_version="1",
        commit_sha="a" * 40,
        branch="main",
        workspace=workspace,
    )


# --------------------------------------------------------------------------
# One per capability, from the adapter's own output
# --------------------------------------------------------------------------


class TestSastByPath:
    def _finding(self, uri: str) -> Any:
        return codeql_normalize(sarif(uri=uri), ctx("sast", "codeql")).findings[0]

    def test_a_codeql_finding_lands_in_the_surface_that_holds_its_file(self) -> None:
        db = S("orders db", {"paths": ["orders/**"]})
        api = S("api", {"paths": ["api/**"]}, kind="entry_point")

        assert surface_for(self._finding("orders/query.py"), [api, db], capability="sast") is db

    def test_a_file_no_selector_names_is_in_nothing(self) -> None:
        """Not the closest surface: a finding placed in an asset nobody
        located it in would borrow that asset's requirements."""
        db = S("orders db", {"paths": ["orders/**"]})

        assert surface_for(self._finding("billing/run.py"), [db], capability="sast") is None

    def test_the_more_specific_glob_wins(self) -> None:
        broad = S("backend", {"paths": ["orders/**"]})
        narrow = S("queries", {"paths": ["orders/query.py"]})

        found = surface_for(self._finding("orders/query.py"), [broad, narrow], capability="sast")

        assert found is narrow


class TestScaByPath:
    def test_a_grype_finding_on_requirements_txt_lands_by_its_manifest(
        self, tmp_path: Path
    ) -> None:
        """Grype writes `/requirements.txt`; the leading slash is not a
        statement about the filesystem root."""
        (tmp_path / "requirements.txt").write_text("requests==2.0\n", encoding="utf-8")
        result = atlas_grype.normalize(
            (DATA / "grype-0.87.0-requirements.sarif").read_bytes(),
            ctx("atlas", "grype", tmp_path),
        )
        backend = S("python deps", {"paths": ["requirements.txt"]})

        assert result.findings
        assert all(
            surface_for(f, [backend], capability="atlas") is backend for f in result.findings
        )


class TestContainersByImage:
    def _findings(self) -> list[Any]:
        return trivy_normalize(
            (DATA / "trivy" / "debian10.sarif").read_bytes(), ctx("containers", "trivy")
        ).findings

    def test_a_trivy_finding_lands_by_the_image_the_adapter_stamped(self) -> None:
        """`debian:buster-slim` in the report, `library/debian` in the
        selector: the tag never decides a match."""
        image = S("base image", {"images": ["debian:bookworm"]})

        findings = self._findings()

        assert findings
        assert all(surface_for(f, [image], capability="containers") is image for f in findings)

    def test_another_image_is_not_this_one(self) -> None:
        other = S("app image", {"images": ["ghcr.io/acme/app:1.2"]})

        assert surface_for(self._findings()[0], [other], capability="containers") is None

    def test_the_file_path_is_not_read_for_a_container_finding(self) -> None:
        """Trivy puts `library/debian` in file_path for an OS package; a path
        selector that happens to spell it must not claim the finding."""
        by_path = S("lookalike", {"paths": ["library/**"]})

        assert surface_for(self._findings()[0], [by_path], capability="containers") is None

    def test_the_lake_form_with_raw_json_as_text_matches_too(self) -> None:
        finding = self._findings()[0]
        row = {
            "capability": "containers",
            "file_path": finding.file_path,
            "raw_finding_json": json.dumps(finding.raw_finding_json),
        }
        image = S("base image", {"images": ["library/debian"]})

        assert surface_for(row, [image]) is image


class TestNetworkByAddress:
    def _findings(self) -> list[Any]:
        return nmap_normalize(NMAP.encode(), ctx("network", "nmap")).findings

    def test_an_nmap_port_lands_by_address_and_port(self) -> None:
        ssh = S("lab ssh", {"addresses": ["192.168.0.14:22"]}, kind="entry_point")
        https = S("lab https", {"addresses": ["192.168.0.14:443"]}, kind="entry_point")

        by_port = {
            f.port: surface_for(f, [ssh, https], capability="network") for f in self._findings()
        }

        assert by_port == {22: ssh, 443: https}

    def test_a_wildcard_host_is_weaker_than_the_exact_one(self) -> None:
        any_ssh = S("any ssh", {"addresses": ["*:22"]})
        this_ssh = S("this ssh", {"addresses": ["192.168.0.14:22"]})
        finding = next(f for f in self._findings() if f.port == 22)

        assert surface_for(finding, [any_ssh, this_ssh], capability="network") is this_ssh
        assert [m.surface for m in matches(finding, [any_ssh, this_ssh], capability="network")] == [
            this_ssh,
            any_ssh,
        ]

    def test_the_hostname_nmap_resolved_matches_a_hostname_selector(self) -> None:
        lab = S("lab host", {"hostnames": ["lab-host"]})

        assert surface_for(self._findings()[0], [lab], capability="network") is lab

    def test_another_port_on_the_same_host_is_not_this_surface(self) -> None:
        db = S("db", {"addresses": ["192.168.0.14:5432"]})

        assert all(surface_for(f, [db], capability="network") is None for f in self._findings())


class TestDastByInstanceHost:
    def _finding(self, uri: str) -> Any:
        return zap_normalize(
            zap_report(instances=[{"uri": uri, "method": "GET"}]), ctx("dast", "zap")
        ).findings[0]

    def test_a_zap_finding_lands_by_the_host_it_probed(self) -> None:
        app = S("public app", {"hostnames": ["mykronos-app.toddbenson.net"]}, kind="entry_point")

        found = surface_for(
            self._finding("https://mykronos-app.toddbenson.net/admin"), [app], capability="dast"
        )

        assert found is app

    def test_the_route_is_never_read_as_a_path(self) -> None:
        """ZAP's file_path is the route. A source directory called `admin`
        must not claim a web finding at `/admin`."""
        source = S("admin code", {"paths": ["admin/**"]})

        found = surface_for(
            self._finding("https://staging.example.com/admin"), [source], capability="dast"
        )

        assert found is None

    def test_a_wildcard_hostname_covers_subdomains_not_the_apex(self) -> None:
        sites = S("sites", {"hostnames": ["*.example.com"]})

        sub = self._finding("https://staging.example.com/x")
        apex = self._finding("https://example.com/x")

        assert surface_for(sub, [sites], capability="dast") is sites
        assert surface_for(apex, [sites], capability="dast") is None

    def test_an_address_selector_matches_the_scheme_default_port(self) -> None:
        local = S("local stack", {"addresses": ["localhost:443"]})

        finding = self._finding("https://localhost/x")

        assert surface_for(finding, [local], capability="dast") is local


class TestTieBreak:
    def test_equally_specific_prefers_the_asset(self) -> None:
        ep = S("way in", {"paths": ["orders/**"]}, kind="entry_point")
        asset = S("orders", {"paths": ["orders/**"]}, kind="asset")
        row = {"capability": "sast", "file_path": "orders/a.py"}

        assert surface_for(row, [ep, asset]) is asset

    def test_an_unknown_capability_with_no_shape_falls_back_to_the_path(self) -> None:
        row = {"file_path": "orders/a.py"}

        assert surface_for(row, [S("orders", {"paths": ["orders/"]})]) is not None


# --------------------------------------------------------------------------
# Selector validation
# --------------------------------------------------------------------------


class TestSelectors:
    def test_every_key_is_present_after_normalising(self) -> None:
        assert normalize_selectors({}) == {
            "paths": [],
            "images": [],
            "addresses": [],
            "hostnames": [],
        }

    def test_values_are_normalised_at_the_door(self) -> None:
        out = normalize_selectors(
            {
                "paths": ["./backend/**", "/frontend/app/"],
                "images": ["postgres:15", "192.168.0.10:5000/toddgbenson/mykronos-backend:abc"],
                "addresses": ["DB.Internal:05432", "[::1]:8080", "*:22"],
                "hostnames": ["MyKronos-App.ToddBenson.net."],
            }
        )

        assert out == {
            "paths": ["backend/**", "frontend/app/"],
            "images": ["library/postgres", "toddgbenson/mykronos-backend"],
            "addresses": ["db.internal:5432", "[::1]:8080", "*:22"],
            "hostnames": ["mykronos-app.toddbenson.net"],
        }

    @pytest.mark.parametrize(
        "raw",
        [
            {"paths": ["../etc/passwd"]},
            {"paths": ["https://example.com/x"]},
            {"addresses": ["10.0.0.5"]},
            {"addresses": ["10.0.0.5:99999"]},
            {"hostnames": ["https://example.com"]},
            {"hostnames": ["example.com:443"]},
            {"images": ["https://ghcr.io/x"]},
            {"paths": "backend/**"},
            {"ports": ["22"]},
        ],
    )
    def test_a_selector_that_cannot_mean_anything_is_refused(self, raw: dict[str, Any]) -> None:
        with pytest.raises(SelectorError):
            normalize_selectors(raw)

    def test_a_pasted_listing_is_refused(self) -> None:
        with pytest.raises(SelectorError, match="at most"):
            normalize_selectors({"paths": [f"f{i}.py" for i in range(51)]})

    def test_requirements_are_h_m_l_or_unset(self) -> None:
        assert validate_requirement("h", "cr") == "H"
        assert validate_requirement(None, "cr") is None
        with pytest.raises(SelectorError, match="CR"):
            validate_requirement("X", "cr")


@pytest.mark.parametrize(
    ("pattern", "path", "expected"),
    [
        ("backend/**", "backend/mykronos/api/x.py", True),
        ("backend/**", "frontend/x.ts", False),
        ("**/*.py", "a/b/c.py", True),
        ("**/*.py", "c.py", True),
        ("*.py", "a/c.py", False),
        ("src/?.ts", "src/a.ts", True),
        ("docs/", "docs/a/b.md", True),
        ("requirements.txt", "requirements.txt", True),
    ],
)
def test_glob(pattern: str, path: str, expected: bool) -> None:
    assert glob_match(pattern, path) is expected
