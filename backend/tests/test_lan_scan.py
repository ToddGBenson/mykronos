"""The LAN nmap wrapper (TheHub #60826) and the boundary around it (spec 14 §3).

Two halves. The refusals: no explicit ranges, no authorization reference, or a
public range without acknowledgement, and nmap is never started. The results:
the XML goes up through the existing `network` capability exactly as any nmap
upload does, and each open port also becomes one `port_published`
observation from the `lan` vantage.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from mykronos import lan_scan
from mykronos.upload import IngestionClient

DATA = Path(__file__).parent / "data" / "control_observations"
XML = (DATA / "nmap_lan.xml").read_text(encoding="utf-8")
TARGETS = ["192.168.0.14/32", "192.168.0.20/32"]


class RecordingClient(IngestionClient):
    def __init__(self) -> None:
        super().__init__("https://mykronos.test", "token")
        self.calls: list[tuple[str, dict[str, Any] | None, dict[str, Any] | None]] = []

    def post(
        self,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        content: bytes | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.calls.append((path, json_body, params))
        if path == "/api/ingest/raw":
            return {"raw_output_ref": "raw/o/lab/run/nmap.xml"}
        if path == "/api/ingest/control-observations":
            return {"accepted": len((json_body or {}).get("observations", []))}
        return {"accepted": len((json_body or {}).get("findings", []))}

    def bodies_for(self, path: str) -> list[dict[str, Any]]:
        return [c[1] for c in self.calls if c[0] == path and c[1] is not None]


class FakeNmap:
    """Stands in for subprocess.run: writes the fixture where -oX points."""

    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    def __call__(self, command: list[str], **kwargs: Any) -> Any:
        self.commands.append(command)
        out = Path(command[command.index("-oX") + 1])
        out.write_text(XML, encoding="utf-8")

        class Done:
            returncode = 0
            stdout = ""
            stderr = ""

        return Done()


def _argv(tmp_path: Path, *extra: str, cidrs: list[str] | None = None) -> list[str]:
    argv = [
        "--ingestion-url",
        "https://mykronos.test",
        "--token",
        "tok",
        "--repo",
        "o/lab",
        "--output-dir",
        str(tmp_path),
    ]
    for cidr in TARGETS if cidrs is None else cidrs:
        argv += ["--cidr", cidr]
    return argv + list(extra)


def _run(tmp_path: Path, *extra: str, cidrs: list[str] | None = None):
    nmap = FakeNmap()
    client = RecordingClient()
    code = lan_scan.main(
        _argv(tmp_path, *extra, cidrs=cidrs),
        runner=nmap,
        client=client,
        which=lambda _name: "C:/nmap/nmap.exe",
        self_addresses=frozenset,
    )
    return code, nmap, client


class TestRefusals:
    def test_no_ranges_is_refused_and_nothing_runs(self, tmp_path: Path) -> None:
        code, nmap, client = _run(tmp_path, "--authorization-reference", "me", cidrs=[])
        assert code == lan_scan.EXIT_REFUSED
        assert nmap.commands == [] and client.calls == []

    def test_no_authorization_reference_is_refused(self, tmp_path: Path) -> None:
        code, nmap, _ = _run(tmp_path)
        assert code == lan_scan.EXIT_REFUSED
        assert nmap.commands == []

    def test_a_blank_authorization_reference_is_refused(self, tmp_path: Path) -> None:
        code, nmap, _ = _run(tmp_path, "--authorization-reference", "   ")
        assert code == lan_scan.EXIT_REFUSED and nmap.commands == []

    def test_a_public_range_needs_acknowledgement(self, tmp_path: Path) -> None:
        code, nmap, _ = _run(
            tmp_path, "--authorization-reference", "me", cidrs=["93.184.215.0/30"]
        )
        assert code == lan_scan.EXIT_REFUSED and nmap.commands == []

    def test_a_malformed_range_is_refused(self, tmp_path: Path) -> None:
        code, nmap, _ = _run(tmp_path, "--authorization-reference", "me", cidrs=["lab-host"])
        assert code == lan_scan.EXIT_REFUSED and nmap.commands == []

    def test_no_nmap_is_an_error_not_a_clean_run(self, tmp_path: Path) -> None:
        client = RecordingClient()
        code = lan_scan.main(
            _argv(tmp_path, "--authorization-reference", "me"),
            runner=FakeNmap(),
            client=client,
            which=lambda _name: None,
            self_addresses=frozenset,
        )
        assert code == lan_scan.EXIT_FAILED and client.calls == []


class TestTheScan:
    def test_the_command_is_the_named_one_against_only_the_listed_hosts(
        self, tmp_path: Path
    ) -> None:
        code, nmap, _ = _run(tmp_path, "--authorization-reference", "CHG-1 Todd 2026-10-17")
        assert code == 0
        (command,) = nmap.commands
        assert command[1:4] == ["-sV", "--top-ports", "1000"]
        assert command[-2:] == TARGETS
        assert "--max-rate" in command

    def test_the_xml_goes_up_through_the_network_capability(self, tmp_path: Path) -> None:
        _, _, client = _run(tmp_path, "--authorization-reference", "me")
        (scan_run, *_) = client.bodies_for("/api/ingest/scan-run")
        assert scan_run["capability"] == "network"
        assert scan_run["tool_name"] == "nmap"
        findings = [f for b in client.bodies_for("/api/ingest/findings") for f in b["findings"]]
        assert {(f["address"], f["port"]) for f in findings} == {
            ("192.168.0.14", 8002),
            ("192.168.0.14", 3389),
        }

    def test_one_observation_per_open_port_from_the_lan(self, tmp_path: Path) -> None:
        _, _, client = _run(tmp_path, "--authorization-reference", "CHG-1")
        (batch,) = client.bodies_for("/api/ingest/control-observations")

        published = [o for o in batch["observations"] if o["state"] == "pass"]
        assert {o["subject"] for o in published} == {"192.168.0.14:8002", "192.168.0.14:3389"}
        assert {o["assertion"] for o in published} == {"port_published"}
        assert {o["vantage"] for o in batch["observations"]} == {"lan"}
        assert {o["raw_ref"] for o in published} == {"raw/o/lab/run/nmap.xml"}
        assert {o["tool_version"] for o in published} == {"7.95"}
        assert batch["run_context"]["authorization_reference"] == "CHG-1"
        assert batch["run_context"]["cidr_ranges"] == TARGETS

    def test_a_listed_host_with_nothing_open_is_unknown_not_silent(
        self, tmp_path: Path
    ) -> None:
        _, _, client = _run(tmp_path, "--authorization-reference", "CHG-1")
        (batch,) = client.bodies_for("/api/ingest/control-observations")
        unknown = [o for o in batch["observations"] if o["state"] != "pass"]
        assert [(o["subject"], o["state"]) for o in unknown] == [("192.168.0.20/32", "unknown")]


@pytest.mark.parametrize(
    "xml",
    ["", "<nmaprun", '<?xml version="1.0"?><nmaprun version="7.95"></nmaprun>'],
)
def test_xml_that_resolves_nothing_is_unknown_per_target(xml: str) -> None:
    observed = lan_scan.observations_from_xml(xml, TARGETS, raw_ref="", collected_at="x")
    assert [o["state"] for o in observed] == ["unknown", "unknown"]


def test_a_port_this_host_found_on_itself_is_host_vantage() -> None:
    """Windows does not filter host-to-self traffic: scanning loopback or this
    machine's own address shows what listens, not what the LAN reaches."""
    observed = lan_scan.observations_from_xml(
        XML, TARGETS, raw_ref="", collected_at="x", self_addresses=frozenset({"192.168.0.14"})
    )
    published = [o for o in observed if o["state"] == "pass"]
    assert {o["vantage"] for o in published} == {"host"}
