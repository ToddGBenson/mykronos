"""Three scripts fetch only http(s); two more Semgrep mediums closed at source (TheHub #61512).

Semgrep's `dynamic-urllib-use-detected` (medium) was open on
`scripts/runsheet_compare.py`, `scripts/time_travel_report.py` and
`scripts/bench_run.py`. Each passed a URL taken from an argument or the
pipeline (`--api-url`, the Hub URL, the platform URL) to
`urllib.request.urlopen`, which also opens `file://`. A mistyped or planted
`file:///...` was read from disk and parsed as the server's answer: the run
sheet comparison would judge a local file, and the bench would treat one as
the platform's reply. Each now opens through an opener with only the HTTP(S)
handlers, so any other scheme raises URLError, which every caller already
handles as no answer. `test_audit_timeouts_url.py` fixed the same shape in two
other scripts with a scheme check; this is the opener form of the same guard.

The same story closes two more mediums:

- `insecure-hash-algorithm-sha1` on `deploy/demo/seed.py`: the seed's stable
  digest is SHA-256 cut to 40 hex, still a git-sha shape.
- `mykronos-jinja2-autoescape-disabled` on the installer's Jinja environment:
  the templates render YAML, so the rule's own fix (autoescape=True) would
  corrupt every workflow. It is suppressed for that one rule, on that one
  call, and the test below fails if the suppression widens or the
  environment starts escaping.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import re
import sys
import threading
import urllib.error
from argparse import Namespace
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = REPO_ROOT / "scripts"
SEED = REPO_ROOT / "deploy" / "demo" / "seed.py"
TEMPLATES = REPO_ROOT / "backend" / "mykronos" / "installer" / "templates.py"
FETCHERS = ("runsheet_compare.py", "time_travel_report.py", "bench_run.py")


def _load(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _Server:
    """A loopback HTTP server answering every request with `body`."""

    def __init__(self, body: bytes) -> None:
        self.hits = 0
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def _answer(self) -> None:
                outer.hits += 1
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:  # noqa: N802 - the stdlib's handler name
                self._answer()

            def do_POST(self) -> None:  # noqa: N802 - the stdlib's handler name
                self._answer()

            def log_message(self, *args: object) -> None:
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def __enter__(self) -> _Server:
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def planted(tmp_path: Path) -> Path:
    """A directory a file:// base URL would read from: valid JSON at every path
    the scripts ask for, so the old code parsed it without complaint."""
    answer = json.dumps({"planted": True, "steps": [], "data": []})
    for rel in ("api/dashboard/today", "api/dev/stories", "api/bench/runs"):
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(answer, encoding="utf-8")
    return tmp_path


@pytest.fixture
def token_file(tmp_path: Path) -> str:
    path = tmp_path / "token"
    path.write_text("not-a-real-token", encoding="utf-8")
    return str(path)


class TestTheRunSheetComparisonReadsOnlyHttp:
    def test_a_file_url_is_not_read(self, planted: Path, token_file: str) -> None:
        module = _load(SCRIPTS / "runsheet_compare.py", "runsheet_compare_61512")
        args = Namespace(today=None, api_url=planted.as_uri(), token_file=token_file)
        with pytest.raises(urllib.error.URLError):
            module._read_sheet(args)

    def test_http_still_reads_the_sheet(self, token_file: str) -> None:
        module = _load(SCRIPTS / "runsheet_compare.py", "runsheet_compare_61512b")
        with _Server(b'{"steps": []}') as server:
            args = Namespace(today=None, api_url=server.url, token_file=token_file)
            assert module._read_sheet(args) == {"steps": []}
            assert server.hits == 1


class TestTheTimeTravelReporterReachesOnlyHttp:
    def test_a_file_url_is_not_read(self, planted: Path) -> None:
        module = _load(SCRIPTS / "time_travel_report.py", "time_travel_report_61512")
        send = module.http_sender(planted.as_uri(), "not-a-real-token")
        with pytest.raises(module.HubError):
            send("GET", "/api/dev/stories", None)

    def test_http_still_answers(self) -> None:
        module = _load(SCRIPTS / "time_travel_report.py", "time_travel_report_61512b")
        with _Server(b'[{"id": 1}]') as server:
            send = module.http_sender(server.url, "not-a-real-token")
            assert send("GET", "/api/dev/stories", None) == (200, [{"id": 1}])


class TestTheBenchPostsOnlyOverHttp:
    def test_a_file_url_is_not_read(self, planted: Path) -> None:
        module = _load(SCRIPTS / "bench_run.py", "bench_run_61512")
        with pytest.raises(urllib.error.URLError):
            module._post(planted.as_uri() + "/api/bench/runs", {"x": 1}, "not-a-real-token")

    def test_http_still_posts(self) -> None:
        module = _load(SCRIPTS / "bench_run.py", "bench_run_61512b")
        with _Server(b'{"ok": true}') as server:
            assert module._post(server.url + "/api/bench/runs", {"x": 1}, "t") == {"ok": True}
            assert server.hits == 1


@pytest.mark.parametrize("script", [SCRIPTS / name for name in FETCHERS] + [SEED], ids=lambda p: p.name)
def test_no_fetcher_calls_urlopen(script: Path) -> None:
    """The static half: a later edit that goes back to urlopen reopens file://.

    `seed.py` already refused a non-http `--url` (test_audit_timeouts_url), and
    its finding was a recorded false positive; it moves to the opener too, so
    the line shift above it cannot reopen that finding under a new line number.
    """
    tree = ast.parse(script.read_text(encoding="utf-8"))
    calls = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "urlopen"
    ]
    assert calls == [], f"{script} calls urlopen at line(s) {calls}"


class TestTheDemoSeedDigest:
    def test_it_is_forty_hex_and_stable(self) -> None:
        seed = _load(SEED, "demo_seed_61512")
        first = seed.commit_sha("acme/web", "sast", 3)
        assert re.fullmatch(r"[0-9a-f]{40}", first)
        assert seed.commit_sha("acme/web", "sast", 3) == first
        assert seed.commit_sha("acme/web", "sast", 4) != first

    def test_it_uses_no_sha1(self) -> None:
        tree = ast.parse(SEED.read_text(encoding="utf-8"))
        sha1 = [
            node.lineno
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute) and node.attr in ("sha1", "md5")
        ]
        assert sha1 == []


class TestTheInstallerTemplatesStayUnescaped:
    RULE = "backend.mykronos.patchwork.mykronos-jinja2-autoescape-disabled"

    def test_the_suppression_names_one_rule_on_the_environment_call(self) -> None:
        lines = TEMPLATES.read_text(encoding="utf-8").splitlines()
        marked = [i for i, line in enumerate(lines) if "nosemgrep" in line]
        assert len(marked) == 1, "one suppression, no more"
        line = lines[marked[0]].strip()
        assert line == f"# nosemgrep: {self.RULE}", "the suppression must name the one rule"
        assert lines[marked[0] + 1].strip() == "return Environment("

    def test_a_rendered_ampersand_is_not_escaped(self, tmp_path: Path) -> None:
        from mykronos.installer.templates import _build_environment

        (tmp_path / "t.yml").write_text("run: << cmd >>\n", encoding="utf-8")
        rendered = _build_environment(tmp_path).get_template("t.yml").render(cmd="a && b < c")
        assert rendered == "run: a && b < c\n"
