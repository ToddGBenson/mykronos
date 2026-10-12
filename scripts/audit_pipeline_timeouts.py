"""Every configured task timeout against what the job has actually taken.

The by-hand run of `mykronos.timeout_audit`, which holds the audit itself, its
thresholds and its waivers. The same audit runs daily against live Concourse
as the backend's `timeout-audit` job (TheHub #60729), which is where a finding
is raised; this script is for reading the full table.

Reads Concourse's API directly. It used to shell out to `fly builds` and parse
the human table, which meant it needed a logged-in target -- and its default
FLY path pointed into a different project's checkout, so it crashed with
FileNotFoundError before reaching any pipeline. The API is readable
anonymously, returns start/end timestamps rather than a formatted column, and
knows about every pipeline instead of the two that were hardcoded here.

    python scripts/audit_pipeline_timeouts.py
    CONCOURSE_URL=http://elsewhere:8080 python scripts/audit_pipeline_timeouts.py

Exit 0 when every cap clears its observed worst run with margin, 1 when a cap
should be raised, 2 when Concourse could not be read -- which is NOT clean.
"""
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import urlopen

# The audit lives in the backend package so the scheduled job, which runs in
# the backend image, can import it. Nothing else from the package is loaded.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from mykronos import timeout_audit  # noqa: E402
from mykronos.timeout_audit import (  # noqa: E402,F401 - re-exported for the tests
    HEADROOM_FLOOR,
    HOOKS,
    OUTLIER_RATIO,
    TIMEOUT_MARGIN,
    TIMEOUT_WAIVERS,
    to_minutes,
    walk,
)


def _http_base(value, name):
    """An http(s) base, or nothing. `urlopen` honours `file://` (B-090).

    Concourse's answer is parsed with `json.load` straight off the response,
    so `CONCOURSE_URL=file:///etc/passwd` is a local file read wearing an
    API call's clothes. Nothing here is reachable by an attacker -- it is a
    developer script reading an env var -- and that is the reason to spend
    two lines on it rather than the reason not to: the check costs nothing
    and the next caller of `_api` may not be a developer script.

    Refused loudly rather than defaulted, because silently substituting
    localhost for what somebody typed is how an audit reports on the wrong
    Concourse.
    """
    scheme = urlsplit(value).scheme
    if scheme not in ("http", "https"):
        sys.exit(f"{name} must be an http:// or https:// URL, not {scheme or 'a bare path'!r}.")
    return value.rstrip("/")


CONCOURSE = _http_base(os.environ.get("CONCOURSE_URL", "http://127.0.0.1:8080"), "CONCOURSE_URL")
TEAM = os.environ.get("CONCOURSE_TEAM", "main")
#: Pipelines this repository holds the definition for. A pipeline Concourse
#: knows about and this checkout does not is somebody else's to audit.
PIPELINE_DIR = Path("deploy/concourse/pipelines")


def _api(path):
    with urlopen(f"{CONCOURSE}{path}", timeout=20) as response:
        return json.load(response)


def main():
    report = timeout_audit.audit(PIPELINE_DIR, _api, team=TEAM, emit=print)
    return timeout_audit.render(report, print)


if __name__ == "__main__":
    sys.exit(main())
