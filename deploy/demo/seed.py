"""Seed the demo environment with realistic, synthetic data (PIP-5).

An empty application has no findings worth having: no repository to drill
into, no severity mix to filter, no history for a trend line, and no
authenticated page for a functional test to reach. A DAST scan of an empty
dashboard reports that an empty dashboard is secure.

Two properties this has to hold, and they pull in opposite directions.

**Realistic.** Enough repositories, capabilities, severities and dates that
every view has something in it and the functional suite can exercise real
paths — a repository page with tabs that have content, a triage queue with
rows, a trend series with more than one point.

**Reproducible.** The same seed produces the same data, every run. A DAST
finding is only comparable between runs if the application it found is the
same application; and a demo that looks different each time cannot be
screenshotted, described in advance, or diffed.

Everything here is invented. No production record, no real credential, no
copied fixture from a live system — a lower environment holding production
data is the most common way a scan becomes a breach, and this one is
deliberately attacked.
"""

from __future__ import annotations

import argparse
import json
import random
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta

#: Fixed. Every random choice below derives from this, so the estate is
#: identical on every run without any of it being hand-written.
SEED = 20260813

REPOS = [
    ("acme/checkout-api", ["sast", "secrets", "atlas", "containers"]),
    ("acme/customer-portal", ["sast", "dast", "secrets", "iac"]),
    ("acme/payments-worker", ["sast", "atlas", "containers"]),
    ("acme/internal-tools", ["secrets", "sast"]),
]

#: Real rule identifiers and real CWEs, because a demo that shows made-up rule
#: names teaches the audience to distrust the numbers next to them.
FINDINGS = {
    "sast": [
        ("CWE-89", "SQL injection in order lookup", "critical", "src/orders/query.py"),
        ("CWE-79", "Reflected XSS in search results", "high", "src/web/search.py"),
        ("CWE-798", "Hard-coded credential in client", "high", "src/clients/vault.py"),
        ("CWE-327", "Weak hash used for token", "medium", "src/auth/tokens.py"),
        ("CWE-306", "Endpoint missing authentication", "high", "src/api/admin.py"),
    ],
    "secrets": [
        ("generic-api-key", "API key committed to source", "critical", "config/dev.env"),
        ("aws-access-token", "AWS access key in history", "critical", "scripts/deploy.sh"),
    ],
    "atlas": [
        ("CVE-2024-3094", "Backdoor in xz-utils", "critical", "requirements.txt"),
        ("CVE-2023-45853", "Integer overflow in zlib", "high", "requirements.txt"),
        ("CVE-2024-22195", "Jinja2 XSS via attributes", "medium", "requirements.txt"),
    ],
    "containers": [
        ("CVE-2023-4911", "glibc buffer overflow", "high", "acme/checkout-api:latest"),
        ("CVE-2024-2961", "iconv out-of-bounds write", "medium", "acme/checkout-api:latest"),
    ],
    "iac": [
        ("CKV_DOCKER_3", "Container runs as root", "medium", "Dockerfile"),
        ("CKV_AWS_18", "S3 bucket without access logging", "low", "infra/s3.tf"),
    ],
    "dast": [
        ("ZAP-10202", "Absent anti-CSRF tokens", "medium", "/account/settings"),
        ("ZAP-10096", "Server leaks version information", "low", "/"),
    ],
}


def mint_token(repo_full_name: str, capabilities: list[str]) -> str:
    """Issue an ingestion token through the CLI and read it back.

    Parsed from `Token     : ...` rather than a machine-readable flag, which
    is a real wart. It is tolerable only because this runs in a container that
    is destroyed minutes later; anything longer-lived should be asking for a
    `--json` output instead of scraping one.
    """
    grants: list[str] = []
    for capability in capabilities:
        grants += ["--grant", capability]

    completed = subprocess.run(
        ["python", "-m", "mykronos.cli", "mint-token", repo_full_name, *grants],
        capture_output=True,
        text=True,
        check=True,
    )
    for line in completed.stdout.splitlines():
        if line.startswith("Token"):
            return line.split(":", 1)[1].strip()
    raise RuntimeError(f"No token in CLI output for {repo_full_name}")


class Client:
    def __init__(self, base: str, admin_token: str, gate_token: str) -> None:
        self.base = base.rstrip("/")
        self.headers = {
            "Authorization": f"Bearer {admin_token}",
            "X-Hub-Token": gate_token,
            "Content-Type": "application/json",
        }

    def call(self, method: str, path: str, body: dict | None = None, token: str = ""):
        headers = dict(self.headers)
        if token:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(
            self.base + path,
            method=method,
            headers=headers,
            data=json.dumps(body).encode() if body is not None else None,
        )
        with urllib.request.urlopen(request, timeout=60) as response:
            payload = response.read()
        return json.loads(payload) if payload else {}


def seed(client: Client) -> dict[str, int]:
    rng = random.Random(SEED)
    counts = {"repos": 0, "scan_runs": 0, "findings": 0}
    now = datetime.now(UTC).replace(microsecond=0)

    for index, (repo_full_name, capabilities) in enumerate(REPOS):
        # Onboarding takes an installation id because the real path creates a
        # GitHub App installation. There is no App here, so the id is a
        # placeholder - the demo must not be able to reach a repository.
        created = client.call(
            "POST",
            "/api/repos",
            {
                "github_repo_full_name": repo_full_name,
                "github_installation_id": 900_000 + index,
            },
        )
        counts["repos"] += 1

        # `install_workflows: false` is the whole reason this works without an
        # App: it enables the capabilities and syncs their grants immediately
        # rather than waiting on a pull request nobody can open here.
        client.call(
            "PATCH",
            f"/api/repos/{created['id']}/capabilities",
            {"capabilities": capabilities, "install_workflows": False},
        )

        # The token comes from the CLI, not the API: minting one deliberately
        # has no HTTP route, because a token is shown exactly once and only
        # its hash is stored (spec 12 §2). This script runs inside the backend
        # container, against the same database the API serves, which is the
        # one place that constraint and this need coincide.
        token = mint_token(repo_full_name, capabilities)

        for capability in capabilities:
            catalogue = FINDINGS.get(capability, [])
            if not catalogue:
                continue

            # Three runs per capability, oldest first, so a trend line has
            # something to draw and mean-time-to-fix has a spread.
            for age_days in (21, 7, 0):
                scan_run_id = f"{repo_full_name}:{capability}:{age_days}".replace("/", "-")
                started = now - timedelta(days=age_days)
                commit = f"{abs(hash((repo_full_name, capability, age_days))):040x}"[:40]

                # One payload, posted twice: the second call finalises the
                # run. Building it once means the finalise cannot omit a
                # required field the open supplied, which it did.
                run_payload = {
                    "scan_run_id": scan_run_id,
                    "repo_full_name": repo_full_name,
                    "capability": capability,
                    "tool_name": "demo",
                    "tool_version": "1.0.0",
                    "commit_sha": commit,
                    "branch": "main",
                    "triggered_by": "push",
                    "started_at": started.isoformat(),
                }
                client.call("POST", "/api/ingest/scan-run", run_payload, token=token)
                counts["scan_runs"] += 1

                # The oldest run reports everything; later runs report a
                # subset, so some findings resolve and the fix metrics move.
                keep = catalogue if age_days == 21 else catalogue[: max(1, len(catalogue) - 1)]
                if age_days == 0:
                    keep = keep[: max(1, len(keep) - 1)]

                submissions = [
                    {
                        "rule_id": rule_id,
                        "title": title,
                        "description": (
                            f"Synthetic finding for the demo environment. "
                            f"{title} — invented for demonstration, not observed."
                        ),
                        "severity": severity,
                        "file_path": path,
                        "line_start": rng.randint(10, 400),
                    }
                    for rule_id, title, severity, path in keep
                ]
                client.call(
                    "POST",
                    "/api/ingest/findings",
                    {
                        # No repo here, deliberately: attribution comes from
                        # the token, so there is nowhere to name another
                        # repository (spec 05 §4).
                        "scan_run_id": scan_run_id,
                        "capability": capability,
                        "findings": submissions,
                    },
                    token=token,
                )
                counts["findings"] += len(submissions)

                client.call(
                    "POST",
                    "/api/ingest/scan-run",
                    {
                        **run_payload,
                        "completed_at": (started + timedelta(minutes=2)).isoformat(),
                        "scan_status": "success",
                        "finding_count": len(submissions),
                    },
                    token=token,
                )

    return counts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://backend:8100")
    parser.add_argument("--admin-token", default="demo-admin-token-not-a-secret")
    parser.add_argument("--gate-token", default="demo-gate-token-not-a-secret")
    args = parser.parse_args(argv)

    client = Client(args.url, args.admin_token, args.gate_token)
    try:
        counts = seed(client)
    except urllib.error.HTTPError as exc:
        print(f"Seeding failed: HTTP {exc.code} {exc.read()[:400]!r}", file=sys.stderr)
        return 1

    print(
        f"Seeded {counts['repos']} repositories, {counts['scan_runs']} scan runs, "
        f"{counts['findings']} findings (seed={SEED})."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
