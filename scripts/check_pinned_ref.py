"""Does the pinned runner package still support what the pipelines ask of it?

Twice now the `mykronos-ref` pin has gone stale in a way that mattered — 53
commits at D-051, 61 at D-074 — and both times it was found by a human
noticing a lane behaving oddly, long after the fact. The unit tests cannot
catch it: they run against the working tree, and CI runs against the tag.

So this runs from the source checkout and introspects the *installed* package,
which is the only place the two versions can be compared. It is deliberately
not a version-distance check — a pin being old is fine, and saying "you are 61
commits behind" every build teaches people to ignore it. What is not fine is a
pipeline invoking a module or a flag the pinned package does not have, and
that is exactly what this asserts.

    python scripts/check_pinned_ref.py

Exit 0 when the pin supports everything below, 1 when it does not, and the
message names the missing thing and the fix (cut a new tag).
"""

from __future__ import annotations

import argparse
import importlib
import importlib.metadata
import io
import json
from contextlib import redirect_stderr, redirect_stdout

#: Modules a pipeline or workflow template invokes with `python -m`.
#:
#: Add to this in the same commit that adds the `python -m` call. That is the
#: whole discipline: the requirement is declared next to nothing, so it has to
#: be declared here, and here is what CI checks.
REQUIRED_MODULES: tuple[str, ...] = (
    "mykronos.upload",
    "mykronos.aegis_signals",
    "mykronos.atlas_counts",
    "mykronos.atlas_sbom",
    "mykronos.atlas_freshness",
    "mykronos.reachability",
    "mykronos.ai_pin_check",
    "mykronos.junit_stage",
)

#: Repository scripts a pipeline fetches by raw URL at `${MYKRONOS_REF}`
#: rather than through the installed package.
#:
#: A second, quieter way the pin goes stale, and nothing checked it.
#: `check_ai.py` has been fetched this way by TheHub's `ai-models` lane since
#: D-047, and `check_links.py` now is too by its `qa` lane. The tag they fetch
#: from is this same pin, so a script added after the tag simply 404s when the
#: lane runs — which reads as a broken job rather than as a stale pin. They are
#: not in the package, so the import check above cannot see them; the only
#: thing that can is asking the ref whether the file is there.
REQUIRED_SCRIPTS: tuple[str, ...] = (
    "scripts/check_ai.py",
    "scripts/check_links.py",
)

#: CLI flags a pipeline or workflow template passes. A flag the pinned package
#: does not accept is worse than a missing module: argparse exits non-zero and
#: takes the step with it, where a missing module at least fails on the import
#: line where somebody can see it.
REQUIRED_FLAGS: dict[str, tuple[str, ...]] = {
    "mykronos.aegis_signals": ("--author-role", "--ai-classifier-file", "--reviews-file"),
    "mykronos.atlas_counts": ("--sbom", "--check-freshness"),
    "mykronos.reachability": ("--commit-sha",),
    "mykronos.atlas_sbom": ("--banned-package", "--blocked-license", "--sarif"),
    "mykronos.ai_pin_check": ("--repo-root", "--output"),
    "mykronos.junit_stage": ("--out", "--suite", "--case"),
}


def _installed_commit() -> str:
    """The commit the installed package was built from, if pip recorded one."""
    try:
        raw = importlib.metadata.distribution("mykronos").read_text("direct_url.json")
    except importlib.metadata.PackageNotFoundError:
        return "not installed"
    if not raw:
        return "local install"
    try:
        return json.loads(raw).get("vcs_info", {}).get("commit_id", "unknown")[:12]
    except json.JSONDecodeError:
        return "unreadable"


def _help_text(module: str) -> str | None:
    """`--help` output for a module, or None if it cannot be produced.

    Invoked in-process rather than as a subprocess so this works the same on
    a Concourse worker and a laptop, and so a module that fails to import is
    reported as a missing module rather than as a missing flag.
    """
    try:
        imported = importlib.import_module(module)
    except ImportError:
        return None

    if getattr(imported, "main", None) is None:
        return ""

    buffer = io.StringIO()
    try:
        with redirect_stdout(buffer), redirect_stderr(buffer):
            imported.main(["--help"])
    except SystemExit:
        # argparse exits 0 after printing help. Expected, not an error.
        pass
    except Exception:  # noqa: BLE001 — any failure means "cannot determine"
        return ""
    return buffer.getvalue()


def _missing_scripts(commit: str) -> list[str]:
    """Which of REQUIRED_SCRIPTS are absent at the pinned commit.

    Fails **open** on any network or resolution problem. This exists to catch a
    stale pin, and turning "GitHub was slow" into a red pipeline would make it
    the thing people pause. A script that is genuinely missing 404s every time,
    so it is caught on the next build regardless.
    """
    if not commit or commit in {"not installed", "local install", "unknown", "unreadable"}:
        print(f"Cannot resolve the pinned commit ({commit}); skipping the script check.")
        return []

    import httpx2

    problems: list[str] = []
    base = f"https://raw.githubusercontent.com/ToddGBenson/mykronos/{commit}"
    try:
        with httpx2.Client(timeout=15.0, follow_redirects=True) as client:
            for script in REQUIRED_SCRIPTS:
                response = client.head(f"{base}/{script}")
                if response.status_code == 404:
                    problems.append(
                        f"{script} does not exist at the pinned ref - a pipeline "
                        f"fetches it by raw URL and will 404"
                    )
                elif response.status_code >= 400:
                    print(f"Could not check {script} (HTTP {response.status_code}); skipping it.")
    except Exception as exc:  # noqa: BLE001 - any transport failure means "cannot determine"
        print(f"Could not reach raw.githubusercontent.com ({exc}); skipping the script check.")
        return []
    return problems


def check(commit: str = "") -> list[str]:
    """Every unmet requirement, as a human-readable line."""
    problems: list[str] = []

    for module in REQUIRED_MODULES:
        try:
            importlib.import_module(module)
        except ImportError as exc:
            problems.append(f"{module} is not in the pinned package ({exc})")

    for module, flags in REQUIRED_FLAGS.items():
        help_text = _help_text(module)
        if help_text is None:
            continue  # already reported as a missing module
        if not help_text:
            problems.append(f"{module} produced no --help, so its flags cannot be checked")
            continue
        problems.extend(
            f"{module} does not accept {flag}" for flag in flags if flag not in help_text
        )

    problems.extend(_missing_scripts(commit))

    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="check-pinned-ref", description=__doc__)
    parser.parse_args(argv)

    commit = _installed_commit()
    print(f"Pinned mykronos package resolves to commit {commit}")

    problems = check(commit)
    if not problems:
        print(
            f"The pin supports all {len(REQUIRED_MODULES)} runner modules, their "
            f"flags, and all {len(REQUIRED_SCRIPTS)} raw-fetched scripts."
        )
        return 0

    print()
    print("The pinned ref does not support what the pipelines invoke:")
    for problem in problems:
        print(f"  - {problem}")
    print()
    print(
        "Cut a new tag at a commit that has these, and point `mykronos-ref` at "
        "it in all three set-pipeline scripts. Do not move the existing tag: a "
        "pin that moves is not a pin, and a scan has to be reproducible "
        "(D-051, D-074)."
    )
    return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
