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
import ast
import importlib
import importlib.metadata
import io
import json
import re
import subprocess
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

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
    # #427. The containers lane installs the pinned package to ask which
    # images the repository deploys. A pin without this module leaves that
    # step failing on an import while the built-image scan beside it still
    # reports, which is the lane going quietly back to scanning four of
    # fifteen.
    "mykronos.estate_images",
    # #382. The same upload step stamps each published image's report with
    # the build SHA it records, for the containers adapter to check.
    "mykronos.image_provenance",
    # TheHub's `image-refresh` lane plans the patched-image rebuilds and
    # decides whether demo moves with it.
    "mykronos.image_refresh",
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
    "mykronos.estate_images": ("--root", "--output"),
}


#: `(capability, tool)` pairs the estate uploads. A pinned runner without an
#: adapter for one of these accepts the scan run and then fails the upload:
#:
#:     ERROR No adapter for capability 'sast' with tool 'shellcheck'.
#:           Supported for 'sast': codeql, semgrep.
#:
#: which is what keel's ShellCheck lane has done on every run since it was
#: enabled. The adapter exists on `main` and in no tag -- `sast_shellcheck.py`
#: landed 2026-09-09 and v8, the newest tag, is from 2026-08-30. The same is
#: true of `sast_psscriptanalyzer.py`.
#:
#: This is the third way the pin goes stale and the one that was not checked.
#: Modules, flags and raw-fetched scripts were; the registry was not, so a
#: repository could enable an analyser, the runner could be unable to
#: normalise its output, and this check stayed green. It did: pin-check
#: succeeded at 2026-09-15 04:09 while keel's lane was failing.
#:
#: Add to this in the same commit that points a lane at a new tool -- the same
#: discipline the lists above ask for, for the same reason.
REQUIRED_ADAPTERS: tuple[tuple[str, str], ...] = (
    # Concourse pipelines
    ("ai", "mykronos-ai-checks"),
    ("atlas", "osv-scanner"),
    ("cloud", "prowler"),
    ("containers", "trivy"),
    ("dast", "zap"),
    # TheHub's three LAN lanes, one tool per environment (D-155).
    ("dast", "zap-demo"),
    ("dast", "zap-prod"),
    ("dast", "zap-staging"),
    # thehub's `dast-edge` (TheHub #60708, D-154). Red here until a tag carries it.
    ("dast", "zap-edge"),
    ("functional", "junit"),
    ("iac", "checkov"),
    # personal-soc's network lanes (TheHub #60813). Red here until a tag
    # carries them and `mykronos-ref` moves to it.
    ("network", "netassess"),
    ("network", "netassess-freshness"),
    ("network", "shodan-internetdb"),
    ("qa", "junit"),
    ("sast", "semgrep"),
    ("secrets", "gitleaks"),
    ("unit", "junit"),
    # GitHub Actions workflow templates
    ("sast", "codeql"),
    ("sast", "shellcheck"),
    ("sast", "psscriptanalyzer"),
)


def _missing_adapters() -> list[str]:
    """Which REQUIRED_ADAPTERS the installed runner cannot normalise.

    Asks the registry rather than listing what it should contain, so this
    cannot drift from the code it is checking. A registry that will not import
    is reported once rather than fifteen times -- the pin is unusable and the
    per-pair detail would be noise.
    """
    try:
        from mykronos.adapters import registry
    except ImportError as exc:
        return [f"the adapter registry will not import from the pinned runner ({exc})"]

    missing = []
    for capability, tool in REQUIRED_ADAPTERS:
        try:
            registry.get_adapter(capability, tool)
        except Exception:
            supported = ", ".join(registry.supported_tools(capability)) or "none"
            missing.append(
                f"no adapter for capability '{capability}' with tool '{tool}' "
                f"(the pin supports: {supported})"
            )
    return missing


#: `(capability, tool)` pairs the GitHub Actions workflow templates upload,
#: rendered with their defaults (`workflow-templates/*.j2`). The Actions
#: workflows install the runner from a DIFFERENT pin from the one this script
#: introspects: `mykronos_package_spec` and `upload_action_ref` in
#: `backend/mykronos/config.py`, stamped into every rendered workflow.
#:
#: That is the fourth way the pin goes stale (#337). Concourse moved to v14 and
#: this check went green, while the Actions pins sat on v8 -- a commit with no
#: ShellCheck and no PSScriptAnalyzer adapter -- so the `sast-shell` and
#: `sast-powershell` templates installed a runner that could not normalise
#: their output. `test_pinned_ref_check` renders the templates and fails if
#: this list stops matching them.
ACTIONS_TEMPLATE_ADAPTERS: tuple[tuple[str, str], ...] = (
    ("ai", "mykronos-ai-checks"),
    ("atlas", "osv-scanner"),
    ("cloud", "prowler"),
    ("containers", "trivy"),
    ("dast", "zap"),
    ("functional", "junit"),
    ("iac", "checkov"),
    ("qa", "junit"),
    ("sast", "codeql"),
    ("sast", "psscriptanalyzer"),
    ("sast", "shellcheck"),
    ("secrets", "gitleaks"),
    ("unit", "junit"),
)

#: The two settings that pin the runner every Actions workflow installs.
ACTIONS_PIN_SETTINGS: tuple[str, ...] = ("mykronos_package_spec", "upload_action_ref")

_REPO_ROOT = Path(__file__).resolve().parents[1]
_CONFIG_SOURCE = _REPO_ROOT / "backend" / "mykronos" / "config.py"
_REGISTRY_PATH = "backend/mykronos/adapters/registry.py"
_SHA = re.compile(r"@([0-9a-f]{40})\b")


def actions_pins(config_source: str | None = None) -> dict[str, str]:
    """The commit each Actions pin names, read from the SOURCE checkout.

    From the file, not from `mykronos.config`: in the pin-check job the
    importable package is the Concourse pin, whose settings are whatever that
    tag shipped -- not the ones this checkout will render into workflows.
    """
    source = config_source if config_source is not None else _CONFIG_SOURCE.read_text("utf-8")
    pins: dict[str, str] = {}
    for node in ast.walk(ast.parse(source)):
        if not (isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)):
            continue
        if node.target.id not in ACTIONS_PIN_SETTINGS or not isinstance(node.value, ast.Call):
            continue
        for keyword in node.value.keywords:
            if keyword.arg == "default" and isinstance(keyword.value, ast.Constant):
                match = _SHA.search(str(keyword.value.value))
                if match:
                    pins[node.target.id] = match.group(1)
    return pins


def registry_pairs(registry_source: str) -> set[tuple[str, str]]:
    """The `(capability, tool)` pairs a version of `registry.py` registers.

    Parsed rather than imported: the commit being asked about is not the one
    installed. Every entry is an `AdapterSpec("<capability>", "<tool>", ...)`
    call, which the registry's own docstring calls "a list you can read".
    """
    pairs: set[tuple[str, str]] = set()
    for node in ast.walk(ast.parse(registry_source)):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "AdapterSpec"
            and len(node.args) >= 2
            and all(isinstance(a, ast.Constant) and isinstance(a.value, str) for a in node.args[:2])
        ):
            pairs.add((node.args[0].value, node.args[1].value))
    return pairs


def registry_source_at(commit: str) -> str | None:
    """`registry.py` as it is at `commit`, or None if it cannot be read here.

    The local object store first (a full clone has every tagged commit), then
    the raw URL `_missing_scripts` already uses. Fails open, for that
    function's reason: "GitHub was slow" must not turn this red.
    """
    try:
        shown = subprocess.run(
            ["git", "-C", str(_REPO_ROOT), "show", f"{commit}:{_REGISTRY_PATH}"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=30,
            check=False,
        )
        if shown.returncode == 0 and shown.stdout:
            return shown.stdout
    except (OSError, subprocess.SubprocessError):
        pass

    try:
        import httpx2

        url = f"https://raw.githubusercontent.com/ToddGBenson/mykronos/{commit}/{_REGISTRY_PATH}"
        with httpx2.Client(timeout=15.0, follow_redirects=True) as client:
            response = client.get(url)
        if response.status_code == 200:
            return response.text
    except Exception:  # noqa: BLE001 - any transport failure means "cannot determine"
        pass
    return None


def _actions_pin_problems() -> list[str]:
    """Which template adapters each Actions pin's commit does not register."""
    problems: list[str] = []
    for setting, commit in sorted(actions_pins().items()):
        source = registry_source_at(commit)
        if source is None:
            print(f"Cannot read the registry at {setting}'s pin ({commit[:12]}); skipping it.")
            continue
        have = registry_pairs(source)
        problems.extend(
            f"config.py `{setting}` pins {commit[:12]}, which has no adapter for "
            f"capability '{capability}' with tool '{tool}' - every GitHub Actions "
            f"workflow uploading it fails at upload (#337)"
            for capability, tool in ACTIONS_TEMPLATE_ADAPTERS
            if (capability, tool) not in have
        )
    return problems


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
    if not can_check_scripts(commit):
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


#: Commits that are not commits. `_installed_commit` returns one of these when
#: the package is absent, installed from a local path, or has no direct_url
#: metadata to read — none of which is a SHA a raw URL can be built from.
_UNRESOLVED = frozenset({"", "not installed", "local install", "unknown", "unreadable"})


def can_check_scripts(commit: str) -> bool:
    """Whether a raw-URL existence check is possible for this pin at all."""
    return commit not in _UNRESOLVED


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
    problems.extend(_missing_adapters())
    problems.extend(_actions_pin_problems())

    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="check-pinned-ref", description=__doc__)
    parser.parse_args(argv)

    commit = _installed_commit()
    print(f"Pinned mykronos package resolves to commit {commit}")

    problems = check(commit)
    if not problems:
        # Only what was actually established. With an unresolvable commit the
        # script half never runs, and the summary used to name those scripts
        # as supported anyway -- a clean bill of health for a check that did
        # not happen, in the one script whose entire purpose is catching a pin
        # that has gone quietly stale. It has bitten twice (53 commits at
        # D-051, 61 at D-074) and both times a person found it late.
        #
        # Still exit 0. Failing open is deliberate here and the docstring
        # argues it well: an unresolvable pin on somebody's laptop is not a
        # broken pipeline, and a check that goes red on a slow network is one
        # people pause. Saying less is the fix, not saying no.
        if can_check_scripts(commit):
            print(
                f"The pin supports all {len(REQUIRED_MODULES)} runner modules, their "
                f"flags, all {len(REQUIRED_SCRIPTS)} raw-fetched scripts, and all "
                f"{len(REQUIRED_ADAPTERS)} (capability, tool) adapter pairs."
            )
        else:
            print(
                f"The pin supports all {len(REQUIRED_MODULES)} runner modules, their "
                f"flags, and all {len(REQUIRED_ADAPTERS)} adapter pairs. The "
                f"{len(REQUIRED_SCRIPTS)} raw-fetched scripts were NOT checked - the "
                "pinned commit could not be resolved here."
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
        "(D-051, D-074). A `config.py` line is the GitHub Actions pin instead: "
        "move `mykronos_package_spec` and `upload_action_ref` together to the "
        "commit of a tag that has the adapter (#337)."
    )
    return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
