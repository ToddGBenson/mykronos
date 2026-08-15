"""Adapter dispatch (spec 04 §4).

One adapter per (capability, tool) pair. The registry is explicit rather than
discovered by import scanning, so the set of tools the platform accepts is a
list you can read, and adding one is a visible change rather than a file
appearing in a directory.

Two families:

- **SARIF-native** tools go through the shared converter. Spec 04 §4 asks for
  one converter rather than a parser per tool, and every entry here that says
  `sarif` is a tool we did not have to write code for.
- **Bespoke** tools have their own module, because their output is not SARIF
  and pretending otherwise would mean a lossy translation step nobody can
  debug.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from mykronos.adapters import network_nmap, tests_junit
from mykronos.adapters.base import AdapterResult, ScanContext
from mykronos.adapters.sarif import sarif_to_findings
from mykronos.schemas import ScanStatus

logger = logging.getLogger(__name__)

Normalizer = Callable[[bytes, ScanContext], AdapterResult]


def _sarif(raw_output: bytes, context: ScanContext) -> AdapterResult:
    return sarif_to_findings(raw_output, context)


@dataclass(frozen=True)
class AdapterSpec:
    capability: str
    tool: str
    normalize: Normalizer
    #: Glob for the files this tool writes into the results directory.
    pattern: str
    #: What "the tool produced nothing" means. For most scanners an empty
    #: result set is a real, successful observation; the *absence of any
    #: output file* is not, and is handled separately.
    description: str = ""


def _build_registry() -> dict[tuple[str, str], AdapterSpec]:
    from mykronos.adapters import (
        atlas_osv,
        cloud_generic,
        containers_trivy,
        dast_zap,
        secrets_gitleaks,
    )

    specs = [
        # --- SARIF-native: no bespoke parser needed ---
        AdapterSpec("sast", "codeql", _sarif, "*.sarif", "CodeQL"),
        AdapterSpec("sast", "semgrep", _sarif, "*.sarif", "Semgrep (spec 04 §3 secondary)"),
        AdapterSpec(
            "containers", "trivy", containers_trivy.normalize, "*.sarif", "Trivy"
        ),
        AdapterSpec("iac", "checkov", _sarif, "*.sarif", "Checkov"),
        # Atlas scores supply-chain trust from counts (spec 07 §5), but the
        # vulnerabilities behind those counts are findings like any other and
        # have to reach the lake through the same path. Without this entry the
        # workflow scans correctly and then fails at upload with "'atlas' has
        # no adapters registered" — the scoring, the counts and the template
        # all existed while the one line joining them to ingestion did not.
        AdapterSpec(
            "atlas", "osv-scanner", atlas_osv.normalize, "*.sarif", "OSV-Scanner"
        ),
        # --- Bespoke: not SARIF ---
        AdapterSpec("secrets", "gitleaks", secrets_gitleaks.normalize, "*.json", "Gitleaks"),
        AdapterSpec("dast", "zap", dast_zap.normalize, "*.json", "OWASP ZAP"),
        AdapterSpec("cloud", "prowler", cloud_generic.normalize, "*.json", "Prowler"),
        AdapterSpec("cloud", "generic", cloud_generic.normalize, "*.json", "Generic OCSF"),
        # Two tools, one adapter: nmap says a port is open, nuclei says a
        # weakness is present on it, and both key on address and port
        # (spec 14 §5). The glob takes both because a network run produces
        # nmap XML and nuclei JSONL side by side in one results directory.
        AdapterSpec("network", "nmap", network_nmap.normalize, "*.xml", "nmap"),
        AdapterSpec("network", "nuclei", network_nmap.normalize, "*.json*", "nuclei"),
        # Quality stages (D-046). JUnit XML because every runner emits it, and
        # neither produces findings - what reaches the lake is that a suite
        # ran and how it ended.
        AdapterSpec("unit", "junit", tests_junit.normalize, "*.xml", "JUnit XML"),
        AdapterSpec(
            "functional", "junit", tests_junit.normalize, "*.xml", "JUnit XML"
        ),
        AdapterSpec("qa", "junit", tests_junit.normalize, "*.xml", "JUnit XML"),
        # SARIF, so any tool can feed this capability (D-047). A capability
        # that only reads its own tool's output is a capability with one tool
        # for ever.
        AdapterSpec("ai", "mykronos-ai-checks", _sarif, "*.sarif", "Mykronos AI checks"),
    ]
    return {(spec.capability, spec.tool): spec for spec in specs}


REGISTRY: dict[tuple[str, str], AdapterSpec] = _build_registry()


#: The tool a capability runs when its config does not name one. Every
#: capability with an adapter needs an entry, and `test_adapters_phase2`
#: enforces that against the templates.
#:
#: This exists because the workflow templates previously defaulted the tool
#: they declare to the *capability name* — so a repo with no `enabled_tool`
#: set installed a workflow announcing `tool: secrets`, and the upload failed
#: with "No adapter for capability 'secrets' with tool 'secrets'". The scan
#: itself was fine. Only the label was wrong, and only at the last step.
#:
#: `cloud` is the reason this is a table rather than "the first registered
#: tool": it has two adapters, and alphabetical order would pick `generic`
#: over the one the template actually runs.
DEFAULT_TOOLS: dict[str, str] = {
    "sast": "codeql",
    "secrets": "gitleaks",
    "dast": "zap",
    "atlas": "osv-scanner",
    "containers": "trivy",
    "iac": "checkov",
    "cloud": "prowler",
    "network": "nmap",
    "unit": "junit",
    "functional": "junit",
    "qa": "junit",
    "ai": "mykronos-ai-checks",
}


def default_tool(capability: str) -> str:
    """The tool a capability runs absent explicit config.

    Returns the capability name for capabilities that upload nothing (the
    Oracle gate, Patchwork, Aegis), which never reach an adapter lookup.
    """
    return DEFAULT_TOOLS.get(capability, capability)


def supported_tools(capability: str) -> list[str]:
    """Tools this capability accepts. Used to validate config at save time
    (spec 04 §7) rather than letting a typo fail a workflow run hours later."""
    return sorted(tool for (cap, tool) in REGISTRY if cap == capability)


def get_adapter(capability: str, tool: str) -> AdapterSpec:
    try:
        return REGISTRY[(capability, tool)]
    except KeyError:
        known = supported_tools(capability)
        raise LookupError(
            f"No adapter for capability '{capability}' with tool '{tool}'. "
            + (
                f"Supported for '{capability}': {', '.join(known)}."
                if known
                else f"'{capability}' has no adapters registered."
            )
        ) from None


def normalize_results(
    capability: str, tool: str, results_path: Path, context: ScanContext
) -> AdapterResult:
    """Parse every output file the tool wrote, merging into one result.

    A missing or empty results directory is a **failure**, not an empty scan.
    The workflow was supposed to write here; if it did not, the scan step
    broke, and reporting that as "found nothing" would let a permanently
    broken scanner look like a permanently clean repo (spec 04 §6).
    """
    spec = get_adapter(capability, tool)
    outcome = AdapterResult()

    if not results_path.exists():
        outcome.warn(
            f"No output at {results_path} — the {spec.description or tool} step "
            "did not produce results. Treated as a failed scan, not a clean one."
        )
        outcome.scan_status = ScanStatus.FAILURE
        return outcome

    files = (
        sorted(results_path.rglob(spec.pattern))
        if results_path.is_dir()
        else [results_path]
    )
    files = [path for path in files if path.is_file() and path.stat().st_size > 0]

    if not files:
        outcome.warn(
            f"No {spec.pattern} files under {results_path} — the "
            f"{spec.description or tool} step produced no output."
        )
        outcome.scan_status = ScanStatus.FAILURE
        return outcome

    for path in files:
        try:
            raw = path.read_bytes()
        except OSError as exc:
            outcome.warn(f"Could not read {path.name}: {exc}")
            outcome.scan_status = ScanStatus.PARTIAL_FAILURE
            continue

        parsed = spec.normalize(raw, context)
        outcome.findings.extend(parsed.findings)
        outcome.warnings.extend(parsed.warnings)
        outcome.skipped += parsed.skipped
        if parsed.scan_status is not ScanStatus.SUCCESS:
            outcome.scan_status = parsed.scan_status

    logger.info(
        "%s/%s: %s finding(s) from %s file(s)",
        capability,
        tool,
        len(outcome.findings),
        len(files),
    )
    return outcome
