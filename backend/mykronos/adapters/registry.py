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
    from mykronos.adapters import cloud_generic, dast_zap, secrets_gitleaks

    specs = [
        # --- SARIF-native: no bespoke parser needed ---
        AdapterSpec("sast", "codeql", _sarif, "*.sarif", "CodeQL"),
        AdapterSpec("sast", "semgrep", _sarif, "*.sarif", "Semgrep (spec 04 §3 secondary)"),
        AdapterSpec("containers", "trivy", _sarif, "*.sarif", "Trivy"),
        AdapterSpec("iac", "checkov", _sarif, "*.sarif", "Checkov"),
        # --- Bespoke: not SARIF ---
        AdapterSpec("secrets", "gitleaks", secrets_gitleaks.normalize, "*.json", "Gitleaks"),
        AdapterSpec("dast", "zap", dast_zap.normalize, "*.json", "OWASP ZAP"),
        AdapterSpec("cloud", "prowler", cloud_generic.normalize, "*.json", "Prowler"),
        AdapterSpec("cloud", "generic", cloud_generic.normalize, "*.json", "Generic OCSF"),
    ]
    return {(spec.capability, spec.tool): spec for spec in specs}


REGISTRY: dict[tuple[str, str], AdapterSpec] = _build_registry()


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
