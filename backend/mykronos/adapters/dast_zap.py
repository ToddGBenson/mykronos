"""OWASP ZAP baseline adapter (spec 04 §3, §4).

DAST findings have no file and no line — they have a URL and an HTTP method.
That makes the fingerprint inputs different from every other adapter: the
"location" is the request, so identity is (repo, capability, rule, route,
method + route).

The *route*, not the concrete URL, and that distinction is the subject of #274.
Keying on the concrete URL made identity churn on things the target changes for
reasons unrelated to the finding, so every scan minted fresh findings and closed
the previous ones by absence as `fixed`. Measured on the estate before this
change: 1,748 of 1,853 DAST findings (94%) were recorded `fixed`, `ZAP-10031`
alone had accumulated 891 distinct identities at 891 distinct URLs — 49 to 66
new ones per day, every completed day's cohort 100% "fixed" — for an alert that
fires on roughly two dozen places per run. Nothing was ever fixed; the identity
moved. This is the same rule the network fingerprint states below: do not key on
something the target changes for unrelated reasons.

Two ephemeral forms were measured, and a fix for either one alone leaves the
other churning:

- a cache-busting **query string**, ``/frontend/js/app.js?v=<commit sha>``,
  which changes on every deploy of the scanned app;
- an ephemeral **path segment**, ``/repos/<repo uuid>``, because the DAST lane
  scans a compose stack that ``deploy/demo/seed.py`` reseeds with fresh row
  ids on every run.

So the URL's identity-bearing part and its instance-bearing part are not
separated by "before or after the ``?``". `_route_of` therefore does both:
it drops the query string entirely and replaces UUID and long-hex path
segments with a placeholder. Across five weeks of scans that reduces 1,381
distinct URLs to 32 routes and 1,853 identities to 136.

The concrete URL is not lost — it stays verbatim in
``raw_finding_json["instance"]["uri"]``, which is where an operator reads the
target anyway. What it stops being is *identity*.

Two things deliberately left alone, both measured rather than assumed:

- **Query parameter names are not kept**, not even with their values
  stripped. The spider visits a different *subset* of the filter parameters
  on each run, so ``?fixable&tab`` and ``?fixable&kev_only&tab`` are the same
  page seen twice; keeping names left 40-odd identities on ``/repos/{id}``.
- **ZAP's ``param`` is not added** to the fingerprint. It is tempting — it is
  what separates two alerts on one URL — but it is not stable: on
  ``/repos/{id}`` the estate holds `ZAP-10055` instances reporting both
  ``Content-Security-Policy`` and ``content-security-policy`` for the same
  route in the same month. Adding it would buy 4 identities and introduce a
  fresh churn source, which is the defect again.

- **Purely numeric path segments are not templated.** They are the commonest
  ephemeral id in the wild, but there is not one of them anywhere in this
  estate's DAST history, so there is nothing here to verify the behaviour
  against. Add it when a target that uses them produces the evidence.

ZAP groups by alert with a list of instances. One alert affecting five URLs is
five findings here, not one: they are fixed and tracked separately, and
collapsing them would make "how many are left" unanswerable.

For the same reason the rule identity comes from `alertRef`, not `pluginid`:
several alerts can share a plugin *and* a CWE, and only `alertRef` tells them
apart.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any
from urllib.parse import urlparse

from mykronos.adapters.base import AdapterResult, ScanContext
from mykronos.schemas import FindingSubmission, ScanStatus, Severity

logger = logging.getLogger(__name__)

TOOL_NAME = "zap"

#: ZAP `riskcode`. There is no critical band — the highest ZAP expresses is
#: High, and inventing a critical tier the tool did not report would
#: misrepresent it.
_RISK_TO_SEVERITY = {
    "3": Severity.HIGH,
    "2": Severity.MEDIUM,
    "1": Severity.LOW,
    "0": Severity.INFO,
}

MAX_INSTANCES_PER_ALERT = 25


def _severity(alert: dict[str, Any]) -> Severity:
    return _RISK_TO_SEVERITY.get(str(alert.get("riskcode", "")).strip(), Severity.MEDIUM)


ROUTE_PLACEHOLDER = "{id}"
"""What an ephemeral path segment is replaced by in the route."""

#: A canonical 8-4-4-4-12 UUID as a whole path segment. Anchored to the whole
#: segment, so a filename that merely *contains* one is left alone.
_UUID_SEGMENT = re.compile(
    r"\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z"
)

#: A bare hex string of twelve or more characters as a whole path segment:
#: a commit sha, a content hash, an opaque token. Twelve is the shortest
#: abbreviated sha this estate emits; below that the risk of eating a real
#: word made only of a-f runs ahead of the benefit.
_HEX_SEGMENT = re.compile(r"\A[0-9a-fA-F]{12,}\Z")


def _route_of(uri: str) -> str:
    """Reduce a scanned URI to the route it exercised (see module docstring).

    Drops the query string and templates ephemeral path segments. Everything
    that survives is a decision the *application* made about its own shape, so
    it changes when the endpoint changes and not before.
    """
    try:
        path = urlparse(uri).path or "/"
    except ValueError:
        path = uri

    segments = [
        ROUTE_PLACEHOLDER
        if (_UUID_SEGMENT.match(segment) or _HEX_SEGMENT.match(segment))
        else segment
        for segment in path.split("/")
    ]
    return "/".join(segments) or "/"


def normalize(raw_output: bytes, context: ScanContext) -> AdapterResult:
    """Parse a ZAP baseline JSON report."""
    result = AdapterResult()

    try:
        text = raw_output.decode("utf-8", errors="replace").strip()
        document = json.loads(text) if text else {}
    except json.JSONDecodeError as exc:
        result.warn(f"ZAP output is not parseable JSON ({exc})")
        result.scan_status = ScanStatus.PARTIAL_FAILURE
        return result

    if not isinstance(document, dict):
        result.warn("ZAP output is not a JSON object")
        result.scan_status = ScanStatus.PARTIAL_FAILURE
        return result

    truncated = 0

    for site in document.get("site") or []:
        if not isinstance(site, dict):
            result.skipped += 1
            continue

        for alert in site.get("alerts") or []:
            if not isinstance(alert, dict):
                result.skipped += 1
                continue

            # `alertRef` first, `pluginid` only as the fallback. ZAP uses
            # `alertRef` to distinguish sub-alerts of one plugin — 10055-4
            # ("CSP: Wildcard Directive"), 10055-5 ("script-src unsafe-inline")
            # and 10055-6 ("style-src unsafe-inline") all carry pluginid 10055
            # and cweid 693. Keying on `pluginid` gave all three the same
            # rule_id, and since `title` is not a `compute_finding_id` input
            # for a finding with a `file_path`, three distinct alerts against
            # one URL collapsed to one finding_id and the last one serialised
            # won. Where a plugin has no sub-alerts `alertRef` equals the
            # pluginid, so single-alert plugins are unaffected.
            rule_id = str(alert.get("alertRef") or alert.get("pluginid") or "").strip()
            name = str(alert.get("alert") or "").strip()
            if not rule_id or not name:
                result.skipped += 1
                continue

            severity = _severity(alert)
            description = str(alert.get("desc") or "")
            solution = str(alert.get("solution") or "")
            cwe = str(alert.get("cweid") or "").strip()

            instances = [i for i in (alert.get("instances") or []) if isinstance(i, dict)]
            if not instances:
                # An alert with no instance is site-wide (a missing header on
                # every response, say). Keep it, anchored to the site.
                instances = [{"uri": str(site.get("@name") or ""), "method": "GET"}]

            if len(instances) > MAX_INSTANCES_PER_ALERT:
                truncated += len(instances) - MAX_INSTANCES_PER_ALERT
                instances = instances[:MAX_INSTANCES_PER_ALERT]

            for instance in instances:
                uri = str(instance.get("uri") or "")
                method = str(instance.get("method") or "GET").upper()
                route = _route_of(uri)

                result.findings.append(
                    FindingSubmission(
                        rule_id=(f"ZAP-{rule_id}" + (f"-CWE-{cwe}" if cwe else ""))[:255],
                        # The route, not the URI: a title that named a concrete
                        # repo uuid would be rewritten on every scan and would
                        # read as a finding about one row rather than a route.
                        title=f"{name} at {method} {route}"[:1000],
                        description="\n\n".join(p for p in (description, solution) if p)[
                            :100_000
                        ],
                        severity=severity,
                        # The request *is* the location. The concrete URI is
                        # kept below in `raw_finding_json["instance"]["uri"]`.
                        file_path=route[:2000] or "/",
                        # Method plus route: stable while the endpoint exists,
                        # and changes when it does. Deliberately not the
                        # matched evidence, which varies per response.
                        code_snippet=f"{method} {route}",
                        raw_finding_json={
                            **{k: v for k, v in alert.items() if k != "instances"},
                            "instance": instance,
                        },
                    )
                )

    if truncated:
        # Silent truncation would read as "that is all of them".
        result.warn(
            f"{truncated} additional ZAP instance(s) beyond "
            f"{MAX_INSTANCES_PER_ALERT} per alert were not ingested. A single "
            "alert matching hundreds of URLs is usually one systemic issue; "
            "raise the cap if you need every instance tracked separately."
        )

    if result.skipped:
        result.warn(f"{result.skipped} ZAP record(s) were unusable and skipped")
        result.scan_status = ScanStatus.PARTIAL_FAILURE

    return result
