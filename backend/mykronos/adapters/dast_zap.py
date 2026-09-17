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

**An alert whose subject is the scanner is not a finding against the target**
(#303). `ZAP is Out of Date` (pluginid 10116) reads, in full, "The latest
version of ZAP is 2.17.0". That is the scanner reporting on *itself*, and ZAP
attaches it to whichever URI it happened to crawl — this estate's archive has
it landing on `/frontend/img/hub-icon.svg`, `/sitemap.xml`, `/healthz`,
`/frontend/css/bundle.css?v=…` and a dozen `/repos/{id}` pages. Nothing is
wrong with any of them. Measured across the archived raw reports it is the
single most frequent alert the lane has ever produced (160 instances, ahead of
`10031`'s 94), and it had accumulated 24 finding identities: 19 recorded
`fixed` because the arbitrary URI moved, 4 dismissed `false_positive` by hand,
1 open.

Two things this deliberately is *not*:

- **Not a `riskcode` filter.** #273 proposes dropping ZAP's Informational band
  (`riskcode` 0), which handles the 22 `ZAP-10031` rows cleanly and does not
  touch this one: `10116` is `riskcode: "1"` (Low) at `confidence: "3"`, a
  higher severity than the noise the informational filter is aimed at.
- **Not a deny-list of rule ids.** A list of "rules we ignore" keyed on plugin
  numbers is the maintenance shape #324 objects to, and it is where real
  findings go to be forgotten. `_is_about_the_scanner` states the actual
  category instead — the alert's own text names ZAP as its subject — so a
  future ZAP release that renumbers or adds a sibling self-report is caught
  without anyone editing a list.

And it is **recorded, not dropped**. It becomes a warning on the
`AdapterResult`, which the uploader puts in the CI step summary and in the
ScanRun's `detail` — so the lane says "zap 2.16.1, latest 2.17.0" beside the
run it belongs to. A rule filtered out of the findings table and written
nowhere is worse than a misattributed finding: at least the misattribution is
visible, and silence is how a scanner quietly stops being a control. It does
not touch `scan_status`, because a DAST lane a minor version behind is a
lane-quality signal and not a release blocker.

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


#: The alert's own name opening with the scanner's name. ZAP titles say what
#: is wrong with the *target* — "Content Security Policy Header Not Set",
#: "Absence of Anti-CSRF Tokens", "Sub Resource Integrity Attribute Missing" —
#: so a title whose grammatical subject is "ZAP" is the tool talking about the
#: tool. Checked against every alert in this estate's archived raw reports:
#: eighteen distinct (pluginid, alert) pairs, and `10116 ZAP is Out of Date`
#: is the only one that matches.
_SCANNER_IS_THE_SUBJECT = re.compile(r"\A\s*(?:OWASP\s+)?ZAP\b", re.IGNORECASE)

#: ZAP stating a version of itself, as a second, independent tell for the same
#: category — so a retitled or newly added self-report is still caught. Scoped
#: to `otherinfo`, which is the alert's per-finding evidence field, and not to
#: `solution`: "upgrade to the latest version of ZAP" is remediation advice and
#: could in principle appear on a real finding, whereas "the latest version of
#: ZAP is 2.17.0" is a statement of fact about the scanner.
_ZAP_VERSION_STATEMENT = re.compile(r"version of ZAP is\s*([0-9][\w.\-]*)", re.IGNORECASE)

#: ZAP's text fields are HTML fragments (`<p>The latest version…</p>`).
_TAG = re.compile(r"<[^>]+>")


def _is_about_the_scanner(alert: dict[str, Any], name: str) -> bool:
    """Is this alert a statement about ZAP rather than about the target?

    The discriminator #303 asks for. Deliberately a predicate over the alert's
    own words rather than a list of plugin ids: the category is "the subject is
    the scanner", and a list of numbers records which members of the category
    someone happened to meet, which is the thing that rots.
    """
    if _SCANNER_IS_THE_SUBJECT.match(name):
        return True
    return bool(_ZAP_VERSION_STATEMENT.search(str(alert.get("otherinfo") or "")))


def _lane_health_note(
    alert: dict[str, Any],
    name: str,
    rule_id: str,
    running_version: str,
    context: ScanContext,
) -> str:
    """One line for the lane, standing in for the finding that was not filed.

    Front-loaded, because the uploader copies only `warnings[0]` into the
    ScanRun's `detail` and truncates it at 200 characters. Everything a person
    needs to act — which scanner, which version, that it is not about their
    application — has to fit before that cut.
    """
    match = _ZAP_VERSION_STATEMENT.search(str(alert.get("otherinfo") or ""))
    latest = f", latest {match.group(1)}" if match else ""
    running = running_version or "version unreported"
    title = _TAG.sub(" ", name).strip()
    return (
        f"zap {running}{latest}: \"{title}\" ({rule_id}) is about the scanner, "
        f"not about {context.repo_full_name} — recorded as lane health rather "
        f"than a finding (#303). It does not gate. ZAP attaches this alert to "
        f"whichever URI it happened to crawl, so the file path it named was "
        f"arbitrary."
    )


def _rule_id(alert_ref: str, cwe: str) -> str:
    return (f"ZAP-{alert_ref}" + (f"-CWE-{cwe}" if cwe else ""))[:255]


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
    #: One note per distinct self-report, not one per instance: ZAP files the
    #: same statement about itself against every URI it crawled, and 24 copies
    #: of "your scanner is out of date" is the noise this is removing.
    lane_health: list[str] = []
    #: The running scanner, straight from the report ZAP wrote — `"@version":
    #: "2.16.1"`. Not `context.tool_version`, which the DAST lane leaves empty:
    #: `deploy/concourse/pipelines/thehub.yml` passes no `--tool-version`, and
    #: `detect_tool_version` only recovers one from SARIF, which ZAP is not.
    running_version = str(document.get("@version") or "").strip()

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

            cwe = str(alert.get("cweid") or "").strip()

            # #303. Routed to the lane, not filed against the application, and
            # not counted in `skipped` — `skipped` means "the parser could not
            # make sense of this", which marks the run PARTIAL_FAILURE. This
            # record was understood perfectly; it is simply not a finding about
            # the target.
            if _is_about_the_scanner(alert, name):
                note = _lane_health_note(
                    alert, name, _rule_id(rule_id, cwe), running_version, context
                )
                if note not in lane_health:
                    lane_health.append(note)
                continue

            severity = _severity(alert)
            description = str(alert.get("desc") or "")
            solution = str(alert.get("solution") or "")

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
                        rule_id=_rule_id(rule_id, cwe),
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

    # Before the truncation warning, because only the first warning survives
    # into the ScanRun's `detail`: a truncated alert still leaves 25 findings
    # in the table to notice, whereas this note is the *only* record that the
    # self-report happened at all.
    for note in lane_health:
        result.warn(note)

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
