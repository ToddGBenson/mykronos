"""The dashboard spider finishes inside its budget (TheHub incident 36403).

From 2026-10-21 every main run's spider hit its 600s budget with 1,400-2,200
responses and never reached 100%: the Findings tab's filter pills and summary
bar (#962) are links that each toggle one value in the query string, and ZAP's
default parameter handling (USE_ALL) treats every combination of values as a
new URL, so the crawl walks their power set. #968 rightly records an overrun as
a partial run, so both uploads went red and nothing could close by absence.

Measured against a page of such toggle links (5 filters, 18 values) with the
same ZAP build: USE_ALL was at 64% after 180s with 21,702 URLs; IGNORE_VALUE
reached 100% in 5s with 34. IGNORE_VALUE keys a URL on its parameter names,
the key ZAP's site tree and passive scanner already use.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "demo-and-dast.yml"


def _script() -> str:
    doc = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps: list[dict[str, Any]] = doc["jobs"]["demo-and-dast"]["steps"]
    found = [s for s in steps if s.get("name") == "Spider, and scan"]
    assert found
    return str(found[0]["run"])


def test_the_spider_keys_urls_on_parameter_names_not_values() -> None:
    script = _script()
    option = "/JSON/spider/action/setOptionHandleParameters/?String=IGNORE_VALUE"
    assert option in script, "the spider walks every combination of filter values"
    assert script.index(option) < script.index("/JSON/spider/action/scan/"), (
        "the option is set after the spider has started"
    )


def test_the_budget_is_not_raised_to_hide_an_unbounded_crawl() -> None:
    # The fix is a finite crawl, not a longer clock: an overrun still uploads
    # as a partial run.
    script = _script()
    assert 'poll "/JSON/spider/view/status/" 600' in script
    assert "the spider did not reach 100% within 600s" in script
