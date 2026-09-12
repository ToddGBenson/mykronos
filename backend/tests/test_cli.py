"""The `mykronos` CLI — the commands an operator runs by hand.

`self-check` is the one that matters most here: it is the command somebody
runs when they suspect something is wrong, so a wrong answer from it costs
more than a wrong answer from a dashboard nobody opened.
"""

from __future__ import annotations

from mykronos import cli


class TestTheIngestionVerdict:
    """"Findings are being lost now" was printed from inside the network.

    That is the most alarming sentence `self-check` can produce, and the one
    vantage point it was produced from cannot establish it. A host inside this
    network reaches its own public hostname through hairpin NAT, which does
    not work here: `https://mykronos.toddbenson.net/healthz` is unreachable
    from the backend container AND from the host, while GitHub Actions uploads
    keep arriving.

    Measured 2026-09-12. `self-check` reported findings being lost; Actions
    runs 34683969779 and 34683887120 had landed at 08:43 and 08:41 that
    morning. Both carry a `github_workflow_run_id`, so both came from a
    GitHub-hosted runner — which cannot reach 192.168.0.14, so they went
    through the public URL. The URL was working for the callers that matter.

    The check is still right that the URL is unreachable from here. It was the
    consequence that needed evidence.
    """

    def test_a_recent_actions_upload_contradicts_the_loss_claim(self) -> None:
        [line] = cli.ingestion_verdict(4.9)

        assert "FROM HERE" in line
        assert "hairpin NAT" in line
        assert "being lost" not in line

    def test_no_recent_upload_keeps_the_stronger_wording(self) -> None:
        lines = cli.ingestion_verdict(30.0)

        assert "findings are being lost now" in lines[0]
        assert "No GitHub Actions upload for 30.0h" in lines[1], (
            "the corroborating fact should be stated, not just the alarm"
        )

    def test_an_unreadable_lake_is_not_permission_to_reassure(self) -> None:
        """`None` is "no evidence", which is not the same as "no problem".

        If the lake cannot be read, this command knows less than it did, and
        the safe direction is the alarm — with nothing appended, because there
        is no corroborating fact to offer.
        """
        lines = cli.ingestion_verdict(None)

        assert "findings are being lost now" in lines[0]
        assert len(lines) == 1

    def test_the_boundary_is_inclusive(self) -> None:
        """A grace period that excludes its own boundary flips on a rounding
        error, and this one decides which of two opposite sentences prints."""
        assert "FROM HERE" in cli.ingestion_verdict(cli._ACTIONS_UPLOAD_GRACE_HOURS)[0]
        assert "being lost" in cli.ingestion_verdict(
            cli._ACTIONS_UPLOAD_GRACE_HOURS + 0.1
        )[0]
