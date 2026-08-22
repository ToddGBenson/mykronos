"""The rotation warning must not be the thing that breaks the upload.

`_warn_rotated` exists because a token rotation spent 24 hours in green build
logs before the 2026-08-15 401 outage. It then crashed on the naive timestamp
the server actually sends — so from the 2026-08-21 run onward, a repository
inside its overlap window had *every* upload fail with a TypeError raised
inside the warning about that very window.

The tests below pin both shapes of header, because the reason the bug survived
review is that the aware case reads correctly and is the one a person imagines.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

import pytest

from mykronos.upload import IngestionClient


@pytest.fixture
def uploader() -> IngestionClient:
    return IngestionClient.__new__(IngestionClient)


class TestANaiveDeadline:
    """What the server sends: every timestamp in this platform is naive UTC."""

    def test_it_does_not_raise(
        self, uploader: IngestionClient, caplog: pytest.LogCaptureFixture
    ) -> None:
        soon = datetime.now(UTC).replace(tzinfo=None) + timedelta(hours=48)

        with caplog.at_level(logging.WARNING):
            uploader._warn_rotated(soon.isoformat())

        assert caplog.records

    def test_the_last_six_hours_are_an_error(
        self, uploader: IngestionClient, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The distinction the outage bought: a warning that looks like every
        other log line is not a signal."""
        soon = datetime.now(UTC).replace(tzinfo=None) + timedelta(hours=2)

        with caplog.at_level(logging.WARNING):
            uploader._warn_rotated(soon.isoformat())

        assert any(record.levelno >= logging.ERROR for record in caplog.records)

    def test_a_distant_deadline_stays_a_warning(
        self, uploader: IngestionClient, caplog: pytest.LogCaptureFixture
    ) -> None:
        distant = datetime.now(UTC).replace(tzinfo=None) + timedelta(days=5)

        with caplog.at_level(logging.WARNING):
            uploader._warn_rotated(distant.isoformat())

        assert caplog.records
        assert all(record.levelno < logging.ERROR for record in caplog.records)


class TestAnAwareDeadline:
    """An older server may legitimately send one, which is why the fix
    normalises rather than assuming."""

    def test_it_does_not_raise(
        self, uploader: IngestionClient, caplog: pytest.LogCaptureFixture
    ) -> None:
        soon = datetime.now(UTC) + timedelta(hours=48)

        with caplog.at_level(logging.WARNING):
            uploader._warn_rotated(soon.isoformat())

        assert caplog.records


class TestAHeaderWithNoDeadline:
    def test_true_is_still_handled(
        self, uploader: IngestionClient, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Older servers send "true" and no time. It warns, without a
        deadline, and does not crash."""
        with caplog.at_level(logging.WARNING):
            uploader._warn_rotated("true")

        assert caplog.records
