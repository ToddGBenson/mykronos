"""The detector benchmark (spec 23 §1).

Spec 04 §7's acceptance criterion — "at least one `Finding`" — has never been
implementable and could never have distinguished a scanner catching nine of ten
seeded injections from one catching one. So the platform runs fifteen checks
and cannot say how well any of them works on code like its own.

The tests worth reading are the ones about what the grader refuses to claim.
`test_unmatched_findings_are_not_false_positives` is the one that keeps a
quality number from being manufactured out of an assumption, and
`test_a_capability_with_nothing_seeded_has_no_recall` is spec 31 §3's
empty-denominator rule applied to a second number.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

import bench_grade  # noqa: E402


def seed(**overrides: Any) -> bench_grade.Seed:
    payload: dict[str, Any] = {
        "identifier": "sqli",
        "file": "src/orders/lookup.py",
        "line_start": 42,
        "line_end": 44,
        "capability": "sast",
        "description": "Order id concatenated into SQL.",
    }
    payload.update(overrides)
    return bench_grade.Seed(**payload)


def finding(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "capability": "sast",
        "file_path": "src/orders/lookup.py",
        "line_start": 42,
        "rule_id": "py/sql-injection",
        "severity": "high",
        "status": "open",
    }
    payload.update(overrides)
    return payload


class TestMatching:
    def test_a_finding_on_the_seeded_line_matches(self) -> None:
        grades, _ = bench_grade.grade([seed()], [finding()])

        assert grades["sast"].seeded_detected == 1

    def test_a_finding_a_few_lines_off_is_the_same_finding(self) -> None:
        """The fingerprint already assumes this much drift (spec 05 §5). A
        grader stricter than the platform's own identity model would report
        regressions the platform does not believe in."""
        grades, _ = bench_grade.grade([seed()], [finding(line_start=46)])

        assert grades["sast"].seeded_detected == 1

    def test_a_finding_far_away_does_not(self) -> None:
        grades, _ = bench_grade.grade([seed()], [finding(line_start=300)])

        assert grades["sast"].seeded_detected == 0

    def test_the_wrong_capability_does_not_count(self) -> None:
        """A secret scanner finding a SQL injection by accident is not the
        secrets lane working, and it is not the SAST lane working either."""
        grades, _ = bench_grade.grade([seed()], [finding(capability="secrets")])

        assert grades["sast"].seeded_detected == 0

    def test_a_finding_with_no_line_matches_on_the_file(self) -> None:
        """A dependency advisory, or a secret the scanner did not locate
        precisely. Refusing it would mark a real detection as a miss for
        lacking a coordinate the tool never produces."""
        grades, _ = bench_grade.grade([seed()], [finding(line_start=None)])

        assert grades["sast"].seeded_detected == 1

    def test_path_separators_do_not_decide_a_grade(self) -> None:
        """A Windows-shaped path and a POSIX one are the same file, and a
        benchmark that graded them differently would grade the runner."""
        grades, _ = bench_grade.grade(
            [seed()], [finding(file_path="./src\\orders\\lookup.py")]
        )

        assert grades["sast"].seeded_detected == 1

    def test_matching_is_never_on_rule_id(self) -> None:
        """A rule identifier is a free-form string the reporting tool chose
        (spec 18 §6). Pinning a grade to one would grade the naming, and every
        scanner rename would need a manifest rewrite."""
        grades, _ = bench_grade.grade([seed()], [finding(rule_id="totally-renamed")])

        assert grades["sast"].seeded_detected == 1


class TestWhatItRefusesToClaim:
    def test_unmatched_findings_are_not_false_positives(self) -> None:
        """The corpus is seeded, not *clean*. An unmatched finding may be a
        real flaw somebody wrote by accident while writing a fixture, and
        calling it a false positive would manufacture a quality number out of
        an assumption."""
        grades, unmatched = bench_grade.grade(
            [seed()], [finding(), finding(file_path="src/other.py", line_start=9)]
        )

        assert len(unmatched) == 1
        assert grades["sast"].seeded_detected == 1
        # And it fails nothing.
        assert grades["sast"].missed == []

    def test_no_precision_figure_exists(self) -> None:
        grade_obj = bench_grade.CapabilityGrade("sast")

        assert not hasattr(grade_obj, "precision")

    def test_a_capability_with_nothing_seeded_has_no_recall(self) -> None:
        """An empty denominator is not a failing grade — spec 31 §3's rule,
        applied to a second number. A lane with nothing to find has not failed
        to find it."""
        assert bench_grade.CapabilityGrade("dast").recall is None

    def test_the_summary_says_what_unmatched_means(self) -> None:
        grades, unmatched = bench_grade.grade(
            [seed()], [finding(file_path="src/other.py")]
        )
        text = bench_grade.render_summary(grades, unmatched)

        assert "Not reported as false positives" in text
        assert "seeded, not clean" in text


class TestTheManifest:
    def _write(self, tmp_path: Path, document: dict[str, Any]) -> Path:
        path = tmp_path / "manifest.yaml"
        path.write_text(yaml.safe_dump(document), encoding="utf-8")
        return path

    def test_the_shipped_example_loads(self) -> None:
        """It is the schema, so it has to parse with the parser."""
        example = Path(__file__).resolve().parents[2] / "bench-manifest.example.yaml"

        seeds = bench_grade.load_manifest(example)

        assert len(seeds) >= 5
        assert {s.capability for s in seeds} >= {"sast", "secrets", "iac"}

    def test_a_seed_with_no_capability_is_refused(self, tmp_path: Path) -> None:
        """Counting it as a miss would mark a detector down for the
        manifest's mistake."""
        path = self._write(tmp_path, {"seeded": [{"file": "a.py"}]})

        with pytest.raises(ValueError, match="capability"):
            bench_grade.load_manifest(path)

    def test_an_empty_manifest_is_refused(self, tmp_path: Path) -> None:
        """An empty corpus grades every detector at 100% recall, which is
        worse than not grading them at all."""
        path = self._write(tmp_path, {"seeded": []})

        with pytest.raises(ValueError, match="no seeded"):
            bench_grade.load_manifest(path)

    def test_a_single_line_becomes_a_window(self, tmp_path: Path) -> None:
        path = self._write(
            tmp_path, {"seeded": [{"file": "a.py", "line": 10, "capability": "sast"}]}
        )

        [entry] = bench_grade.load_manifest(path)

        assert (entry.line_start, entry.line_end) == (10, 10)


class TestTheReport:
    def _suite(self, seeds: list[Any], findings: list[Any]) -> ElementTree.Element:
        grades, unmatched = bench_grade.grade(seeds, findings)
        return ElementTree.fromstring(bench_grade.to_junit(grades, unmatched))

    def test_every_seed_gets_a_case(self) -> None:
        """`tests` has to equal the number of cases the report contains. A
        count with no cases behind it is a report nobody can check."""
        suite = self._suite([seed(), seed(identifier="b", file="src/b.py")], [finding()])

        assert suite.get("tests") == "2"
        assert len(suite.findall("testcase")) == 2

    def test_a_missed_seed_fails_its_case(self) -> None:
        suite = self._suite([seed()], [])

        assert suite.get("failures") == "1"
        assert suite.find("testcase/failure") is not None

    def test_the_failure_says_what_was_missed(self) -> None:
        """"The thing the scanner did not find" is only useful if somebody can
        tell what it was."""
        suite = self._suite([seed()], [])

        assert "concatenated into SQL" in (suite.find("testcase/failure").text or "")

    def test_a_detected_seed_passes(self) -> None:
        suite = self._suite([seed()], [finding()])

        assert suite.get("failures") == "0"
        assert suite.find("testcase/failure") is None

    def test_unmatched_is_a_property_not_a_case(self) -> None:
        """It is information. A lane whose green depends on nobody having
        written an extra bug into a fixture would be green for the wrong
        reason."""
        suite = self._suite([seed()], [finding(), finding(file_path="src/x.py")])

        values = {
            p.get("name"): p.get("value") for p in suite.findall("properties/property")
        }

        assert values["unmatched_findings"] == "1"
        assert suite.get("failures") == "0"

    def test_recall_is_published_per_capability(self) -> None:
        suite = self._suite(
            [seed(), seed(identifier="b", file="src/b.py")], [finding()]
        )
        values = {
            p.get("name"): p.get("value") for p in suite.findall("properties/property")
        }

        assert values["recall.sast"] == "0.5"


class TestTheFloor:
    """`--fail-under` is off unless asked for.

    The first runs of a new corpus establish a baseline, and a threshold
    picked before there is one is a number somebody invented — which would
    fail every build on day one of a corpus nobody has calibrated yet.
    """

    def _run(self, tmp_path: Path, monkeypatch: Any, *extra: str) -> int:
        manifest = tmp_path / "manifest.yaml"
        manifest.write_text(
            yaml.safe_dump(
                {"seeded": [{"file": "src/orders/lookup.py", "line": 42,
                             "capability": "sast"}]}
            ),
            encoding="utf-8",
        )
        # Nothing detected: the worst possible grade.
        monkeypatch.setattr(bench_grade, "findings_for", lambda *a, **k: [])
        # Something DID scan the commit — it just caught nothing. Stubbed
        # alongside `findings_for` since #60015, because these two facts are
        # now read separately and this class is about the case where the run
        # happened. Without this the grader would (correctly) refuse to grade
        # at all, and these tests would be asserting the wrong branch.
        monkeypatch.setattr(bench_grade, "scan_runs_for", lambda *a, **k: 4)
        return bench_grade.main(
            [
                str(manifest),
                "--repo", "acme/bench",
                "--commit", "a" * 40,
                "--lake", str(tmp_path),
                *extra,
            ]
        )

    def test_a_total_miss_still_exits_zero_without_a_floor(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """A measured 0% is still not a build failure unless a floor is set.

        Unchanged by #60015 and worth keeping distinct from it: this run was
        measured. Four scan runs looked at the commit and caught none of the
        seeded issues, which is a real grade of zero — the thing the story
        insisted must stay distinguishable from no grade at all.
        """
        assert self._run(tmp_path, monkeypatch) == bench_grade.EXIT_OK

    def test_the_same_run_fails_once_a_floor_is_set(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        assert (
            self._run(tmp_path, monkeypatch, "--fail-under", "0.8")
            == bench_grade.EXIT_FAILED
        )

    def test_a_capability_below_the_floor_is_named(self) -> None:
        grades, _ = bench_grade.grade([seed()], [])
        below = [
            g.capability
            for g in grades.values()
            if g.recall is not None and g.recall < 0.8
        ]

        assert below == ["sast"]


class TestAGradeThatCouldNotBeTaken:
    """#60015: 0% recall and "no grade" must not be the same exit code.

    Before this, every real run of the grader hit an empty lake — the corpus
    repo does not exist — scored 0% on every capability and returned 0. A
    typo'd `--repo`, a lake nobody wrote, and a detector that genuinely missed
    everything were one number, so wiring this into a pipeline would have added
    a permanently green lane reporting 0%.
    """

    def _manifest(self, tmp_path: Path) -> Path:
        manifest = tmp_path / "manifest.yaml"
        manifest.write_text(
            yaml.safe_dump(
                {"seeded": [{"file": "src/orders/lookup.py", "line": 42,
                             "capability": "sast"}]}
            ),
            encoding="utf-8",
        )
        return manifest

    def _run(self, tmp_path: Path, *extra: str) -> int:
        return bench_grade.main(
            [
                str(self._manifest(tmp_path)),
                "--repo", "acme/bench",
                "--commit", "a" * 40,
                "--lake", str(tmp_path),
                *extra,
            ]
        )

    def test_an_empty_lake_is_not_a_zero_percent_grade(
        self, tmp_path: Path, capsys: Any
    ) -> None:
        """The exact run this script does today, and it must not be green.

        No stub anywhere: `tmp_path` holds no `scan_runs` partition, which is
        what the real lake looks like for a corpus that was never built.
        """
        assert self._run(tmp_path) == bench_grade.EXIT_NOT_MEASURED

        error = capsys.readouterr().err
        assert "NOT MEASURED" in error
        # The message has to carry the distinction, not just the number: an
        # operator reading "0%" and an operator reading this must not go and
        # investigate the same thing.
        assert "no scan run" in error
        assert "0% would mean the detectors ran and missed" in error

    def test_a_floor_does_not_turn_an_unmeasured_run_into_a_failure(
        self, tmp_path: Path
    ) -> None:
        """Still 3, not 1, with `--fail-under` set.

        The floor grades detectors. Reporting "below the floor" for a commit
        nothing scanned would blame the detectors for the corpus being absent,
        and send somebody to fix a scanner that is working.
        """
        assert (
            self._run(tmp_path, "--fail-under", "0.8")
            == bench_grade.EXIT_NOT_MEASURED
        )

    def test_scan_runs_present_but_no_findings_is_a_real_zero(
        self, tmp_path: Path, monkeypatch: Any, capsys: Any
    ) -> None:
        """The other side of the line, and the one easy to get wrong.

        A lane that ran and correctly found nothing writes a scan run and no
        finding rows. That is the cleanest possible measurement, and inferring
        "not measured" from the absence of findings would report it as the
        opposite of what it is.
        """
        monkeypatch.setattr(bench_grade, "scan_runs_for", lambda *a, **k: 2)
        monkeypatch.setattr(bench_grade, "findings_for", lambda *a, **k: [])

        assert self._run(tmp_path) == bench_grade.EXIT_OK
        assert "Graded against 2 scan run(s)" in capsys.readouterr().out

    def test_an_unreadable_lake_is_not_a_failing_grade(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """A corrupt lake used to arrive as an uncaught traceback — exit 1,
        the same number as "a capability fell below the floor"."""
        def explode(*a: Any, **k: Any) -> int:
            raise bench_grade.CouldNotMeasure("parquet is not readable")

        monkeypatch.setattr(bench_grade, "scan_runs_for", explode)

        assert (
            self._run(tmp_path, "--fail-under", "0.8")
            == bench_grade.EXIT_NOT_MEASURED
        )

    def test_an_empty_parquet_directory_reads_as_no_runs_not_as_an_error(
        self, tmp_path: Path
    ) -> None:
        """`_has_parquet` is checked on the filesystem, not by catching duckdb.

        A `scan_runs/` directory that exists and holds no parquet is the state
        a freshly-initialised lake is in, and it must reach the "nothing
        scanned this commit" branch rather than the "lake is broken" one.
        """
        (tmp_path / "scan_runs").mkdir()

        assert not bench_grade._has_parquet(tmp_path / "scan_runs")
        assert bench_grade.scan_runs_for(tmp_path, "acme/bench", "a" * 40) == 0

    def test_an_empty_findings_partition_is_no_findings_not_an_error(
        self, tmp_path: Path
    ) -> None:
        """`findings_for` over a lake with no findings must return [], not raise.

        This is the asymmetry between the two reads and the easy one to get
        backwards. An absent `scan_runs` partition means nothing scanned the
        commit, which is "could not measure". An absent `findings` partition
        means the scanners ran and reported nothing, which is a perfect result.
        Raising here would report a clean corpus as a broken lake.
        """
        assert bench_grade.findings_for(tmp_path, "acme/bench", "a" * 40) == []

    def test_the_two_controls_agree_on_what_the_numbers_mean(self) -> None:
        """#60015 asked for the distinction in BOTH tools' exit codes.

        The constants are declared twice — `bench_grade` runs standalone in a
        pipeline container with no `mykronos` package importable — so this is
        what stops the two halves of one convention from drifting into two
        conventions.
        """
        from mykronos import host_controls

        for name in ("EXIT_OK", "EXIT_FAILED", "EXIT_USAGE", "EXIT_NOT_MEASURED"):
            assert getattr(bench_grade, name) == getattr(host_controls, name), name

        assert bench_grade.EXIT_NOT_MEASURED == 3
        assert len(
            {
                bench_grade.EXIT_OK,
                bench_grade.EXIT_FAILED,
                bench_grade.EXIT_USAGE,
                bench_grade.EXIT_NOT_MEASURED,
            }
        ) == 4
