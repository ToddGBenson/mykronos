"""A practice a repository cannot evidence is not a practice it failed (B-058).

`ssdf.summarise` counted four statuses and the fourth was zero everywhere,
because nothing set it. `keel` was marked down on PW.4 for not scanning
containers it does not build, and on RV.1 for not running DAST against an
application that does not exist; `personal-soc` is PowerShell with no build
artifact at all. On a compliance view an understatement is not the safe
direction to be wrong in -- it is the one that gets somebody told to build
what they do not need, or to switch a lane on over an empty target purely to
move a number.

The inference only ever runs one way. An absence of Dockerfiles is strong
evidence that no image is built; their presence proves nothing about anything
else. Anything not positively established stays applicable, because a wrong
`not_applicable` converts "we did not look" into "this does not apply to us".
"""

from __future__ import annotations

from mykronos import composition, ssdf


def read(*paths: str) -> composition.Composition:
    return composition.read(list(paths))


class TestReadingATree:
    def test_a_tree_that_could_not_be_read_claims_nothing(self) -> None:
        """The distinction the whole module rests on: "we looked and there are
        no Dockerfiles" against "we did not look"."""
        unknown = composition.read(None)

        assert unknown.unknown is True
        assert composition.inapplicable(unknown) == {}

    def test_an_empty_repository_is_known_and_empty(self) -> None:
        """Different from unreadable: this one was listed, and it has nothing
        in it."""
        empty = composition.read([])

        assert empty.unknown is False
        assert "containers" in composition.inapplicable(empty)

    def test_a_dockerfile_anywhere_counts(self) -> None:
        for path in ("Dockerfile", "deploy/Dockerfile", "Dockerfile.prod", "src/Containerfile"):
            assert read(path).builds_container, path

    def test_a_workflow_is_infrastructure_the_iac_lane_reads(self) -> None:
        """`CKV_GHA_*` is where this platform's own IaC findings come from, so
        a repository with ten workflows and no Terraform has a real IaC
        surface -- which is why `iac` was the one capability enabled on both
        of these repositories on 2026-09-04."""
        assert read(".github/workflows/ci.yml").has_iac

    def test_terraform_and_compose_count_too(self) -> None:
        assert read("infra/main.tf").has_iac
        assert read("docker-compose.yml").has_iac

    def test_a_dependency_manifest_is_recognised(self) -> None:
        for path in ("requirements.txt", "backend/pyproject.toml", "web/package.json", "go.mod"):
            assert read(path).declares_dependencies, path

    def test_the_test_matcher_is_deliberately_generous(self) -> None:
        """Claiming a repository has no tests is the inference most likely to
        be wrong, and being wrong tells a team their tests do not count."""
        for path in (
            "tests/test_thing.py",
            "test/dashboard.test.py",
            "src/__tests__/thing.test.tsx",
            "pkg/thing_test.go",
            "Module.Tests.ps1",
            "src/ThingTest.java",
        ):
            assert read(path).has_tests, path

    def test_a_shell_only_repository_has_none_of_it(self) -> None:
        shell = read("bin/run.sh", "lib/helpers.ps1", "README.md")

        assert not shell.builds_container
        assert not shell.declares_dependencies
        assert not shell.has_tests


class TestWhatIsRuledOut:
    def test_no_dockerfile_rules_out_containers_and_dast(self) -> None:
        """DAST needs something running to point at, and this estate deploys
        images."""
        out = composition.inapplicable(read("main.py", "requirements.txt", "tests/test_x.py"))

        assert "containers" in out
        assert "dast" in out
        assert "Dockerfile" in out["containers"]

    def test_a_repository_that_builds_an_image_rules_out_nothing_there(self) -> None:
        out = composition.inapplicable(
            read("Dockerfile", "requirements.txt", "tests/test_x.py", ".github/workflows/ci.yml")
        )

        assert out == {}

    def test_no_tests_rules_out_all_three_test_lanes(self) -> None:
        out = composition.inapplicable(read("Dockerfile", "requirements.txt", "app.py"))

        assert {"unit", "functional", "qa"} <= set(out)
        assert "containers" not in out

    def test_every_reason_reads_as_a_sentence(self) -> None:
        """"No container image is built here" reads differently from "the
        container lane has never run", and that difference is the entry."""
        for reason in composition.inapplicable(read("README.md")).values():
            assert reason[0].islower()
            assert len(reason.split()) >= 5


class TestThroughTheAssessment:
    def _assess(self, inapplicable=None, **kwargs):
        base = dict(
            reporting_capabilities=set(),
            enabled_capabilities=set(),
            confirmed_controls=set(),
            known_controls=set(),
        )
        base.update(kwargs)
        return {
            result.practice_id: result
            for result in ssdf.assess(**base, inapplicable_capabilities=inapplicable)
        }

    def test_a_practice_whose_every_lane_is_inapplicable_is_not_applicable(self) -> None:
        """PW.4 is atlas and containers. `personal-soc` has neither, and was
        reported as failing to reuse well-secured software."""
        results = self._assess(
            inapplicable={
                "atlas": "no dependency manifest is declared here",
                "containers": "no container image is built here",
            }
        )

        assert results["PW.4"].status == "not_applicable"
        assert results["PW.4"].missing == []
        assert len(results["PW.4"].not_applicable_because) == 2

    def test_an_inapplicable_lane_is_not_a_gap_beside_a_reporting_one(self) -> None:
        """RV.1 is five lanes. `keel` reports two and cannot have three, which
        is met -- it was `partial`, and the shortfall named containers it does
        not build."""
        results = self._assess(
            reporting_capabilities={"sast", "secrets"},
            inapplicable={
                "containers": "no container image is built here",
                "atlas": "no dependency manifest is declared here",
                "dast": "nothing here is deployed as a running application",
            },
        )

        assert results["RV.1"].status == "met"
        assert results["RV.1"].missing == []

    def test_a_reporting_lane_beats_the_inference(self) -> None:
        """If the lane is actually producing scans then whatever the file
        listing suggested is wrong, and the observation wins."""
        results = self._assess(
            reporting_capabilities={"containers"},
            inapplicable={"containers": "no container image is built here"},
        )

        assert "containers lane is reporting successful scans" in results["PW.4"].evidence
        assert results["PW.4"].not_applicable_because == []

    def test_a_lane_that_is_merely_not_enabled_is_still_a_gap(self) -> None:
        """The whole point is telling the two apart. Nothing observed says
        this repository has no dependencies, so PW.4 is outstanding work."""
        results = self._assess(enabled_capabilities=set())

        assert results["PW.4"].status == "not_evidenced"
        assert results["PW.4"].not_applicable_because == []

    def test_unknown_composition_changes_nothing(self) -> None:
        """A tree the platform could not read must not quietly excuse a
        repository from anything."""
        with_none = self._assess(inapplicable=composition.inapplicable(composition.read(None)))
        without = self._assess()

        assert [r.status for r in with_none.values()] == [r.status for r in without.values()]

    def test_the_counts_keep_not_applicable_separate(self) -> None:
        """"12 of 13, one not applicable" and "12 of 13, one outstanding" are
        different sentences about different repositories."""
        results = self._assess(
            inapplicable={
                "atlas": "no dependency manifest is declared here",
                "containers": "no container image is built here",
            }
        )
        counts = ssdf.summarise(list(results.values()))

        assert counts["not_applicable"] >= 1
        assert set(counts) == {"met", "partial", "not_evidenced", "not_applicable"}
