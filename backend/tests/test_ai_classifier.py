"""The AI-authorship classifier call — spec 20 §1.

`ai_authorship_flag` has had three-state logic, a `SIGNAL_CAP` entry, and a
dead "configured but unreachable" branch since spec 06. `ai_classifier_url`
has been a validated config field. Nothing anywhere called it — the workflow
template said so in a comment. This wires the call.

Every assertion here is about a failure staying *null*. The one thing a local
runner must never say is "we checked, it is human", and there are five ways to
get there wrongly: no classifier, an unreachable one, a malformed answer, a
non-boolean, and a hedge.
"""

from __future__ import annotations

import json

import pytest
import yaml

from mykronos.aegis_signals import (
    AI_CLASSIFIER_MIN_CONFIDENCE,
    main,
    parse_classifier_result,
)
from mykronos.capabilities import AegisConfig
from mykronos.config import get_settings
from mykronos.installer import TemplateLibrary


class TestParsingTheAnswer:
    def test_a_confident_yes_is_true(self) -> None:
        assert parse_classifier_result({"ai_authored": True, "confidence": 0.95}) is True

    def test_a_confident_no_is_false(self) -> None:
        """The only path on which this platform is entitled to record `false`.
        A classifier was configured, it answered, and it was sure."""
        assert parse_classifier_result({"ai_authored": False, "confidence": 0.9}) is False

    def test_a_hedge_is_null(self) -> None:
        """"Probably, 0.3" has established nothing, and spec 06 §5 has a value
        for exactly that. Recording it as true would let a guess read as a
        finding about a person."""
        assert parse_classifier_result({"ai_authored": True, "confidence": 0.3}) is None

    @pytest.mark.parametrize(
        "payload",
        [
            None,
            "yes",
            {},
            {"ai_authored": True},
            {"confidence": 0.9},
            {"ai_authored": "true", "confidence": 0.9},
            {"ai_authored": True, "confidence": "high"},
            {"ai_authored": True, "confidence": 1.5},
            {"ai_authored": True, "confidence": True},
        ],
    )
    def test_anything_else_is_null(self, payload) -> None:
        """A boolean and a confidence float, nothing else accepted. The
        classifier is a third party by construction — letting free-form text
        back from it into a record about a named colleague would give away on
        the return trip what spec 06 §5 protects on the way out."""
        assert parse_classifier_result(payload) is None

    def test_the_threshold_is_a_named_constant(self) -> None:
        """Where the line sits is a judgement, and a judgement buried in a
        comparison is one nobody can find to argue with."""
        assert 0.5 <= AI_CLASSIFIER_MIN_CONFIDENCE <= 1.0


class TestTheScorerReadsIt:
    def reviews_file(self, tmp_path):
        """One independent approval, saying nothing about verification.

        `unverified_ai` is about a machine writing a change and no person
        checking it — with no reviews at all, `self_approval` and the plain
        absence of review already cover the case, so it stays silent. That is
        the state these tests have to get past to see it fire.
        """
        path = tmp_path / "reviews.json"
        path.write_text(
            json.dumps(
                [{"user": {"login": "reviewer"}, "state": "APPROVED", "body": "lgtm"}]
            ),
            encoding="utf-8",
        )
        return str(path)

    def run(self, tmp_path, monkeypatch, capsys, classifier=None, reviews=False):
        monkeypatch.chdir(tmp_path)
        args = [
            "--pr-number", "1",
            "--commit-sha", "abc123",
            "--author", "octocat",
            "--base-ref", "HEAD",
            "--head-ref", "HEAD",
        ]
        if classifier is not None:
            path = tmp_path / "classifier.json"
            path.write_text(
                classifier if isinstance(classifier, str) else json.dumps(classifier),
                encoding="utf-8",
            )
            args += ["--ai-classifier-file", str(path)]
        if reviews:
            args += ["--reviews-file", self.reviews_file(tmp_path)]
        main(args)
        return json.loads(capsys.readouterr().out)

    def test_no_classifier_means_null(self, tmp_path, monkeypatch, capsys) -> None:
        payload = self.run(tmp_path, monkeypatch, capsys)

        assert payload["ai_authorship_flag"] is None

    def test_a_missing_file_means_null(self, tmp_path, monkeypatch, capsys) -> None:
        """The "configured but unreachable" branch — the one the platform has
        modelled since spec 06 and never been able to exercise. The workflow
        step deletes its output file when curl fails, so this is that."""
        monkeypatch.chdir(tmp_path)
        main(
            [
                "--pr-number", "1",
                "--commit-sha", "abc",
                "--author", "octocat",
                "--base-ref", "HEAD",
                "--head-ref", "HEAD",
                "--ai-classifier-file", str(tmp_path / "never-written.json"),
            ]
        )

        assert json.loads(capsys.readouterr().out)["ai_authorship_flag"] is None

    def test_unparseable_json_means_null(self, tmp_path, monkeypatch, capsys) -> None:
        payload = self.run(tmp_path, monkeypatch, capsys, classifier="{not json")

        assert payload["ai_authorship_flag"] is None

    def test_a_confident_answer_reaches_the_payload(
        self, tmp_path, monkeypatch, capsys
    ) -> None:
        payload = self.run(
            tmp_path, monkeypatch, capsys, {"ai_authored": True, "confidence": 0.9}
        )

        assert payload["ai_authorship_flag"] is True

    def test_the_classifier_can_raise_unverified_ai(
        self, tmp_path, monkeypatch, capsys
    ) -> None:
        """The point of feeding it in before scoring rather than after. A PR
        that did not disclose AI assistance, classified as AI-authored, is
        exactly the case `unverified_ai` exists for — and the description
        alone would have missed it."""
        payload = self.run(
            tmp_path,
            monkeypatch,
            capsys,
            {"ai_authored": True, "confidence": 0.9},
            reviews=True,
        )

        assert any(s["key"] == "unverified_ai" for s in payload["signals"])

    def test_it_cannot_withdraw_a_disclosure(self, tmp_path, monkeypatch, capsys) -> None:
        """A pull request that says it was AI-assisted was, whatever a model
        thinks. `unverified_ai` is about the gap between disclosure and
        review, not about the model's opinion."""
        monkeypatch.chdir(tmp_path)
        body = tmp_path / "body.txt"
        body.write_text("Written with Claude's help.", encoding="utf-8")
        classifier = tmp_path / "classifier.json"
        classifier.write_text(
            json.dumps({"ai_authored": False, "confidence": 0.99}), encoding="utf-8"
        )

        main(
            [
                "--pr-number", "1",
                "--commit-sha", "abc",
                "--author", "octocat",
                "--base-ref", "HEAD",
                "--head-ref", "HEAD",
                "--pr-body-file", str(body),
                "--ai-classifier-file", str(classifier),
                "--reviews-file", self.reviews_file(tmp_path),
            ]
        )
        payload = json.loads(capsys.readouterr().out)

        # The flag reports what the classifier said; the signal reports what
        # the author said. They are different questions.
        assert payload["ai_authorship_flag"] is False
        assert any(s["key"] == "unverified_ai" for s in payload["signals"])


class TestTheWorkflowTemplate:
    def render(self, **config):
        library = TemplateLibrary(get_settings().workflow_templates_dir)
        return library.render(
            "aegis",
            repo_full_name="acme/widgets",
            default_branch="main",
            ingestion_api_url="https://mykronos.example",
            token_secret_name="MYKRONOS_TOKEN",
            upload_action_ref="ToddGBenson/mykronos@v1",
            mykronos_package_spec="mykronos @ git+https://example.invalid@v1",
            config=config,
        ).content

    def test_unconfigured_renders_no_step_at_all(self) -> None:
        """Not a step that runs and no-ops. Somebody auditing what this
        workflow sends to third parties should be able to see the answer by
        reading it, and an `if:`-guarded step that posts a diff is a step that
        posts a diff as far as that reading goes."""
        rendered = self.render()

        assert "classifier" not in rendered.lower()

    def test_configured_renders_the_call(self) -> None:
        rendered = self.render(ai_classifier_url="https://classify.example/v1")

        assert "https://classify.example/v1" in rendered
        assert "--ai-classifier-file classifier.json" in rendered

    def test_it_is_still_valid_yaml(self) -> None:
        assert yaml.safe_load(
            self.render(ai_classifier_url="https://classify.example/v1")
        )

    def test_the_credential_is_a_secret_reference(self) -> None:
        """spec 12 §2. A workflow file is something anybody with read access
        can see, so the template carries the secret's name and never a
        value."""
        rendered = self.render(ai_classifier_url="https://classify.example/v1")

        assert "secrets.MYKRONOS_AI_CLASSIFIER_TOKEN" in rendered

    def test_the_secret_name_is_configurable(self) -> None:
        rendered = self.render(
            ai_classifier_url="https://classify.example/v1",
            ai_classifier_secret_name="ACME_CLASSIFIER_KEY",
        )

        assert "secrets.ACME_CLASSIFIER_KEY" in rendered

    def test_the_step_cannot_fail_the_job(self) -> None:
        """A slow or down classifier costs one flag, never the assessment.
        The other signals are still worth publishing."""
        rendered = self.render(ai_classifier_url="https://classify.example/v1")

        assert "continue-on-error: true" in rendered

    def test_the_classifier_runs_before_the_scorer(self) -> None:
        """Its answer is an input to the assessment, not a footnote on it. A
        step producing classifier.json after the scorer read it would have
        silently done nothing."""
        rendered = self.render(ai_classifier_url="https://classify.example/v1")

        assert rendered.index("Ask the configured AI-authorship classifier") < rendered.index(
            "python -m mykronos.aegis_signals"
        )

    def test_the_diff_is_capped(self) -> None:
        """An unbounded POST of a forty-megabyte refactor to a third party is
        a different act from asking about a change somebody could read."""
        rendered = self.render(ai_classifier_url="https://classify.example/v1")

        assert "head -c 200000" in rendered

    def test_the_diff_does_not_outlive_the_request(self) -> None:
        rendered = self.render(ai_classifier_url="https://classify.example/v1")

        assert "rm -f classifier-diff.txt" in rendered

    def test_aegis_still_cannot_write_to_pull_requests(self) -> None:
        """spec 06 §6, re-asserted because this change touched the template
        that carries the guarantee."""
        rendered = self.render(ai_classifier_url="https://classify.example/v1")
        permissions = yaml.safe_load(rendered)["permissions"]

        assert permissions["pull-requests"] == "read"


class TestConfig:
    def test_the_secret_name_defaults(self) -> None:
        assert AegisConfig().ai_classifier_secret_name == "MYKRONOS_AI_CLASSIFIER_TOKEN"

    def test_a_lowercase_secret_name_is_refused(self) -> None:
        """GitHub secret names are uppercase; a lowercase one silently
        resolves to empty, which sends an empty bearer token."""
        with pytest.raises(ValueError):
            AegisConfig(ai_classifier_secret_name="my_token")

    def test_no_default_classifier_endpoint(self) -> None:
        """spec 12 §5.2: a deployment that changed no configuration must
        never be shipping its code to a third party."""
        assert AegisConfig().ai_classifier_url is None
