"""TheHub's tests/security step runs against a Redis it started itself.

TheHub's rate limiter keeps its counters in Redis and fails OPEN when the
store is unreachable (utils/rate_limiter.py, swallow_errors=True). The unit
task had no Redis, so on thehub/unit builds 324 and 325 every limit was a
no-op and test_rate_limit.py's 429 checks failed for a reason about the task,
not the code. These tests pin the fix: a local redis-server is started and
pinged before the step, and the step is refused, not run, when it won't answer.
"""

from __future__ import annotations

from pathlib import Path

import yaml

PIPELINE = Path(__file__).resolve().parents[2] / "deploy" / "concourse" / "pipelines" / "thehub.yml"


def _unit_script() -> str:
    document = yaml.safe_load(PIPELINE.read_text(encoding="utf-8"))
    (job,) = [j for j in document["jobs"] if j["name"] == "unit"]
    scripts: list[str] = []

    def walk(node: object) -> None:
        if isinstance(node, dict):
            run = node.get("run")
            if isinstance(run, dict):
                scripts.extend(a for a in run.get("args", []) if isinstance(a, str))
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(job)
    (script,) = [s for s in scripts if "pytest tests/security" in s]
    return script


def test_redis_is_started_and_pinged_before_tests_security() -> None:
    script = _unit_script()
    start = script.index("redis-server --daemonize yes")
    ping = script.index("redis-cli -h 127.0.0.1 -p 6379 ping")
    run = script.index("python -m pytest tests/security")
    assert start < ping < run


def test_the_step_is_refused_when_redis_does_not_answer() -> None:
    script = _unit_script()
    refusal = script.index('elif [ "$REDIS_UP" != true ]; then')
    run = script.index("python -m pytest tests/security")
    assert refusal < run
    branch = script[refusal:run]
    assert "sec_rc=1" in branch
    assert "::error::tests/security NOT RUN" in branch


def test_redis_listens_on_the_limiters_default_address() -> None:
    # TheHub's settings.redis_url defaults to redis://localhost:6379/0 and the
    # step sets no REDIS_URL, so the server must be on loopback port 6379.
    script = _unit_script()
    assert "--port 6379 --bind 127.0.0.1" in script
    assert "REDIS_URL" not in script.split("python -m pytest tests/security")[0].split(
        "redis-server --daemonize yes"
    )[1]
