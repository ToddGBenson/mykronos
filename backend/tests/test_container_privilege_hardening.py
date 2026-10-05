"""Production containers start with no privilege and cannot gain any.

The backend image's remaining high CVEs with no Debian fix (libacl symlink
traversal, systemd-homed) need a privileged caller to matter. These pin what
guarantees there is none: no setuid/setgid binary in the image, and
no-new-privileges plus no capabilities at runtime. Verified on 2026-10-05
against both images run with these options: healthy, 0 setuid binaries,
CapEff 0, NoNewPrivs 1.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def _service(name: str) -> dict:
    compose = yaml.safe_load((ROOT / "deploy" / "mykronos" / "docker-compose.yml").read_text(encoding="utf-8"))
    return compose["services"][name]


def test_backend_and_frontend_drop_every_capability_and_cannot_gain_one():
    for name in ("backend", "frontend"):
        svc = _service(name)
        assert "no-new-privileges:true" in svc.get("security_opt", []), name
        assert svc.get("cap_drop") == ["ALL"], name
        assert not svc.get("cap_add"), name
        assert not svc.get("privileged"), name


def test_the_backend_image_ships_no_setuid_binary():
    dockerfile = (ROOT / "backend" / "Dockerfile").read_text(encoding="utf-8")
    runtime = dockerfile[dockerfile.index("AS runtime"):]
    assert re.search(r"find / -xdev -perm /6000 -type f -exec chmod a-s \{\} \+", runtime)
    # The build fails if any survive, rather than trusting the chmod.
    assert 'test -z "$(find / -xdev -perm /6000 -type f)"' in runtime
    assert runtime.index("chmod a-s") < runtime.index("USER mykronos")
