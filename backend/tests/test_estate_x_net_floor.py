"""The registry-src rebuild links golang.org/x/net 0.62.0 or later.

The containers lane reported two low advisories in golang.org/x/net's HTML
parser (CVE-2026-78661, text-node coalescing in addText and fosterParent, and
CVE-2026-97045, childTextNodesAreLiteral), both fixed in 0.62.0, in four static
binaries this repository declares (TheHub #61076):

    bin/registry               registry-src rebuild   x/net v0.60.0
    usr/bin/silo               pgsty/silo             x/net v0.61.0
    bin/vault                  hashicorp/vault        x/net v0.60.0
    usr/local/concourse/bin/runc  concourse/concourse  x/net v0.55.0

Only `bin/registry` is built here: the recipe pins the x/net module it asks
`go get` for, so moving that pin is the fix. SILO, Vault and Concourse are
vendor binaries already on their newest release (checked 2026-11-05); they
move when their vendors ship a build on 0.62.0, per the operator decision of
2026-10-18 (Concourse and Vault wait for their vendors), and SILO is
distroless with no rebuild recipe.

This is a floor, not an exact pin: a later x/net passes, and only a pin back
below 0.62.0 fails.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
REGISTRY_SRC = REPO_ROOT / "deploy" / "images" / "registry-src" / "Dockerfile"

#: The first golang.org/x/net release with both HTML-parser fixes.
X_NET_FLOOR = (0, 62, 0)


def _arg(name: str) -> str:
    text = REGISTRY_SRC.read_text(encoding="utf-8")
    match = re.search(rf"^ARG {name}=(\S+)$", text, re.M)
    assert match, f"registry-src no longer declares ARG {name}"
    return match.group(1)


def test_the_x_net_pin_is_past_the_html_parser_fixes() -> None:
    pin = _arg("X_NET")
    match = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)", pin)
    assert match, f"X_NET={pin} is not an exact vX.Y.Z module version"
    version = tuple(int(part) for part in match.groups())
    assert version >= X_NET_FLOOR, (
        f"registry-src pins golang.org/x/net {pin}, which carries CVE-2026-78661 and "
        f"CVE-2026-97045 (fixed in v{'.'.join(map(str, X_NET_FLOOR))})"
    )


def test_the_pin_is_what_go_get_asks_for() -> None:
    # The ARG is only the fix while the module bump reads it.
    text = REGISTRY_SRC.read_text(encoding="utf-8")
    assert re.search(r'go get "golang\.org/x/net@\$\{X_NET\}"', text)
