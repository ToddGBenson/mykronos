"""The committed API types are checked against the live schema here (#60001).

`scripts/regen_api_types.py` reports `frontend/lib/api-types.d.ts` stale and
NOTHING CALLED IT. Its only invoker is `scripts/hooks/pre-commit`, which runs
only if `core.hooksPath` points at `scripts/hooks` -- and it does not: not
locally, not globally, and `.git/hooks/` holds only the fourteen `*.sample`
files git ships. `scripts/install_hooks.py`, which would set it, has zero
references anywhere in the repository. It has never been run in this clone.

So the types drifted, and they drifted for a real reason: #495 added
`decision_type` to `EvaluateResult` and the types were never regenerated. The
frontend was being type-checked against a contract the backend no longer
served.

WHY THIS TEST EXISTS RATHER THAN A CALL TO THE SCRIPT. The script needs python
AND `npx openapi-typescript` in one process, and the lane that enforces this
today cannot provide both: `lint-types-build` runs in `node:slim`, whose own
comment in the pipeline says "node:slim has no python and the uploader is a
python package". That is why the lane reimplements the comparison inline
instead of calling the script, and it is a consequence of the image split
rather than an oversight.

This check needs NEITHER node NOR the network. It reads the schema straight out
of the app object and compares it against the committed declarations as text,
so it runs in the ordinary unit lane and catches the drift class that actually
happened: a backend field added without regenerating. It does not replace the
lane's check, which compares the generated file byte for byte; it fails FIRST
and in seconds, which is the whole complaint the pre-commit hook was written
about.

WHAT IT CANNOT SEE, stated so nobody reads more into a pass than is there: it
compares NAMES, not types. A field whose type changed from `string` to `number`
keeps its name and passes here. The lane's byte-for-byte diff is what catches
that, and this does not make the lane redundant.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
TYPES = REPO_ROOT / "frontend" / "lib" / "api-types.d.ts"

#: Floors. The schema had 90 paths and 189 component schemas when this was
#: written; a discovery that finds a handful would otherwise pass everything.
MINIMUM_COMPONENTS = 100
MINIMUM_PROPERTIES = 400


def _component_block(declared: str, name: str) -> str | None:
    """The text of one component's object literal, braces matched.

    Searching the WHOLE FILE for a field name is not a check, and this function
    is here because the first version of this test did exactly that and was
    caught by mutation: restoring the stale types that were on `main` left it
    GREEN. `decision_type` was missing from `EvaluateResult` and present in
    another component, so a file-wide search found it and the drift that
    prompted this whole story went unreported.

    Returns None for a component with no object literal -- an enum, or an alias
    -- which callers must treat as "cannot check here" rather than as absent.
    """
    opening = re.search(rf"^(\s+){re.escape(name)}:\s*\{{", declared, re.MULTILINE)
    if opening is None:
        return None
    depth, start = 0, opening.end() - 1
    for index in range(start, len(declared)):
        char = declared[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return declared[start : index + 1]
    return None


@pytest.fixture(scope="module")
def schema() -> dict:
    """The live OpenAPI document, built the way `dump_openapi.py` builds it."""
    from mykronos.main import create_app

    app = create_app()
    return app.openapi()


@pytest.fixture(scope="module")
def declared() -> str:
    assert TYPES.is_file(), f"{TYPES} is missing"
    text = TYPES.read_text(encoding="utf-8")
    assert len(text) > 10_000, "the committed types are too small to be the real file"
    return text


def test_the_schema_itself_is_not_empty(schema: dict) -> None:
    components = (schema.get("components") or {}).get("schemas") or {}
    assert len(components) >= MINIMUM_COMPONENTS, (
        f"only {len(components)} component schemas built from the app; expected "
        f"at least {MINIMUM_COMPONENTS}. An app that failed to register its "
        "routers would otherwise make every assertion below vacuous."
    )
    assert schema.get("paths"), "the app exposes no paths"


def test_every_component_the_backend_serves_is_declared(
    schema: dict, declared: str
) -> None:
    components = (schema.get("components") or {}).get("schemas") or {}
    missing = sorted(
        name
        for name in components
        # An object component is emitted as `        Name: {`, but an enum is
        # emitted as `        Name: "a" | "b";`. Requiring a brace here matched
        # only the object form and silently excused all five enums -- which are
        # exactly the components most likely to gain a member without anyone
        # regenerating. Caught by the assertion below failing on them.
        if not re.search(rf"^\s+{re.escape(name)}:\s", declared, re.MULTILINE)
    )
    assert not missing, (
        f"the backend serves these schemas and the committed types do not "
        f"declare them: {missing}\n"
        "Run `python scripts/regen_api_types.py` and commit the result."
    )


def test_every_enum_member_the_backend_serves_is_declared(
    schema: dict, declared: str
) -> None:
    """The drift a name-only check would miss entirely.

    A new `Capability` or `Severity` member is a one-word backend change that
    leaves every component name and every field name intact, so both checks
    above pass while the frontend's union type quietly excludes a value the API
    now returns.
    """
    components = (schema.get("components") or {}).get("schemas") or {}
    enums = {
        name: definition["enum"]
        for name, definition in sorted(components.items())
        if isinstance(definition.get("enum"), list) and definition["enum"]
    }
    assert enums, "no enum components found; the discovery broke, not the estate"

    missing: list[str] = []
    for name, members in enums.items():
        line = re.search(rf"^\s+{re.escape(name)}:\s(.*)$", declared, re.MULTILINE)
        if line is None:
            missing.append(f"{name} (not declared at all)")
            continue
        for member in members:
            if f'"{member}"' not in line.group(1):
                missing.append(f"{name}.{member}")
    assert not missing, (
        f"the backend serves these enum members and the committed types do not "
        f"declare them: {missing}\n"
        "The frontend's union type excludes a value the API can return. Run "
        "`python scripts/regen_api_types.py` and commit it."
    )


def test_every_field_the_backend_serves_is_declared(
    schema: dict, declared: str
) -> None:
    """The drift that actually happened.

    #495 added `decision_type` to `EvaluateResult`. The component already
    existed, so a component-level check would have passed; the field is what
    was missing.
    """
    components = (schema.get("components") or {}).get("schemas") or {}
    checked = 0
    missing: list[str] = []
    for name, definition in sorted(components.items()):
        fields = definition.get("properties") or {}
        if not fields:
            continue
        block = _component_block(declared, name)
        assert block is not None, f"`{name}` has properties but no object block"
        for field in fields:
            checked += 1
            # Property names are emitted verbatim, quoted only when they are
            # not valid identifiers, and `?:` when optional.
            pattern = rf'^\s+"?{re.escape(field)}"?\??:\s'
            if not re.search(pattern, block, re.MULTILINE):
                missing.append(f"{name}.{field}")

    assert checked >= MINIMUM_PROPERTIES, (
        f"only {checked} properties compared; expected at least "
        f"{MINIMUM_PROPERTIES}. A check that inspects nothing passes everything."
    )
    assert not missing, (
        f"the backend serves these fields and the committed types do not "
        f"declare them: {missing}\n"
        "The frontend is being type-checked against a contract the backend no "
        "longer serves. Run `python scripts/regen_api_types.py` and commit it."
    )
