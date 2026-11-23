"""Library signatures from Python: a pack ``binbun sig make`` makes of
the library objects ``tests/fixtures/sigs-app-gcc.elf`` links (stripped; built by
``scripts/build-fixtures.sh``), read from ``BINBUN_SIGNATURES``, names its
``exit`` as the binary opens: ``Function.name_source`` and
``Function.signature_match`` say so, ``db.signatures`` lists the pack and the
match and rejects it (undone, it is back); a script's rename wins over
the match; ``signatures=False`` names nothing."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import pytest
from conftest import ROOT, cli

import binbun

FIXTURES = ROOT / "tests" / "fixtures"
APP = FIXTURES / "sigs-app-gcc.elf"
# exit's entry (it never returns), and app_start's, which no pack names.
EXIT = 0x401360
START = 0x401380


@pytest.fixture(scope="module")
def packs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A folder holding the pack of the app's library (``sigs-1@1``)."""
    folder = tmp_path_factory.mktemp("signatures")
    cli(
        "sig",
        "make",
        "--library",
        "sigs",
        "--version",
        "1",
        "--licence",
        "MIT",
        "--build",
        "gcc-O2",
        str(FIXTURES / "sigs-gcc.a"),
        str(FIXTURES / "sigs-exit-gcc.o"),
        "-o",
        str(folder / "sigs.jsonl.zst"),
    )
    return folder


@pytest.fixture
def installed(packs: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The pack read by every database opened in the test."""
    monkeypatch.setenv("BINBUN_SIGNATURES", str(packs))
    return packs


def open_app(signatures: bool | Literal["exact"] = "exact") -> binbun.Database:
    """The app, matched once the exact pass is done (by identity alone
    unless said: no background change to race the test's)."""
    return binbun.open(APP, project=False, signatures=signatures, wait=binbun.Stage.SIGNATURES)


def test_a_match_names_the_function_and_says_where_from(installed: Path) -> None:
    with open_app() as db:
        assert db.signatures.packs == ["sigs-1@1"]
        f = db.functions[EXIT]
        assert (f.name, f.name_source) == ("exit", "signature")
        match = f.signature_match
        assert match is not None
        assert (match.pack, match.library, match.version, match.name, match.how) == (
            "sigs-1@1",
            "sigs",
            "1",
            "exit",
            "exact",
        )
        assert (match.states, match.ruled_out) == (None, None)
        assert not match.returns and not match.rejected
        matches = db.signatures.matches()
        assert all(isinstance(m, binbun.FunctionMatch) for m in matches)
        assert dict(matches)[f] == match
        assert [m.match for m in matches if m.function.entry == EXIT] == [match]
        # No pack names app_start: binbun's own name, nothing matched.
        start = db.functions[START]
        assert (start.name_source, start.signature_match) == (None, None)


def test_a_rejected_match_is_gone_until_undone(installed: Path) -> None:
    with open_app() as db:
        f = db.functions[EXIT]
        db.signatures.reject(f)
        assert f.name == f.default_name and f.name_source is None
        match = f.signature_match
        assert match is not None and match.rejected and match.name == "exit"
        # Rejected once, it cannot be again.
        with pytest.raises(binbun.BinbunError):
            db.signatures.reject(EXIT)
        db.undo()
        assert (f.name, f.name_source) == ("exit", "signature")
        back = f.signature_match
        assert back is not None and not back.rejected


def test_a_scripts_rename_wins_over_the_match(installed: Path) -> None:
    with open_app() as db:
        f = db.functions[EXIT]
        db.functions.set_name(f, "bye")
        assert (f.name, f.name_source) == ("bye", "script")
        # The match is kept, under the script's name.
        assert f.signature_match is not None and f.signature_match.name == "exit"


def test_signatures_off_names_nothing(installed: Path) -> None:
    with open_app(signatures=False) as db:
        f = db.functions[EXIT]
        assert (f.name_source, f.signature_match) == (None, None)
        assert db.signatures.matches() == []
    with pytest.raises(ValueError, match="signatures="):
        binbun.open(APP, project=False, signatures="all")


def test_symbols_names_are_the_binarys(fixture_db: binbun.Database) -> None:
    f = fixture_db.functions.get_by_name("loop_sum")
    assert f is not None and f.name_source == "symbol"
