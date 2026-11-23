"""Processor profiles in the Python API: runs and verifications on a
processor (``profile=``), on tests/fixtures/undefined-x86_64.elf, whose
``shrd_jo`` branches on SHRD's OF, which Intel's P-cores and E-cores set
differently."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

import binbun

from conftest import ROOT

UNDEFINED = ROOT / "tests" / "fixtures" / "undefined-x86_64.elf"


@pytest.fixture(scope="module")
def undefined_db() -> Iterator[binbun.Database]:
    with binbun.open(UNDEFINED, project=False, debug="none") as db:
        db.wait(binbun.Stage.CALLERS)
        yield db


def shrd_jo(db: binbun.Database) -> binbun.Function:
    f = db.functions.get_by_name("shrd_jo")
    assert f is not None
    return f


def test_runs_take_the_profiles_values(undefined_db: binbun.Database) -> None:
    function = shrd_jo(undefined_db)
    # The post's input: OF 1 on the P-cores (returns 1), 0 on the E-cores
    # (returns 2); on the architecture, undetermined.
    state = 'format = 1\nname = "post"\narguments = ["0x8f"]\n'
    none = function.run(state)
    p = function.run(state, profile="intel-raptor-cove")
    e = function.run(state, profile="intel-gracemont")
    assert none.profile is None and none.stop == "undetermined"
    assert p.profile == "intel-raptor-cove r2" and e.profile == "intel-gracemont r2"
    assert p.agree is True and e.agree is True
    assert p.stop == e.stop == "returned" and p.detail != e.detail
    assert p.detail.startswith("returned") and e.detail.startswith("returned")
    with pytest.raises(ValueError):
        function.run(state, profile="intel-pentium")


def test_verify_on_a_profile_skips_nothing(undefined_db: binbun.Database) -> None:
    function = shrd_jo(undefined_db)
    plain = function.verify()
    assert plain.profile is None and plain.verdict == "not_checkable"
    for name in ("intel-raptor-cove", "intel-gracemont"):
        verified = function.verify(profile=name)
        assert verified.profile == f"{name} r2"
        assert verified.verdict == "agreed" and verified.agreed == verified.states > 0
        assert verified.skips == {}
