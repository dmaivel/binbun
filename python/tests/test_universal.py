"""A universal Mach-O file (the checked-in ``program-universal.macho``:
x86_64, arm64 and arm64e) opens one slice: the one ``slice=`` names, as the
CLI's ``--arch`` does, else this machine's instruction set's."""

from __future__ import annotations

import platform

import pytest

import binbun
from conftest import ROOT

UNIVERSAL = ROOT / "tests" / "fixtures" / "program-universal.macho"


@pytest.mark.parametrize(
    ("name", "architecture"), [("x86_64", "x86_64"), ("arm64", "aarch64"), ("arm64e", "aarch64")]
)
def test_slice_opens_that_slice_with_a_project_of_its_own(name: str, architecture: str) -> None:
    with binbun.open(UNIVERSAL, slice=name) as db:
        assert db.slice == name
        assert db.architecture == architecture
        assert db.format == binbun.Format.MACHO
        assert db.functions.get_by_name("main") is not None
        sha256 = db.sha256
    # Each slice is keyed by its own bytes: another slice, another key.
    another = "arm64" if name == "x86_64" else "x86_64"
    with binbun.Database.open(UNIVERSAL, slice=another) as other:
        assert other.slice == another
        assert other.sha256 is not None and other.sha256 != sha256


def test_without_slice_the_slice_is_this_machines() -> None:
    # Windows says ARM64, macOS arm64, Linux aarch64.
    host = "arm64" if platform.machine().lower() in ("arm64", "aarch64") else "x86_64"
    with binbun.open(UNIVERSAL, project=False) as db:
        assert db.slice == host


def test_a_slice_the_file_lacks_is_refused_by_name() -> None:
    with pytest.raises(binbun.OpenError, match="no i386 slice"):
        binbun.open(UNIVERSAL, project=False, slice="i386")


def test_a_file_that_is_not_universal_has_no_slice(fixture_db: binbun.Database) -> None:
    assert fixture_db.slice is None
