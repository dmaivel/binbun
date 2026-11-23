"""The package itself: importing it starts nothing, the extension links
no libpython, the stubs match the runtime."""

from __future__ import annotations

import subprocess
import struct
import sys
from pathlib import Path

import pytest

import binbun
import binbun._native


def test_importing_starts_no_thread() -> None:
    # Native threads are counted where Linux lists them (/proc/self/task);
    # elsewhere Python's only: macOS has no such list, and Windows' loader
    # starts worker threads of its own while it loads DLLs.
    script = (
        "import os, threading\n"
        "def native():\n"
        "    return len(os.listdir('/proc/self/task')) if os.path.isdir('/proc/self/task') else 0\n"
        "before = native()\n"
        "import binbun, binbun.ir\n"
        "after = native()\n"
        "print(threading.active_count(), before, after)\n"
    )
    done = subprocess.run(
        [sys.executable, "-c", script], check=True, capture_output=True, text=True
    )
    active, before, after = map(int, done.stdout.split())
    assert active == 1
    assert after == before


def test_the_extension_links_no_libpython() -> None:
    """The extension is abi3: on Linux and macOS named so and linking no
    libpython (the interpreter's symbols are found at load); on Windows,
    where the name says nothing, importing the stable ABI's
    ``python3.dll``, not a version's (``python313.dll``)."""
    native = Path(binbun._native.__file__)
    if sys.platform == "win32":
        imported = pe_imports(native)
        assert "python3.dll" in imported, imported
        assert not [name for name in imported if name.startswith("python3") and name != "python3.dll"], imported
        return
    assert ".abi3." in native.name, native.name
    lister = ["otool", "-L"] if sys.platform == "darwin" else ["ldd"]
    linked = subprocess.run([*lister, str(native)], check=True, capture_output=True, text=True).stdout
    assert "libpython" not in linked and "Python.framework" not in linked, linked


def pe_imports(path: Path) -> list[str]:
    """The DLLs a PE file imports, lowercase: its import directory's
    descriptors' names."""
    data = path.read_bytes()
    (pe,) = struct.unpack_from("<I", data, 0x3C)
    assert data[pe : pe + 4] == b"PE\0\0"
    sections, optional_size = struct.unpack_from("<H12xH", data, pe + 6)
    optional = pe + 24
    (magic,) = struct.unpack_from("<H", data, optional)
    # The data directories follow the optional header's fixed part (PE32+'s
    # is 16 bytes longer); the import directory is the second.
    directories = optional + (112 if magic == 0x20B else 96)
    (imports,) = struct.unpack_from("<I", data, directories + 8)
    table = optional + optional_size

    def offset(rva: int) -> int:
        for at in range(table, table + 40 * sections, 40):
            size, address, _, raw = struct.unpack_from("<4I", data, at + 8)
            if address <= rva < address + size:
                return rva - address + raw
        raise AssertionError(f"RVA {rva:#x} is in no section")

    names = []
    descriptor = offset(imports)
    while (name := struct.unpack_from("<I", data, descriptor + 12)[0]) != 0:
        start = offset(name)
        names.append(data[start : data.index(b"\0", start)].decode().lower())
        descriptor += 20
    return names


def test_the_stubs_match_the_runtime() -> None:
    pytest.importorskip("mypy.stubtest")
    done = subprocess.run(
        [sys.executable, "-m", "mypy.stubtest", "binbun"],
        capture_output=True,
        text=True,
    )
    assert done.returncode == 0, done.stdout + done.stderr


def test_every_class_is_documented() -> None:
    undocumented = [
        name
        for name in dir(binbun._native)
        if isinstance(getattr(binbun._native, name), type)
        and not (getattr(binbun._native, name).__doc__ or "").strip()
    ]
    assert undocumented == []


def test_versions_and_names() -> None:
    assert binbun.__version__ == binbun._native.__version__
    assert binbun.API_VERSION == (0, 1)
    assert issubclass(binbun.InvalidAddressError, LookupError)
    assert issubclass(binbun.OpenError, OSError)
    assert issubclass(binbun.TimeoutError, TimeoutError)
    assert issubclass(binbun.FunctionGoneError, binbun.StaleError)
    assert issubclass(binbun.NoFunctionError, KeyError)
    assert issubclass(binbun.NoFunctionError, binbun.BinbunError)
    exported = {
        "AddressLike",
        "FunctionLike",
        "ExplanationItem",
        "Stages",
        "StageText",
        "Author",
        "SuggestionDraft",
        "Named",
        "Comment",
        "CComment",
        "Use",
        "Successor",
        "CorrectedItem",
        "CorrectedFunction",
        "FunctionMatch",
        "Definition",
    }
    assert exported <= set(binbun.__all__), exported - set(binbun.__all__)
    assert all(hasattr(binbun, name) for name in binbun.__all__)
    for gone in ("EvidenceItem", "MemberEdit", "Edit", "RemoteEvent"):
        assert not hasattr(binbun, gone), gone
        assert gone not in binbun.__all__, gone
    # The records are tuples still.
    assert binbun.Named(0x10, "x") == (0x10, "x")
    address, name = binbun.Named(0x10, "x")
    assert (address, name) == (0x10, "x")
