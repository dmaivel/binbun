"""Fixtures of binbun's Python tests: the checked-in fixture binary, bash
(skipped where absent), and the CLI the API is compared with
(``BINBUN_CLI``, set by ``scripts/python-tests.sh``).

The tests never touch the user's binbun files: before anything opens a
database, ``HOME`` (on Windows ``USERPROFILE``, ``APPDATA`` and
``LOCALAPPDATA`` too) and the XDG base directories (``XDG_CONFIG_HOME``,
``XDG_DATA_HOME``, ``XDG_STATE_HOME``, ``XDG_CACHE_HOME``, and
``XDG_RUNTIME_DIR``, where servers put their sockets) point into a
scratch directory of this run (its process id in the name), for this
process and every process it starts (each pytest-xdist worker has one of
its own), and ``BINBUN_HOME``, which would
win over them, is unset; cargo and rustup keep the real ones
(``CARGO_HOME``, ``RUSTUP_HOME``). What the tests write lands under the
XDG directories there. The run fails if binbun wrote under the scratch
``HOME`` itself (``~/.config/binbun``, ``~/.local/…/binbun``,
``~/.cache/binbun``, macOS' ``~/Library/…/binbun``, Windows'
``AppData\…\binbun``: a path found without its XDG variable), where the
real ``HOME`` would have taken it. The user's real directories are never
looked at, so the user's own binbun running meanwhile changes nothing."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

import binbun

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "program-x86_64.elf"
BASH = Path("/usr/bin/bash")


# binbun's directories under a HOME when no XDG variable says otherwise.
HOME_DIRS = [
    ".config/binbun",
    ".local/share/binbun",
    ".local/state/binbun",
    ".cache/binbun",
    "Library/Application Support/binbun",
    "Library/Caches/binbun",
    "AppData/Roaming/binbun",
    "AppData/Local/binbun",
]


def binbun_files(home: Path) -> list[str]:
    """Every file or directory binbun made under ``home`` itself (its
    directories there, as found without the XDG variables), relative to
    ``home``."""
    found = []
    for name in HOME_DIRS:
        root = home / name
        if root.exists():
            found.append(name)
            found.extend(path.relative_to(home).as_posix() for path in root.rglob("*"))
    return sorted(found)


def _isolate() -> Path:
    """Points HOME and the XDG directories into a scratch directory of
    this run (cargo's and rustup's homes kept): its path."""
    real_home = Path.home()
    os.environ.setdefault("CARGO_HOME", str(real_home / ".cargo"))
    os.environ.setdefault("RUSTUP_HOME", str(real_home / ".rustup"))
    # macOS' temporary directory (/var/folders/…/T/) is too long a start
    # for a server's socket under the scratch's runtime directory: a
    # socket's path is at most 104 bytes there.
    base = "/tmp" if sys.platform == "darwin" else None
    scratch = Path(tempfile.mkdtemp(prefix=f"binbun-tests-{os.getpid()}-", dir=base))
    (scratch / "home").mkdir()
    os.environ["HOME"] = str(scratch / "home")
    if sys.platform == "win32":
        os.environ["USERPROFILE"] = str(scratch / "home")
        os.environ["APPDATA"] = str(scratch / "home" / "AppData" / "Roaming")
        os.environ["LOCALAPPDATA"] = str(scratch / "home" / "AppData" / "Local")
    os.environ.pop("BINBUN_HOME", None)
    for variable, name in [
        ("XDG_CONFIG_HOME", "config"),
        ("XDG_DATA_HOME", "data"),
        ("XDG_STATE_HOME", "state"),
        ("XDG_CACHE_HOME", "cache"),
        ("XDG_RUNTIME_DIR", "runtime"),
    ]:
        os.environ[variable] = str(scratch / name)
    return scratch


SCRATCH = _isolate()

# What binbun wrote under the scratch HOMEs of pytest-xdist's workers (each
# imports this module, so has a scratch directory of its own), as each hands
# it to the process running them.
WORKERS_WRITTEN: list[str] = []


@pytest.hookimpl(optionalhook=True)
def pytest_testnodedown(node: Any, error: object) -> None:
    WORKERS_WRITTEN.extend(getattr(node, "workeroutput", {}).get("binbun_written", []))


# Files whose tests pytest-xdist's workers take one by one under --dist
# loadfile (scripts/python-tests.sh), not the whole file: their slow tests
# each take long on their own (CLI runs analysing bash, bash analysed anew
# after writes), longer than analysing bash again in another worker.
SPREAD = {"test_bash.py", "test_writes.py"}


@pytest.hookimpl(tryfirst=True, optionalhook=True)
def pytest_xdist_make_scheduler(config: pytest.Config, log: Any) -> Any:
    if config.getvalue("dist") != "loadfile":
        return None
    from xdist.scheduler import LoadFileScheduling

    class Scheduling(LoadFileScheduling):
        def _split_scope(self, nodeid: str) -> str:
            file = nodeid.split("::", 1)[0]
            return nodeid if Path(file).name in SPREAD else file

    return Scheduling(config, log)


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Fails the run if binbun wrote under the scratch HOME itself
    (where the user's HOME would have taken it); a pytest-xdist worker
    hands what it found to the process running it, which fails."""
    written = binbun_files(SCRATCH / "home")
    shutil.rmtree(SCRATCH, ignore_errors=True)
    workeroutput = getattr(session.config, "workeroutput", None)
    if workeroutput is not None:
        workeroutput["binbun_written"] = written
        return
    written += WORKERS_WRITTEN
    if written:
        print("\nbinbun wrote under HOME, not its XDG directories:\n  " + "\n  ".join(written))
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


def cli_path() -> str | None:
    """The ``binbun`` CLI to compare with, if there is one."""
    return os.environ.get("BINBUN_CLI") or shutil.which("binbun")


def cli(*args: str, status: int = 0) -> str:
    """What ``binbun ARGS`` prints; it must exit with ``status``."""
    path = cli_path()
    if path is None:
        pytest.skip("no binbun CLI (BINBUN_CLI)")
    done = subprocess.run([path, *args], capture_output=True, text=True, timeout=3600)
    assert done.returncode == status, (args, done.returncode, done.stdout, done.stderr)
    return done.stdout


@pytest.fixture(scope="session")
def fixture_path() -> Path:
    return FIXTURE


@pytest.fixture(scope="session")
def fixture_db() -> Iterator[binbun.Database]:
    with binbun.open(FIXTURE, project=False, debug="none") as db:
        db.wait(binbun.Stage.CALLERS)
        yield db


@pytest.fixture(scope="session")
def bash_path() -> Path:
    if not BASH.exists():
        pytest.skip("no /usr/bin/bash")
    return BASH


@pytest.fixture(scope="session")
def bash_db(bash_path: Path) -> Iterator[binbun.Database]:
    # As the CLI reads it: no debug information searched for.
    with binbun.open(bash_path, project=False, debug="none") as db:
        db.wait(binbun.Stage.CALLERS)
        yield db
