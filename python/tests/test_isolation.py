"""The run's isolation (``conftest``): HOME and the XDG directories in a
scratch directory of the run, and the tripwire over binbun's directories
under that HOME."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import binbun
from conftest import FIXTURE, SCRATCH, binbun_files, cli


def test_home_and_the_xdg_directories_are_the_runs_and_cargos_are_not() -> None:
    assert str(os.getpid()) in SCRATCH.name
    for variable in ["HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "XDG_RUNTIME_DIR"]:
        assert Path(os.environ[variable]).is_relative_to(SCRATCH), variable
    assert Path.home() == SCRATCH / "home"
    for variable in ["CARGO_HOME", "RUSTUP_HOME"]:
        assert not Path(os.environ[variable]).is_relative_to(SCRATCH), variable


def test_the_tripwire_finds_binbun_files_under_home_and_nothing_else(tmp_path: Path) -> None:
    assert binbun_files(tmp_path) == []
    (tmp_path / ".config" / "other").mkdir(parents=True)
    (tmp_path / ".bashrc").write_text("")
    assert binbun_files(tmp_path) == []
    (tmp_path / ".local" / "state" / "binbun").mkdir(parents=True)
    (tmp_path / ".local" / "state" / "binbun" / "recent").write_text("x")
    (tmp_path / ".cache" / "binbun" / "symbols").mkdir(parents=True)
    assert binbun_files(tmp_path) == [
        ".cache/binbun",
        ".cache/binbun/symbols",
        ".local/state/binbun",
        ".local/state/binbun/recent",
    ]


def test_what_binbun_keeps_lands_in_the_xdg_directories_not_under_home() -> None:
    """A project opened the default way (binbun's data directory) and a
    database served (its socket): both under the run's XDG directories."""
    with binbun.open(FIXTURE, debug="none") as db:
        db.wait(binbun.Stage.ANALYSED)
        db.comments.set_at(0x11F0, "kept")
        with db.serve() as server:
            if sys.platform == "win32":
                # A named pipe, told in a discovery file there.
                assert server.socket.startswith("\\\\.\\pipe\\binbun-gui-"), server.socket
                assert list((SCRATCH / "runtime" / "binbun").glob("gui-*.json"))
            else:
                assert Path(server.socket).is_relative_to(SCRATCH / "runtime")
        assert Path(db.project_dir).is_relative_to(SCRATCH / "data")
    assert binbun_files(SCRATCH / "home") == []


def test_paths_are_the_runs_folders_as_the_cli_lists_them() -> None:
    """``binbun.paths()``: each folder under its XDG variable here, in
    order, sized; as ``binbun paths --json`` says, but for sizes changed
    meanwhile."""
    listed = binbun.paths()
    assert list(listed) == ["config", "data", "state", "cache", "runtime"]
    for name, variable in [
        ("config", "config"),
        ("data", "data"),
        ("state", "state"),
        ("cache", "cache"),
        ("runtime", "runtime"),
    ]:
        assert listed[name]["path"] == str(SCRATCH / variable / "binbun"), name
        assert isinstance(listed[name]["size"], int)
    assert all(folder["size"] is None for folder in binbun.paths(sizes=False).values())
    from_cli = json.loads(cli("paths", "--json"))
    assert {name: folder["path"] for name, folder in from_cli.items()} == {
        name: folder["path"] for name, folder in listed.items()
    }
