"""Writes: a transaction is one history entry, one project file write and one
merged change event; an exception rolls it back byte for byte; undo and
redo restore the project file; corrections are analysed anew and swapped
in, the handles of functions still there working, those gone raising;
refused C says where; and the rules around transactions (nesting, other
threads, writes outside one, authors)."""

from __future__ import annotations

import hashlib
import re
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

import binbun
from conftest import FIXTURE, cli

# Corrections made on a copy of Arch's bash 5.3.20 (BASH_SHA256), with which
# 1,777 of its 1,801 functions verified with 0 differences. Their addresses
# are that build's, so the test that makes them runs on it alone.
BASH_SHA256 = "c14c8f498f3be96f076ceb07d65dba584a86dca3c86b5dce65ed0f6cae73358d"
BASH_CORRECTIONS = {
    "strings": [(0xECB0A, 23)],
    "dwords": [(0xED554, 4)],
    "undefined": [(0xEDE95, 25)],
    "functions": [(0x225AD, None), (0x22890, 0x22932)],
    "deleted": [0x2B7A0],
}


def project_file(db: binbun.Database) -> bytes | None:
    """The project file's bytes, if it is written."""
    assert db.project_dir is not None
    path = Path(db.project_dir) / "project.toml"
    return path.read_bytes() if path.exists() else None


def changed(queue: binbun.EventQueue) -> list[binbun.Changed]:
    """The ``Changed`` events waiting on `queue` (each wait ends 2 s after
    the last event)."""
    found = []
    while (event := queue.get(timeout=2.0)) is not None:
        if isinstance(event, binbun.Changed):
            found.append(event)
    return found


@pytest.fixture()
def fixture_writable(tmp_path: Path) -> Iterator[binbun.Database]:
    """The fixture with a project of its own."""
    with binbun.open(FIXTURE, project=tmp_path / "project", debug="none") as db:
        db.wait(binbun.Stage.CALLERS)
        yield db


@pytest.fixture(scope="module")
def bash_writable(bash_path: Path, tmp_path_factory: pytest.TempPathFactory) -> Iterator[binbun.Database]:
    """bash with a project of its own, its callers known."""
    project = tmp_path_factory.mktemp("bash") / "project"
    with binbun.open(bash_path, project=project, debug="none") as db:
        db.wait(binbun.Stage.CALLERS)
        yield db


def edits(entries: list[int]) -> list[tuple[str, int, str]]:
    """210 writes: 100 functions renamed, 100 addresses commented, 10
    prototypes."""
    return (
        [("name", e, f"renamed_{i}") for i, e in enumerate(entries[:100])]
        + [("comment", e, f"comment {i}") for i, e in enumerate(entries[100:200])]
        + [("prototype", e, f"long proto_{i}(long a)") for i, e in enumerate(entries[200:210])]
    )


def make(db: binbun.Database, edit: tuple[str, int, str]) -> None:
    kind, entry, value = edit
    if kind == "name":
        db.functions.set_name(entry, value)
    elif kind == "comment":
        db.comments.set_at(entry, value)
    else:
        db.functions.set_prototype(entry, value)


def test_a_transaction_is_one_step_one_save_one_change_and_undoes_byte_for_byte(
    bash_writable: binbun.Database, bash_path: Path, tmp_path: Path
) -> None:
    db = bash_writable
    entries = db.functions.entries()[10:220]
    # A first change, so that the project file exists before.
    db.comments.set_at(entries[0], "before")
    before = project_file(db)
    assert before is not None
    history = len(db.history)
    saves = db._saves
    queue = db.events.subscribe(binbun.Changed)
    with db.transaction("Name bash helpers") as tx:
        for edit in edits(entries):
            make(db, edit)
        # Read your writes inside it.
        assert db.functions[entries[0]].name == "renamed_0"
    one = changed(queue)
    after = project_file(db)
    assert len(db.history) == history + 1
    entry = db.history[0]
    assert (entry.label, entry.edits, entry.mine) == ("Name bash helpers", 210, True)
    assert isinstance(entry.author, binbun.Author)
    assert entry.author.via == tx.author and entry.author.via.startswith("script:")
    assert tx.entry is not None and tx.entry.id == entry.id
    assert db._saves == saves + 1
    assert len(one) == 1, one

    # The same writes made one by one, on another copy: their changes'
    # documents together are the transaction's.
    with binbun.open(bash_path, project=tmp_path / "alone", debug="none") as alone:
        alone.wait(binbun.Stage.CALLERS)
        separately = alone.events.subscribe(binbun.Changed)
        for edit in edits(entries):
            make(alone, edit)
        assert len(alone.history) == 210
        union = {f.entry for event in changed(separately) for f in event.functions}
    assert {f.entry for f in one[0].functions} == union

    # Undo restores the project file byte for byte; redo makes it again.
    undone = db.undo()
    assert undone is not None and undone.label == "Undo: Name bash helpers"
    assert project_file(db) == before
    assert db.functions[entries[0]].user_name is None
    db.redo()
    assert project_file(db) == after
    assert db.functions[entries[0]].name == "renamed_0"


def test_an_exception_rolls_the_transaction_back_byte_for_byte(bash_writable: binbun.Database) -> None:
    db = bash_writable
    entries = db.functions.entries()[300:400]
    db.comments.set_at(entries[-1], "a project file to compare")
    before = project_file(db)
    history = [e.id for e in db.history]
    with pytest.raises(KeyError, match="raised on purpose"):
        with db.transaction("Fails half way"):
            for i, entry in enumerate(entries[:50]):
                db.functions.set_name(entry, f"half_{i}")
            assert db.functions[entries[49]].name == "half_49"
            raise KeyError("raised on purpose")
    assert project_file(db) == before
    assert [e.id for e in db.history] == history
    assert all(db.functions[e].user_name is None for e in entries[:50])


def test_corrections_are_analysed_anew_once_and_swapped_in_at_commit(
    bash_writable: binbun.Database, bash_path: Path
) -> None:
    if hashlib.sha256(bash_path.read_bytes()).hexdigest() != BASH_SHA256:
        pytest.skip("the corrections are for Arch's bash 5.3.20, not this bash")
    db = bash_writable
    main = db.functions.get_by_name("main")
    assert main is not None
    analysis = db.revision.analysis
    with db.transaction("Correct bash"):
        for address, count in BASH_CORRECTIONS["strings"]:
            db.corrections.make_data(address, binbun.Unit.STRING, count)
        for address, count in BASH_CORRECTIONS["dwords"]:
            db.corrections.make_data(address, binbun.Unit.DWORD, count)
        for address, size in BASH_CORRECTIONS["undefined"]:
            db.corrections.undefine(address, size)
        for entry, end in BASH_CORRECTIONS["functions"]:
            db.functions.create(entry, end=end)
        for entry in BASH_CORRECTIONS["deleted"]:
            db.functions.remove(entry)
        # Applied once, at commit: nothing is analysed anew yet.
        assert db.revision.analysis == analysis
    assert db.revision.analysis == analysis + 1
    assert len(db.functions) == 1801
    assert 0x225AD in db.functions and 0x2B7A0 not in db.functions
    # A handle of a function still there works.
    assert main.name == "main" and "main" in main.decompile().text
    # The corrections saved are those above: the CLI verifies the binary
    # recovered with them as it did.
    printed = cli("verify", str(bash_path), "--view", "reading", "--project", str(db.project_dir))
    # Which functions are conclusive at the fuel given depends on the random
    # states; what the corrections decide is the function count and that
    # nothing differs.
    found = re.search(r"1801 functions: agreed (\d+), differs 0, not checkable (\d+)", printed)
    assert found, printed
    assert int(found[1]) + int(found[2]) == 1801, printed


def test_a_function_gone_raises_and_an_iterator_across_the_swap_is_stale(
    fixture_writable: binbun.Database,
) -> None:
    db = fixture_writable
    classify = db.functions.get_by_name("classify")
    assert classify is not None
    iterator = iter(db.functions)
    next(iterator)
    analysis = db.revision.analysis
    db.functions.remove(classify)  # outside a transaction: waits for the swap
    assert db.revision.analysis == analysis + 1
    assert classify.entry not in db.functions
    with pytest.raises(binbun.FunctionGoneError):
        _ = classify.name
    with pytest.raises(binbun.StaleError):
        next(iterator)
    # Undone, it is analysed anew again and the handle works again.
    undone = db.undo()
    assert undone is not None and undone.label == "Undo: Correct recovery"
    assert db.revision.analysis == analysis + 2
    assert classify.name == "classify"


def test_refused_c_says_where_and_changes_nothing(fixture_writable: binbun.Database) -> None:
    db = fixture_writable
    revision, history = db.revision, len(db.history)
    c = "struct x {"
    with pytest.raises(binbun.CDeclarationError) as raised:
        db.types.define(c)
    assert isinstance(raised.value, ValueError)
    assert raised.value.span == (len(c), len(c)), raised.value.span
    assert raised.value.c == c
    assert (db.revision, len(db.history), db.types.definitions()) == (revision, history, [])
    # Inside a transaction too, and the transaction goes on.
    with db.transaction("Types"):
        with pytest.raises(binbun.CDeclarationError):
            db.functions.set_prototype(db.functions.get_by_name("classify"), "int classify(int")
        key = db.types.define("struct pair { int a; int b; };")
    assert key == "struct pair"
    assert [d.key for d in db.types.definitions()] == ["struct pair"]
    assert isinstance(db.types.definitions()[0], binbun.Definition)
    assert db.history[0].label == "Types" and db.history[0].edits == 1


def test_inner_transactions_join_and_their_rollback_dooms_the_outer(fixture_writable: binbun.Database) -> None:
    db = fixture_writable
    main = db.functions.get_by_name("main")
    with db.transaction("Outer"):
        db.functions.set_name(main, "outer_name")
        with db.transaction("Inner (joins)") as inner:
            db.comments.set_at(main.entry, "inner")
        assert inner.entry is None
    assert (db.history[0].label, db.history[0].edits) == ("Outer", 2)
    history = len(db.history)
    with pytest.raises(binbun.TransactionError):
        with db.transaction("Doomed"):
            db.functions.set_name(main, "doomed")
            try:
                with db.transaction("Fails"):
                    raise RuntimeError
            except RuntimeError:
                pass
            # Rolled back with the inner one: nothing more is written.
            assert db.functions[main.entry].name == "outer_name"
            with pytest.raises(binbun.TransactionError):
                db.comments.set_at(main.entry, "late")
    assert len(db.history) == history


def test_writes_outside_a_transaction_are_steps_of_their_own_by_the_script(
    fixture_writable: binbun.Database,
) -> None:
    db = fixture_writable
    main = db.functions.get_by_name("main")
    history = len(db.history)
    db.functions.set_name(main, "start")
    db.bookmarks.set_at(main.entry, "here")
    assert [e.label for e in db.history[:2]] == ["Bookmark", "Rename function"]
    assert len(db.history) == history + 2
    assert all(e.author == db.history[0].author for e in db.history[:2])
    assert db.history[0].author.via.startswith("script:")
    assert db.bookmarks.get_at(main.entry) == "here"
    assert db.bookmarks.get_all() == [binbun.Named(main.entry, "here")]
    db.undo()
    assert db.bookmarks.get_at(main.entry) is None and db.functions[main.entry].name == "start"


def test_another_thread_cannot_write_into_a_transaction(fixture_writable: binbun.Database) -> None:
    db = fixture_writable
    main = db.functions.get_by_name("main")
    raised: list[BaseException] = []

    def other() -> None:
        try:
            db.comments.set_at(main.entry, "from another thread")
        except BaseException as error:  # noqa: BLE001 - the test looks at it
            raised.append(error)

    with db.transaction("Mine", author="plugin:test"):
        db.functions.set_name(main, "mine")
        thread = threading.Thread(target=other)
        thread.start()
        thread.join()
    assert len(raised) == 1 and isinstance(raised[0], binbun.TransactionError)
    assert db.comments.get_at(main.entry) is None
    assert (db.history[0].author.via, db.history[0].edits) == ("plugin:test", 1)


def test_writes_at_an_unmapped_address_are_refused_and_write_nothing(
    fixture_writable: binbun.Database,
) -> None:
    db = fixture_writable
    revision, history, saved = db.revision, len(db.history), project_file(db)
    comments = db.comments.get_all()
    with pytest.raises(binbun.InvalidAddressError):
        db.comments.set_at(0xDEAD_0000, "x")
    with pytest.raises(binbun.InvalidAddressError):
        db.names.set_name(0xDEAD_0000, "x")
    assert (db.revision, len(db.history), project_file(db)) == (revision, history, saved)
    assert db.comments.get_all() == comments and db.names.get_ea("x") is None
    # A comment where something is: a Comment record.
    main = db.functions.get_by_name("main")
    db.comments.set_at(main, "here")
    assert binbun.Comment(main.entry, "here") in db.comments.get_all()
    assert all(isinstance(c, binbun.Comment) for c in db.comments.get_all())


def test_variables_types_and_number_forms(fixture_writable: binbun.Database) -> None:
    db = fixture_writable
    loop_sum = db.functions.get_by_name("loop_sum")
    document = loop_sum.decompile()
    parameter = next(v for v in document.variables if v.kind == "parameter")
    # A parameter is typed through the prototype; a local by itself.
    counter = next(v for v in document.variables if v.name == "i")
    with db.transaction("Variables"):
        parameter.rename("limit")
        counter.set_type("unsigned int")
    text = loop_sum.decompile().text
    # The counter is declared in its `for`'s header (scoped declarations).
    assert "int32_t loop_sum(int32_t limit)" in text and "for (uint32_t i = 0; " in text, text
    assert any(v.name == "limit" for v in loop_sum.decompile(view=binbun.View.READING).variables)
    assert db.history[0].edits == 2
    with pytest.raises(binbun.CDeclarationError):
        db.types.check(counter, "char[16]")
    layout = db.types.layout("struct pair { int a; char b; };")
    assert (layout.key, layout.size, [m.name for m in layout.members]) == ("struct pair", 8, ["a", "b"])
    with pytest.raises(binbun.CorrectionError):
        db.corrections.make_data(loop_sum.entry, binbun.Unit.DWORD, 0)


def test_a_number_shown_by_an_enumerations_constants(fixture_writable: binbun.Database) -> None:
    db = fixture_writable
    loop_sum = db.functions.get_by_name("loop_sum")
    start = db.listing.line_of(loop_sum.entry)
    # The first decimal immediate of the function (`1`, not `0Ah`).
    line, value = next(
        (line, int(text))
        for line in db.listing.lines(start, 64)
        if line.kind == "instruction"
        for text, role, _ in line.tokens
        if role == "number" and text.isdigit() and int(text) > 0
    )
    db.types.define(f"enum shown : uint32_t {{ SHOWN_OTHER = {value + 1}, SHOWN_IT = {value} }};")
    db.listing.set_enum_form(line.address, value, "enum shown")
    shown = db.listing.lines(line.number, 1)[0].text
    assert "SHOWN_IT" in shown and "SHOWN_OTHER" not in shown, shown
    with pytest.raises(binbun.CDeclarationError):
        db.listing.set_enum_form(line.address, value, "enum nothing_by_this_name")
    db.listing.set_number_form(line.address, value, None)
    assert "SHOWN_IT" not in db.listing.lines(line.number, 1)[0].text
