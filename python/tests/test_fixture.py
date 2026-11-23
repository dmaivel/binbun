"""The read surface on the checked-in fixture (``classify`` called by
``checked``, called by ``loop_sum``): functions and blocks, names, bytes
and searches, the listing, documents with provenance, binbun's facts,
events, errors."""

from __future__ import annotations

import pytest

import binbun


def by_name(db: binbun.Database, name: str) -> binbun.Function:
    f = db.functions.get_by_name(name)
    assert f is not None, name
    return f


def test_functions_are_found_by_entry_address_and_name(fixture_db: binbun.Database) -> None:
    db = fixture_db
    entries = db.functions.entries()
    assert entries == sorted(entries)
    assert len(db.functions) == len(entries)
    assert [f.entry for f in db.functions] == entries
    checked = by_name(db, "checked")
    assert db.functions[checked.entry] == checked
    assert db.functions[checked] == checked
    assert checked.entry in db.functions and checked in db.functions
    # No function there: NoFunctionError, which is a KeyError.
    with pytest.raises(binbun.NoFunctionError):
        db.functions[checked.entry + 1]
    try:
        db.functions[checked.entry + 1]
    except KeyError as error:
        assert isinstance(error, binbun.NoFunctionError)
    else:
        raise AssertionError("no KeyError")
    # Inside a function: the one holding it; past every function: none.
    inside = checked.blocks[-1].start
    assert db.functions.get_at(inside) == checked
    assert db.functions.get_containing(inside) == [checked]
    assert db.functions.get_by_name(f"sub_{checked.entry:X}") == checked
    assert db.functions.get_by_name("no_such_function") is None
    between = db.functions.get_between(checked.entry, checked.entry + 1)
    assert between == [checked]
    after = db.functions.get_next(checked.entry)
    assert after is not None and after.entry == entries[entries.index(checked.entry) + 1]
    # Handles are keyed by entry: equal and hashable.
    assert len({checked, db.functions[checked.entry]}) == 1


def test_addresses_outside_the_image_hold_nothing(fixture_db: binbun.Database) -> None:
    db = fixture_db
    assert db.functions.get_at(0xFFFF_FFFF_0000) is None
    assert db.functions.get_at(0xDEAD_0000) is None
    assert db.functions.get_containing(0xDEAD_0000) == []
    assert db.bytes.get_byte_at(0xDEAD_0000) is None
    assert db.bytes.get_word_at(0xDEAD_0000) is None
    assert db.bytes.get_dword_at(0xDEAD_0000) is None
    assert db.bytes.get_qword_at(0xDEAD_0000) is None
    with pytest.raises(ValueError):
        db.functions.get_at(-1)
    with pytest.raises(binbun.NoFunctionError):
        db.decompile(by_name(db, "checked").entry + 1)
    assert db.bytes.get_bytes_at(0xFFFF_FFFF_0000, 4) is None


def test_an_address_is_an_int_or_an_object_at_one(fixture_db: binbun.Database) -> None:
    db = fixture_db
    classify = by_name(db, "classify")
    # A function is at its entry.
    assert db.xrefs.to_ea(classify) == db.xrefs.to_ea(classify.entry)
    assert db.names.get_at(classify) == db.names.get_at(classify.entry) == "classify"
    # A string, a segment: at their address, their start.
    string = db.strings.get_all()[0]
    assert isinstance(string, binbun.StringItem)
    found = db.strings.get_at(string)
    assert found is not None and (found.address, found.text) == (string.address, string.text)
    segment = db.segments.get_at(classify)
    assert segment is not None
    again = db.segments.get_at(segment)
    assert again is not None and (again.start, again.end) == (segment.start, segment.end)
    # Objects at several addresses name the one to give.
    xref = db.xrefs.to_ea(classify)[0]
    with pytest.raises(TypeError, match="to_ea"):
        db.xrefs.to_ea(xref)
    line = next(l for l in classify.decompile().lines if l.addresses)
    with pytest.raises(TypeError, match="addresses"):
        db.names.get_at(line)
    # Neither an int nor such an object; an int out of 0..2**64.
    with pytest.raises(TypeError):
        db.names.get_at(4496.0)
    with pytest.raises(ValueError):
        db.names.get_at(-1)


def test_an_in_process_database_has_no_cursor(fixture_db: binbun.Database) -> None:
    with pytest.raises(binbun.CapabilityError):
        _ = fixture_db.cursor


def test_blocks_ranges_calls_and_xrefs_agree(fixture_db: binbun.Database) -> None:
    db = fixture_db
    checked, classify, loop_sum = (by_name(db, n) for n in ("checked", "classify", "loop_sum"))
    blocks = checked.blocks
    assert [b.start for b in blocks] == sorted(b.start for b in blocks)
    for block in blocks:
        assert block.end > block.start and block.count >= 1
        assert checked in block.functions
        assert any(start <= block.start < end for start, end in checked.ranges)
    assert classify in checked.callees()
    assert checked in classify.callers()
    assert checked in loop_sum.callees()
    calls = [x for x in classify.xrefs_to() if x.is_call]
    assert calls and all(x.to_ea == classify.entry for x in calls)
    assert {x.function for x in calls} == {checked}
    assert db.xrefs.calls_to_ea(classify.entry) == [x.from_ea for x in calls]
    made = [x for x in checked.xrefs_from() if x.to_ea == classify.entry]
    assert made and made[0].kind is binbun.XrefKind.CALL
    assert db.xrefs.from_ea(made[0].from_ea, kinds={binbun.XrefKind.CALL}) == [made[0]]
    assert repr(made[0]).startswith(f"Xref(from_ea={made[0].from_ea:#x}, to_ea={classify.entry:#x}, ")
    table = db.xrefs.table(ea=classify.entry)
    assert table.from_ea == [x.from_ea for x in classify.xrefs_to()]
    assert table.to_ea == [classify.entry] * len(table.from_ea)
    assert made[0] in db.xrefs.to_range(classify.entry, classify.entry + 1)


def test_names_bytes_and_searches(fixture_db: binbun.Database) -> None:
    db = fixture_db
    classify = by_name(db, "classify")
    assert db.names.get_at(classify.entry) == "classify"
    assert db.names.get_ea("classify") == classify.entry
    assert db.names.get_display_at(classify.entry) == "classify"
    named = db.names.get_all()
    assert binbun.Named(classify.entry, "classify") in named
    assert all(isinstance(n, binbun.Named) for n in named)
    assert binbun.Names.demangle("_ZNSt6vectorIiSaIiEE9push_backERKi") == (
        "std::vector<int, std::allocator<int> >::push_back(int const&)"
    )
    code = db.bytes.get_bytes_at(classify.entry, 4)
    assert code is not None and len(code) == 4
    assert db.bytes.get_byte_at(classify.entry) == code[0]
    assert db.bytes.get_dword_at(classify.entry) == int.from_bytes(code, "little")
    assert db.bytes.is_code_at(classify.entry)
    pattern = f"{code[0]:02x} ?? {code[2]:02x}"
    assert classify.entry in db.bytes.find_bytes(pattern)
    assert db.bytes.find_bytes(code[:3], classify.entry, classify.entry + 1) == [classify.entry]
    hits = db.bytes.find_text("classify", where="c", case=True)
    assert any(h.source == "c" and h.function == by_name(db, "checked") for h in hits)
    for hit in hits:
        assert all(hit.text[s:e] == "classify" for s, e in hit.ranges)
    listed = db.bytes.find_text("call", where="listing")
    assert any(h.function == by_name(db, "checked") for h in listed)


def test_immediates_are_found_where_the_listing_shows_them(fixture_db: binbun.Database) -> None:
    db = fixture_db
    loop_sum = by_name(db, "loop_sum")
    line = db.listing.line_of(loop_sum.entry)
    lines = db.listing.lines(line, 200)
    numbers = [
        (l.address, text)
        for l in lines
        if l.kind == "instruction"
        for text, role, _ in l.tokens
        if role == "number"
    ]
    assert numbers
    address, text = numbers[0]
    value = int(text[:-1], 16) if text.endswith("h") else int(text, 0)
    assert address in db.bytes.find_immediate(value)


def test_segments_sections_strings_entries_imports(fixture_db: binbun.Database) -> None:
    db = fixture_db
    segments = db.segments.get_all()
    assert segments and len(db.segments) == len(segments)
    assert db.minimum_ea == min(s.start for s in segments)
    code = by_name(db, "classify").entry
    seg = db.segments.get_at(code)
    assert seg is not None and seg.executable
    assert db.sections.get_by_name(".text") is not None
    strings = db.strings.get_all()
    assert strings
    first = strings[0]
    assert db.strings.get_at(first.address).text == first.text
    assert db.bytes.get_cstring_at(first.address) == first.text
    assert any(e.kind == "entry" and e.address == db.start_ip for e in db.entries)
    assert all(isinstance(i.name, str) for i in db.imports)
    assert db.format is binbun.Format.ELF and db.machine is binbun.Machine.X86_64
    assert db.bitness == 64 and len(db.sha256) == 64


def test_the_listing_reads_as_the_session_shows_it(fixture_db: binbun.Database) -> None:
    db = fixture_db
    checked = by_name(db, "checked")
    text = db.listing.text(start=checked, end=checked.ranges[-1][1])
    assert "checked" in text and "call" in text
    first = db.listing.lines(line=db.listing.line_of(checked), count=1)[0]
    assert first.address == checked.entry
    assert "".join(t for t, _, _ in first.tokens) == first.text


def test_a_document_links_lines_tokens_and_instructions(fixture_db: binbun.Database) -> None:
    db = fixture_db
    checked = by_name(db, "checked")
    doc = checked.decompile()
    assert doc is not None and doc.function == checked and doc.view is binbun.View.EXACT
    assert doc.text == db.decompile(checked.entry).text
    lines = doc.lines
    assert "\n".join(l.text for l in lines) == doc.text
    made = [l for l in lines if l.addresses]
    assert made
    for line in made:
        assert doc.lines[line.number].addresses == line.addresses
        for address in line.addresses:
            found = doc.lines_of(address)
            assert line in found
            assert all(isinstance(l, binbun.CLine) and address in l.addresses for l in found)
            assert any(s <= address < e for s, e in checked.ranges)
    # Lines are hashable: equal lines are one in a set.
    assert len(set(made) | set(doc.lines_of(made[0].addresses[0]))) == len(made)
    assert all(line.function == checked for line in lines)
    call = next(l for l in lines if "classify(" in l.text and l.addresses)
    token = doc.token_at(call.number, call.text.index("classify"))
    assert token is not None and token.text == "classify"
    for token in doc.tokens:
        assert doc.text[token.start : token.end] == token.text
    names = [v.name for v in doc.variables]
    assert len(names) == len(set(names))
    parameter = next(v for v in doc.variables if v.kind == "parameter")
    assert doc.variable(parameter.name) == parameter
    assert parameter.type
    with pytest.raises(binbun.NoVariableError):
        doc.variable("no_such_variable")
    assert set(doc.counts) == {"casts", "gotos", "escapes"}


def test_c_tokens_say_what_each_name_is(fixture_db: binbun.Database) -> None:
    doc = by_name(fixture_db, "checked").decompile()
    assert doc is not None
    kinds = {(t.text, t.kind, t.category, t.automatic) for t in doc.tokens}
    # The callee, named by its symbol; the parameter, named by binbun.
    assert ("classify", "function", "identifier", False) in kinds
    assert ("a1", "parameter", "identifier", True) in kinds
    assert ("if", "control_keyword", "keyword", False) in kinds
    assert ('"negative"', "string", "literal", False) in kinds
    assert ("binbun_unreachable", "macro", "identifier", False) in kinds
    assert ("int32_t", "builtin_type", "type", False) in kinds


def test_facts_are_answered_and_kept(fixture_db: binbun.Database) -> None:
    db = fixture_db
    loop_sum = by_name(db, "loop_sum")
    verified = loop_sum.verify()
    assert verified.verdict == "agreed" and verified.agreed == verified.states > 0
    assert verified.function == loop_sum
    assert verified.view is binbun.View.EXACT and verified.fuel == 1000
    why = loop_sum.why()
    assert why.function == loop_sum
    assert why.items and all(isinstance(i, binbun.ExplanationItem) for i in why.items)
    doc = loop_sum.decompile()
    assert {v.name for v in doc.variables} <= {i.name for i in why.items} | {
        v.name for v in doc.variables if v.kind == "global"
    }
    variable = next(v for v in doc.variables if v.kind == "parameter")
    origins = loop_sum.origins(variable)
    assert origins.function == loop_sum and origins.chains
    assert all(isinstance(u, binbun.Use) for u in origins.uses)
    ran = loop_sum.run()
    assert ran.machine and ran.statements > 0
    # The stop a word; what it says, text.
    assert ran.stop.isidentifier() and ran.stop.islower() and ran.detail, ran
    stages = loop_sum.stages()
    assert isinstance(stages, binbun.Stages) and stages.function == loop_sum
    assert stages.names()[-1] == stages.stages[-1].name
    c = stages.get(stages.names()[-1])
    assert isinstance(c, binbun.StageText) and c.level == "c"
    reading = loop_sum.decompile(view=binbun.View.READING)
    assert reading.view is binbun.View.READING


def test_decompile_all_yields_every_function_in_address_order(fixture_db: binbun.Database) -> None:
    db = fixture_db
    pairs = list(db.decompile_all(workers=3))
    assert [f.entry for f, _ in pairs] == db.functions.entries()
    for f, doc in pairs:
        if isinstance(doc, binbun.CDocument):
            assert doc.text == f.decompile().text
        else:
            assert isinstance(doc, binbun.DecompileError)


def test_events_are_pulled_and_filtered(fixture_path) -> None:
    with binbun.open(fixture_path, project=False, wait=None) as db:
        queue = db.events.subscribe(binbun.StageReached)
        stages = []
        while (event := queue.get(timeout=60)) is not None:
            assert isinstance(event, binbun.StageReached)
            stages.append(event.stage)
            if event.stage >= binbun.Stage.CALLERS:
                break
        assert stages == sorted(stages) and stages[-1] >= binbun.Stage.CALLERS
        # Closed: nothing more, at once.
        queue.close()
        assert queue.get(timeout=0.01) is None
        assert list(queue) == []
        assert db.revision.edits == 0


def test_a_closed_database_and_a_missing_file_raise(fixture_path, tmp_path) -> None:
    db = binbun.open(fixture_path, project=False)
    f = db.functions.get_by_name("classify")
    db.close()
    with pytest.raises(binbun.BinbunError):
        _ = f.name
    with pytest.raises(binbun.OpenError):
        binbun.open(tmp_path / "missing", project=False)


def test_project_false_writes_nothing(fixture_path, tmp_path) -> None:
    with binbun.Database.open(fixture_path, project=False) as db:
        assert db.project_dir is None
        assert db.revision.edits == 0
    with binbun.open(fixture_path, project=tmp_path / "project") as db:
        assert db.project_dir == str(tmp_path / "project")


def test_plain_types_print_c_names_at_open_and_when_set(fixture_path) -> None:
    with binbun.open(fixture_path, project=False, debug="none", types="plain") as db:
        loop_sum = by_name(db, "loop_sum")
        plain = db.decompile(loop_sum).text
        assert "int checked(long);" in plain and "int64_t" not in plain, plain
        db.set_style(types="fixed")
        fixed = db.decompile(loop_sum).text
        assert "int64_t" in fixed, fixed
        db.set_style(types="plain")
        assert db.decompile(loop_sum).text == plain
    with pytest.raises(ValueError):
        binbun.open(fixture_path, project=False, types="long")


def test_braces_set_the_next_documents_layout(fixture_path) -> None:
    def indents(text: str) -> set[int]:
        return {len(l) - len(l.lstrip(" ")) for l in text.splitlines() if l.strip()}

    with binbun.open(fixture_path, project=False, debug="none") as db:
        loop_sum = by_name(db, "loop_sum")
        kr = db.decompile(loop_sum).text
        # Four spaces a level.
        assert 4 in indents(kr) and 2 not in indents(kr), kr
        db.set_style(braces="llvm")
        llvm = db.decompile(loop_sum).text
        # Two spaces a level.
        assert llvm != kr and 2 in indents(llvm), llvm
        with pytest.raises(ValueError):
            db.set_style(braces="nope")
        db.set_style(braces="kr")
        assert db.decompile(loop_sum).text == kr
