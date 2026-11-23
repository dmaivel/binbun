"""The decoders (``binbun.x86``, ``binbun.aarch64``): the C API's numbers,
every instruction of the fixtures' code as the C API (and so the Rust API)
decodes it, invalid and truncated bytes, buffers, and ``sweep()``."""

from __future__ import annotations

import os
import re
import struct
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

import binbun
from binbun import aarch64, x86
from conftest import ROOT

# The C API's headers the decoders' constants are in.
HEADERS = [ROOT / "crates" / "binbun-capi" / "include" / "binbun" / name for name in ("core.h", "disasm.h")]
FIXTURES = ROOT / "tests" / "fixtures"
# The fixtures the C API's own test sweeps (`tests/capi.rs`).
CODE = [
    "program-x86_64.elf",
    "program-x86_64.exe",
    "program-i686.exe",
    "resolve-aarch64.elf",
    "dozen-aarch64.elf",
    "mangled-aarch64.elf",
    "opaque-aarch64.elf",
]


def header_constants() -> dict[str, int]:
    """Every ``BINBUN_*`` enumerator and object-like macro of ``core.h`` and ``disasm.h``."""
    text = re.sub(r"/\*.*?\*/", "", "\n".join(header.read_text() for header in HEADERS), flags=re.S)
    value = r"\(?\s*(?:0x[0-9A-Fa-f]+|\d+)u?(?:\s*<<\s*\d+)?\s*\)?"
    constants: dict[str, int] = {}
    for name, number in re.findall(
        rf"^\s*(?:#define\s+)?(BINBUN_[A-Z0-9_]+)(?:\s*=\s*|\s+)({value})\s*,?\s*$",
        text,
        flags=re.M,
    ):
        expression = re.sub(r"(?<=[0-9A-Fa-f])u\b", "", number)
        constants[name] = eval(expression, {"__builtins__": {}})  # digits and shifts only
    return constants


# Each Python enum and the prefix of its C constants.
ENUMS: list[tuple[type, str]] = [
    (binbun.Status, "BINBUN_STATUS_"),
    (binbun.Access, "BINBUN_ACCESS_"),
    (binbun.BranchKind, "BINBUN_BRANCH_"),
    (binbun.TargetKind, "BINBUN_TARGET_"),
    (binbun.TextOptions, "BINBUN_TEXT_"),
    (binbun.TokenKind, "BINBUN_TOKEN_"),
    (x86.Mode, "BINBUN_X86_MODE_"),
    (x86.Encoding, "BINBUN_X86_ENCODING_"),
    (x86.Condition, "BINBUN_X86_CONDITION_"),
    (x86.Flag, "BINBUN_X86_FLAG_"),
    (x86.OperandKind, "BINBUN_X86_OPERAND_"),
    (x86.OperandField, "BINBUN_X86_FIELD_"),
    (x86.Visibility, "BINBUN_X86_VISIBILITY_"),
    (x86.Action, "BINBUN_X86_ACTION_"),
    (aarch64.Cond, "BINBUN_AARCH64_COND_"),
    (aarch64.RegisterClass, "BINBUN_AARCH64_REG_"),
    (aarch64.Element, "BINBUN_AARCH64_ELEMENT_"),
    (aarch64.Predication, "BINBUN_AARCH64_PREDICATION_"),
    (aarch64.ConditionKind, "BINBUN_AARCH64_CONDITION_"),
    (aarch64.CompareKind, "BINBUN_AARCH64_COMPARE_"),
    (aarch64.Flag, "BINBUN_AARCH64_FLAG_"),
    (aarch64.MemoryKind, "BINBUN_AARCH64_MEMORY_"),
    (aarch64.OperandKind, "BINBUN_AARCH64_OPERAND_"),
    (aarch64.Radix, "BINBUN_AARCH64_RADIX_"),
    (aarch64.ListStyle, "BINBUN_AARCH64_LIST_"),
    (aarch64.ShiftKind, "BINBUN_AARCH64_SHIFT_"),
    (aarch64.ExtendKind, "BINBUN_AARCH64_EXTEND_"),
    (aarch64.OffsetKind, "BINBUN_AARCH64_OFFSET_"),
    (aarch64.Writeback, "BINBUN_AARCH64_WRITEBACK_"),
    (aarch64.Modifier, "BINBUN_AARCH64_MODIFIER_"),
    (aarch64.LabelBase, "BINBUN_AARCH64_LABEL_"),
    (aarch64.NameKind, "BINBUN_AARCH64_NAME_"),
    (aarch64.SliceDirection, "BINBUN_AARCH64_SLICE_"),
    (aarch64.ZaListKind, "BINBUN_AARCH64_ZA_LIST_"),
]
# Constants with an enum's prefix that are no member of it.
NOT_MEMBERS = {"BINBUN_TOKEN_NO_OPERAND"}


def test_every_enum_has_the_c_headers_names_and_numbers() -> None:
    constants = header_constants()
    assert constants["BINBUN_STATUS_X86_BAD_REGISTER_MATCH"] == 28
    assert constants["BINBUN_X86_FLAG_FC3"] == 1 << 31
    for enum, prefix in ENUMS:
        in_c = {
            name.removeprefix(prefix): value
            for name, value in constants.items()
            if name.startswith(prefix) and name not in NOT_MEMBERS
        }
        in_python = {member.name: int(member) for member in enum.__members__.values()}
        assert in_python == in_c, enum
    assert x86.MAX_LENGTH == constants["BINBUN_X86_MAX_LENGTH"]
    assert aarch64.LENGTH == constants["BINBUN_AARCH64_LENGTH"]
    assert all(s.is_invalid == (constants["BINBUN_STATUS_INVALID"] <= s <= 63) for s in binbun.Status)


# --------------------------------------------------------------------------
# The fixtures' code, in the C API test program's notation (`tests/capi.rs`)


def code_sections(name: str) -> Iterator[tuple[str, int, bytes]]:
    """The architecture (as the C program names it), address and bytes of
    each code section of fixture `name`."""
    with binbun.open(
        FIXTURES / name, project=False, debug="none", wait=binbun.Stage.IMAGE
    ) as db:
        arch = {
            binbun.Machine.X86_64: "x86-64",
            binbun.Machine.X86: "x86-32",
            binbun.Machine.AARCH64: "aarch64",
        }[db.machine]
        for section in db.sections:
            if section.is_code:
                data = db.bytes.get_bytes_at(section.start, section.end - section.start)
                assert data is not None
                yield arch, section.start, data


BRANCH_KINDS = ["none", "jump", "call", "return", "trap", "syscall", "eret", "halt"]


def branch_line(branch: binbun.Branch) -> str:
    kind = branch.target_kind
    if kind is binbun.TargetKind.NONE:
        target = "none"
    elif kind is binbun.TargetKind.ADDRESS:
        target = f"address:{branch.target:x}"
    elif kind is binbun.TargetKind.POINTER:
        target = f"pointer:{branch.target:x}/{branch.pointer_size}"
    elif kind is binbun.TargetKind.INDIRECT:
        target = "indirect"
    else:
        target = f"far:{branch.selector:x}:{branch.target:x}"
    question = "?" if branch.conditional else ""
    fall = int(branch.falls_through)
    return f" branch={BRANCH_KINDS[branch.kind]}{question} fall={fall} target={target}"


def access_name(access: binbun.Access) -> str:
    return {0: "-", 1: "r", 2: "w", 3: "rw"}[int(access)]


def x86_operand_line(op: x86.Operand) -> str:
    kind = {x86.OperandKind.SECOND_IMMEDIATE: "second"}.get(op.kind, op.kind.name.lower())
    action = ["", "r", "w", "rw", "cr", "cw", "crw", "rcw"][op.action]
    line = (
        f" op={kind} field={op.field.name} vis={op.visibility.name.lower()}"
        f" act={action} acc={access_name(op.access)} bits={op.bits}"
    )
    if op.kind is x86.OperandKind.REGISTER:
        line += f" reg={op.register or '-'}"
    elif op.kind is x86.OperandKind.MEMORY:
        line += (
            f" seg={op.segment or '-'} base={op.base or '-'} index={op.index or '-'}"
            f" scale={op.scale} disp={op.displacement} size={op.memory_size}"
        )
    elif op.kind is x86.OperandKind.IMMEDIATE:
        line += f" value={op.value:x} signed={int(op.signed_immediate)}"
    elif op.kind is x86.OperandKind.RELATIVE:
        line += f" disp={op.displacement}"
    else:
        line += f" value={op.value:x}"
    return line


def x86_dump(mode: x86.Mode, address: int, data: bytes) -> list[str]:
    out = []
    for item in x86.Decoder(data, address, mode):
        if isinstance(item, binbun.Invalid):
            out.append(f"@{item.address:x} {item.status.name}")
            continue
        i = item
        cond = "-" if i.condition is x86.Condition.NONE else i.condition.name.lower()
        out.append(
            f"@{i.address:x} len={i.length} mnem={i.mnemonic} form={i.form} cat={i.category}"
            f" ext={i.extension} isa={i.isa_set} enc={i.encoding.name.lower()} cond={cond}"
            f" w={i.operand_width},{i.address_width},{i.stack_address_width}"
        )
        out.append(f" text={i.text()}")
        out.append(branch_line(i.branch))
        if i.computed_address is not None:
            out.append(f" computed={i.computed_address:x}")
        f = i.flags
        out.append(
            f" flags={int(f.read):x},{int(f.written):x},{int(f.undefined):x},"
            f"{int(f.may_write)},{int(f.must_write)}"
        )
        out.extend(x86_operand_line(op) for op in i.operands)
    return out


def a64_register(label: str, r: aarch64.Register) -> str:
    element = "-" if r.element is aarch64.Element.NONE else r.element.name.lower()
    index = "-" if r.index is None else str(r.index)
    predication = ["-", "z", "m"][r.predication]
    return (
        f" {label}={r.register_class.name.lower()}{r.number}"
        f"/{r.lanes}{element}/{index}/{predication}"
    )


RADIXES = ["", "hex", "dec", "padded"]
A64_KINDS = {
    aarch64.OperandKind.SYSTEM_REGISTER: "sysreg",
    aarch64.OperandKind.INDEXED_REGISTER: "indexed",
}
NAME_KINDS = ["", "prefetch", "barrier", "bti", "pstate", "pattern", "sysop", "keyword"]


def a64_extend(kind: aarch64.ExtendKind, amount: int | None) -> str:
    return f" {kind.name.lower()}" + ("" if amount is None else f"={amount}")


def a64_za(za: aarch64.Za) -> str:
    tile = "-" if za.tile is None else str(za.tile)
    element = "-" if za.element is aarch64.Element.NONE else za.element.name.lower()
    direction = ["-", "h", "v"][za.direction]
    line = f" za={tile}/{element}/{direction}"
    if za.slice_index is not None:
        line += f"/w{za.slice_index}+{za.slice_offset}"
        if za.slice_last is not None:
            line += f":{za.slice_last}"
        line += f"x{za.group}"
    return line


def a64_memory(m: aarch64.Memory) -> str:
    line = a64_register("base", m.base)
    if m.offset_kind is aarch64.OffsetKind.NONE:
        line += " offset=none"
    elif m.offset_kind is aarch64.OffsetKind.IMMEDIATE:
        assert m.offset_radix is not None
        line += f" offset={m.offset} signed={int(m.offset_signed)} radix={RADIXES[m.offset_radix]}"
    elif m.offset_kind is aarch64.OffsetKind.REGISTER:
        assert m.index is not None
        line += a64_register("index", m.index)
        if m.modifier is aarch64.Modifier.SHIFT:
            assert m.modifier_kind is not None
            line += f" {m.modifier_kind.name.lower()}={m.modifier_amount}"
        elif m.modifier is aarch64.Modifier.EXTEND:
            assert isinstance(m.modifier_kind, aarch64.ExtendKind)
            line += a64_extend(m.modifier_kind, m.modifier_amount)
    else:
        line += f" offset={m.offset}vl"
    return line + f" wb={m.writeback.name.lower()}"


def a64_operand_line(op: aarch64.Operand) -> str:
    kind = A64_KINDS.get(op.kind, op.kind.name.lower())
    line = f" op={kind} acc={access_name(op.access)}"
    v = op.value
    if isinstance(v, aarch64.Register):
        line += a64_register("reg", v)
    elif isinstance(v, aarch64.RegisterList):
        line += a64_register("first", v.first)
        line += f" count={v.count} stride={v.stride} style={v.style.name.lower()}"
    elif isinstance(v, aarch64.Immediate):
        line += f" value={v.value:x} signed={int(v.signed)} radix={RADIXES[v.radix]}"
    elif isinstance(v, aarch64.Float):
        bits = struct.unpack("<Q", struct.pack("<d", v.value))[0]
        line += f" bits={bits:016x} exact={int(v.exact)}"
    elif isinstance(v, aarch64.Shift):
        line += f" {v.kind.name.lower()}={v.amount}"
    elif isinstance(v, aarch64.Extend):
        line += a64_extend(v.kind, v.amount)
    elif isinstance(v, aarch64.Memory):
        line += a64_memory(v)
    elif isinstance(v, aarch64.Label):
        base = "pc" if v.base is aarch64.LabelBase.INSTRUCTION else "page"
        line += f" offset={v.offset} base={base} radix={RADIXES[v.radix]}"
    elif isinstance(v, aarch64.Cond):
        line += f" cond={v.name.lower()}"
    elif isinstance(v, aarch64.SystemRegister):
        line += f" sysreg={v.encoding:x}/{v.name or ''}"
    elif isinstance(v, aarch64.Named):
        line += f" {NAME_KINDS[v.kind]}={v.name}"
    elif isinstance(v, aarch64.Za):
        line += a64_za(v)
    elif isinstance(v, aarch64.ZaList):
        line += f" tiles={v.tiles:x}" if v.za is None else a64_za(v.za)
    elif isinstance(v, aarch64.IndexedRegister):
        line += a64_register("reg", v.register) + a64_register("index", v.index)
        line += f" offset={v.offset}"
    else:
        line += f" slice={v}"
    return line


def a64_condition_line(c: aarch64.Condition) -> str:
    if c.kind is aarch64.ConditionKind.FLAGS:
        assert c.cond is not None
        return f" cond=flags:{c.cond.name.lower()}"
    assert c.register is not None
    if c.kind is aarch64.ConditionKind.ZERO:
        return f" cond=zero:{int(c.sense)}" + a64_register("reg", c.register)
    if c.kind is aarch64.ConditionKind.BIT:
        return f" cond=bit:{c.bit}:{int(c.sense)}" + a64_register("reg", c.register)
    assert c.cond is not None
    line = f" cond=compare:{c.cond.name.lower()}" + a64_register("reg", c.register)
    if c.right_register is not None:
        return line + a64_register("right", c.right_register)
    return line + f" right={c.right_immediate}"


def aarch64_dump(address: int, data: bytes) -> list[str]:
    out = []
    for item in aarch64.Decoder(data, address):
        if isinstance(item, binbun.Invalid):
            out.append(f"@{item.address:x} {item.status.name}")
            continue
        i = item
        out.append(
            f"@{i.address:x} word={i.word:08x} enc={i.encoding}"
            f" base={i.encoding_mnemonic} mnem={i.mnemonic}"
        )
        out.append(f" text={i.text()}")
        out.append(f" relative={i.text(binbun.TextOptions.RELATIVE_LABELS)}")
        out.append(branch_line(i.branch))
        if i.computed_address is not None:
            out.append(f" computed={i.computed_address:x}")
        if i.condition is not None:
            out.append(a64_condition_line(i.condition))
        out.append(f" flags={int(i.flags.read):x},{int(i.flags.written):x}")
        if i.memory is not None:
            out.append(f" memory={i.memory.kind.name.lower()}/{i.memory.size}")
        for label, registers in (("reads", i.implicit_reads), ("writes", i.implicit_writes)):
            if registers:
                out.append(f" {label}:" + "".join(a64_register("r", r) for r in registers))
        out.extend(a64_operand_line(op) for op in i.operands)
    return out


@pytest.fixture(scope="module")
def c_program() -> Path:
    """The C API's test program (`tests/c/disasm_test.c`), built by
    `scripts/python-tests.sh`."""
    path = os.environ.get("BINBUN_DISASM_TEST")
    if not path:
        pytest.skip("no C API test program (BINBUN_DISASM_TEST)")
    return Path(path)


@pytest.mark.parametrize("name", CODE)
def test_fixture_code_decodes_as_the_c_api_says(
    name: str, c_program: Path, tmp_path: Path
) -> None:
    compared = 0
    for arch, address, data in code_sections(name):
        code = tmp_path / f"{address:x}.text"
        code.write_bytes(data)
        printed = subprocess.run(
            [c_program, "dump", arch, f"{address:x}", code],
            check=True,
            capture_output=True,
            text=True,
            env={k: v for k, v in os.environ.items() if k != "LD_LIBRARY_PATH"},
        ).stdout.splitlines()
        if arch == "aarch64":
            dumped = aarch64_dump(address, data)
        else:
            mode = x86.Mode.BITS64 if arch == "x86-64" else x86.Mode.BITS32
            dumped = x86_dump(mode, address, data)
            # The C program prints XED's iclass as it is; Python lowers it.
            printed = [re.sub(r"(?<= mnem=)\S+", lambda m: m.group().lower(), line) for line in printed]
        for number, (python, c) in enumerate(zip(dumped, printed), 1):
            assert python == c, f"{name} {address:#x}: line {number}"
        assert len(dumped) == len(printed)
        compared += len(printed)
    assert compared > 50


@pytest.mark.parametrize("name", CODE)
def test_tokens_spell_the_text_and_name_real_operands(name: str) -> None:
    for arch, address, data in code_sections(name):
        if arch == "aarch64":
            decoder: Iterator[object] = aarch64.Decoder(data, address)
            options = [binbun.TextOptions.DEFAULT, binbun.TextOptions.RELATIVE_LABELS]
        else:
            mode = x86.Mode.BITS64 if arch == "x86-64" else x86.Mode.BITS32
            decoder = x86.Decoder(data, address, mode)
            options = [binbun.TextOptions.DEFAULT]
        for i in decoder:
            if not isinstance(i, (x86.Instruction, aarch64.Instruction)):
                continue
            for option in options:
                tokens = i.tokens(option)
                assert "".join(t.text for t in tokens) == i.text(option)
                assert [t.offset for t in tokens] == [
                    sum(len(u.text) for u in tokens[:n]) for n in range(len(tokens))
                ]
                assert all(t.operand is None or t.operand < len(i.operands) for t in tokens)
                separators = [t for t in tokens if t.kind is binbun.TokenKind.SEPARATOR]
                assert all(t.operand is None for t in separators)


@pytest.mark.parametrize("name", CODE)
def test_sweep_is_the_decoder_in_columns(name: str) -> None:
    for arch, address, data in code_sections(name):
        if arch == "aarch64":
            sweep = aarch64.sweep(data, address)
            items: list[object] = list(aarch64.Decoder(data, address))
        else:
            mode = x86.Mode.BITS64 if arch == "x86-64" else x86.Mode.BITS32
            sweep = x86.sweep(data, address, mode)
            items = list(x86.Decoder(data, address, mode))
        expected: list[tuple[int, int, int, int, int, int | None]] = []
        for item in items:
            if isinstance(item, binbun.Invalid):
                expected.append((item.address, item.length, int(item.status), 0, 0, None))
            else:
                assert isinstance(item, (x86.Instruction, aarch64.Instruction))
                b = item.branch
                expected.append(
                    (item.address, item.length, 0, int(b.kind), int(b.target_kind), b.target)
                )
        columns = list(
            zip(
                sweep.addresses,
                sweep.lengths,
                sweep.statuses,
                sweep.branch_kinds,
                sweep.target_kinds,
                sweep.targets,
            )
        )
        assert len(sweep) == len(expected)
        assert columns == expected


# --------------------------------------------------------------------------
# One instruction, bad bytes, buffers


def test_x86_decodes_one_instruction_at_its_address() -> None:
    call = x86.decode(b"\xe8\x00\x01\x00\x00", address=0x401000)
    assert (call.text(), call.length, call.mnemonic, call.bytes) == (
        "call 0x401105",
        5,
        "call_near",
        b"\xe8\x00\x01\x00\x00",
    )
    assert call.branch.kind is binbun.BranchKind.CALL
    assert call.branch.target == 0x401105 and call.branch.falls_through
    mov = x86.decode(bytes.fromhex("488b4310"), mode=x86.Mode.BITS64)
    assert mov.text() == "mov rax, qword ptr [rbx+0x10]"
    destination, source = mov.operands
    assert (destination.register, destination.access) == ("rax", binbun.Access.WRITE)
    assert (source.kind, source.base, source.displacement, source.memory_size) == (
        x86.OperandKind.MEMORY,
        "rbx",
        0x10,
        8,
    )
    assert source.access == binbun.Access.READ
    add = x86.decode(b"\x01\xd8")  # add eax, ebx
    assert add.flags.written & x86.Flag.ZF and add.flags.must_write
    assert [(t.kind, t.text, t.operand) for t in add.tokens()] == [
        (binbun.TokenKind.MNEMONIC, "add", None),
        (binbun.TokenKind.WHITESPACE, " ", None),
        (binbun.TokenKind.REGISTER, "eax", 0),
        (binbun.TokenKind.SEPARATOR, ", ", None),
        (binbun.TokenKind.REGISTER, "ebx", 1),
    ]
    assert x86.decode(b"\x66\x90", mode=x86.Mode.BITS16).text() == "data32 nop"
    assert x86.decode_length(b"\x48\x89\xc7\xc3") == 3


def test_aarch64_decodes_the_crates_examples() -> None:
    assert aarch64.decode_word(0x8B020020).text() == "add\tx0, x1, x2"
    b = aarch64.decode_word(0x14000010, 0x1000)
    assert b.text(binbun.TextOptions.RELATIVE_LABELS) == "b\t#0x40"
    assert b.text() == "b\t0x1040" and b.branch.target == 0x1040
    assert aarch64.decode(bytes.fromhex("1f2003d5")).encoding == "NOP_HI_hints"
    ldr = aarch64.decode(bytes.fromhex("200440f9"), 0x2000)
    assert ldr.text() == "ldr\tx0, [x1, #0x8]"
    assert [op.access for op in ldr.operands] == [binbun.Access.WRITE, binbun.Access.READ]
    assert ldr.memory is not None and ldr.memory.kind is aarch64.MemoryKind.LOAD
    ret = aarch64.decode_word(0xD65F03C0)
    assert [str(r) for r in ret.implicit_reads] == ["x30"]
    assert ret.branch.kind is binbun.BranchKind.RETURN


def test_bytes_that_are_no_instruction() -> None:
    with pytest.raises(binbun.DecodeError) as error:
        aarch64.decode_word(0x0BC20020, 0x40)
    assert (error.value.status, error.value.address) == (binbun.Status.AARCH64_UNDEFINED, 0x40)
    assert isinstance(error.value, ValueError)
    with pytest.raises(binbun.DecodeError) as error:
        aarch64.decode_word(0xFFFFFFFF)
    assert error.value.status is binbun.Status.AARCH64_UNALLOCATED
    with pytest.raises(binbun.DecodeError) as error:
        x86.decode(b"\x06")  # push es: none in 64-bit mode
    assert error.value.status is binbun.Status.INVALID and error.value.status.is_invalid
    with pytest.raises(binbun.DecodeError) as error:
        x86.decode(b"\xf0\x90")
    assert error.value.status is binbun.Status.X86_BAD_LOCK_PREFIX
    # A sweep steps one byte over x86 it cannot decode and resynchronises.
    swept = list(x86.Decoder(b"\x55\x06\xc3", address=0x10))
    assert [type(i).__name__ for i in swept] == ["Instruction", "Invalid", "Instruction"]
    invalid = swept[1]
    assert isinstance(invalid, binbun.Invalid)
    assert (invalid.address, invalid.length, invalid.bytes, invalid.status) == (
        0x11,
        1,
        b"\x06",
        binbun.Status.INVALID,
    )


def test_truncated_bytes() -> None:
    for data in (b"", b"\x48\x89", b"\x0f"):
        with pytest.raises(binbun.DecodeError) as error:
            x86.decode(data)
        assert error.value.status is binbun.Status.TRUNCATED
        assert not error.value.status.is_invalid
    with pytest.raises(binbun.DecodeError) as error:
        aarch64.decode(b"\x1f\x20\x03")
    assert error.value.status is binbun.Status.TRUNCATED
    tail = list(aarch64.Decoder(bytes.fromhex("1f2003d5c0035f"), 0x100))
    assert isinstance(tail[0], aarch64.Instruction) and str(tail[0]) == "nop"
    assert isinstance(tail[1], binbun.Invalid)
    assert (tail[1].address, tail[1].length, tail[1].status) == (
        0x104,
        3,
        binbun.Status.TRUNCATED,
    )
    x86_tail = list(x86.Decoder(b"\xc3\x48\x89"))
    assert [i.status for i in x86_tail[1:] if isinstance(i, binbun.Invalid)] == [
        binbun.Status.TRUNCATED,
        binbun.Status.TRUNCATED,
    ]


def test_buffers_and_arguments() -> None:
    code = bytes.fromhex("554889e5c3")
    expected = [str(i) for i in x86.Decoder(code)]
    assert [str(i) for i in x86.Decoder(bytearray(code))] == expected
    assert [str(i) for i in x86.Decoder(memoryview(code))] == expected
    assert x86.sweep(memoryview(code)).lengths == [1, 3, 1]
    decoder = x86.Decoder(code, address=0x1000)
    decoder.offset = 1
    assert decoder.address == 0x1001
    assert [i.text() for i in decoder] == ["mov rbp, rsp", x86.decode(b"\xc3").text()]
    with pytest.raises(ValueError):
        x86.decode(code, mode=9)
    with pytest.raises(ValueError):
        x86.decode(code).text(binbun.TextOptions.RELATIVE_LABELS)
    with pytest.raises(ValueError):
        x86.decode(code, address=-1)
    with pytest.raises(TypeError):
        x86.decode("55")  # type: ignore[arg-type]
    # Values: equal when the same bytes decode at the same address.
    assert x86.decode(code, 0x10) == x86.decode(bytearray(code), 0x10)
    assert x86.decode(code, 0x10) != x86.decode(code, 0x11)
    assert len({aarch64.decode_word(0xD65F03C0), aarch64.decode_word(0xD65F03C0)}) == 1
