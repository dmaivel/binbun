"""One decoder for both architectures (``binbun.Decoder``,
``binbun.Instruction``, ``binbun.disassemble``): every instruction of the
fixtures' code as the native decoders (``binbun.x86``, ``binbun.aarch64``)
decode it, the registers read and written as their operands say, the
architecture and mode arguments, bad bytes and text options."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

import binbun
from binbun import aarch64, x86
from test_disasm import CODE, code_sections

# Flags are left out of the register facts, and XED's pseudo registers
# that are no machine state.
X86_FLAGS = {"flags", "eflags", "rflags"}
X86_NOT_STATE = {"stackpush", "stackpop", "x87push", "x87pop", "x87pop2"} | {
    f"dfv{n}" for n in range(16)
}
X86_WRITE_ONLY = {x86.Action.WRITE, x86.Action.CONDITIONAL_WRITE}
X86_READ_ONLY = {x86.Action.READ, x86.Action.CONDITIONAL_READ}


def add(names: list[str], name: str) -> None:
    if name not in names:
        names.append(name)


def x86_registers(i: x86.Instruction) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """What ``i``'s operands say it may read and write."""
    read: list[str] = []
    written: list[str] = []
    for op in i.operands:
        if op.kind is x86.OperandKind.REGISTER:
            name = op.register
            if name is None or name in X86_FLAGS | X86_NOT_STATE:
                continue
            if op.action not in X86_WRITE_ONLY:
                add(read, name)
            if op.action not in X86_READ_ONLY:
                add(written, name)
        elif op.kind is x86.OperandKind.MEMORY:
            for name in (op.segment, op.base, op.index):
                if name is not None and name not in X86_NOT_STATE:
                    add(read, name)
    return tuple(read), tuple(written)


def a64_name(r: aarch64.Register) -> str:
    """The register itself, without arrangement, index or qualifier."""
    text = str(r)
    for mark in ".[/":
        text = text.split(mark)[0]
    return text


def a64_registers(i: aarch64.Instruction) -> tuple[tuple[str, ...], tuple[str, ...]] | None:
    """What ``i``'s operands and implicit registers say it may read and
    write; ``None`` for SME operands, which this does not model."""
    read: list[str] = []
    written: list[str] = []
    kinds = aarch64.OperandKind
    for op in i.operands:
        reads = bool(op.access & binbun.Access.READ)
        writes = bool(op.access & binbun.Access.WRITE)
        names: list[str] = []
        if op.kind in (kinds.REGISTER, kinds.WRITEBACK):
            assert isinstance(op.value, aarch64.Register)
            if op.value.register_class is not aarch64.RegisterClass.C:
                names = [a64_name(op.value)]
        elif op.kind is kinds.LIST:
            assert isinstance(op.value, aarch64.RegisterList)
            names = [a64_name(r) for r in op.value.registers]
        elif op.kind is kinds.SYSTEM_REGISTER:
            assert isinstance(op.value, aarch64.SystemRegister)
            e = op.value.encoding
            names = [op.value.name or f"S{e >> 14}_{(e >> 11) & 7}_C{(e >> 7) & 15}_C{(e >> 3) & 15}_{e & 7}"]
        elif op.kind is kinds.MEMORY:
            m = op.value
            assert isinstance(m, aarch64.Memory)
            add(read, a64_name(m.base))
            if m.index is not None:
                add(read, a64_name(m.index))
            if m.writeback is not aarch64.Writeback.NONE:
                add(written, a64_name(m.base))
            continue
        elif op.kind in (kinds.ZA, kinds.ZA_LIST, kinds.TABLE_SLICE, kinds.INDEXED_REGISTER):
            return None
        for name in names:
            if reads:
                add(read, name)
            if writes:
                add(written, name)
    for r in i.implicit_reads:
        add(read, a64_name(r))
    for r in i.implicit_writes:
        add(written, a64_name(r))
    return tuple(read), tuple(written)


def decoders(arch: str, address: int, data: bytes) -> Iterator[tuple[object, object]]:
    """The generic and the native decoder's items, side by side."""
    if arch == "aarch64":
        generic = binbun.Decoder(data, arch=binbun.Arch.AARCH64, address=address)
        native: Iterator[object] = aarch64.Decoder(data, address)
    else:
        mode = x86.Mode.BITS64 if arch == "x86-64" else x86.Mode.BITS32
        generic = binbun.Decoder(data, arch=binbun.Arch.X86, address=address, mode=mode)
        native = x86.Decoder(data, address, mode)
    items = list(generic)
    expected = list(native)
    assert len(items) == len(expected)
    yield from zip(items, expected)


@pytest.mark.parametrize("name", CODE)
def test_fixture_code_decodes_as_the_native_decoders_say(name: str) -> None:
    for arch, address, data in code_sections(name):
        for item, native in decoders(arch, address, data):
            if isinstance(native, binbun.Invalid):
                assert item == native
                continue
            assert isinstance(item, binbun.Instruction)
            assert isinstance(native, (x86.Instruction, aarch64.Instruction))
            assert (item.address, item.length, len(item), item.bytes) == (
                native.address,
                native.length,
                len(native),
                native.bytes,
            )
            assert (item.text(), str(item)) == (native.text(), str(native))
            assert item.branch == native.branch
            if isinstance(native, x86.Instruction):
                assert item.arch is binbun.Arch.X86
                assert (item.x86, item.aarch64) == (native, None)
                # The mnemonic is the token the text writes as one.
                mnemonics = [t.text for t in native.tokens() if t.kind is binbun.TokenKind.MNEMONIC]
                assert mnemonics == [item.mnemonic]
                assert (item.registers_read, item.registers_written) == x86_registers(native)
            else:
                assert item.arch is binbun.Arch.AARCH64
                assert (item.x86, item.aarch64) == (None, native)
                assert item.mnemonic == native.mnemonic
                assert item.text(binbun.TextOptions.RELATIVE_LABELS) == native.text(
                    binbun.TextOptions.RELATIVE_LABELS
                )
                expected = a64_registers(native)
                if expected is not None:
                    assert (item.registers_read, item.registers_written) == expected, item


def test_shared_facts_of_both_architectures() -> None:
    push, rep, ret = binbun.disassemble(bytes.fromhex("55f3a4c3"), arch=binbun.Arch.X86, address=0x1000)
    assert isinstance(push, binbun.Instruction) and isinstance(rep, binbun.Instruction)
    assert (push.mnemonic, push.registers_read, push.registers_written) == ("push", ("rbp", "rsp"), ("rsp",))
    # The text's mnemonic, not XED's iclass (lowered); flags left out.
    assert (rep.text(), rep.mnemonic, rep.x86 and rep.x86.mnemonic) == (
        "rep movsb byte ptr [rdi], byte ptr [rsi]",
        "movsb",
        "rep_movsb",
    )
    assert rep.registers_read == ("rdi", "rsi", "rcx") == rep.registers_written
    assert isinstance(ret, binbun.Instruction) and ret.branch.kind is binbun.BranchKind.RETURN
    code = bytes.fromhex("e00301aa" "40d03bd5" "fd7bbfa9" "00000014")
    mov, mrs, stp, b = binbun.disassemble(code, arch="aarch64", address=0x2000)
    assert isinstance(mov, binbun.Instruction) and isinstance(mrs, binbun.Instruction)
    assert isinstance(stp, binbun.Instruction) and isinstance(b, binbun.Instruction)
    assert (mov.text(), mov.mnemonic, mov.aarch64 and mov.aarch64.encoding_mnemonic) == ("mov\tx0, x1", "mov", "ORR")
    assert (mrs.registers_read, mrs.registers_written) == (("TPIDR_EL0",), ("x0",))
    assert (stp.registers_read, stp.registers_written) == (("x29", "x30", "sp"), ("sp",))
    assert (b.text(), b.text(binbun.TextOptions.RELATIVE_LABELS)) == ("b\t0x200c", "b\t#0x0")
    assert b.branch.target == 0x200C and b.bytes == bytes.fromhex("00000014")


def test_architecture_and_mode_arguments() -> None:
    code = bytes.fromhex("4889c7")
    # x86 is 64-bit unless a mode says otherwise.
    assert [str(i) for i in binbun.disassemble(code, arch=binbun.Arch.X86)] == ["mov rdi, rax"]
    in32 = list(binbun.disassemble(code, arch="x86", mode=x86.Mode.BITS32))
    assert [str(i) for i in in32] == ["dec eax", "mov edi, eax"]
    assert isinstance(in32[0], binbun.Instruction) and in32[0].x86 is not None
    assert in32[0].x86.mode is x86.Mode.BITS32
    # The same bytes in another mode are another instruction.
    assert in32[1] != next(binbun.disassemble(code[1:], arch=binbun.Arch.X86, mode=x86.Mode.BITS64, address=1))
    with pytest.raises(ValueError):
        binbun.Decoder(code, arch=binbun.Arch.AARCH64, mode=x86.Mode.BITS64)
    with pytest.raises(ValueError):
        binbun.Decoder(code, arch="mips")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        binbun.Decoder(code, arch=binbun.Arch.X86, mode=9)
    with pytest.raises(ValueError):
        binbun.Decoder(code, arch=binbun.Arch.X86, address=-1)
    with pytest.raises(TypeError):
        binbun.Decoder("4889c7", arch=binbun.Arch.X86)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        binbun.Decoder(code, binbun.Arch.X86)  # type: ignore[call-arg]
    mov = next(binbun.disassemble(code, arch=binbun.Arch.X86))
    assert isinstance(mov, binbun.Instruction)
    with pytest.raises(ValueError):
        mov.text(binbun.TextOptions.RELATIVE_LABELS)
    assert binbun.Decoder(code, arch="aarch64").arch is binbun.Arch.AARCH64


def test_bytes_that_are_no_instruction_and_buffers() -> None:
    # x86 steps one byte, AArch64 four (fewer at the end), as the native sweeps.
    items = list(binbun.disassemble(b"\x55\x06\xc3\x48\x89", arch=binbun.Arch.X86, address=0x10))
    assert [(type(i).__name__, i.address, i.length) for i in items] == [
        ("Instruction", 0x10, 1),
        ("Invalid", 0x11, 1),
        ("Instruction", 0x12, 1),
        ("Invalid", 0x13, 1),
        ("Invalid", 0x14, 1),
    ]
    invalid = items[1]
    assert isinstance(invalid, binbun.Invalid) and invalid.status is binbun.Status.INVALID
    assert [i.status for i in items[3:] if isinstance(i, binbun.Invalid)] == [binbun.Status.TRUNCATED] * 2
    tail = list(binbun.disassemble(bytes.fromhex("1f2003d5ffffffffc0035f"), arch=binbun.Arch.AARCH64, address=0x100))
    assert [(type(i).__name__, i.address, i.length) for i in tail] == [
        ("Instruction", 0x100, 4),
        ("Invalid", 0x104, 4),
        ("Invalid", 0x108, 3),
    ]
    assert [i.status for i in tail if isinstance(i, binbun.Invalid)] == [
        binbun.Status.AARCH64_UNALLOCATED,
        binbun.Status.TRUNCATED,
    ]
    code = bytes.fromhex("554889e5c3")
    expected = [str(i) for i in binbun.disassemble(code, arch=binbun.Arch.X86)]
    assert [str(i) for i in binbun.disassemble(bytearray(code), arch=binbun.Arch.X86)] == expected
    assert [str(i) for i in binbun.disassemble(memoryview(code), arch=binbun.Arch.X86)] == expected
    decoder = binbun.Decoder(code, arch=binbun.Arch.X86, address=0x1000)
    decoder.offset = 1
    assert decoder.address == 0x1001
    assert [str(i) for i in decoder] == expected[1:]
    # Values: equal when the same bytes decode at the same address.
    one = next(binbun.disassemble(code, arch=binbun.Arch.X86, address=0x10))
    assert one == next(binbun.disassemble(bytearray(code), arch=binbun.Arch.X86, address=0x10))
    assert one != next(binbun.disassemble(code, arch=binbun.Arch.X86, address=0x11))
    assert len({one, next(binbun.disassemble(code, arch=binbun.Arch.X86, address=0x10))}) == 1
