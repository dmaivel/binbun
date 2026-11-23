import binbun

code = bytes.fromhex("554889e531c05dc3")

for insn in binbun.disassemble(code, arch=binbun.Arch.X86, address=0x401000):
    print(f"{insn.address:#x}  {insn.text()}")
