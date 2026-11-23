# IDAPython, for `idat -A -S"ida_functions.py OUT" FILE`: after auto-analysis,
# writes the image base, then every function's start, in hex, one per line.
import ida_auto
import ida_nalt
import ida_pro
import idautils
import idc

ida_auto.auto_wait()
with open(idc.ARGV[1], "w") as out:
    out.write("%x\n" % ida_nalt.get_imagebase())
    for address in idautils.Functions():
        out.write("%x\n" % address)
ida_pro.qexit(0)
