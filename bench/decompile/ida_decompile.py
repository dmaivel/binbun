# IDAPython, for `idat -A -S"ida_decompile.py OUT" FILE`: after
# auto-analysis, Hex-Rays decompiles every function into OUT.c as IDA's
# File > Produce file > Create C file does (`decompile_many`: `#include
# <defs.h>`, the declarations of every function and datum, then each
# function after a `//----- (ADDRESS) ---` line), then writes OUT.names:
# the image base, then every name IDA has, `address name` in hex, one per
# line. OUT.version holds Hex-Rays' version.
import ida_auto
import ida_hexrays
import ida_nalt
import ida_pro
import idautils
import idc

out = idc.ARGV[1]
ida_auto.auto_wait()
if not ida_hexrays.init_hexrays_plugin():
    ida_pro.qexit(2)
with open(out + ".version", "w") as f:
    f.write(ida_hexrays.get_hexrays_version() + "\n")
ida_hexrays.decompile_many(
    out + ".c", None, ida_hexrays.VDRUN_NEWFILE | ida_hexrays.VDRUN_SILENT
)
with open(out + ".names", "w") as f:
    f.write("%x\n" % ida_nalt.get_imagebase())
    for address, name in idautils.Names():
        f.write("%x %s\n" % (address, name))
ida_pro.qexit(0)
