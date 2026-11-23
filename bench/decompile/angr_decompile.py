# angr's decompiler as DecompileBench's runner sets it up
# (decompiler-service/src/runners/angr/angr_runner.py): CFGFast with
# indirect jumps resolved and data references, CompleteCallingConventions
# with variables recovered and call sites analysed, then Decompiler on each
# function with that CFG. Functions are the CFG's, without PLT stubs, angr's
# stand-ins (SimProcedures) and alignment padding, as its
# decompile_angr.py runner takes them.
#
#   python angr_decompile.py FILE OUT [SHARD COUNT [SECONDS]]
#
# writes OUT.c: each function after a line `//@bench ADDRESS` (in the
# file's own addresses), then its C, or `//@failed REASON`; OUT.names: the
# main object's base, then every function's and label's `address name`,
# in hex, one per line; OUT.version: angr's version. With SHARD and COUNT,
# only the functions whose index (by address) is SHARD modulo COUNT are
# decompiled (the names are written by shard 0 only); with SECONDS, a
# function taking longer is given up (`//@failed timed out`).
import logging
import signal
import sys

import angr

logging.disable(logging.CRITICAL)
sys.setrecursionlimit(100000)
path, out = sys.argv[1], sys.argv[2]
shard, count = (int(sys.argv[3]), int(sys.argv[4])) if len(sys.argv) > 4 else (0, 1)
seconds = int(sys.argv[5]) if len(sys.argv) > 5 else 0


class TimedOut(Exception):
    pass


def alarm(signum, frame):
    raise TimedOut()


signal.signal(signal.SIGALRM, alarm)

project = angr.Project(path, auto_load_libs=False, load_debug_info=False)
cfg = project.analyses.CFGFast(
    normalize=True, resolve_indirect_jumps=True, data_references=True
)
project.analyses.CompleteCallingConventions(
    cfg=cfg.model, recover_variables=True, analyze_callsites=True
)
base = project.loader.main_object.mapped_base
functions = sorted(
    (
        f
        for f in cfg.functions.values()
        if not f.is_plt and not f.is_simprocedure and not f.is_alignment
    ),
    key=lambda f: f.addr,
)
if shard == 0:
    with open(out + ".version", "w") as f:
        f.write(angr.__version__ + "\n")
    with open(out + ".names", "w") as f:
        f.write("%x\n" % base)
        for function in cfg.functions.values():
            f.write("%x %s\n" % (function.addr, function.name))
        for address, name in project.kb.labels.items():
            f.write("%x %s\n" % (address, name))
with open(out + ".c", "w") as f:
    for index, function in enumerate(functions):
        if index % count != shard:
            continue
        f.write("//@bench %x\n" % (function.addr - base))
        try:
            signal.alarm(seconds)
            decompiler = project.analyses.Decompiler(function, cfg=cfg.model)
            signal.alarm(0)
            if decompiler.codegen is None or not decompiler.codegen.text:
                f.write("//@failed no output\n")
            else:
                f.write(decompiler.codegen.text + "\n")
        except TimedOut:
            f.write("//@failed timed out\n")
        except Exception as error:
            signal.alarm(0)
            reason = " ".join(str(error).split())[:200]
            f.write("//@failed %s: %s\n" % (type(error).__name__, reason))
        f.flush()
