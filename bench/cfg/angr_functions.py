# angr's CFGFast: `python angr_functions.py FILE OUT` writes the main
# object's base, then every function's start (not angr's own stand-ins for
# imports and system calls), in hex, one per line.
import logging
import sys

import angr

logging.disable(logging.CRITICAL)
project = angr.Project(sys.argv[1], auto_load_libs=False, load_debug_info=False)
cfg = project.analyses.CFGFast(normalize=True)
with open(sys.argv[2], "w") as out:
    out.write("%x\n" % project.loader.main_object.mapped_base)
    for address, function in cfg.kb.functions.items():
        if not (function.is_simprocedure or function.is_syscall):
            out.write("%x\n" % address)
