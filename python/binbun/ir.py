"""Unstable: binbun's intermediate representations, as text.

A function through every stage of its decompilation (``f.stages()``):
the machine code, L1 after each pass, L2 after each pass, the C. Excluded
from ``binbun.API_VERSION``: the stages, their names and their text change
with the engine (``IR_VERSION``).
"""

from __future__ import annotations

from binbun._native import Stages, StageText, __version__

IR_VERSION: str = __version__
"""The engine version the text forms are of."""

__all__ = ["IR_VERSION", "StageText", "Stages"]
