#!/usr/bin/env python3
"""Reports and charts from the benchmarks' raw results.

    python3 plot.py [RESULTS_DIR]      # default: results/ next to this script

Renders whatever is there:

- decode.json (`cargo run --release` on x86-64 files) and
  decode-aarch64.json (on AArch64 files): README.md, with a section for each,
  and throughput.svg and throughput-aarch64.svg.
  The same file in full/, from a run over a larger corpus (`--out
  results/full`), is summarised in that section.
- cfg.json (`cargo run --release --bin cfg`): cfg.md, cfg-overview.svg
  (accuracy against time) and cfg-precision-recall.svg.
- decompile.json (`cargo run --release --bin decompile`): decompile.md and
  decompile-overview.svg.
  results/private/ holds the run with Hex-Rays and Binary Ninja
  (`--private`), whose results are not published (UNPUBLISHED); render it
  with `python3 plot.py results/private`.

Needs matplotlib. The SVGs keep text as text, have no background and use
mid-tone colours, so they read on light and dark pages alike.
"""

import json
import math
import sys
from pathlib import Path

import matplotlib

matplotlib.use("svg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.ticker import PercentFormatter

MUTED = "#7d8590"
ACCENT = "#e8590c"
OTHER = "#4c6ef5"
# Colour and marker per function recovery tool.
TOOLS = {
    "binbun": (ACCENT, "*"),
    "ida": ("#4c6ef5", "o"),
    "ghidra": ("#e03131", "s"),
    "angr": ("#2f9e44", "^"),
    "radare2": ("#7048e8", "D"),
    "rizin": ("#1098ad", "v"),
    "falcon": ("#b08968", "P"),
    "binbun-reading": ("#f59f00", "*"),
    "hexrays": ("#4c6ef5", "o"),
    "binja": ("#7048e8", "D"),
}

plt.rcParams.update(
    {
        "svg.fonttype": "none",
        "svg.hashsalt": "binbun",
        "font.family": "sans-serif",
        "font.size": 10,
        "text.color": MUTED,
        "axes.labelcolor": MUTED,
        "axes.edgecolor": MUTED,
        "axes.titlecolor": MUTED,
        "xtick.color": MUTED,
        "ytick.color": MUTED,
        "grid.color": MUTED,
        "grid.alpha": 0.25,
        "legend.frameon": False,
        "savefig.transparent": True,
        "savefig.bbox": "tight",
    }
)


def save(figure, path):
    figure.savefig(path, metadata={"Date": None})
    plt.close(figure)
    print(f"wrote {path}")


def grid(count, width=4.2, height=3.2):
    """A figure with `count` panels, at most three per row."""
    columns = min(3, count)
    rows = math.ceil(count / columns)
    figure, axes = plt.subplots(
        rows, columns, figsize=(width * columns, height * rows), squeeze=False
    )
    panels = [a for row in axes for a in row]
    for spare in panels[count:]:
        spare.set_visible(False)
    return figure, panels[:count]


def tool_style(tool):
    return TOOLS.get(tool, (OTHER, "o"))


# Decoder throughput.

# Per results file: the architecture, its chart, how a sweep skips what does
# not decode, and the column counting that.
ARCHES = {
    "decode.json": ("x86-64", "throughput.svg", "skipping one byte", "Skipped bytes"),
    "decode-aarch64.json": (
        "AArch64",
        "throughput-aarch64.svg",
        "skipping the 4-byte word",
        "Invalid words",
    ),
}
# A run over a larger corpus, written with `--out results/full`, is
# summarised after the main run's section.
LARGER = "full"


def interval(estimate):
    """The 95% confidence interval in MB, or a dash with too few samples."""
    if estimate["low"] is None:
        return "—"
    return f"{estimate['low'] / 1e6:.0f}–{estimate['high'] / 1e6:.0f}"


def spread(estimate):
    """How far the interval reaches below and above the median, in MB."""
    if estimate["low"] is None:
        return 0, 0
    return (
        estimate["median"] / 1e6 - estimate["low"] / 1e6,
        estimate["high"] / 1e6 - estimate["median"] / 1e6,
    )


def shown(path):
    """`path` as the README shows it: under the home directory as `~/...`."""
    home = Path.home()
    return (
        f"~/{Path(path).relative_to(home)}" if Path(path).is_relative_to(home) else path
    )


def decode(results, out, name):
    """Draws the chart for one results file; returns its README section."""
    arch, chart, skipping, skipped = ARCHES[name]
    tasks = results["tasks"]
    # One panel per task, stacked: decoder names go left of each panel.
    heights = [0.38 * len(t["measurements"]) + 0.9 for t in tasks]
    figure, panels = plt.subplots(
        len(tasks),
        1,
        figsize=(8, sum(heights)),
        squeeze=False,
        gridspec_kw={"height_ratios": heights},
        layout="constrained",
    )
    panels = [row[0] for row in panels]
    for panel, task in zip(panels, tasks):
        measurements = task["measurements"]
        names = [m["contender"] for m in measurements]
        mb = [m["bytes_per_second"]["median"] / 1e6 for m in measurements]
        low = [spread(m["bytes_per_second"])[0] for m in measurements]
        high = [spread(m["bytes_per_second"])[1] for m in measurements]
        colours = [ACCENT if n.startswith("binbun") else OTHER for n in names]
        rows = range(len(names))
        panel.barh(
            rows,
            mb,
            xerr=[low, high],
            color=colours,
            error_kw={"ecolor": MUTED, "capsize": 3},
        )
        panel.set_yticks(list(rows), names)
        panel.invert_yaxis()
        for row, value, above in zip(rows, mb, high):
            panel.annotate(
                f"{value:,.0f}",
                (value + above, row),
                xytext=(6, 0),
                textcoords="offset points",
                va="center",
                fontsize=8,
            )
        panel.set_title(task["name"])
        if panel is panels[-1]:
            panel.set_xlabel("MB/s of code (higher is better)")
        panel.grid(axis="x")
        panel.set_axisbelow(True)
        panel.spines[["top", "right"]].set_visible(False)
    save(figure, out / chart)

    lines = [f"# {arch} decoder throughput", ""]
    if arch == "x86-64":
        lines.append(f"CPU: {results['cpu']}  ")
    else:
        # The decoders run on the benchmark's host, not on the architecture
        # they decode.
        lines.append(f"CPU: {results['cpu']} (decoding {arch} code)  ")
    corpus = results["corpus"]
    lines.append(f"Corpus ({sum(f['bytes'] for f in corpus)} bytes of code):")
    lines.append("")
    lines += [f"- `{shown(f['path'])}`: {f['bytes']} bytes" for f in corpus]
    lines.append("")
    if all(
        m["bytes_per_second"]["low"] is not None
        for t in tasks
        for m in t["measurements"]
    ):
        lines.append(
            f"Each decoder linearly sweeps the corpus, {skipping} where nothing decodes. "
            f"Values are the median of {results['samples']} timed samples, taken one per decoder per round; "
            "the whiskers and the CI column give the 95% confidence interval for the median "
            "(order statistics). The interval covers noise within this run only."
        )
    else:
        lines.append(
            f"Each decoder linearly sweeps the corpus, {skipping} where nothing decodes. "
            f"Values are the median of {results['samples']} timed samples, taken one per decoder per round; "
            "that is too few for a 95% confidence interval for the median (order statistics need 6)."
        )
    lines += ["", f"![Throughput]({link(chart, out)})"]
    for task in tasks:
        lines += ["", f"## {task['name']}", ""]
        lines.append(
            f"| Decoder | MB/s | 95% CI | M instructions/s | Instructions | {skipped} | How |"
        )
        lines.append("|---|---:|---:|---:|---:|---:|---|")
        for m in task["measurements"]:
            b = m["bytes_per_second"]
            lines.append(
                f"| {m['contender']} | {b['median'] / 1e6:.0f} | {interval(b)} "
                f"| {m['instructions_per_second']['median'] / 1e6:.1f} | {m['sweep']['instructions']} "
                f"| {m['sweep']['invalid']} | {m['detail']} |"
            )
    return lines


def larger(results, name):
    """The README section summarising a run over a larger corpus."""
    tasks = results["tasks"]
    corpus = results["corpus"]
    lines = ["", "## Larger corpus", ""]
    lines.append(
        f"The same benchmark over {sum(f['bytes'] for f in corpus)} bytes of code "
        f"(`{LARGER}/{name}`):"
    )
    lines.append("")
    lines += [f"- `{shown(f['path'])}`: {f['bytes']} bytes" for f in corpus]
    lines.append("")
    lines.append(
        f"`cargo run --release -- --out results/{LARGER} "
        + " ".join(shown(f["path"]) for f in corpus)
        + "`"
    )
    lines.append("")
    lines.append(f"MB/s of code, median of {results['samples']} samples (95% CI):")
    lines.append("")
    lines.append("| Decoder | " + " | ".join(t["name"] for t in tasks) + " |")
    lines.append("|---|" + "---:|" * len(tasks))
    by_task = [{m["contender"]: m for m in t["measurements"]} for t in tasks]
    contenders = dict.fromkeys(m["contender"] for t in tasks for m in t["measurements"])
    for contender in contenders:
        cells = []
        for measurements in by_task:
            m = measurements.get(contender)
            if m is None:
                cells.append("—")
                continue
            b = m["bytes_per_second"]
            cells.append(f"{b['median'] / 1e6:.0f} ({interval(b)})")
        lines.append(f"| {contender} | " + " | ".join(cells) + " |")
    return lines


# Function recovery.


def cfg(results, out):
    files = results["files"]
    tools = list(dict.fromkeys(r["tool"] for f in files for r in f["results"]))
    legend = [
        Line2D(
            [],
            [],
            color=tool_style(t)[0],
            marker=tool_style(t)[1],
            linestyle="",
            markersize=9,
            label=t,
        )
        for t in tools
    ]

    # Accuracy against time: up and to the left is better.
    figure, panels = grid(len(files))
    for panel, file in zip(panels, files):
        missing = []
        for r in file["results"]:
            colour, marker = tool_style(r["tool"])
            size = 220 if r["tool"] == "binbun" else 70
            if r["status"] == "ok":
                panel.scatter(
                    r["seconds"], r["f1"], s=size, color=colour, marker=marker, zorder=3
                )
            elif r["status"] == "timeout":
                # Hollow, at the time it was given and F1 0.
                panel.scatter(
                    r["seconds"],
                    0,
                    s=size,
                    facecolors="none",
                    edgecolors=colour,
                    marker=marker,
                    zorder=3,
                )
                missing.append(f"{r['tool']} timed out")
            else:
                missing.append(f"{r['tool']} failed")
        panel.set_xscale("log")
        panel.set_ylim(-0.04, 1.04)
        panel.set_title(f"{file['name']} ({file['stated']:,} functions)")
        panel.set_xlabel("seconds (log)")
        panel.set_ylabel("F1 of function starts")
        panel.grid(True, which="major")
        panel.spines[["top", "right"]].set_visible(False)
        if missing:
            panel.text(
                0.98,
                0.04,
                "\n".join(missing),
                transform=panel.transAxes,
                ha="right",
                va="bottom",
                fontsize=8,
            )
    figure.legend(
        handles=legend, loc="upper center", ncol=len(tools), bbox_to_anchor=(0.5, 1.03)
    )
    figure.suptitle(
        "Function recovery: accuracy against time (up and left is better)", y=1.08
    )
    figure.tight_layout()
    save(figure, out / "cfg-overview.svg")

    # Precision and recall per tool: a line from one to the other.
    figure, panels = grid(len(files), height=0.32 * len(tools) + 1.3)
    for panel, file in zip(panels, files):
        rows = file["results"]
        for row, r in enumerate(rows):
            colour, _ = tool_style(r["tool"])
            if r["status"] != "ok":
                panel.text(
                    0.01,
                    row,
                    "timed out" if r["status"] == "timeout" else "failed",
                    va="center",
                    fontsize=8,
                )
                continue
            p, q = r["precision"], r["recall"]
            panel.plot(
                [p, q], [row, row], color=colour, linewidth=2, alpha=0.5, zorder=2
            )
            panel.scatter(p, row, color=colour, marker="o", s=45, zorder=3)
            panel.scatter(
                q,
                row,
                facecolors="none",
                edgecolors=colour,
                marker="D",
                s=45,
                linewidths=1.5,
                zorder=3,
            )
        panel.set_yticks(range(len(rows)), [r["tool"] for r in rows])
        panel.invert_yaxis()
        panel.set_xlim(0, 1.02)
        panel.xaxis.set_major_formatter(PercentFormatter(1.0))
        panel.set_title(f"{file['name']} ({file['stated']:,} functions)")
        panel.grid(axis="x")
        panel.spines[["top", "right"]].set_visible(False)
    figure.legend(
        handles=[
            Line2D(
                [],
                [],
                color=MUTED,
                marker="o",
                linestyle="",
                label="precision (found starts that are right)",
            ),
            Line2D(
                [],
                [],
                color=MUTED,
                marker="D",
                markerfacecolor="none",
                linestyle="",
                label="recall (stated starts found)",
            ),
        ],
        loc="upper center",
        ncol=2,
        bbox_to_anchor=(0.5, 1.03),
    )
    figure.suptitle("Function recovery: precision and recall", y=1.08)
    figure.tight_layout()
    save(figure, out / "cfg-precision-recall.svg")

    lines = ["# Function recovery", ""]
    lines.append(
        f"CPU: {results['cpu']}; timeout {results['timeout_seconds']} s per tool and file."
    )
    lines.append("")
    lines.append(
        "Each tool gets a copy of each file stripped of its symbol tables (unwind tables and dynamic "
        "symbols stay). Its function starts are scored against what the original states: function "
        "symbols, unwind table entries and PE exports, read with binutils, in executable memory; "
        "PLT entries and import thunks are left out on both sides. Times are wall-clock, including "
        "each tool's startup."
    )
    lines += [
        "",
        f"![Accuracy against time]({link('cfg-overview.svg', out)})",
        "",
        f"![Precision and recall]({link('cfg-precision-recall.svg', out)})",
    ]
    for file in files:
        note = (
            ""
            if file["stripped"]
            else " (no symbol table to strip: the file as distributed)"
        )
        lines += [
            "",
            f"## {file['name']}",
            "",
            f"{file['stated']:,} functions stated{note}.",
            "",
        ]
        lines.append("| Tool | Found | Correct | Precision | Recall | F1 | Seconds |")
        lines.append("|---|---:|---:|---:|---:|---:|---:|")
        for r in file["results"]:
            if r["status"] == "ok":
                lines.append(
                    f"| {r['tool']} | {r['found']:,} | {r['correct']:,} | {r['precision']:.1%} "
                    f"| {r['recall']:.1%} | {r['f1']:.3f} | {r['seconds']:.2f} |"
                )
            else:
                lines.append(
                    f"| {r['tool']} | {r['note'].replace('|', '/')} | | | | | |"
                )
    write(out / "cfg.md", lines)


def write(path, lines):
    path.write_text("\n".join(lines) + "\n")
    print(f"wrote {path}")


# Decompilation.

# How the decompiler report names each tool.
DECOMPILERS = {
    "binbun": "binbun (exact)",
    "binbun-reading": "binbun (reading view)",
    "hexrays": "Hex-Rays",
    "ghidra": "Ghidra",
    "binja": "Binary Ninja",
    "angr": "angr",
}

# Tools whose results stay out of the published results/: Hex-Rays' licence
# (IDA Pro 9.4's license.txt) restricts benchmarking it and publishing the
# results without first inviting Hex-Rays to review them, and Binary Ninja's
# free edition is licensed for evaluation and non-commercial use only.
# `decompile --private` runs them, into results/private/.
UNPUBLISHED = {"hexrays": "Hex-Rays", "binja": "Binary Ninja"}


def measured(results):
    """The tools `results` scores."""
    return {t["tool"] for f in results.get("quality", {}).get("files", []) for t in f["tools"]}


def listed(names):
    """`names` as an English list: "a", "a and b", "a, b and c"."""
    return " and ".join(filter(None, [", ".join(names[:-1]), names[-1]])) if names else ""


def share(part, whole):
    return f"{part / whole:.1%}" if whole else "—"


def number(value, digits=2):
    return "—" if value is None else f"{value:.{digits}f}"


def decompile_intro(results, quality):
    versions = quality.get("versions", {})
    compilers = quality.get("compilers", {})
    commit = quality.get("binbun_commit")
    built = f", commit {commit}" if commit else ""
    tools = measured(results)
    others = [
        versions.get(tool, name) + (" (IDA Pro 9.4)" if tool == "hexrays" else "")
        for tool, name in DECOMPILERS.items()
        if tool in tools and not tool.startswith("binbun")
    ]
    found = (
        "Ghidra and IDA load the one the link names, Ghidra also"
        if "hexrays" in tools
        else "Ghidra loads the one the link names and"
    )
    beside = ", Binary Ninja one beside the file" if "binja" in tools else ""
    lines = [
        f"CPU: {results['cpu']}; every tool pinned to 16 of its CPUs (`taskset -c 16-31`). "
        f"Tools: {versions.get('binbun', 'binbun')} (the `binbun` command, a release build{built}), "
        f"{', '.join(others)}. Compilers: {compilers.get('clang', 'clang')}; "
        f"{compilers.get('gcc', 'gcc')}.",
        "",
        "The method is DecompileBench's (Gao et al., [Findings of ACL 2025]"
        "(https://aclanthology.org/2025.findings-acl.1194/)): does each function's C compile, "
        "and does the program still behave the same with the function replaced by its recompiled "
        "C; plus how its prototype and structure compare with the source, and how long a whole "
        "file takes. Its LLM-judged readability is left out. Its own harness and functions could "
        "not be used (see [Why not DecompileBench's own corpus](#why-not-decompilebenchs-own-corpus)), "
        "so the method runs on this corpus:",
        "",
        "- bash: Debian 12's (5.2.15-2+b7, amd64; the binary of the README's picture), its "
        "`bash-dbgsym` debug file and its source with Debian's patches;",
        "- libc: Arch's glibc 2.44+r50 `libc.so.6` (the gates' libc), its debug file and the "
        "source its debug package carries;",
        "",
        "Every tool gets the same copy of each file, alone in a directory: `strip --strip-all "
        "--remove-section=.gnu_debuglink`, then its build ID zeroed in place (neither file as "
        "distributed has a symbol table). So no tool finds the debug file: "
        f"{found} one the debuginfod client's cache has under the "
        f"build ID{beside}; each tool's log was checked for it. angr's "
        "output is the published run's, made from the files as distributed: angr loads no debug "
        "information (`load_debug_info=False`), and the code is the same. The debug "
        "files and sources are read only to score. Functions are those the debug file states "
        "with code, matched to a tool's by entry address, except those of assembly compile "
        "units (412 of libc's, none of bash's), which state no prototype; a function a tool did "
        "not find or decompile counts against it everywhere.",
        "",
        "Reproduce with `bench/decompile/run.sh CORPUS_DIR` (fetches the corpus, runs "
        "`cargo run --release --bin decompile -- quality`, `behaviour` and `speed`, then "
        "`python3 plot.py`).",
    ]
    return lines


def decompile_notes(results):
    quality = results.get("quality", {})
    versions = quality.get("versions", {})
    tools = measured(results)
    ida = "hexrays" in tools
    ran = [versions[tool] for tool in DECOMPILERS if tool in tools and tool in versions and not tool.startswith("binbun")]
    lines = ["", "## The commonest errors, examined", ""]
    lines += [
        "The first error (clang, C17) of every function that does not compile as written, "
        f"grouped by the name or line it is at, on this run's output ({', '.join(ran)}); each "
        "is in the tool's own text:",
        "",
    ]
    examined = [
        ("hexrays", "Hex-Rays, *unknown type name*: types neither IDA's `defs.h` nor the produced file "
        "defines. On bash the C library's: `size_t` (482), `FILE` (92), `__sighandler_t` (46), "
        "`sigset_t` (35), and `__m128i` (44). On libc `u32` (848) and the vector types `__m128i` "
        "(620), `__m128` (146) and `__m512i` (27), as in `signed __int64 (__fastcall "
        "*j_strlen())(const __m128i *a1);`. The *libc headers* setting supplies the C library's."),
        ("hexrays", "Hex-Rays, *use of undeclared identifier*: `nullptr` (bash 368, libc 96), C23's "
        "constant, in C17. In C23 nothing compiles (0%): IDA 9.4's `include/defs.h` declares "
        "`typedef int bool;`, which C23 rejects (`bool` is a keyword there)."),
        ("hexrays", "Hex-Rays, *call to undeclared function*: its own `__readfsqword` (bash 69, libc 199) "
        "and `__writefsdword` (libc 50), which `defs.h` does not declare."),
        ("ghidra", "Ghidra, *unknown type name* and *use of undeclared identifier*: `bool` (bash 290, "
        "libc 249) and `true` (77, 91), which its export header does not define for C17 (C23 "
        "has them: its C23 column), and its type `pointer` (140, 62)."),
        ("ghidra", "Ghidra on libc, *brackets are not allowed here* (352): a 16-byte return value "
        "written as an array, `undefined1 [16] __lll_lock_wake_private(void);` (that prototype "
        "alone in 247 functions)."),
        ("binja", "Binary Ninja, *expected function body after function declarator* (bash 363, libc "
        "1,147): an attribute after a prototype, `void __stack_chk_fail() __noreturn;` (274 "
        "and 550 functions). *expected ')'* (164, 217): a parameter's register, `char arg2 @ "
        "rax`. On bash, *type name requires a specifier or qualifier* (143): `__offset(0x28);` "
        "in a struct. `nullptr` in C17 (67, 44)."),
        ("angr", "angr on bash, *call to undeclared function* (1,357): angr's C declares its globals "
        "and structs but not the functions it calls; DecompileBench's rule turns the error off."),
    ]
    lines += [f"- {text}" for tool, text in examined if tool in tools]
    lines += ["", "## Method", ""]
    hexrays = (
        "Hex-Rays runs in `idat -A` with `bench/decompile/ida_decompile.py`: "
        "auto-analysis, then `decompile_many` (File > Produce file > Create C file), one thread. "
        if ida
        else ""
    )
    lines += [
        "**Running the tools.** binbun runs as `binbun decompile FILE` (exact C) and "
        f"`binbun decompile FILE --view reading`, every function in parallel. {hexrays}"
        "Ghidra runs in `analyzeHeadless` with `bench/decompile/ghidra/DecompileAll.java`, which "
        "does what File > Export Program > C/C++ does (its decompiler options and default "
        "timeout, its parallel decompiler, the same C) but keeps each function apart. angr runs "
        "`bench/decompile/angr_decompile.py`, set up as DecompileBench's angr runner (CFGFast with "
        "indirect jumps resolved and data references, CompleteCallingConventions with variables "
        "recovered, then `Decompiler` per function); for the quality scores it runs in 8 parallel "
        "shards with a 300 s limit per function, for speed in one process.",
        "",
    ]
    if "binja" in tools:
        lines += [
            "**Binary Ninja.** The free edition has no API and no headless mode; its GUI hosts an "
            "MCP server (its `MCP\\Start Server` action, or the setting `ui.mcp.enabled`), and "
            "`bench/decompile/binja_mcp.py` drives that: it opens a copy of the file alone in a "
            "directory (Binary Ninja loads a debug file it finds beside a binary), waits for the "
            "analysis, and asks for every function's Pseudo C (`bn_function_decompile`). Its *as "
            "written* file is the items the function uses of a header made from what the server "
            "tells of the view (its types as C, its data variables as `extern` declarations, its "
            "functions' prototypes, each in the text Binary Ninja gives for the type with the "
            "name put in) after `<stdbool.h>`, `<stddef.h>`, `<stdint.h>` and typedefs of its own "
            "names for integer types (`int128_t`, `uint128_t`, `wchar16`, `wchar32`), then the "
            "function; the paid editions' own header export may differ. Pseudo C is a rendering "
            "of its IL for reading, and the compile columns show how little of it a compiler "
            "takes. Its time is from opening the file to the last function's Pseudo C (what the "
            "header is made from is asked for after), the GUI's threads pinned to the same 16 "
            "CPUs meanwhile: its startup is not in it (the GUI is up already), an HTTP request "
            "per function is. It is run only where `BINJA_MCP` names a running server.",
            "",
        ]
    ida_header = (
        "for Hex-Rays, IDA's `include/defs.h` and the declarations the produced C file has for "
        "the names the function uses (and what those use), then the function; "
        if ida
        else ""
    )
    binja_line = ", Binary Ninja's `void f() __noreturn;`" if "binja" in tools else ""
    lines += [
        "**Compiling.** Each function is one translation unit, piped unmodified to the compiler with "
        f"`{' '.join(quality.get('flags', []))}` (clang also with `-fno-spell-checking`, which "
        "changes no verdict but keeps clang from taking minutes on a few files; a 60 s limit "
        "per compile). *As written* is the file the tool's own declarations make, with its own "
        "header: binbun's file per function (its declarations, `#include \"binbun_defs.h\"`); for "
        f"{ida_header}for Ghidra, the export "
        "header's items the function uses (its fake-type `#define`s, data types and prototypes), "
        "the globals it references (but functions, which the header declares), then the "
        "function; for angr, which has no header, "
        "DecompileBench's `fix/angr/defs.h`, then the function (whose text declares its globals "
        "and structs). The items are found by reading a tool's declarations one at a time with "
        f"tree-sitter; one that is no C (Ghidra's `undefined1 [16] f(void);`{binja_line}) "
        "is kept whole, for the functions that use the name it "
        "declares. *DecompileBench* is that benchmark's own setting (`evaluate_rsr.py`): its "
        "`fix/TOOL/defs.h` included before the function's text alone, compiled under its lenient "
        "rule; DecompileBench's per-function source prologue (the original's declarations, from "
        "`clang-extract`) has no counterpart here, and its fix-up scripts (`fix/TOOL/__init__.py`) "
        "are not applied, the C being taken unmodified. Its headers are fetched at commit "
        "761c651 by `corpus.sh`, not vendored: the repository states no licence.",
        "",
    ]
    behaviour_method = (
        "**Behaves the same.** DecompileBench replaces a function in an OSS-Fuzz fuzzer by its "
        "recompiled C (prologue patched to jump to it) and compares branch coverage over the "
        "fuzzer's seed corpus. Here the program is bash and the inputs are bash's own test "
        "suite (`tests/run-*` but `run-jobs`, which needs a terminal), each test in a "
        "bubblewrap sandbox (read-only file system, private `/tmp`, a private overlay of the "
        "tests' directory); for libc's functions the same bash runs on the corpus' glibc "
        "(interpreter and library path set with patchelf). A test is kept if three runs of the "
        "original agree on output and exit status. Which functions each kept test reaches is "
        "found by a breakpoint on every function entry, removed at its first hit. The sample: "
        "functions of at least 13 bytes (the patch) that a kept test reaches, a seeded random "
        "sample per file. For each tool and sampled function, the C is compiled in the first "
        "setting that compiles (as written strictly, as written leniently, libc headers, "
        "DecompileBench's) with `-fno-plt`, linked into a shared object, and loaded into every "
        "process of the test by a preloaded library (`bench/decompile/substitute.c`): the C's "
        "references to the program's functions and data, by the tool's own names (binbun's "
        f"address comments; the name lists {listed((['IDA'] if ida else []) + ['Ghidra', 'angr'])} "
        "give), are bound to the "
        "original's addresses, so the C runs on the program's own state; the original's entry "
        "becomes a jump to the C. It *behaves the same* if every kept test reaching the "
        "function (up to the 10 quickest) gives the original's output and exit status and the "
        "C was reached. This compares outputs where DecompileBench compares coverage: it misses "
        "differences no test's output shows, and catches some its coverage would not."
    )
    if not results.get("behaviour"):
        behaviour_method = (
            "**Not run in this round:** the behaviour test (`decompile behaviour`, DecompileBench's "
            "runtime test on bash's test suite, `bench/decompile/substitute.c`), angr's "
            "whole-file timing on libc, and the speed run on a PE (`decompile speed`)."
        )
    lines += [
        behaviour_method,
        "",
        "**Matches the source.** Prototypes and locals come from the debug file (DWARF, read by "
        "`binbun-debuginfo`), types compared by class and width (typedefs and enums looked "
        "through; a pointer is a pointer whatever it points to). The C of every tool and the "
        "source are read by tree-sitter's C grammar, which reads C a compiler rejects. Compiler "
        "clones (`.isra`, `.part`, `.constprop` symbols) are left out of the prototype scores: "
        "their interface is not the source's.",
        "",
        "**Speed.** Wall-clock seconds for the whole file, startup included, each tool as it "
        "runs by default, all pinned to the same 16 CPUs: binbun decompiles on 16 threads (one "
        "per CPU it may use); Ghidra's analysis and its parallel decompiler use up to 16 "
        "threads; "
        + ("IDA's analysis and Hex-Rays' `decompile_many` use one; " if ida else "")
        + "angr runs in one Python process (one thread). So the times compare tools as "
        "shipped, not per CPU.",
    ]
    lines += ["", "## Why not DecompileBench's own corpus", ""]
    lines += [
        "DecompileBench's code is public ([vul337/DecompileBench](https://github.com/vul337/DecompileBench), "
        "commit 761c651, October 2025) but states no licence, so it may be read but not reused or "
        "redistributed. Its dataset (23,400 functions from 130 OSS-Fuzz projects) is not "
        "published: the request to release it ([issue 1](https://github.com/vul337/DecompileBench/issues/1), "
        "May 2025) is open, and its README notes that rebuilding it gives different functions, "
        "as the fuzzers' build scripts take each project's latest commit. Rebuilding it needs "
        "Docker images from the authors' server and OSS-Fuzz builds of the 130 projects (far "
        "beyond the disk this benchmark may use)"
        + (
            ", and its Hex-Rays runner does not run on IDA 9 "
            "([issue 3](https://github.com/vul337/DecompileBench/issues/3))"
            if ida
            else ""
        )
        + ". Its method is applied to this corpus instead, with its headers and compile rule "
        "where they apply.",
    ]
    lines += ["", "## Fairness and limits", ""]
    alone = "Hex-Rays' and angr's" if ida else "angr's"
    lines += [
        "- *As written* is binbun's design goal and not the others': binbun prints a file per "
        f"function that declares what it uses, {'Hex-Rays and Ghidra print' if ida else 'Ghidra prints'} "
        "declarations for a whole program that are taken here per function, and angr prints "
        "none for callees. The "
        "*libc headers* and *DecompileBench* columns give the others the headers they assume.",
        "- The libc headers setting conflicts with binbun's own declarations of the C library's "
        "functions (its types are the binary's, not the headers'), so binbun gains nothing there.",
        f"- binbun's whole-file time runs on 16 CPUs, {alone} on one; Ghidra's decompiler runs "
        "in parallel too.",
        "- binbun's exact C and reading view are counted as separate rows; the reading view "
        "hides checks under stated assumptions.",
        "- The first version of this page (binbun 49fc7f4) was scored with two errors, both "
        "fixed since and applied to every tool: binbun's `BINBUN_SYMBOL` annotations made the "
        "parser take some declarations for the next function's definition (186 of bash's "
        "functions, 76 of libc's), and libc's 412 assembly functions were scored as taking no "
        "parameters. Both lowered binbun's scores, most its libc parameter counts"
        + ("; the second lowered Hex-Rays' too (libc's parameter count right was 82.8%)" if ida else "")
        + ".",
        "- The second version (binbun 9293b9c) gave the tools libc with its `.gnu_debuglink` and "
        "build ID, beside its debug file: "
        + (
            "Hex-Rays and Ghidra analysed it with the DWARF the scores are made from (their logs "
            "say so), and their libc parameter counts right were 90.9% and 98.7%"
            if ida
            else "Ghidra analysed it with the DWARF the scores are made from (its log says so), "
            "and its libc parameter count right was 98.7%"
        )
        + ". Since this run every tool gets a copy it cannot find a debug file "
        "for. Three faults of the scorer, which without DWARF cost the other tools functions "
        "that compile, were fixed in this run too: a line of a tool's declarations that is no C "
        "was given to functions that do not use it, or hid the lines after it; and Ghidra's "
        "globals declared a function whose address is taken as data.",
    ]
    lines += decompile_losses(results)
    return lines


def structure_apart(tool):
    """Whether `tool`'s results have no structure figures: compared on another
    run's common functions (a run of some tools, `decompile quality
    --tools`), not these."""
    return tool["source"].get("common") == 0


def decompile_losses(results):
    """Each score where another tool beats binbun's exact C, stated."""
    quality = results.get("quality", {})
    behaviour = {f["name"]: f for f in results.get("behaviour", {}).get("files", [])}
    losses = []
    for f in quality.get("files", []):
        by_tool = {t["tool"]: t for t in f["tools"]}
        ours = by_tool.get("binbun")
        if ours is None:
            continue
        n = f["functions"]

        def compare(label, value, higher=True, kind="share", key=None):
            """`key` orders the values (better is higher) where it is not the value."""
            key = key or (lambda v: v if higher else -v)
            mine = value(ours)
            for tool, t in by_tool.items():
                if tool.startswith("binbun"):
                    continue
                theirs = value(t)
                if mine is None or theirs is None:
                    continue
                if key(theirs) > key(mine):
                    shown = (
                        (lambda v: f"{v:.1%}")
                        if kind == "share"
                        else (lambda v: f"{v:.2f}")
                    )
                    losses.append(
                        f"- {f['name']}: {label}: {DECOMPILERS[tool]} {shown(theirs)}, "
                        f"binbun {shown(mine)}."
                    )

        compare("decompiled", lambda t: t["decompiled"] / n)
        compare("compiles as written (clang, C17 or C23)", lambda t: t["recompile"]["own_strict"] / n)
        compare("compiles as written (gcc)", lambda t: t["recompile"]["own_gcc"] / n)
        compare("compiles in any setting", lambda t: t["recompile"]["any"] / n)
        s = lambda t, k, w: t["source"][k] / t["source"][w] if t["source"][w] else None
        compare("parameter count right", lambda t: s(t, "parameter_count", "functions"))
        compare("return type exact", lambda t: s(t, "returns_exact", "functions"))
        compare("return type width", lambda t: s(t, "returns_width", "functions"))
        compare("parameter types exact", lambda t: s(t, "parameters_exact", "parameters"))
        compare("parameter types width", lambda t: s(t, "parameters_width", "parameters"))
        compare("gotos per function", lambda t: t["source"]["gotos_mean"], higher=False, kind="number")
        nearer_one = lambda v: -abs(v - 1)
        compare(
            "lines per source line (median; binbun's is further from 1)",
            lambda t: t["source"]["lines_ratio_median"],
            kind="number",
            key=nearer_one,
        )
        compare(
            "locals per source local (median; binbun's is further from 1)",
            lambda t: t["source"]["locals_ratio_median"],
            kind="number",
            key=nearer_one,
        )
        if structure_apart(ours):
            losses.append(
                f"- {f['name']}: gotos per function, lines and locals per source line: not "
                "compared (binbun's results are from a run of binbun alone; see the table)."
            )
        timings = {t["tool"]: t for t in f.get("speed", [])}
        mine = timings.get("binbun")
        for tool, t in timings.items():
            if tool.startswith("binbun") or mine is None:
                continue
            if t["status"] == "ok" and mine["status"] == "ok" and t["seconds"] < mine["seconds"]:
                losses.append(
                    f"- {f['name']}: whole-file time: {DECOMPILERS[tool]} {t['seconds']:.1f} s, "
                    f"binbun {mine['seconds']:.1f} s."
                )
        b = behaviour.get(f["name"])
        if b:
            bt = {t["tool"]: t for t in b["tools"]}
            if "binbun" in bt:
                for tool, t in bt.items():
                    if not tool.startswith("binbun") and t["same"] > bt["binbun"]["same"]:
                        losses.append(
                            f"- {f['name']}: behaves the same: {DECOMPILERS[tool]} "
                            f"{t['same'] / b['sampled']:.1%}, binbun "
                            f"{bt['binbun']['same'] / b['sampled']:.1%}."
                        )
    lines = ["", "## Where binbun loses", ""]
    if losses:
        lines.append(
            "Every score above where another tool does better than binbun's exact C (for the "
            "ratios: is nearer 1; the lines and locals ratios are a description, not a goal):"
        )
        lines.append("")
        lines += losses
    else:
        lines.append("No score above has another tool ahead of binbun's exact C.")
    return lines


def decompile(results, out):
    quality = results.get("quality", {})
    behaviour = results.get("behaviour", {})
    speed = results.get("speed", {})
    qfiles = quality.get("files", [])
    bfiles = {f["name"]: f for f in behaviour.get("files", [])}
    tools = list(dict.fromkeys(t["tool"] for f in qfiles for t in f["tools"]))
    names = [f["name"] for f in qfiles]
    sfiles = [(f["name"], f["speed"]) for f in qfiles] + [
        (f["name"], f["speed"]) for f in speed.get("files", [])
    ]

    # The chart: recompiles, the parameter count, (behaves the same,) time;
    # a bar per tool and file, files told apart by shade; the tools named
    # once, on the left.
    count = 4 if bfiles else 3
    figure, panels = plt.subplots(
        1, count, figsize=(3.6 * count + 1.2, 0.55 * len(tools) + 1.9), sharey=True
    )
    timing_panel = panels[-1]
    shades = [1.0, 0.55, 0.3]

    def bars(panel, rows, title, xlabel, fraction=True, origin=0):
        count = max(len(r[1]) for r in rows) if rows else 1
        height = 0.8 / count
        for row, (tool, values) in enumerate(rows):
            colour = tool_style(tool)[0]
            for index, (value, low, high, label) in enumerate(values):
                y = row - 0.4 + height * (index + 0.5)
                if value is None:
                    panel.text(origin, y, f" {label}", va="center", fontsize=7)
                    continue
                error = None
                if low is not None:
                    error = [[value - low], [high - value]]
                panel.barh(
                    y,
                    value - origin,
                    left=origin,
                    height=height * 0.9,
                    color=colour,
                    alpha=shades[index % len(shades)],
                    xerr=error,
                    error_kw={"ecolor": MUTED, "capsize": 2, "linewidth": 1},
                )
                text = f"{label} {value:.0%}" if fraction else label
                panel.annotate(
                    text,
                    (high if high is not None else value, y),
                    xytext=(4, 0),
                    textcoords="offset points",
                    va="center",
                    fontsize=8,
                )
        panel.set_yticks(range(len(rows)), [DECOMPILERS.get(t, t) for t, _ in rows])
        if panel is panels[0]:
            panel.invert_yaxis()
        panel.set_title(title)
        panel.set_xlabel(xlabel)
        panel.grid(axis="x")
        panel.set_axisbelow(True)
        panel.spines[["top", "right"]].set_visible(False)

    rows = []
    for tool in tools:
        values = []
        for f in qfiles:
            t = next(t for t in f["tools"] if t["tool"] == tool)
            values.append((t["recompile"]["own_strict"] / f["functions"], None, None, f["name"]))
        rows.append((tool, values))
    bars(panels[0], rows, "Compiles as written\n(clang, C17 or C23)", "share of the functions")
    panels[0].set_xlim(0, 1.12)
    panels[0].xaxis.set_major_formatter(PercentFormatter(1.0))

    rows = []
    for tool in tools:
        values = []
        for f in qfiles:
            t = next(t for t in f["tools"] if t["tool"] == tool)
            s = t["source"]
            values.append((s["parameter_count"] / s["functions"], None, None, f["name"]))
        rows.append((tool, values))
    bars(panels[1], rows, "Parameter count right\n(against the debug information)", "share of the functions")
    panels[1].set_xlim(0, 1.12)
    panels[1].xaxis.set_major_formatter(PercentFormatter(1.0))

    if bfiles:
        rows = []
        for tool in tools:
            values = []
            for name in names:
                f = bfiles.get(name)
                t = next((t for t in f["tools"] if t["tool"] == tool), None) if f else None
                if t is None:
                    values.append((None, None, None, "not run"))
                else:
                    values.append((t["same"] / f["sampled"], t["low"], t["high"], name))
            rows.append((tool, values))
        bars(panels[2], rows, "Program behaves the same\n(95% CI)", "share of the sampled functions")
        panels[2].set_xlim(0, 1.12)
        panels[2].xaxis.set_major_formatter(PercentFormatter(1.0))

    rows = []
    slowest = 0.0
    for tool in tools:
        values = []
        for name, timings in sfiles:
            t = next((t for t in timings if t["tool"] == tool), None)
            if t is None:
                values.append((None, None, None, f"{name}: not run"))
            elif t["status"] == "failed":
                values.append((None, None, None, f"{name}: {t['note'] or 'failed'}"))
            elif t["status"] == "timeout":
                values.append(
                    (None, None, None, f"{name}: timed out (over {results['timeout_seconds']} s)")
                )
            else:
                slowest = max(slowest, t["seconds"])
                values.append((t["seconds"], None, None, f"{name} {t['seconds']:.1f} s"))
        rows.append((tool, values))
    startup = "startup included, but Binary Ninja's" if "binja" in tools else "startup included"
    bars(timing_panel, rows, f"Whole-file decompile time\n({startup})", "seconds", fraction=False)
    timing_panel.set_xlim(0, slowest * 1.45)
    file_names = names + [name for name, _ in sfiles[len(qfiles):]]
    figure.legend(
        handles=[
            plt.Rectangle((0, 0), 1, 1, color=MUTED, alpha=shades[i % len(shades)], label=n)
            for i, n in enumerate(file_names)
        ],
        loc="lower center",
        ncol=len(file_names),
        bbox_to_anchor=(0.5, -0.14),
        title="bar shade: file",
    )
    figure.tight_layout()
    save(figure, out / "decompile-overview.svg")

    lines = ["# Decompilation", ""]
    lines += decompile_intro(results, quality)
    lines += [
        "",
        f"![Compiles as written, parameter count right, whole-file time]"
        f"({link('decompile-overview.svg', out)})",
    ]

    lines += ["", "## Recompiles", ""]
    lines.append(
        "Functions whose C compiles, of those the debug file states. *As written*: the file "
        "the tool's own declarations make, with its header (see Method), unmodified, strictly "
        "(the compiler's default errors), as C17 (`-std=gnu17`, clang's default) or C23 "
        "(`-std=gnu23`, where `nullptr` is C but `f()` declares `f(void)`); "
        "*lenient*: DecompileBench's rule, C17 (failing files "
        "compiled again with `-Wno-X` for each `[-WX]` in the diagnostics); *libc headers*: "
        "the file after the C library's common headers, lenient; *DecompileBench*: "
        "DecompileBench's own `defs.h` for the tool before the function's text alone, "
        "lenient (it has none for binbun); *any*: one of these compiles."
    )
    for f in qfiles:
        lines += ["", f"### {f['name']}", ""]
        lines.append(
            f"{f['functions']:,} functions stated by the debug file ({f['clones']:,} of them "
            "compiler clones such as `.isra`/`.part`)."
        )
        lines += [""]
        lines.append(
            "| Tool | Decompiled | As written (clang, C17) | As written (clang, C23) "
            "| As written (gcc, C17) | Lenient (clang) | libc headers | DecompileBench | Any |"
        )
        lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|")
        n = f["functions"]
        for t in f["tools"]:
            r = t["recompile"]
            bench = "—" if r["decompilebench"] is None else share(r["decompilebench"], n)
            lines.append(
                f"| {DECOMPILERS.get(t['tool'], t['tool'])} | {share(t['decompiled'], n)} "
                f"| {share(r['own_clang'], n)} | {share(r['own_c23'], n)} | {share(r['own_gcc'], n)} "
                f"| {share(r['own_lenient'], n)} | {share(r['libc_lenient'], n)} | {bench} "
                f"| {share(r['any'], n)} |"
            )
        lines += [
            "",
            "Commonest reasons as written (clang, C17: its first error, quoted names left out; "
            "*no such function*: the tool found no function there):",
            "",
        ]
        lines.append("| Tool | Reasons (functions) |")
        lines.append("|---|---|")
        for t in f["tools"]:
            reasons = "; ".join(
                f"{category.replace('|', '/')} ({count:,})" for category, count in t["errors"][:5]
            )
            lines.append(f"| {DECOMPILERS.get(t['tool'], t['tool'])} | {reasons} |")

    if bfiles:
        lines += ["", "## Behaves the same", ""]
        lines.append(
            "Sampled functions whose recompiled C, put in the running program in place of the "
            f"original, leaves every test reaching it (up to {behaviour['tests_per_function']}) "
            "with the original's output and exit status. 95% confidence intervals are Wilson's. "
            "A function with no C, or C that compiles in no setting, fails."
        )
        for name in names:
            f = bfiles.get(name)
            if f is None:
                continue
            lines += ["", f"### {name}", ""]
            lines.append(
                f"{f['sampled']:,} functions sampled (seed {f['seed']}) of the "
                f"{f['reached']:,} that the {f['tests_kept']} kept tests reach."
            )
            lines += [""]
            lines.append(
                "| Tool | Same | 95% CI | Differs | Not reached | No C | Does not compile "
                "| Does not link |"
            )
            lines.append("|---|---:|---:|---:|---:|---:|---:|---:|")
            for t in f["tools"]:
                s = t["statuses"]
                lines.append(
                    f"| {DECOMPILERS.get(t['tool'], t['tool'])} | {share(t['same'], f['sampled'])} "
                    f"| {t['low']:.1%}–{t['high']:.1%} | {s.get('differs', 0)} "
                    f"| {s.get('not-reached', 0)} | {s.get('not-decompiled', 0)} "
                    f"| {s.get('not-compiled', 0)} | {s.get('not-linked', 0)} |"
                )

    lines += ["", "## Matches the source", ""]
    lines.append(
        "Prototypes against the debug file (functions that are not compiler clones; a function "
        "a tool did not decompile counts as wrong): the parameter count; the return type and "
        "each parameter's type, *exact* when class (signed, unsigned, bool, float, pointer, "
        "struct, void) and width agree, *width* when the width does ("
        + ("Hex-Rays' `_QWORD` or " if "hexrays" in tools else "")
        + "Ghidra's `undefined8` for a `long` counts for width only). Structure on the functions "
        "every tool decompiled and whose source definition was found: the median ratio of "
        "declared locals to the debug file's (and the share of functions with as many, more, "
        "fewer), and of lines (with code, comments aside) to the "
        "source's; gotos per function; the deepest nesting of `if`, loops and `switch`."
    )
    for f in qfiles:
        src = f["source"]
        lines += ["", f"### {f['name']}", ""]
        sig = f["tools"][0]["source"]
        apart = [DECOMPILERS.get(t["tool"], t["tool"]) for t in f["tools"] if structure_apart(t)]
        compared = len(apart) < len(f["tools"])
        lines.append(
            f"Prototypes: {sig['functions']:,} functions, {sig['parameters']:,} parameters."
            + (f" Structure: {src['common']:,} functions." if compared else "")
            + (
                f" Structure (locals, lines, gotos, nesting) is not shown for {listed(apart)}: "
                "it was compared on another run's common functions, not on these."
                if apart
                else ""
            )
        )
        lines += [""]
        lines.append(
            "| Tool | Parameter count right | Too many | Too few | Return exact | Return width "
            "| Parameters exact | Parameters width | Locals ratio | Locals same | More | Fewer "
            "| Lines ratio | Gotos per function "
            "| Functions with gotos | Nesting |"
        )
        lines.append("|---|" + "---:|" * 15)
        for t in f["tools"]:
            s = t["source"]
            common = s["common"]
            lines.append(
                f"| {DECOMPILERS.get(t['tool'], t['tool'])} "
                f"| {share(s['parameter_count'], s['functions'])} "
                f"| {share(s.get('parameter_count_more', 0), s['functions'])} "
                f"| {share(s.get('parameter_count_fewer', 0), s['functions'])} "
                f"| {share(s['returns_exact'], s['functions'])} "
                f"| {share(s['returns_width'], s['functions'])} "
                f"| {share(s['parameters_exact'], s['parameters'])} "
                f"| {share(s['parameters_width'], s['parameters'])} "
                f"| {number(s['locals_ratio_median'])} | {share(s.get('locals_same', 0), common)} "
                f"| {share(s.get('locals_more', 0), common)} | {share(s.get('locals_fewer', 0), common)} "
                f"| {number(s['lines_ratio_median'])} "
                f"| {number(s['gotos_mean'])} | {share(s['functions_with_gotos'], s['common'])} "
                f"| {number(s['nesting_mean'])} |"
            )
        if compared:
            lines.append(
                f"| source | | | | | | | | 1.00 | | | | 1.00 | {number(src['gotos_mean'])} "
                f"| {share(src['functions_with_gotos'], src['common'])} | {number(src['nesting_mean'])} |"
            )

    lines += ["", "## Speed", ""]
    apart = (
        " Binary Ninja's is from opening the file in its running GUI to its last function: "
        "its startup is not in it, a request per function is."
        if "binja" in tools
        else ""
    )
    lines.append(
        f"Wall-clock seconds to decompile the whole file, startup included; timeout "
        f"{results['timeout_seconds']} s.{apart}"
    )
    lines += [""]
    lines.append("| Tool | " + " | ".join(name for name, _ in sfiles) + " |")
    lines.append("|---|" + "---:|" * len(sfiles))
    for tool in tools:
        cells = []
        for _, timings in sfiles:
            t = next((t for t in timings if t["tool"] == tool), None)
            if t is None:
                cells.append("—")
            elif t["status"] == "ok":
                cells.append(f"{t['seconds']:.1f}")
            elif t["status"] == "timeout":
                cells.append(f"over {results['timeout_seconds']}")
            else:
                cells.append(t["note"] or "failed")
        lines.append(f"| {DECOMPILERS.get(tool, tool)} | " + " | ".join(cells) + " |")
    lines += decompile_notes(results)
    write(out / "decompile.md", lines)


def main():
    results = Path(__file__).parent / "results"
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else results
    decompiled = out / "decompile.json"
    scored = json.loads(decompiled.read_text()) if decompiled.exists() else None
    if scored and out.resolve() == results.resolve():
        kept = [name for tool, name in UNPUBLISHED.items() if tool in measured(scored)]
        if kept:
            sys.exit(
                f"{decompiled} has {listed(kept)}'s results, which are not published: "
                "they belong in results/private/ (`decompile --private`)"
            )
    readme = []
    for name in ARCHES:
        path = out / name
        if path.exists():
            if readme:
                readme.append("")
            readme += decode(json.loads(path.read_text()), out, name)
            path = out / LARGER / name
            if path.exists():
                readme += larger(json.loads(path.read_text()), name)
    if readme and scored:
        others = [
            name
            for tool, name in DECOMPILERS.items()
            if tool in measured(scored) and not tool.startswith("binbun")
        ]
        readme += [
            "",
            "# Decompilation",
            "",
            f"binbun against {listed(others)} (recompiles, behaves the same, matches the "
            "source, speed): [decompile.md](decompile.md), reproduced with "
            "`bench/decompile/run.sh CORPUS_DIR`.",
        ]
    if readme:
        write(out / "README.md", readme)
    path = out / "cfg.json"
    if path.exists():
        cfg(json.loads(path.read_text()), out)
    if scored:
        decompile(scored, out)
    if not readme and not path.exists() and not scored:
        sys.exit(f"no {', '.join(ARCHES)}, cfg.json or decompile.json in {out}")
    if out.resolve() == results.resolve():
        publish(out)


# The charts the reports and the top-level README show: of results/ only the
# reports (README.md, cfg.md) are tracked, so the charts are copied into the
# tracked media/ when the published results are rendered (not when rendering
# elsewhere, a scratch directory).
PUBLISHED = {
    "cfg-overview.svg": "bench-cfg-overview.svg",
    "throughput.svg": "bench-throughput-x86.svg",
    "throughput-aarch64.svg": "bench-throughput-aarch64.svg",
    "cfg-precision-recall.svg": "bench-cfg-precision-recall.svg",
    "decompile-overview.svg": "bench-decompile-overview.svg",
}


def link(chart, out):
    """A report's link to `chart`: in the published results its copy in
    media/ (the reports are tracked, the charts beside them are not),
    elsewhere the chart beside the report."""
    published = (Path(__file__).parent / "results").resolve()
    return f"../../media/{PUBLISHED[chart]}" if out.resolve() == published else chart


def publish(out):
    media = Path(__file__).parent.parent / "media"
    for chart, name in PUBLISHED.items():
        path = out / chart
        if path.exists():
            (media / name).write_bytes(path.read_bytes())
            print(f"wrote {media / name}")


if __name__ == "__main__":
    main()
