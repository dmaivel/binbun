# Benchmarks

The benchmarks are a separate workspace in `bench/`, so their C dependencies stay out of the main build. Each benchmark writes their raw numbers as JSON to `bench/results/`; `plot.py` turns them into Markdown reports with SVG charts, so charts can be redrawn without measuring again. Of `bench/results/` only the reports (`README.md`, `decompile.md`, and `cfg.md` when function recovery has been measured) are tracked; rendering them there copies their charts into `media/` (`bench-*.svg`), which the reports and the top-level README link to.

## Decoders

```sh
cd bench
XED_DIR=/path/to/built/xed cargo run --release -- /usr/lib/libc.so.6 /usr/lib/libcrypto.so.3
python3 plot.py
```

Each decoder linearly sweeps the executable sections of the given x86-64 ELF files. The run prints Markdown tables and writes `results/decode.json`; `plot.py` makes `results/README.md` with a chart of every task (length only, full decode, decode + format). Each value is the median of 20 samples, taken one per decoder per round so that drift hits all decoders alike, with a 95% confidence interval for the median (only noise within the run; compare `perf stat` instruction counts for changes smaller than that). XED is included when `XED_DIR` points at a built XED checkout (build it with `python3 mfile.py --opt=3`; XED's default is unoptimised), LLVM when `llvm-config` is on `PATH`; Zydis, bddisasm and Capstone build from their crates (CMake and a C compiler are needed).

On CPUs with performance and efficiency cores, pin the run to one performance core (`taskset -c 2 cargo run --release -- …`); otherwise the thread migrates between core types and results vary by 20% or more.

## Function recovery

```sh
cd bench
cargo run --release --bin cfg -- [--tools NAME,...] [--timeout SECS] FILE...
python3 plot.py
```

binbun against other disassemblers and analysis frameworks (the names `--tools` takes, and how each is built or found, are in `bench/src/bin/cfg/`): each tool gets a copy of each file stripped of its symbol tables (unwind tables and dynamic symbols stay, as in stripped binaries in the wild), and its function starts are scored against what the original states: function symbols, unwind table entries and PE exports, read with binutils rather than binbun's own loader (leaving out PLT sections and import thunks, which tools count as functions or not by taste). Precision, recall, F1 and wall-clock time including each tool's startup go to `results/cfg.json`; `plot.py` makes `results/cfg.md` with a chart of accuracy against time and one of precision and recall, a panel per file. Tools are run as separate processes with a timeout; where each is looked for, and how its addresses are moved to the file's own base, is documented in `bench/src/bin/cfg/` (the scripts some tools run are in `bench/cfg/`). A missing tool is reported and skipped.

## Decompilers

```sh
cd bench
decompile/run.sh CORPUS_DIR
python3 plot.py
```

`run.sh` fetches the corpus once through `decompile/corpus.sh` (Debian bash, glibc's libc, their debug information and sources, checked against their SHA-256), runs each tool on a copy of each file alone in a directory (stripped, and without its `.gnu_debuglink`, so that no tool loads the debug file the scores are made from), compiles and scores every function, times whole-file decompilation, and writes `results/decompile.json`, from which `plot.py` makes `results/decompile.md` and its chart. It reads `BINBUN` and `BINBUN_COMMIT` (the build measured), `IDA_DIR`, `GHIDRA_DIR`, `ANGR_PYTHON` and `GHIDRA_PROJECTS` (a path with no element starting with a dot). The method, the settings and the tools' versions are in the report.

The published report compares binbun with Ghidra and angr. Hex-Rays and Binary Ninja are measured only privately: Hex-Rays' licence (IDA Pro 9.4's `license.txt`) restricts benchmarking it and publishing the results without first inviting Hex-Rays to review them, and Binary Ninja's free edition is licensed for evaluation and non-commercial use only. With `PRIVATE=1`, `run.sh` repeats the run with them (`decompile --private`) into `results/private/`, which is not tracked, reusing the other tools' outputs, and renders that report there (`python3 plot.py results/private`); `plot.py` refuses to render `results/` when its `decompile.json` has their results.

Binary Ninja is run in a private run where `BINJA_MCP` is the URL of the MCP server a running Binary Ninja hosts (its free edition has no API and no headless mode): start the server with its `MCP\Start Server` action (or the setting `ui.mcp.enabled`), take the URL from `MCP\Copy Connection Info` (`http://127.0.0.1:24642/mcp` here, with no token set), and leave the window open for the run. `decompile/binja_mcp.py` drives it.
