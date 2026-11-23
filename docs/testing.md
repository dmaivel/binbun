# Testing

## Every change

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p binbun-cli --no-default-features --all-targets -- -D warnings
cargo test --workspace --release
cargo xtask codegen --check
cargo xtask header --check
scripts/python-tests.sh                # the wheel built into a venv; Python tests, examples and stubtest
(cd gui && cargo fmt --all --check)
(cd gui && cargo clippy --workspace --all-targets -- -D warnings)
(cd gui && cargo test --workspace)
```

## By kind of change

| Change | Also run |
|---|---|
| Decompiled C (lowering, structuring, types, printing) | `binbun decompile FILE --stats` on `/usr/bin/bash` and your libc, before and after: identical when the output should not change, otherwise compare the numbers; `binbun verify FILE`: no differences |
| Function recovery | `binbun eval --seeds entry /usr/lib/libc.so.6 /usr/bin/bash` before and after |
| x86 decoder | the XED oracle tests and the fuzz targets (`fuzz/README.md`) |
| AArch64 decoder | the LLVM and exarmo oracle tests |
| x86 lifter semantics | the CPU oracle test |
| AArch64 lifter semantics | the AArch64 CPU oracle test; `tools/isla-check` for proofs against Arm's model |
| PE or PDB handling | a Windows executable with its PDB |
| Type databases | `scripts/typedb.sh TARGET` (inputs pinned in the script) |
| Test fixtures | `scripts/build-fixtures.sh` |
| Python API, CLI help or the C API's comments | `BINBUN=target/release/binbun scripts/site/generate.py` (then `--check`) to regenerate the site's reference pages |
| The site | `zola check` in `site/` |
| The GUI | run the app and try the change by hand |
