#!/usr/bin/env bash
# Builds the `binbun` wheel (maturin, release) into a venv and runs the
# Python tests (`python/tests`) with the CLI they compare against, and the
# C API's test program (`crates/binbun-capi/tests/c/disasm_test.c`,
# built with the system's `cc`), whose output the decoders' are compared
# with, and the Rust examples (`examples/rust`), which
# `python/tests/test_examples.py` runs.
#
#   scripts/python-tests.sh [pytest arguments]
#
# BINBUN_PY_VENV: the venv (default ~/.cache/binbun-py1-venv), made with
# maturin, pytest, pytest-xdist and mypy if missing (pytest-xdist added to
# one without it); its maturin builds the wheel, else
# the one on PATH (the wheel is abi3: one build serves every Python from
# 3.11). Packages go in with the venv's pip, else uv's. BINBUN_CLI: the
# `binbun` CLI to compare with (default: built from this tree).
# BINBUN_PY_WORKERS: pytest-xdist's workers (default auto: one a core this
# script may use; 0: the tests run in pytest's own process). Each worker
# takes whole files (--dist loadfile): a file's tests share its databases
# as without workers; the slow files' tests are taken one by one
# (python/tests/conftest.py's SPREAD), bash analysed once a worker.
# CARGO_TARGET_DIR is used as cargo uses it.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
venv=${BINBUN_PY_VENV:-$HOME/.cache/binbun-py1-venv}
target=${CARGO_TARGET_DIR:-$root/target}

if [ ! -x "$venv/bin/python" ]; then
    python3 -m venv "$venv"
    "$venv/bin/python" -m pip install --quiet maturin pytest pytest-xdist mypy
fi
if "$venv/bin/python" -m pip --version >/dev/null 2>&1; then
    install=("$venv/bin/python" -m pip install --quiet)
else
    install=(uv pip install --quiet --python "$venv/bin/python")
fi
"$venv/bin/python" -c "import xdist" 2>/dev/null || "${install[@]}" pytest-xdist
maturin=$venv/bin/maturin
[ -x "$maturin" ] || maturin=$(command -v maturin)

cd "$root"
cargo build --release -p binbun-cli -p binbun-capi
cargo build --release --examples -p binbun -p binbun-session -p binbun-x86 -p binbun-aarch64 -p binbun-disasm
export BINBUN_CLI=${BINBUN_CLI:-$target/release/binbun}
export BINBUN_RUST_EXAMPLES=$target/release/examples

wheels=$(mktemp -d "${TMPDIR:-$HOME/.cache}/binbun-wheel.XXXXXX")
trap 'rm -rf "$wheels"' EXIT
cc -std=c11 -Wall -Wextra -Werror -O1 -I crates/binbun-capi/include \
    crates/binbun-capi/tests/c/disasm_test.c -o "$wheels/disasm_test" \
    -L"$target/release" -lbinbun_capi -Wl,-rpath,"$target/release"
export BINBUN_DISASM_TEST=$wheels/disasm_test
"$maturin" build --release --out "$wheels" --interpreter "$venv/bin/python"
"${install[@]}" --force-reinstall --no-deps "$wheels"/binbun-*.whl

cd "$root/python/tests"
"$venv/bin/python" -m pytest -n "${BINBUN_PY_WORKERS:-auto}" --dist loadfile "$@"
