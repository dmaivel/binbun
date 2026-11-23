# Oracles

The decoders and lifters are checked against independent implementations: XED for the x86 decoder, LLVM and exarmo for the AArch64 decoder, the processor itself for both lifters, and Arm's formal model for the AArch64 lifter. Each oracle is built by a script; ignored tests then compare binbun with it.

## x86 decoder and XED

With a built XED, `scripts/xed-oracle.sh /path/to/xed` builds the oracle, and the ignored tests in `crates/binbun-x86/tests/oracle.rs` compare binbun with it on random instructions in every mode (`decodes_match_xed`) and on a linear sweep of real binaries (`real_code_matches_xed`); without XED, a checked-in sample of its answers is compared instead:

```sh
scripts/xed-oracle.sh /path/to/built/xed
BINBUN_XED_ORACLE=target/xed-oracle BINBUN_ORACLE_CASES=3000000 \
  cargo test --release -p binbun-x86 --test oracle -- --ignored
```

## AArch64 decoder, LLVM and exarmo

`scripts/llvm-oracle.sh` builds LLVM's AArch64 disassembler (its C API, every feature enabled) against the installed LLVM, and `scripts/exarmo-oracle.sh` builds exarmo, an AArch64 decoder generated from Arm's specification, for encodings newer than LLVM's. The ignored tests in `crates/binbun-aarch64/tests/oracle.rs` compare binbun with both.

```sh
scripts/llvm-oracle.sh && scripts/exarmo-oracle.sh
BINBUN_LLVM_ORACLE=target/llvm-oracle BINBUN_EXARMO_ORACLE=target/exarmo-oracle \
  cargo test --release -p binbun-aarch64 --test oracle -- --ignored
```

## x86 lifter and the processor

`scripts/cpu-oracle.sh` builds the CPU oracle as `target/cpu-oracle` (Linux x86-64, any C compiler). It runs one instruction at a time on this machine, from the registers and memory a line on stdin gives, and prints the state after it, or the fault; `tools/cpu-oracle/cpu_oracle.c` describes the protocol, and `tools/cpu-oracle/smoke.txt` has sample cases. With it, the ignored test in `crates/binbun-x86-lift/tests/hardware.rs` runs every instruction with semantics, taken from real code and from systematic and random encodings (every opcode, prefix and `ModRM` field), in the L0 interpreter and on the processor from the same random states (with float edge values, random rounding and exception masks for vector and x87 code), and compares every bit L0 defines (registers, flags, vector, MXCSR and x87 state, memory, where execution continues, faults):

```sh
scripts/cpu-oracle.sh
BINBUN_CPU_ORACLE=target/cpu-oracle \
  cargo test --release -p binbun-x86-lift --test hardware -- --ignored --nocapture
```

## AArch64 lifter, the processor and Arm's model

`scripts/cpu-oracle-aarch64.sh` builds the same oracle for AArch64, a static Linux binary that runs one instruction from a given state natively or under `qemu-aarch64`; the ignored test in `crates/binbun-aarch64-lift/tests/hardware.rs` compares the L0 interpreter with it.

```sh
scripts/cpu-oracle-aarch64.sh
BINBUN_CPU_ORACLE_AARCH64=target/cpu-oracle-aarch64 \
  cargo test --release -p binbun-aarch64-lift --test hardware -- --ignored --nocapture
```

`tools/isla-check` proves binbun's AArch64 L0 equal to sail-arm's execute pseudocode for every input state, word by word (isla runs the Armv9.4-A model symbolically, z3 looks for a counterexample); `scripts/isla-snapshot.sh` fetches the model snapshot it reads.
