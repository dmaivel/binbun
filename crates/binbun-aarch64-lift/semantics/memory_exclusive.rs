// Load and store exclusive. The exclusive monitors are the processor's:
// `exclusive_load` marks them (Arm's `AArch64.SetExclusiveMonitors`) and
// `exclusive_store` says whether they fail (`!AArch64.ExclusiveMonitorsPass`),
// after the alignment check and before any other abort of the store (Arm's
// order: a misaligned store exclusive faults whether or not the monitors
// pass; that a failing one takes no translation or permission fault is the
// IMPLEMENTATION DEFINED choice of Arm's pseudocode and qemu, not the Apple
// M3's). Accesses are single-copy atomic: the alignment fault if they cross
// an aligned 16-byte block (FEAT_LSE2). `o0` is set in the acquiring loads
// (LDAXR) and the releasing stores (STLXR). Operands are read before any
// register is written, so a status register that is also the data or base
// register stores the original value at the original address (CONSTRAINED
// UNPREDICTABLE: binbun's choice `Constraint_NONE`).

// LDXR, LDAXR (and B/H): the bytes zero-extended into `t`; the monitors
// marked once the load succeeded.
#[operation(LDXR, LDXRB, LDXRH, LDAXR, LDAXRB, LDAXRH)]
fn load_exclusive(t: Op, m: Op) {
    check_alignment(m);
    let data = load(m, 0, width(m));
    intrinsic("exclusive_load", address(m), fit(width(m) / 8, 8));
    if field(o0) == 1 {
        intrinsic("acquire");
    }
    t = zext(data, width(t));
}

// LDXP, LDAXP: one access of both registers, `t1` from the lower address.
#[operation(LDXP, LDAXP)]
fn load_exclusive_pair(t1: Op, t2: Op, m: Op) {
    check_alignment(m);
    let data = load(m, 0, width(m));
    intrinsic("exclusive_load", address(m), fit(width(m) / 8, 8));
    if field(o0) == 1 {
        intrinsic("acquire");
    }
    t1 = bits(data, 0, width(t1));
    t2 = bits(data, width(t1), width(t2));
}

// STXR, STLXR (and B/H): the low bytes of `t` if the monitors pass; `s` is
// 0 if the store happened, else 1.
#[operation(STXR, STXRB, STXRH, STLXR, STLXRB, STLXRH)]
fn store_exclusive(s: Op, t: Op, m: Op) {
    if field(o0) == 1 {
        intrinsic("release");
    }
    check_alignment(m);
    let failed = intrinsic("exclusive_store", address(m), fit(width(m) / 8, 8));
    if failed == 0 {
        store(m, 0, trunc(t, width(m)));
    }
    s = zext(failed, 32);
}

// STXP, STLXP: both registers in one access if the monitors pass, `t1` at
// the lower address; `s` as for STXR.
#[operation(STXP, STLXP)]
fn store_exclusive_pair(s: Op, t1: Op, t2: Op, m: Op) {
    if field(o0) == 1 {
        intrinsic("release");
    }
    check_alignment(m);
    let failed = intrinsic("exclusive_store", address(m), fit(width(m) / 8, 8));
    if failed == 0 {
        store(m, 0, concat(t2, t1));
    }
    s = zext(failed, 32);
}
