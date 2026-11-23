// LSE atomics (Arm's `MemAtomic`): one indivisible read-modify-write (the
// runtime makes the whole entry an atomic block), single-copy atomic: the
// alignment fault if it crosses an aligned 16-byte block (FEAT_LSE2). The
// release half (`R`) comes before the access, the acquire half (`A`) after
// it; an LD<op> or SWP whose destination is the zero register (ST<op>)
// does not acquire (`acquire = A == '1' && Rt != '11111'`). Operands are
// read before any register is written.

// LDADD, LDCLR, LDEOR, LDSET, LDSMAX, LDSMIN, LDUMAX, LDUMIN (and B/H,
// A/L/AL; ST<op> when `t` is the zero register): `t` gets the old value,
// memory the old value combined with `s` by the operation `opc` selects.
#[operation(
    LDADD, LDADDB, LDADDH, LDCLR, LDCLRB, LDCLRH, LDEOR, LDEORB, LDEORH, LDSET, LDSETB, LDSETH,
    LDSMAX, LDSMAXB, LDSMAXH, LDSMIN, LDSMINB, LDSMINH, LDUMAX, LDUMAXB, LDUMAXH, LDUMIN, LDUMINB,
    LDUMINH
)]
fn load_operate(s: Op, t: Op, m: Op) {
    check_alignment(m);
    if field(R) == 1 {
        intrinsic("release");
    }
    let old = load(m, 0, width(m));
    let value = trunc(s, width(m));
    let op = field(opc);
    let new = if op == 0 {
        old + value
    } else if op == 1 {
        old & !value
    } else if op == 2 {
        old ^ value
    } else if op == 3 {
        old | value
    } else if op == 4 {
        if sgt(old, value) { old } else { value }
    } else if op == 5 {
        if slt(old, value) { old } else { value }
    } else if op == 6 {
        if old > value { old } else { value }
    } else {
        if old < value { old } else { value }
    };
    store(m, 0, new);
    if field(A) == 1 && field(Rt) != 31 {
        intrinsic("acquire");
    }
    t = zext(old, width(t));
}

// SWP (and B/H, A/L/AL): memory gets `s`, `t` the old value.
#[operation(SWP, SWPB, SWPH)]
fn swap(s: Op, t: Op, m: Op) {
    check_alignment(m);
    if field(R) == 1 {
        intrinsic("release");
    }
    let old = load(m, 0, width(m));
    store(m, 0, trunc(s, width(m)));
    if field(A) == 1 && field(Rt) != 31 {
        intrinsic("acquire");
    }
    t = zext(old, width(t));
}

// CAS (and B/H, A/L/AL): memory gets `t` if it held `s`; `s` gets the old
// value either way. Nothing is written when the comparison fails.
#[operation(CAS, CASB, CASH)]
fn compare_and_swap(s: Op, t: Op, m: Op) {
    check_alignment(m);
    if field(R) == 1 {
        intrinsic("release");
    }
    let old = load(m, 0, width(m));
    if old == trunc(s, width(m)) {
        store(m, 0, trunc(t, width(m)));
    }
    if field(A) == 1 {
        intrinsic("acquire");
    }
    s = zext(old, width(s));
}

// CASP (A/L/AL): the pair `s1`, `s2` (`s1` at the lower address) against
// memory, one access; memory gets `t1`, `t2` if equal; `s1`, `s2` get the
// old pair either way.
#[operation(CASP)]
fn compare_and_swap_pair(s1: Op, s2: Op, t1: Op, t2: Op, m: Op) {
    check_alignment(m);
    if field(R) == 1 {
        intrinsic("release");
    }
    let old = load(m, 0, width(m));
    if old == concat(s2, s1) {
        store(m, 0, concat(t2, t1));
    }
    if field(A) == 1 {
        intrinsic("acquire");
    }
    s1 = bits(old, 0, width(s1));
    s2 = bits(old, width(s1), width(s2));
}
