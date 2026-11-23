// Load-acquire and store-release. The access must be single-copy atomic:
// `check_alignment(m)` raises the alignment fault if it crosses an aligned
// 16-byte block (FEAT_LSE2, `SCTLR_EL1.nAA` clear). The ordering is the
// `acquire` intrinsic after a load's access and `release` before a store's.
// LDLAR and STLLR (LORegions) order at least as LDAR and STLR do within a
// region; with no regions configured they are LDAR and STLR. LDAPR and
// LDAPUR are RCpc acquires, ordered by the same intrinsic.

// LDAR, LDLAR, LDAPR, LDAPUR (and B/H; LDAPR also with writeback): the
// bytes zero-extended into `t`, then acquire.
#[operation(
    LDAR, LDARB, LDARH, LDLAR, LDLARB, LDLARH, LDAPR, LDAPRB, LDAPRH, LDAPUR_gen, LDAPURB, LDAPURH
)]
fn load_acquire(t: Op, m: Op) {
    check_alignment(m);
    let data = load(m, 0, width(m));
    intrinsic("acquire");
    t = zext(data, width(t));
}

// LDAPURSB, LDAPURSH, LDAPURSW: the bytes sign-extended into `t`, then
// acquire.
#[operation(LDAPURSB, LDAPURSH, LDAPURSW)]
fn load_acquire_signed(t: Op, m: Op) {
    check_alignment(m);
    let data = load(m, 0, width(m));
    intrinsic("acquire");
    t = sext(data, width(t));
}

// STLR, STLLR, STLUR (and B/H; STLR also with writeback): release, then
// the low bytes of `t`.
#[operation(STLR, STLRB, STLRH, STLLR, STLLRB, STLLRH, STLUR_gen, STLURB, STLURH)]
fn store_release(t: Op, m: Op) {
    check_alignment(m);
    intrinsic("release");
    store(m, 0, trunc(t, width(m)));
}
