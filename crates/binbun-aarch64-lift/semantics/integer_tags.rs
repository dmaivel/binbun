// The tag instructions of FEAT_MTE in the data-processing groups, and
// PACGA. Under the execution context every allocation tag is excluded
// (Linux's `GCR_EL1.Exclude` = 0xffff until a process asks for tags with
// PR_SET_TAGGED_ADDR_CTRL; qemu-user does the same), so the tags IRG, ADDG
// and SUBG generate are 0: Arm's `ChooseNonExcludedTag` and
// `ChooseRandomNonExcludedTag` give 0000 when all are excluded. Tag checks
// are off. A pointer's allocation tag is bits 59..56.

// The address with allocation tag 0 (`AddressWithAllocationTag(x, '0000')`).
fn int_untagged(x: Op) {
    x & 0xf0ff_ffff_ffff_ffff
}

// IRG: n with a random tag not excluded by GCR_EL1.Exclude OR m<15:0>,
// which is 0 here, whatever m. (The `RGSR_EL1` seed it advances is EL1
// state, invisible at EL0, and every later tag is 0 anyway.)
#[operation(IRG)]
fn irg(d: Op, n: Op, m: Op) {
    d = int_untagged(n);
}

// GMI: m with the bit of n's allocation tag set.
#[operation(GMI)]
fn gmi(d: Op, n: Op, m: Op) {
    d = m | (zext(1, 64) << bits(n, 56, 4));
}

// ADDG: n + offset (uimm6 * 16), with the tag `ChooseNonExcludedTag`
// gives from n's and the tag offset: 0 here.
#[operation(ADDG)]
fn addg(d: Op, n: Op, offset: Op, tag_offset: Op) {
    d = int_untagged(n + offset);
}

// SUBG: n - offset (uimm6 * 16), tagged as ADDG.
#[operation(SUBG)]
fn subg(d: Op, n: Op, offset: Op, tag_offset: Op) {
    d = int_untagged(n - offset);
}

// The 56-bit address of a pointer, sign-extended (`SignExtend(x<55:0>)`).
fn int_address(x: Op) {
    sext(bits(x, 0, 56), 64)
}

// SUBP: the difference of the pointers' 56-bit addresses.
#[operation(SUBP)]
fn subp(d: Op, n: Op, m: Op) {
    d = int_address(n) - int_address(m);
}

// SUBPS, and CMPP: SUBP with the flags of AddWithCarry(a, NOT(b), 1).
#[operation(SUBPS)]
fn subps(d: Op, n: Op, m: Op) {
    let a = int_address(n);
    let b = int_address(m);
    let r = a - b;
    N = msb(r);
    Z = r == 0;
    C = a >= b;
    V = sub_of(a, b, 0);
    d = r;
}

// PACGA: ComputePAC(n, m, APGAKey)<63:32>:Zeros(32); the key is the
// process's (`compute_pac` key 4).
#[operation(PACGA)]
fn pacga(d: Op, n: Op, m: Op) {
    let pac = intrinsic("compute_pac", n, m, zext(4, 3));
    d = pac & 0xffff_ffff_0000_0000;
}
