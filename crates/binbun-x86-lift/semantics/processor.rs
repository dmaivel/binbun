// Instructions whose results the processor supplies: L0 intrinsics, declared
// with their widths in `src/registers.rs`.

// CPUID: leaf eax, subleaf ecx; the 32-bit results clear the upper halves.
#[iclass(CPUID)]
fn cpuid(a: Op, b: Op, c: Op, d: Op) {
    let (ra, rb, rc, rd) = intrinsic("cpuid", a, c);
    a = ra;
    b = rb;
    c = rc;
    d = rd;
}

// RDTSC and RDTSCP: the time-stamp counter in edx:eax (RDTSCP also
// IA32_TSC_AUX in ecx). The counter registers XED lists are not read.
#[iclass(RDTSC)]
fn rdtsc(lo: Op, hi: Op, _counter: Op) {
    let tsc = intrinsic("rdtsc");
    lo = trunc(tsc, 32);
    hi = bits(tsc, 32, 32);
}

#[iclass(RDTSCP)]
fn rdtscp(lo: Op, hi: Op, aux: Op, _counter: Op, _aux_register: Op) {
    let (tsc, id) = intrinsic("rdtscp");
    lo = trunc(tsc, 32);
    hi = bits(tsc, 32, 32);
    aux = id;
}

// RDPID: IA32_TSC_AUX, zero-extended in 64-bit mode.
#[iform(RDPID_GPR64u64)]
fn rdpid64(dst: Op, _aux_register: Op) {
    dst = zext(intrinsic("rdpid"), 64);
}

#[iform(RDPID_GPR32u32)]
fn rdpid32(dst: Op, _aux_register: Op) {
    dst = intrinsic("rdpid");
}

// XGETBV: extended control register ecx in edx:eax; #GP for one the
// processor does not have.
#[iclass(XGETBV)]
fn xgetbv(number: Op, hi: Op, lo: Op, _register: Op) {
    let (value, valid) = intrinsic("xgetbv", number);
    if !valid {
        trap(GP);
    }
    lo = trunc(value, 32);
    hi = bits(value, 32, 32);
}

// RDRAND and RDSEED: CF says whether a value was available; if not, the
// destination is 0.
#[iclass(RDRAND)]
fn rdrand(dst: Op) {
    let (value, ok) = intrinsic("rdrand");
    cf = ok;
    dst = if ok { trunc(value, osz) } else { 0 };
}

#[iclass(RDSEED)]
fn rdseed(dst: Op) {
    let (value, ok) = intrinsic("rdseed");
    cf = ok;
    dst = if ok { trunc(value, osz) } else { 0 };
}

// XTEST: ZF is clear inside a transaction; #UD on a processor without RTM
// and HLE.
#[iclass(XTEST)]
fn xtest() {
    let (active, supported) = intrinsic("xtest");
    if !supported {
        trap(UD);
    }
    zf = !active;
}

// Fences order memory accesses between processors; nothing else changes.
#[iclass(LFENCE)]
fn lfence() {
    intrinsic("lfence");
}

#[iclass(SFENCE)]
fn sfence() {
    intrinsic("sfence");
}

#[iclass(MFENCE)]
fn mfence() {
    intrinsic("mfence");
}

// HLT is privileged: #GP in user mode, where binbun's semantics are.
#[iclass(HLT)]
fn hlt() {
    trap(GP);
}
