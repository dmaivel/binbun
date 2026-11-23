// Hints, barriers, PSTATE and system registers at EL0 under Linux.
// System registers are their encodings `op0:op1:CRn:CRm:op2` (2, 3, 4, 4, 3
// bits), SYS operations likewise with op0 = 1. What EL0 may do is Linux's
// configuration (SCTLR_EL1.UMA = 0, DZE = UCT = UCI = 1, nTWE = nTWI = 1;
// CNTKCTL_EL1: the virtual counter and frequency only; the ID registers
// Linux emulates); everything else traps as UNDEFINED (SIGILL).

// NOP, and hints without architectural effect in the context: YIELD
// (scheduling), DGH (gathering), CLRBHB (branch history, speculation
// only), ESB (no RAS error is synchronised at EL0 here), PSB CSYNC (no
// statistical profiling), TSB CSYNC (no trace), GCSB DSYNC (no guarded
// control stack), BTI (no guarded pages: the landing-pad check is not
// made).
#[operation(NOP, YIELD, DGH, CLRBHB, ESB, PSB, TSB, GCSB, BTI)]
fn hint() {}

// The unallocated hints: NOP.
#[operation(HINT)]
fn hint_unallocated(imm: Op) {}

// WFE, WFI, SEV, SEVL: the event register and waiting.
#[operation(WFE)]
fn wfe() {
    intrinsic("wfe");
}

#[operation(WFI)]
fn wfi() {
    intrinsic("wfi");
}

#[operation(SEV)]
fn sev() {
    intrinsic("sev");
}

#[operation(SEVL)]
fn sevl() {
    intrinsic("sevl");
}

// CSDB: the consumption of speculative data barrier.
#[operation(CSDB)]
fn csdb() {
    intrinsic("csdb");
}

// CHKFEAT: X16 AND NOT the bits of the enabled features; the only one,
// GCS (bit 0), is disabled in the context, so x16 is unchanged.
#[operation(CHKFEAT)]
fn chkfeat(t: Op) {
    t = t;
}

// DMB with its option (CRm).
#[operation(DMB)]
fn dmb() {
    intrinsic("dmb", fit(field(8, 4), 4));
}

// DSB: CRm 0 and 4 are SSBB and PSSBB; otherwise the option (CRm); the nXS
// form (opc, bits 7:5, 001; imm2 in bits 11:10: the domain, always for
// loads and stores) as option bit 4.
#[operation(DSB)]
fn dsb() {
    if field(5, 3) == 1 {
        // Option bit 4 set, the domain in bits 3:2, loads and stores (11).
        intrinsic("dsb", fit((field(10, 2) << 2) + 19, 5));
    } else if field(8, 4) == 0 {
        intrinsic("ssbb");
    } else if field(8, 4) == 4 {
        intrinsic("pssbb");
    } else {
        intrinsic("dsb", fit(field(8, 4), 5));
    }
}

// ISB (its option, CRm, is SY or reserved, which is SY).
#[operation(ISB)]
fn isb() {
    intrinsic("isb");
}

// SB: the speculation barrier.
#[operation(SB)]
fn sb() {
    intrinsic("sb");
}

// CLREX: the local exclusive monitor is cleared (CRm is ignored).
#[operation(CLREX)]
fn clrex() {
    intrinsic("clear_exclusive");
}

// CFINV: C inverted.
#[operation(CFINV)]
fn cfinv() {
    C = !C;
}

// AXFLAG: Arm's floating-point condition flags to the external format.
#[operation(AXFLAG)]
fn axflag() {
    let z = Z | V;
    let c = C & !V;
    N = 0;
    Z = z;
    C = c;
    V = 0;
}

// XAFLAG: the external format back to Arm's.
#[operation(XAFLAG)]
fn xaflag() {
    let n = !C & !Z;
    let z = Z & C;
    let c = C | Z;
    let v = !C & Z;
    N = n;
    Z = z;
    C = c;
    V = v;
}

// MSR (immediate): the PSTATE field from op1 (bits 18:16) and op2 (bits
// 7:5), the immediate CRm (bits 11:8; SMSTART and the like show none).
// DIT, SSBS and TCO take CRm<0>; SVCR (SME) is not lifted; PAN,
// UAO, SPSel, ALLINT, PM and DAIFSet/DAIFClr (SCTLR_EL1.UMA = 0) are not
// accessible at EL0.
#[operation(MSR_imm)]
fn msr_immediate() {
    let pstate = (field(16, 3) << 3) | field(5, 3);
    if pstate == 0x1a {
        dit = fit(field(8, 1), 1);
    } else if pstate == 0x19 {
        ssbs = fit(field(8, 1), 1);
    } else if pstate == 0x1c {
        tco = fit(field(8, 1), 1);
    } else if pstate == 0x1b {
        unlifted();
    } else {
        trap(UNDEFINED);
    }
}

// FPCR bits every implementation of the context keeps (FIZ, AH, NEP, EBF,
// FZ16, RMode, FZ, DN, AHP); the others are trap enables an
// implementation may not have, AArch32-only or RES0: what reads back is
// the implementation's.
fn fpcr_written(value: Op) -> Op {
    (bits(value, 0, 32) & 0x07c8_2007) | (undefined(32) & 0xf837_dff8)
}

// FPSR: the cumulative flags and QC are kept; N, Z, C, V (AArch32 only)
// and RES0 bits are the implementation's.
fn fpsr_written(value: Op) -> Op {
    (bits(value, 0, 32) & 0x0800_009f) | (undefined(32) & 0xf7ff_ff60)
}

// MRS. NZCV, FPCR, FPSR, DIT, SSBS, TCO and the thread pointers are state;
// the counter-timer frequency and virtual count, CTR_EL0, DCZID_EL0, MIDR,
// MPIDR, REVIDR and the AArch64 ID registers (CRm 4 to 7, which Linux
// emulates) are the system's. FPMR, SVCR, TPIDR2_EL0 (FP8, SME), RNDR,
// RNDRRS and GCSPR_EL0 are not lifted.
#[operation(MRS)]
fn mrs(t: Op, r: Op) {
    if r == 0xda10 {
        t = (zext(N, 64) << 31) | (zext(Z, 64) << 30) | (zext(C, 64) << 29) | (zext(V, 64) << 28);
    } else if r == 0xda15 {
        t = zext(dit, 64) << 24;
    } else if r == 0xda16 {
        t = zext(ssbs, 64) << 12;
    } else if r == 0xda17 {
        t = zext(tco, 64) << 25;
    } else if r == 0xda20 {
        t = zext(fpcr, 64);
    } else if r == 0xda21 {
        t = zext(fpsr, 64);
    } else if r == 0xde82 {
        t = tpidr_el0;
    } else if r == 0xde83 {
        t = tpidrro_el0;
    } else if r == 0xd801
        || r == 0xd807
        || r == 0xdf00
        || r == 0xdf02
        || r == 0xdf06
        || r == 0xc000
        || r == 0xc005
        || r == 0xc006
        || (r >= 0xc020 && r <= 0xc03f)
    {
        t = intrinsic("system_register", fit(r, 16));
    } else if r == 0xda12 || r == 0xda22 || r == 0xde85 || r == 0xd920 || r == 0xd921 || r == 0xd929
    {
        unlifted();
    } else {
        trap(UNDEFINED);
    }
}

// MSR (register): NZCV from bits 31:28; FPCR, FPSR as kept; DIT, SSBS, TCO
// from their bits; TPIDR_EL0. FPMR, SVCR, TPIDR2_EL0 and GCSPR_EL0 are not
// lifted; everything else (TPIDRRO_EL0, DAIF, the read-only registers) is
// not writable at EL0.
#[operation(MSR_reg)]
fn msr_register(r: Op, t: Op) {
    if r == 0xda10 {
        N = bit(t, 31);
        Z = bit(t, 30);
        C = bit(t, 29);
        V = bit(t, 28);
    } else if r == 0xda15 {
        dit = bit(t, 24);
    } else if r == 0xda16 {
        ssbs = bit(t, 12);
    } else if r == 0xda17 {
        tco = bit(t, 25);
    } else if r == 0xda20 {
        fpcr = fpcr_written(t);
    } else if r == 0xda21 {
        fpsr = fpsr_written(t);
    } else if r == 0xde82 {
        tpidr_el0 = t;
    } else if r == 0xda12 || r == 0xda22 || r == 0xde85 || r == 0xd929 {
        unlifted();
    } else {
        trap(UNDEFINED);
    }
}

// DC ZVA: zeroes the naturally aligned block of 4 << DCZID_EL0.BS bytes
// (BS is at most 9: 2 KiB) holding the address; DCZID_EL0.DZP set
// prohibits it (UNDEFINED).
fn zero_block(address: Op) {
    let dczid = intrinsic("system_register", fit(0xd807, 16));
    if bit(dczid, 4) == 1 {
        trap(UNDEFINED);
    }
    let bs = bits(dczid, 0, 4);
    for size in 0..10 {
        if bs == size {
            let base = address & (0 - (4 << size));
            if size < 4 {
                write_memory(base, fit(0, 32 << size));
            } else {
                for i in 0..(1 << (size - 4)) {
                    write_memory(base + i * 64, fit(0, 512));
                }
            }
        }
    }
}

// SYS: at EL0, DC ZVA; cache maintenance by address (DC CVAC, CVAU, CVAP,
// CVADP, CIVAC, IC IVAU); the MTE tag operations (DC GVA, GZVA, CGVAC,
// CGDVAC, CGVAP, CGDVAP, CGVADP, CGDVADP, CIGVAC, CIGDVAC) are not lifted;
// everything else (TLBI, AT, set/way and EL1 cache maintenance, the
// prediction restrictions with SCTLR_EL1.EnRCTX = 0, GCS with GCS
// disabled, BRB, TRCIT) is UNDEFINED.
#[operation(SYS)]
fn sys(op1: Op, cn: Op, cm: Op, op2: Op, t: Op) {
    let operation = 0x4000 | (op1 << 11) | (cn << 7) | (cm << 3) | op2;
    if operation == 0x5ba1 {
        zero_block(t);
    } else if operation == 0x5bd1
        || operation == 0x5bd9
        || operation == 0x5be1
        || operation == 0x5be9
        || operation == 0x5bf1
        || operation == 0x5ba9
    {
        intrinsic("cache_maintenance", fit(operation, 16), t);
    } else if operation == 0x5ba3
        || operation == 0x5ba4
        || operation == 0x5bd3
        || operation == 0x5bd5
        || operation == 0x5be3
        || operation == 0x5be5
        || operation == 0x5beb
        || operation == 0x5bed
        || operation == 0x5bf3
        || operation == 0x5bf5
    {
        unlifted();
    } else {
        trap(UNDEFINED);
    }
}
