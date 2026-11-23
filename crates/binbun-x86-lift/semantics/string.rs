// String operations. The pointers are rsi and rdi at the address size
// (`arsi`, `ardi`), moved by the element size, down if DF is set. One
// execution handles one element: with a REP prefix the instruction counts
// down the count register and runs again (`repeat()`) until it reaches 0,
// or until the comparison ends it (CMPS, SCAS), which is how the processor
// runs it (a single step, an interrupt or a fault comes between two
// elements, with the earlier ones done).
//
// Measured on an i9-14900 (P- and E-cores), where the SDM is silent:
// - With a count of 0 nothing is accessed, but with a 32-bit address size
//   the count and pointers are written back (clearing their upper halves):
//   MOVS writes the count and both pointers, STOS the count and rdi, CMPS
//   and SCAS the count. For LODS the cores differ (P-cores clear rcx's
//   upper half, E-cores keep it), so it is undefined.
// - REPE/REPNE CMPS and SCAS set the flags only on the element that ends
//   the instruction; between elements they are as before it.

// The pointer to the next element.
fn advance(pointer: Op) -> Op {
    if df {
        pointer - osz / 8
    } else {
        pointer + osz / 8
    }
}

#[iclass(MOVSB, MOVSW, MOVSD, MOVSQ)]
fn movs(dst: Op, src: Op) {
    dst = src;
    ardi = advance(ardi);
    arsi = advance(arsi);
}

#[iclass(REP_MOVSB, REP_MOVSW, REP_MOVSD, REP_MOVSQ)]
fn rep_movs(dst: Op, src: Op, count: Op) {
    if count != 0 {
        dst = src;
        ardi = advance(ardi);
        arsi = advance(arsi);
        count = count - 1;
        if count != 0 {
            repeat();
        }
    } else {
        count = count;
        ardi = ardi;
        arsi = arsi;
    }
}

#[iclass(STOSB, STOSW, STOSD, STOSQ)]
fn stos(dst: Op, src: Op) {
    dst = src;
    ardi = advance(ardi);
}

#[iclass(REP_STOSB, REP_STOSW, REP_STOSD, REP_STOSQ)]
fn rep_stos(dst: Op, src: Op, count: Op) {
    if count != 0 {
        dst = src;
        ardi = advance(ardi);
        count = count - 1;
        if count != 0 {
            repeat();
        }
    } else {
        count = count;
        ardi = ardi;
    }
}

#[iclass(LODSB, LODSW, LODSD, LODSQ)]
fn lods(dst: Op, src: Op) {
    dst = src;
    arsi = advance(arsi);
}

#[iclass(REP_LODSB, REP_LODSW, REP_LODSD, REP_LODSQ)]
fn rep_lods(dst: Op, src: Op, count: Op) {
    if count != 0 {
        dst = src;
        arsi = advance(arsi);
        count = count - 1;
        if count != 0 {
            repeat();
        }
    } else if asz == 32 {
        rcx = concat(undefined(32), ecx);
    }
}

// CMPS compares [rsi] with [rdi], SCAS the accumulator with [rdi]; flags as
// CMP. REPE repeats while they are equal, REPNE while they differ.
#[iclass(CMPSB, CMPSW, CMPSD, CMPSQ)]
fn cmps(a: Op, b: Op) {
    subtract(a, b);
    arsi = advance(arsi);
    ardi = advance(ardi);
}

#[iclass(REPE_CMPSB, REPE_CMPSW, REPE_CMPSD, REPE_CMPSQ)]
fn repe_cmps(a: Op, b: Op, count: Op) {
    if count != 0 {
        // The elements are read before the pointers move.
        let continues = a == b;
        arsi = advance(arsi);
        ardi = advance(ardi);
        count = count - 1;
        if count != 0 && continues {
            repeat();
        } else {
            subtract(a, b);
        }
    } else {
        count = count;
    }
}

#[iclass(REPNE_CMPSB, REPNE_CMPSW, REPNE_CMPSD, REPNE_CMPSQ)]
fn repne_cmps(a: Op, b: Op, count: Op) {
    if count != 0 {
        // The elements are read before the pointers move.
        let continues = a != b;
        arsi = advance(arsi);
        ardi = advance(ardi);
        count = count - 1;
        if count != 0 && continues {
            repeat();
        } else {
            subtract(a, b);
        }
    } else {
        count = count;
    }
}

#[iclass(SCASB, SCASW, SCASD, SCASQ)]
fn scas(acc: Op, element: Op) {
    subtract(acc, element);
    ardi = advance(ardi);
}

#[iclass(REPE_SCASB, REPE_SCASW, REPE_SCASD, REPE_SCASQ)]
fn repe_scas(acc: Op, element: Op, count: Op) {
    if count != 0 {
        // The elements are read before the pointers move.
        let continues = acc == element;
        ardi = advance(ardi);
        count = count - 1;
        if count != 0 && continues {
            repeat();
        } else {
            subtract(acc, element);
        }
    } else {
        count = count;
    }
}

#[iclass(REPNE_SCASB, REPNE_SCASW, REPNE_SCASD, REPNE_SCASQ)]
fn repne_scas(acc: Op, element: Op, count: Op) {
    if count != 0 {
        // The elements are read before the pointers move.
        let continues = acc != element;
        ardi = advance(ardi);
        count = count - 1;
        if count != 0 && continues {
            repeat();
        } else {
            subtract(acc, element);
        }
    } else {
        count = count;
    }
}
