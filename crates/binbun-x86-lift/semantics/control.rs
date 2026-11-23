// Jumps, calls and returns. A target operand is an address: a relative
// branch's is computed from the next instruction's address.

#[iclass(JMP)]
fn jmp(target: Op) {
    jump(target);
}

#[iclass(
    JO, JNO, JB, JNB, JZ, JNZ, JBE, JNBE, JS, JNS, JP, JNP, JL, JNL, JLE, JNLE
)]
fn jcc(target: Op) {
    if cond() {
        jump(target);
    }
}

// The target is checked (#GP) before the return address is pushed, as the
// SDM's CALL orders it: a call to a non-canonical address writes nothing.
#[iclass(CALL_NEAR)]
fn call_near(target: Op) {
    let checked = target(target);
    push(next());
    call(checked);
}

#[iform(RET_NEAR)]
fn ret_near() {
    let target = pop();
    ret(target);
}

// `ret n` also releases n bytes of arguments.
#[iform(RET_NEAR_IMMw)]
fn ret_near_release(bytes: Op) {
    let target = pop();
    rsp = rsp + zext(bytes, 64);
    ret(target);
}

#[iclass(JRCXZ)]
fn jrcxz(target: Op, count: Op) {
    if count == 0 {
        jump(target);
    }
}

// LOOP, LOOPE, LOOPNE: the count register (the address size's) counts
// down; the jump is taken while it is not 0 (and ZF is set, or clear).
#[iclass(LOOP)]
fn loop_count(target: Op, count: Op) {
    let left = count - 1;
    count = left;
    if left != 0 {
        jump(target);
    }
}

#[iclass(LOOPE)]
fn loop_equal(target: Op, count: Op) {
    let left = count - 1;
    count = left;
    if left != 0 && zf {
        jump(target);
    }
}

#[iclass(LOOPNE)]
fn loop_not_equal(target: Op, count: Op) {
    let left = count - 1;
    count = left;
    if left != 0 && !zf {
        jump(target);
    }
}

#[iclass(UD2)]
fn ud2() {
    trap(UD);
}

#[iclass(INT3)]
fn int3() {
    trap(BP);
}

// INT n enters the handler of interrupt vector n: what it does (and
// whether execution comes back) is the platform's.
#[iclass(INT)]
fn int(vector: Op) {
    interrupt(vector);
}

// SYSCALL saves the return address in rcx and RFLAGS in r11 (only partly
// modelled, so left undefined), then enters the system.
#[iclass(SYSCALL)]
fn syscall(link: Op, saved_flags: Op) {
    link = next();
    saved_flags = undefined();
    system_call();
}
