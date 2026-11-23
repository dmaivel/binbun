//! Every instruction of the fixtures whose form has semantics lifts, and
//! its L0 passes the verifier and round-trips through the text form; a
//! call checks its target before it pushes; every undefined value is a
//! site's, of the instruction's form.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

mod support;

use std::collections::BTreeSet;

use binbun_semantics::Semantics;
use binbun_semantics::ir::{Expr, ExprId, RegisterId, Stmt};
use binbun_semantics::text::{parse, print};
use binbun_semantics::verify::verify;
use binbun_x86::{Form, Instruction, Mode, Register, RegisterClass, Value, decode};
use binbun_x86_lift::registers::{FPR0, FTOP, FTW, K0, MXCSR, ZMM0, ZMM16, gpr, mask, vector};
use binbun_x86_lift::sites::SITES;
use binbun_x86_lift::{LiftError, X86, lift, lift_opaque, opaque_outputs};

/// Why an undefined value of `semantics` (lifted from a form) is not as it
/// should be: without a site, or of a site that does not list the form.
/// One that is only a site's input needs none: what an entry stores to
/// memory in a branch, which the input would have to load again.
fn site_problems(semantics: &Semantics, form: Form) -> Vec<String> {
    let mut problems = Vec::new();
    let inputs: BTreeSet<ExprId> = semantics
        .sites
        .iter()
        .flat_map(|site| site.inputs.iter().copied())
        .collect();
    let mut used = BTreeSet::new();
    for &(expr, _) in &semantics.exprs {
        used.extend(expr.operands());
    }
    for stmt in &semantics.body {
        stmt.clone().map_exprs(&mut |id| {
            used.insert(id);
            id
        });
    }
    for (&(expr, _), id) in semantics.exprs.iter().zip((0..).map(ExprId)) {
        let Expr::Undefined { serial, .. } = expr else {
            continue;
        };
        match semantics.site(serial) {
            None if inputs.contains(&id) && !used.contains(&id) => {}
            None => problems.push(format!("undefined {serial} has no site")),
            Some(site) => {
                let listed = SITES
                    .get(usize::from(site.site.0))
                    .is_some_and(|info| info.forms.contains(&form));
                if !listed {
                    let name = X86.site(site.site).map_or("?", |info| info.name);
                    problems.push(format!("site {name} does not list {form:?}"));
                }
            }
        }
    }
    problems
}

#[test]
fn covered_fixture_instructions_lift_and_verify() {
    let mut lifted = 0;
    let mut forms = BTreeSet::new();
    let mut failures = Vec::new();
    for name in [
        "program-x86_64.elf",
        "exceptions-x86_64.elf",
        "program-x86_64.exe",
    ] {
        for found in support::sweep(&support::fixture(name)) {
            let text = found.instruction.intel(found.address).to_string();
            match lift(&found.instruction, Mode::Bits64, found.address) {
                Ok(semantics) => {
                    if let Err(error) = verify(&semantics, &X86) {
                        failures.push(format!("{text}: does not verify: {error}"));
                        continue;
                    }
                    for problem in site_problems(&semantics, found.instruction.form()) {
                        failures.push(format!("{text}: {problem}"));
                    }
                    let printed = print(&semantics, &X86);
                    if parse(&printed, &X86).as_ref() != Ok(&semantics) {
                        failures.push(format!("{text}: text form does not round-trip"));
                    }
                    lifted += 1;
                    forms.insert(found.instruction.form());
                }
                Err(LiftError::Unsupported) => {}
                Err(error) => failures.push(format!("{text}: {error:?}")),
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    // The fixtures are small C programs: most of their code is covered.
    assert!(
        lifted > 500 && forms.len() > 40,
        "{lifted} lifted, {} forms",
        forms.len()
    );
}

/// Random bytes decode to every prefix and operand-size combination
/// compilers rarely emit (16-bit operands, address-size overrides, odd
/// REX bits): each covered one must lift and verify, so width mistakes in
/// an entry show up for every form and size it covers; each undefined value
/// must be a site's (whose inputs the verifier checks: widths, defined
/// before use), and the text form must round-trip.
#[test]
fn covered_forms_lift_at_every_operand_size() {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut seen = BTreeSet::new();
    let mut sites = BTreeSet::new();
    let mut failures = Vec::new();
    for _ in 0..400_000 {
        let mut bytes = [0u8; 15];
        for chunk in bytes.chunks_mut(8) {
            let word = next().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
        // Common prefixes, so that sizes and segments vary.
        if next() % 2 == 0 {
            bytes[0] = [0x66, 0x67, 0x48, 0x41, 0x4c, 0x64, 0xf0, 0x66]
                [usize::try_from(next() % 8).unwrap()];
        }
        let Ok(instruction) = decode(&bytes, Mode::Bits64) else {
            continue;
        };
        match lift(&instruction, Mode::Bits64, 0x40_1000) {
            Ok(semantics) => {
                seen.insert(instruction.form());
                if let Err(error) = verify(&semantics, &X86) {
                    failures.push(format!("{}: {error}", instruction.intel(0x40_1000)));
                }
                for problem in site_problems(&semantics, instruction.form()) {
                    failures.push(format!("{}: {problem}", instruction.intel(0x40_1000)));
                }
                sites.extend(semantics.sites.iter().map(|site| site.site));
                if !semantics.sites.is_empty()
                    && parse(&print(&semantics, &X86), &X86).as_ref() != Ok(&semantics)
                {
                    let text = instruction.intel(0x40_1000);
                    failures.push(format!("{text}: text form does not round-trip"));
                }
            }
            Err(LiftError::Unsupported) => {}
            Err(LiftError::Problem(problem))
                if problem
                    .split("; ")
                    .all(|part| part.ends_with("is not modelled")) =>
            {
                // Segment, control or APX registers: not in L0 yet.
            }
            Err(error) => failures.push(format!("{}: {error:?}", instruction.intel(0x40_1000))),
        }
    }
    failures.sort();
    failures.dedup();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(seen.len() > 300, "only {} forms reached", seen.len());
    assert!(sites.len() > 200, "only {} sites reached", sites.len());
}

/// SHRD's OF for a count other than 1 is site `shrd.of`, whose inputs are
/// the operands as read, the count, OF before, and what SHRD defines (the
/// result and CF); the text form names them and reads them back.
#[test]
fn the_text_form_names_a_site_and_its_inputs() {
    // shrd rdx, rdx, 0x1d
    let instruction = decode(&[0x48, 0x0f, 0xac, 0xd2, 0x1d], Mode::Bits64).unwrap();
    let semantics = lift(&instruction, Mode::Bits64, 0x1000).unwrap();
    let site = X86.find_site("shrd.of").unwrap();
    let info = X86.site(site).unwrap();
    assert_eq!(
        info.inputs,
        ["dst", "src", "count", "old", "defined.dst", "defined.cf"]
    );
    let uses: Vec<_> = semantics.sites.iter().filter(|s| s.site == site).collect();
    assert_eq!(uses.len(), 1);
    let inputs = &uses[0].inputs;
    let widths: Vec<u16> = inputs.iter().map(|&id| semantics.width(id)).collect();
    assert_eq!(widths, [64, 64, 8, 1, 64, 1]);
    let Some((Expr::Const(count), _)) = semantics.expr(inputs[2]) else {
        panic!("the count is not the immediate");
    };
    assert_eq!(count.low_u64(), 0x1d);

    let printed = print(&semantics, &X86);
    let line = printed
        .lines()
        .find(|line| line.contains("@shrd.of"))
        .unwrap();
    let expected = format!(
        "(undefined {} @shrd.of dst=e{} src=e{} count=e{} old=e{} defined.dst=e{} defined.cf=e{})",
        uses[0].serial,
        inputs[0].0,
        inputs[1].0,
        inputs[2].0,
        inputs[3].0,
        inputs[4].0,
        inputs[5].0
    );
    assert!(line.ends_with(&format!("{expected})")), "{line}");
    assert_eq!(parse(&printed, &X86), Ok(semantics.clone()));

    // A site's inputs are named as it declares them, all of them.
    let renamed = printed.replace(" src=", " source=");
    assert!(parse(&renamed, &X86).is_err());
    let short = printed.replace(&format!(" defined.cf=e{}", inputs[5].0), "");
    assert!(parse(&short, &X86).is_err());
}

/// The registers `semantics` writes anywhere.
fn written(statements: &[Stmt], out: &mut BTreeSet<RegisterId>) {
    for statement in statements {
        match statement {
            Stmt::Write { view, .. } => {
                out.insert(view.register);
            }
            Stmt::If {
                then, otherwise, ..
            } => {
                written(then, out);
                written(otherwise, out);
            }
            Stmt::Loop(body) | Stmt::Atomic(body) => written(body, out),
            Stmt::Read { .. }
            | Stmt::Load { .. }
            | Stmt::Store { .. }
            | Stmt::Break
            | Stmt::Trap(_)
            | Stmt::Jump { .. }
            | Stmt::Call { .. }
            | Stmt::Return { .. }
            | Stmt::SystemCall
            | Stmt::Intrinsic { .. } => {}
        }
    }
}

/// What an instruction may change must be what `lift_opaque` makes
/// unknown, or analyses built on it would keep stale values: every
/// general-purpose or vector register, and `mxcsr`, an operand may write
/// (a vector register whole), and all the x87 state if it writes an x87
/// register. Checked on random encodings of every extension.
#[test]
fn opaque_semantics_write_every_register_an_operand_may_write() {
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let x87 = [FPR0, FTOP, FTW];
    let mut failures = Vec::new();
    let mut checked = 0;
    for _ in 0..200_000 {
        let mut bytes = [0u8; 15];
        for chunk in bytes.chunks_mut(8) {
            let word = next().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
        // VEX prefixes and the x87 escape bytes now and then.
        match next() % 4 {
            0 => bytes[0] = 0xc5,
            1 => bytes[0] = 0xd8 + u8::try_from(next() % 8).unwrap(),
            _ => {}
        }
        let Ok(instruction) = decode(&bytes, Mode::Bits64) else {
            continue;
        };
        let semantics = lift_opaque(&instruction, Mode::Bits64, 0x40_1000);
        verify(&semantics, &X86).unwrap();
        let mut wrote = BTreeSet::new();
        written(&semantics.body, &mut wrote);
        let text = instruction.intel(0x40_1000).to_string();
        for operand in instruction.operands() {
            let Value::Register(Some(register)) = operand.value else {
                continue;
            };
            if !operand.action.writes() {
                continue;
            }
            let expected: Vec<RegisterId> =
                if let Some(view) = gpr(register).or_else(|| vector(register)) {
                    vec![view.register]
                } else if register.class() == RegisterClass::Mxcsr {
                    vec![MXCSR]
                } else if matches!(
                    register.class(),
                    RegisterClass::X87 | RegisterClass::Pseudox87
                ) {
                    x87.to_vec()
                } else {
                    Vec::new()
                };
            for id in expected {
                checked += 1;
                if !wrote.contains(&id) {
                    failures.push(format!(
                        "{text}: {register:?} written, {id:?} not made unknown"
                    ));
                }
            }
        }
    }
    failures.sort();
    failures.dedup();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(checked > 10_000, "only {checked} writes checked");
}

/// What `lift_opaque` gives an instruction: the registers it reads as
/// inputs of its intrinsic, the registers it writes, and the widths of
/// the intrinsic's outputs.
struct Opaque {
    inputs: BTreeSet<RegisterId>,
    writes: BTreeSet<RegisterId>,
    outputs: Vec<u16>,
}

fn opaque(instruction: &Instruction) -> Opaque {
    let semantics: Semantics = lift_opaque(instruction, Mode::Bits64, 0x40_1000);
    verify(&semantics, &X86).unwrap();
    let mut read = Vec::new();
    let mut writes = BTreeSet::new();
    let mut inputs = BTreeSet::new();
    let mut outputs = Vec::new();
    for statement in &semantics.body {
        match statement {
            Stmt::Read { local, view } => read.push((*local, view.register)),
            Stmt::Write { view, .. } => {
                writes.insert(view.register);
            }
            Stmt::Intrinsic {
                inputs: values,
                outputs: locals,
                ..
            } => {
                for &value in values {
                    let Some((Expr::Local(local), _)) = semantics.expr(value) else {
                        continue;
                    };
                    inputs.extend(
                        read.iter()
                            .filter(|&&(read, _)| read == local)
                            .map(|&(_, register)| register),
                    );
                }
                outputs.extend(
                    locals
                        .iter()
                        .map(|local| semantics.locals[local.0 as usize]),
                );
            }
            Stmt::Load { .. }
            | Stmt::Store { .. }
            | Stmt::If { .. }
            | Stmt::Loop(_)
            | Stmt::Atomic(_)
            | Stmt::Break
            | Stmt::Trap(_)
            | Stmt::Jump { .. }
            | Stmt::Call { .. }
            | Stmt::Return { .. }
            | Stmt::SystemCall => {}
        }
    }
    Opaque {
        inputs,
        writes,
        outputs,
    }
}

/// The register L0 places a vector or mask register in.
fn avx512_register(register: Register) -> Option<RegisterId> {
    vector(register)
        .map(|view| view.register)
        .or_else(|| mask(register))
}

/// Whether `instruction`'s two sources (no write mask) are one register:
/// for a zero idiom (`vpxorq xmm16, xmm16, xmm16`) it is no input.
fn one_source(instruction: &Instruction) -> bool {
    let sources: Vec<Value> = instruction
        .operands()
        .filter(|operand| !operand.writemask && operand.action.reads())
        .map(|operand| operand.value)
        .collect();
    matches!(sources.as_slice(), [a @ Value::Register(Some(_)), b] if a == b)
}

/// AVX-512's state is L0's, so what instructions without semantics do to
/// it is seen: on random EVEX encodings, every vector register (`zmm16`–
/// `zmm31` included) and mask register an operand writes is written,
/// every one an operand reads is an input of the intrinsic, but for the
/// write mask `k0` (no masking) and a zero idiom's sources, and no output
/// is wider than C's widest integer (128 bits), as `opaque_outputs` lists
/// them.
#[test]
fn opaque_semantics_place_avx512_state() {
    let mut state = 0x6a09_e667_f3bc_c908u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut failures = Vec::new();
    let (mut masks, mut upper, mut unmasked) = (0, 0, 0);
    for _ in 0..200_000 {
        let mut bytes = [0u8; 15];
        for chunk in bytes.chunks_mut(8) {
            let word = next().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
        bytes[0] = 0x62;
        // P0's bit 3 is 0 and its map one of AVX-512's, P1's bit 2 is 1:
        // other prefixes do not decode.
        bytes[1] = (bytes[1] & 0xf0) | [1, 2, 3, 5, 6][usize::from(bytes[1] & 7) % 5];
        bytes[2] |= 0x04;
        let Ok(instruction) = decode(&bytes, Mode::Bits64) else {
            continue;
        };
        let text = instruction.intel(0x40_1000).to_string();
        let lifted = opaque(&instruction);
        let expected: Vec<u16> = opaque_outputs(&instruction, Mode::Bits64)
            .iter()
            .map(|view| view.width)
            .collect();
        if expected != lifted.outputs || lifted.outputs.iter().any(|&width| width > 128) {
            failures.push(format!(
                "{text}: outputs {:?}, listed {expected:?}",
                lifted.outputs
            ));
        }
        let reads_k0 = instruction.operands().any(|operand| {
            !operand.writemask
                && operand.action.reads()
                && operand.value == Value::Register(Some(Register::K0))
        });
        for operand in instruction.operands() {
            let Value::Register(Some(register)) = operand.value else {
                continue;
            };
            let Some(id) = avx512_register(register) else {
                continue;
            };
            masks += usize::from(id.0 >= K0.0 && id.0 < K0.0 + 8);
            upper += usize::from(id.0 >= ZMM16.0);
            if operand.writemask && register == Register::K0 {
                unmasked += 1;
                if !reads_k0 && lifted.inputs.contains(&K0) {
                    failures.push(format!("{text}: the write mask k0 is read"));
                }
                continue;
            }
            if operand.action.writes() && !lifted.writes.contains(&id) {
                failures.push(format!("{text}: {register:?} written, {id:?} not"));
            }
            if operand.action.reads() && !lifted.inputs.contains(&id) && !one_source(&instruction) {
                failures.push(format!("{text}: {register:?} read, {id:?} no input"));
            }
        }
    }
    failures.sort();
    failures.dedup();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(
        masks > 5_000 && upper > 5_000 && unmasked > 300,
        "masks {masks}, zmm16-31 {upper}, k0 write masks {unmasked}"
    );
}

/// The AVX-512 state instructions without semantics change that XED does
/// not list (`vp2intersect`'s second mask register, all of the state
/// `xrstor` restores) is written; merge masking reads the destination,
/// zeroing does not; a 512-bit result is four 128-bit outputs; a zero
/// idiom reads nothing.
#[test]
fn opaque_semantics_of_avx512_special_forms() {
    let lifted = |bytes: &[u8]| opaque(&decode(bytes, Mode::Bits64).unwrap());
    let k = |n: u16| RegisterId(K0.0 + n);
    // vp2intersectd k2, zmm1, zmm0; vp2intersectq k4, zmm17, zmm30
    let pair = lifted(&[0x62, 0xf2, 0x77, 0x48, 0x68, 0xd0]);
    assert!(pair.writes.contains(&k(2)) && pair.writes.contains(&k(3)));
    let pair = lifted(&[0x62, 0x92, 0xf7, 0x40, 0x68, 0xe6]);
    assert!(pair.writes.contains(&k(4)) && pair.writes.contains(&k(5)));
    assert!(pair.inputs.contains(&RegisterId(ZMM16.0 + 1)));
    assert!(pair.inputs.contains(&RegisterId(ZMM16.0 + 14)));
    // xrstor, xrstor64, xrstors, xrstors64 [rax]
    let restored: BTreeSet<RegisterId> = (0..16)
        .map(|n| RegisterId(ZMM0.0 + n))
        .chain((0..16).map(|n| RegisterId(ZMM16.0 + n)))
        .chain((0..8).map(k))
        .chain([MXCSR, FPR0, FTOP, FTW])
        .collect();
    for bytes in [
        &[0x0f, 0xae, 0x28][..],
        &[0x48, 0x0f, 0xae, 0x28],
        &[0x0f, 0xc7, 0x18],
        &[0x48, 0x0f, 0xc7, 0x18],
    ] {
        let restore = lifted(bytes);
        let missing: Vec<_> = restored.difference(&restore.writes).collect();
        assert!(missing.is_empty(), "{bytes:x?}: {missing:?} not restored");
    }
    // vmovdqu8 zmm1{k1}, [rax] keeps what k1 masks; with {z} it zeroes it.
    let zmm1 = RegisterId(ZMM0.0 + 1);
    let merging = lifted(&[0x62, 0xf1, 0x7f, 0x49, 0x6f, 0x08]);
    assert!(merging.inputs.contains(&zmm1) && merging.inputs.contains(&k(1)));
    let zeroing = lifted(&[0x62, 0xf1, 0x7f, 0xc9, 0x6f, 0x08]);
    assert!(!zeroing.inputs.contains(&zmm1) && zeroing.inputs.contains(&k(1)));
    // vbroadcastss zmm2, xmm0: four 128-bit outputs, no mask read.
    let broadcast = lifted(&[0x62, 0xf2, 0x7d, 0x48, 0x18, 0xd0]);
    assert_eq!(broadcast.outputs, [128; 4]);
    assert!(!broadcast.inputs.contains(&K0));
    // vpxorq xmm16, xmm16, xmm16 clears zmm16 whatever it held; with
    // xmm17 as a source it is a function of both.
    let zmm = |n: u16| RegisterId(ZMM16.0 + n - 16);
    let cleared = lifted(&[0x62, 0xa1, 0xfd, 0x00, 0xef, 0xc0]);
    assert!(cleared.inputs.is_empty() && cleared.writes.contains(&zmm(16)));
    let xored = lifted(&[0x62, 0xa1, 0xf5, 0x00, 0xef, 0xc0]);
    assert!(xored.inputs.contains(&zmm(16)) && xored.inputs.contains(&zmm(17)));
}

#[test]
fn general_purpose_registers_map_to_their_full_register() {
    let check = |register, name: &str, offset, width| {
        let view = gpr(register).unwrap();
        assert_eq!(
            (
                X86.info(view.register).unwrap().name,
                view.offset,
                view.width
            ),
            (name, offset, width),
            "{register:?}"
        );
    };
    check(Register::RAX, "rax", 0, 64);
    check(Register::EAX, "rax", 0, 32);
    check(Register::AH, "rax", 8, 8);
    check(Register::BH, "rbx", 8, 8);
    check(Register::SPL, "rsp", 0, 8);
    check(Register::R8W, "r8", 0, 16);
    check(Register::R12D, "r12", 0, 32);
    check(Register::R15B, "r15", 0, 8);
    check(Register::RDI, "rdi", 0, 64);
    // Not general-purpose, or not modelled yet (APX).
    assert!(gpr(Register::XMM0).is_none());
    assert!(gpr(Register::R16).is_none());
}

/// The traps and stores of `statements`, in order (an `if`'s then its
/// `else`'s).
fn effects(statements: &[Stmt], out: &mut Vec<String>) {
    for statement in statements {
        match statement {
            Stmt::Trap(trap) => out.push(format!("{trap:?}")),
            Stmt::Store { .. } => out.push("store".into()),
            Stmt::If {
                then, otherwise, ..
            } => {
                effects(then, out);
                effects(otherwise, out);
            }
            Stmt::Loop(body) | Stmt::Atomic(body) => effects(body, out),
            Stmt::Read { .. }
            | Stmt::Write { .. }
            | Stmt::Load { .. }
            | Stmt::Break
            | Stmt::Jump { .. }
            | Stmt::Call { .. }
            | Stmt::Return { .. }
            | Stmt::SystemCall
            | Stmt::Intrinsic { .. } => {}
        }
    }
}

/// A near call checks its target (#GP) and then the stack (#SS) before it
/// pushes the return address, as the SDM's CALL does: L0's interpreter
/// undoes a trapping instruction's effects, but L1, built from L0's
/// statements, does not, so a push first would write memory for a call
/// that traps.
#[test]
fn a_call_checks_its_target_before_the_push() {
    // call rax; call [rip + 0x10] (whose load checks its address first)
    for (bytes, load) in [
        (&[0xff, 0xd0][..], false),
        (&[0xff, 0x15, 0x10, 0, 0, 0], true),
    ] {
        let instruction = decode(bytes, Mode::Bits64).unwrap();
        let semantics = lift(&instruction, Mode::Bits64, 0x40_1000).unwrap();
        let mut found = Vec::new();
        effects(&semantics.body, &mut found);
        let call = ["Protection", "Stack", "store"];
        let expected = if load {
            [&["Protection"][..], &call].concat()
        } else {
            call.to_vec()
        };
        assert_eq!(found, expected, "{bytes:x?}");
    }
}
