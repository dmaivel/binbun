//! What the callers of each function read of it, over the whole program
//! ([`callers`]): computed once per binary (cached by
//! [`Database`](crate::Database)), so one function decompiled alone and
//! the whole program agree.
//!
//! A function's interface found from its body over-approximates: a result
//! register every exit writes is a return value even where it only holds
//! what a callee left (`void f(void) { g(); }`). Only callers can tell.
//! The rule: **a function's return value is dropped when no caller reads
//! it**: at no call to it does the caller's lowering use the result before
//! overwriting it, and every tail call to it (or call whose result only
//! reaches the caller's own return) is in a function whose own return
//! value is dropped, recursively. Functions with callers we cannot see
//! keep their body's interface: the entry point, exported functions,
//! functions whose address is taken (in code or data: calls through
//! pointers are unknown callers of every one of them), functions no call
//! or jump of the program reaches, and the callees of a function whose
//! body cannot be lowered.
//!
//! Soundness: a return value no caller reads is a value nothing observes;
//! dropping it removes no effect and no value any C statement uses (the
//! callers' calls had no result place for it, or its place was dead, as
//! their lowering found). Callers' interfaces only shrink when a callee's
//! result is dropped (its register after the call becomes undefined), so a
//! call found not to read a result never reads it after the drop.
//!
//! Likewise a parameter register is one where the body passes it on by
//! rule 1 or merely sits before a later one. Two rules drop such
//! registers from the interface, whatever lowering found.
//!
//! First, from the callees: **an argument register belongs to a
//! function's interface only if its body reads it, or passes it to a
//! callee at a parameter that belongs to that callee's interface** (System
//! V AMD64 psABI §3.2.1: registers other than `rbx`, `rbp`, `r12`–`r15`
//! "belong to the called function"; AAPCS64 §6.1.1 and §6.1.2: a
//! subroutine need not preserve the argument registers `x0`–`x7` and
//! `v0`–`v7`: so what a caller leaves in an argument register its callee
//! never reads is a dead store; the Microsoft x64 convention's volatile
//! registers, `rcx`, `rdx`, `r8`, `r9` and `xmm0`–`xmm5`, the same). Its
//! body reads a register when it uses its entry value otherwise than as a
//! call's register argument ([`Found::reads`]), or passes it to a callee
//! whose reads no interface of the program decides ([`Found::opaque`]: a
//! declared prototype's parameters, a call through a pointer, to code no
//! function of the program starts at; such a callee is assumed to read
//! every argument it is given), or to a function with no interface (its
//! callers take the convention's integer argument registers), or to a
//! variadic one past its named parameters. The read ones are the least
//! fixed point over the call graph from those ([`unread_parameters`]), so
//! recursion keeps nothing on its own: a register a cycle of functions
//! only passes around is read by none. A register before a read one in
//! the convention's order stays a parameter (C passes arguments by
//! position), but passing on what it holds makes no caller read anything;
//! with stack parameters, every integer argument register stays. The rule
//! reads only the function's body and its callees, so it holds for every
//! function, whoever calls it: the entry point, exported functions and
//! functions whose address is taken too. An indirect caller may assume
//! no more than the ABI promises, and the ABI makes a callee's behaviour
//! depend only on what it reads; the C declaration every reference to the
//! address takes is the one interface (below), so a call through the
//! pointer passes exactly what the definition takes.
//! A function whose prototype is its own, its definition's (debug
//! information's, the user's: [`Found::own_reads`]), reads only what its
//! body reads or computes a call's argument from: a register its
//! declaration places no parameter in, which it only passes on in place
//! to a callee (whose prototype is unknown: `PyModule_GetState(m)` passes
//! on `x1`..`x7` as it found them), is no parameter, whatever the callee
//! reads. The declaration says the function takes nothing there, so what
//! it passes on there is garbage to that callee.
//! A declaration that is not the function's own (the type library's for
//! the name a definition is exported under, a mangling's) states the
//! registers its parameters are in, which stay parameters whatever the
//! body does; any other register is the function's parameter as for one
//! with no declaration, by what its body reads or passes on: such a
//! declaration may say less than the definition takes (`main`'s of
//! `envp`).
//!
//! The reading view makes five assumptions here (`assume`, stated in its
//! C with its others: [`View::ASSUMPTIONS`](super::View::ASSUMPTIONS)).
//! The first: **an argument register a function only passes on as it
//! found it, where nothing says the callee reads it, holds no argument**
//! ([`Found::forwarded`]: past a variadic prototype's named parameters
//! with no format string counting them, or to an import with no
//! declaration, or at a call through a pointer after the last argument
//! that call sets: a call setting an argument was given its arguments by
//! the function's code, which left the registers after them alone; not a
//! call setting none, as a dispatch hands its own arguments to a pointer
//! so; and, as [`unread_parameters`] finds it passed to a
//! function of the program: to one with no interface, as an import's
//! stub, or past the named parameters of a variadic definition
//! recognised from its code ([`Interface::variadic`]) that has no format
//! of its own), unless a call of the program sets it: passes a computed
//! value there, or the entry value of a register of its caller that is
//! read or is itself set (a value handed down a chain of functions that
//! each only pass it on is an argument of each).
//! `open(path, O_RDONLY)` leaves `rdx` as it was, and so does a
//! wrapper passing its third argument on: the exact view keeps the
//! register a parameter of both (sound: the wrapper's is one), the
//! reading view of neither unless a caller is seen to set it. So the
//! assumption can hide an argument a function with callers unseen passes
//! on; it adds nothing.
//! A recognised definition says no more than a prototype's `...`: its
//! `va_start` saves every unnamed argument register whatever a call
//! passes (System V AMD64 psABI §3.5.7, the register save area), and
//! which of them a `va_arg` then reads its named arguments decide when
//! it runs. The exact view keeps the register (the saved copy may be
//! read); the reading view assumes as for the prototype.
//!
//! The second: **an argument register a function only passes on as it
//! found it, to whatever callees no declaration states the parameters
//! of, holds no argument where some call of the program leaves it
//! undefined** ([`Found::passed_on`], [`Passed::undefined`]: an earlier
//! call's leftover, or the entry value of such a register of the caller
//! that is itself left so). C gives a function one prototype, so a call
//! that passes nothing there shows the function takes nothing there; a
//! value another call happens to leave in the register is then a stale
//! one, not an argument (`png_free(png_ptr, ptr)` after `rdx` was
//! loaded for something else). This holds for a function with callers
//! unseen too, and through a call by pointer (`error_fn(png_ptr, msg)`
//! with `rdx` to `r9` untouched): one call seen suffices. A register the
//! function's own code reads, computes an argument from, passes in
//! another register or at a declared parameter stays, whatever its
//! callers leave there. So this one hides an argument only of a
//! function called with fewer arguments than it takes, which only
//! passes the missing one on.
//!
//! The third: **a function with a declaration that is not its own (not
//! a variadic one) takes no argument in a register that declaration
//! places no parameter in and its code only passes on as it found it**
//! ([`Found::declared_reads`]). Every call of the program to it is
//! lowered by that declaration and passes nothing there, as a caller
//! in another module compiled against it does. So no call sets such a
//! register, whatever it holds at the call (a stale value at a call of
//! `__stack_chk_fail()` is no argument of it), and what the function
//! passes on of it is left undefined for its callee (the second
//! assumption's evidence; what a function passes on of a register its
//! own prototype places nothing in is so too). The exact view keeps the
//! register, as stated above. The assumption hides an argument only of
//! a definition that takes more than its declaration states and does
//! nothing with it but pass it on in place; a register its code reads,
//! computes from or passes in another register stays in both views.
//!
//! The fourth: **no function takes an argument in the x87 unit**
//! ([`Convention::x87`]: its registers, tag word, TOP, control and status
//! words and condition codes): no convention passes one there (System V
//! x86-64 passes the X87 classes in memory; Microsoft x64 leaves the
//! stack unused), and the reading view takes the stack as empty at entry
//! ([`AssumeEmptyX87`](binbun_ssa::float::AssumeEmptyX87)), so what a
//! function reads of the unit there (a stored environment, an exception
//! raised with `fwait`) is no caller's argument.
//!
//! The fifth: **a register the convention has a function keep, which it
//! saves and restores, holds no argument** ([`Found::kept`]: saved in a
//! slot that holds nothing else, its entry value back wherever it
//! returns). Every convention binbun has (System V x86-64's `rbx`, `rbp`,
//! `r12`–`r15`; Microsoft x64's and its `rdi`, `rsi`, `xmm6`–`xmm15`;
//! AAPCS64's `x19`–`x29`, `d8`–`d15`) has callers expect those preserved,
//! never read; what else the function reads of the entry value is its
//! own variable on a path that has not assigned it (GCC leaves one
//! uninitialised where its use is guarded by the same condition as its
//! assignment). Unread, the register leaves its interface, and so its
//! callers', which only passed theirs on. Code that does take a value in
//! such a register does not save it (a retpoline thunk, `setjmp`), or is
//! Swift's (`self` in `r13`/`x20`), whose mangled functions are left out;
//! the exact view keeps the read.
//!
//! Soundness: every call of the program to a function of the program with
//! no prototype is seen (its passes, [`Found::passes`]), and every other
//! use of a register's entry value makes it read. A register dropped by
//! this rule is one whose entry value no run of the function hands to
//! anything that reads it: its body never uses it, and each callee it
//! passes it to drops that parameter in turn (or keeps it only for the
//! position of a later one, and never reads it). So taking its entry value
//! as undefined changes no value any statement or callee uses.
//!
//! Second, from the callers: **a parameter register is dropped when every
//! caller leaves garbage in it** (at every
//! call to the function the register holds, on every path, an undefined
//! value or the caller's own entry value of a register that is itself
//! dropped), **and the body reads it only to pass it to calls**; to a
//! least fixed point of the kept ones, in the stream's order. The same
//! functions keep their body's interface as for return values, and a
//! parameter before a kept one in the convention's order stays (C passes
//! arguments by position). The function's lowering then takes the
//! register's entry value as undefined, as for the first rule
//! ([`Context::dropped`](binbun_decompile::lower::Context::dropped)): it
//! is no parameter, what it passed on is undefined, and rule 1 at its
//! calls through pointers stops before it where nothing later is passed.
//! This rule runs on the interfaces the first leaves.
//!
//! Soundness: every caller the program has is seen (the visible functions
//! keep everything), and each one passes nothing defined there, so in no
//! run of the program does the function get a value in that register;
//! the body only hands that undefined value on, never computes, stores,
//! branches on or returns it, so taking it as undefined changes no
//! value any statement uses. The differential checks each function from
//! the states its callers start it from: the dropped registers undefined
//! ([`Mapping::dropped`](binbun_decompile::mapping::Mapping::dropped)),
//! and a call's argument agrees only where L2 defines every bit L1
//! defines: L2 passing an undefined value where L1 passes a defined one
//! (one not from a dropped register) is a difference, no longer hidden by
//! comparing only the bits both define.
//!
//! Then **one interface per function**, which its definition, every call
//! to it and every reference to its address take ([`Callers::interfaces`]):
//! each function's interface found again by lowering with the drops
//! above, callees first, and again for every function whose lowering read
//! an interface that changed after it was found, until none changes
//! ([`settle`]; a cycle of calls starts from its members' interfaces
//! less the drops, not the convention; bounded by [`ROUNDS`]).
//! Lowering a function with the same interfaces finds the same interface,
//! so the definition is what its callers declare and pass.
//!
//! Last, the solver's top-down specialisation: each function's sweep solve
//! (callees first, with its callees' schemes) records what each of its
//! calls to a function of the program passes at each parameter
//! ([`Found::arguments`]: the class its argument rounds to alone, a
//! constant zero, another integer constant). The rule: **a parameter of a
//! function whose callers we all see, other than one its body only passes
//! on in the same register ([`Found::padding`]: callers leave anything
//! there), takes the class every call to it passes there** (zero
//! agreeing with any class, other integer constants with any integer; a
//! caller whose solve gave nothing blocks it), as a lower bound in the
//! function's own solve at Related strength, below its body's flags and
//! operations ([`Callers::specialised`]). Once: the classes are the
//! bottom-up sweep's, not solved again with the specialisation; return
//! values are not specialised. Types change no value, so soundness is
//! not at stake.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use binbun_decompile::data::Data;
use binbun_decompile::lower::{Convention, Found, Interface, Passed, Read};
use binbun_decompile::mapping::Source;
use binbun_decompile::prototype::Prototypes;
use binbun_decompile::typing::{Argument, Class, Schemes};
use binbun_loader::{Image, SymbolSource};
use binbun_semantics::ir::RegisterId;

use super::stream::{interface, lifted, summarise};
use super::{Interfaces, Prepared};
use crate::analysis::names;
use crate::cfg::{Destination, Exit, FunctionId, Program};
use crate::classes::classes;
use crate::progress::Progress;
use crate::references::{Kind, References};
use crate::summary::{Summaries, callees_first};
use crate::target::{convention, setup};
use crate::user::data_model;

/// What callers read of the functions of a program ([`callers`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Callers {
    /// The entries of the functions whose return value no caller reads.
    pub unread: BTreeSet<u64>,
    /// For each function some of whose parameter registers are dropped
    /// from its interface (no callee reads what its body passes on of
    /// them, or every caller leaves garbage in them), those registers (in
    /// order), by entry.
    pub dropped: BTreeMap<u64, Vec<RegisterId>>,
    /// Every function's interface, with the drops above, by entry: the
    /// one its definition, every call to it and every reference to its
    /// address take. A function with none (it does not lower, or leaves
    /// for code it does not know) is called by the convention.
    pub interfaces: BTreeMap<u64, Interface>,
    /// Each function's scheme, computed callees first with the
    /// interfaces its body gives (before the drops above: a scheme's
    /// parameters are by where they are, so a dropped one is just not
    /// passed).
    pub schemes: Arc<Schemes>,
    /// For each function whose callers all agree on the class of some of
    /// its parameters (the top-down specialisation), those parameters
    /// with the class, by entry.
    pub specialised: BTreeMap<u64, Vec<(Source, Class)>>,
    /// For each function whose return value is the vector result
    /// register's though every exit leaves a value in the integer one
    /// too, that register, by entry ([`preferred`]).
    pub preferred: BTreeMap<u64, RegisterId>,
    /// Whether these are the reading view's: lowering with them takes its
    /// `futex` assumption ([`Context::assume_futex`](binbun_decompile::lower::Context::assume_futex))
    /// and its frame's ([`Context::assume_forward_reach`](binbun_decompile::lower::Context::assume_forward_reach)).
    pub assume: bool,
}

impl Callers {
    /// Whether no caller reads the return value of the function at
    /// `entry`.
    pub fn result_unread(&self, entry: u64) -> bool {
        self.unread.contains(&entry)
    }

    /// The parameter registers dropped from the interface of the function
    /// at `entry`.
    pub fn dropped(&self, entry: u64) -> &[RegisterId] {
        self.dropped.get(&entry).map_or(&[], Vec::as_slice)
    }

    /// The parameters of the function at `entry` every caller passes one
    /// class at, with the class.
    pub fn specialised(&self, entry: u64) -> &[(Source, Class)] {
        self.specialised.get(&entry).map_or(&[], Vec::as_slice)
    }

    /// The vector result register the function at `entry` returns in,
    /// where its callers showed it does ([`Self::preferred`]).
    pub fn preferred(&self, entry: u64) -> Option<RegisterId> {
        self.preferred.get(&entry).copied()
    }
}

/// What the callers of every function of `program` (recovered from
/// `image`, with `summaries`, its `references`, declared `prototypes` and
/// the image's `data`) read of it, the passes `disabled` as decompilation
/// runs them: every function's interface is found from its body, callees
/// first as [`stream`](super::stream) finds them, with how it reads each
/// callee's return value ([`Read`]) and what it passes in each register
/// ([`Passed`]) and its scheme (with its callees' schemes known so far:
/// in a cycle of calls, the first reached has none of the others'); then
/// the return values no caller reads, the parameters no callee reads or
/// every caller leaves garbage in, the classes every caller passes, and
/// every function's one interface, as the [module](self) states. The
/// sweeps themselves are one thread's; the functions' L1 (which reads
/// only the finished `summaries`) is lifted ahead of them on `threads`
/// threads, so the result is the same whatever the threads. With
/// `assume`, under the reading view's assumption about registers only
/// passed on (the [module](self) states it).
#[expect(
    clippy::too_many_arguments,
    reason = "what the sweep reads of the program, and how to share the lifting"
)]
pub fn callers(
    image: &Image<'_>,
    program: &Program,
    summaries: &Summaries,
    references: &References,
    prototypes: &dyn Prototypes,
    data: &dyn Data,
    disabled: &[String],
    threads: usize,
    assume: bool,
) -> Callers {
    callers_for(
        image,
        program,
        summaries,
        references,
        prototypes,
        data,
        disabled,
        threads,
        &[assume],
        &Progress::default(),
    )
    .pop()
    .unwrap_or_default()
}

/// [`callers`] under each of `assume` (the reading view's assumption or
/// not), in its order, found together: the sweeps, which no assumption
/// changes, run once, and [`settle`] lifts a function once a round for
/// every view that finds it again. Each is the same as found alone; both
/// views together cost little more than one. Each sweep and round is a
/// pass of `progress`, each function lifted a step.
#[expect(
    clippy::too_many_arguments,
    reason = "what the sweep reads of the program, and how to share the lifting"
)]
pub fn callers_for(
    image: &Image<'_>,
    program: &Program,
    summaries: &Summaries,
    references: &References,
    prototypes: &dyn Prototypes,
    data: &dyn Data,
    disabled: &[String],
    threads: usize,
    assume: &[bool],
    progress: &Progress,
) -> Vec<Callers> {
    let names = names(image);
    let order = targets_first(program);
    let mut kept = Kept::new();
    // The sweep, with the functions `preferred` returning in the vector
    // result register: what is known after it, the functions whose
    // body's interface stays (callers we do not see, or whose calls
    // lowering does not see), and what each function's body gave.
    let sweep = |preferred: &BTreeMap<u64, RegisterId>, kept: &mut Kept| {
        let callers = Callers {
            preferred: preferred.clone(),
            ..Callers::default()
        };
        let mut known = Interfaces::of(program, &callers);
        Arc::make_mut(&mut known.callers.schemes).set_classes(classes(image));
        let mut whole = visible(image, program, references);
        let mut found: BTreeMap<u64, Found> = BTreeMap::new();
        progress.start(order.len());
        each_lifted(
            image,
            program,
            &order,
            summaries,
            disabled,
            threads,
            kept,
            |id, prepared| {
                progress.step();
                let Some(entry) = program.functions.get(id).map(|f| f.entry) else {
                    return;
                };
                Arc::make_mut(&mut known.callers.schemes).visit(entry);
                let function = prepared
                    .as_ref()
                    .ok()
                    .and_then(|prepared| summarise(image, prepared, prototypes, data, &known).ok());
                let Some((mut function, summary)) = function else {
                    whole.extend(targets(program, id));
                    return;
                };
                let schemes = Arc::make_mut(&mut known.callers.schemes);
                if let Some(summary) = summary {
                    schemes.insert(entry, summary);
                }
                let structs = core::mem::take(&mut function.structs);
                schemes.add_structs(entry, names.get(&entry).map(String::as_str), structs);
                for target in targets(program, id) {
                    if !function.results.contains_key(&target) {
                        whole.insert(target);
                    }
                }
                if let Some(interface) = &function.interface {
                    known.interfaces.insert(entry, interface.clone());
                }
                found.insert(entry, function);
            },
        );
        (known, whole, found)
    };
    // A function its callers show to return in the vector register
    // ([`preferred`]) is one from the start of a second sweep: its scheme
    // and its callers' interfaces and schemes are then found with the
    // return value it has. Once: what that sweep shows of others is left.
    let (mut known, mut whole, mut found) = sweep(&BTreeMap::new(), &mut kept);
    let preferred = preferred(program, &found);
    if !preferred.is_empty() {
        (known, whole, found) = sweep(&preferred, &mut kept);
    }
    unkept_in_swift(&mut found, &names);
    let convention = setup(image, image.entry.unwrap_or_default())
        .map(|setup| convention(image, setup.declarations));
    let assumed = reading_found(&found);
    let specialised = specialised(&whole, &found);
    let unread = unread(program, whole.clone(), &found);
    let mut views: Vec<Interfaces> = assume
        .iter()
        .map(|&assume| {
            let view = match &assumed {
                Some(assumed) if assume => assumed,
                Some(_) | None => &found,
            };
            let dropped = convention
                .as_ref()
                .map(|convention| drops(convention, &whole, view, assume))
                .unwrap_or_default();
            Interfaces {
                interfaces: less(view, &dropped, &unread),
                functions: known.functions.clone(),
                callers: Callers {
                    unread: unread.clone(),
                    dropped,
                    interfaces: BTreeMap::new(),
                    schemes: Arc::clone(&known.callers.schemes),
                    specialised: specialised.clone(),
                    preferred: preferred.clone(),
                    assume,
                },
            }
        })
        .collect();
    settle(
        image, program, &order, summaries, prototypes, data, disabled, threads, &mut views,
        progress, &mut kept,
    );
    let pointer = u16::from(data_model(image).pointer) * 8;
    views
        .into_iter()
        .map(|known| typed(known, prototypes, data, pointer))
        .collect()
}

/// The functions `found` as the reading view lowers them, where that
/// differs: one making a `futex` call its code does not settle, or whose
/// frame is all memory only because a stack address may step back from
/// where it points, as under the view's assumptions ([`Found::assumed`]).
fn reading_found(found: &BTreeMap<u64, Found>) -> Option<BTreeMap<u64, Found>> {
    found.values().any(|f| f.assumed.is_some()).then(|| {
        found
            .iter()
            .map(|(&entry, f)| (entry, f.assumed.as_deref().unwrap_or(f).clone()))
            .collect()
    })
}

/// The parameter registers dropped from the interfaces of the functions
/// `found` (of `whole`, those whose callers are not all seen), under
/// `convention`, with the reading view's assumptions if `assume`: those no
/// run reads, and those every caller leaves garbage in.
fn drops(
    convention: &Convention,
    whole: &BTreeSet<u64>,
    found: &BTreeMap<u64, Found>,
    assume: bool,
) -> BTreeMap<u64, Vec<RegisterId>> {
    let unread = unread_parameters(convention, found, assume);
    let garbage = garbage(convention, whole, found, &unread);
    dropped(found, &unread, &garbage)
}

/// Each function's interface its body gave (of those `found`, by entry)
/// less the registers `dropped` from it, and the return value if no
/// caller reads it (`unread`).
fn less(
    found: &BTreeMap<u64, Found>,
    dropped: &BTreeMap<u64, Vec<RegisterId>>,
    unread: &BTreeSet<u64>,
) -> BTreeMap<u64, Interface> {
    found
        .iter()
        .filter_map(|(&entry, function)| {
            let mut interface = function.interface.clone()?;
            let dropped = dropped.get(&entry).map_or(&[][..], Vec::as_slice);
            interface.parameters.retain(|source| match source {
                Source::Register(piece) => !dropped.contains(&piece.register),
                Source::Stack { .. } => true,
            });
            if unread.contains(&entry) {
                interface.returns.clear();
            }
            Some((entry, interface))
        })
        .collect()
}

/// What callers read with the interfaces `known` settled: one type per
/// global, joined from every function's evidence and the final
/// interfaces of the functions stored in them (finding interfaces solves
/// no types, so it reads neither; pointers `pointer` bits), then the
/// user's versions of structs (`prototypes`): the table's structs stay
/// the ones the sweep found, as the join left them.
fn typed(
    mut known: Interfaces,
    prototypes: &dyn Prototypes,
    data: &dyn Data,
    pointer: u16,
) -> Callers {
    let schemes = Arc::make_mut(&mut known.callers.schemes);
    schemes.settle_globals(data, prototypes, &known.interfaces, pointer);
    if let Some((types, stated)) = prototypes.user_structs() {
        schemes.state_structs(&types, &stated);
    }
    Callers {
        interfaces: known.interfaces,
        ..known.callers
    }
}

/// How many times [`settle`] finds interfaces again at most. Interfaces
/// mostly shrink, and a change reaches the functions that read it in the
/// next round; on the corpus the most rounds any binary takes is 14
/// (python313.dll: long cycles of calls, a few functions a round at the
/// end), most take 3 or 4. A register a callee gains (a vector register a
/// cycle's convention did not pass) can grow its callers, so termination
/// is bounded rather than proved.
const ROUNDS: usize = 64;

/// Every function's interface ([`Callers::interfaces`]) with the drops
/// each of `views` has, into it: found by lowering each function of
/// `order` (callees first) with the interfaces known then, which start as
/// each function's from the sweep less its drops; then again each whose
/// lowering read an interface (of a function it calls or jumps to) that
/// changed after, until none did or [`ROUNDS`] rounds, each a pass of
/// `progress`. Each round lifts
/// only the functions some view finds again (`program`, `image`,
/// `summaries`, the passes `disabled`, on `threads` threads), once for
/// all of them; a view lowers only its own, in the order it would alone.
/// A function that does not lower, or leaves for code it does not know,
/// has none.
#[expect(
    clippy::too_many_arguments,
    reason = "what the sweep reads of the program, and how to share the lifting"
)]
fn settle(
    image: &Image<'_>,
    program: &Program,
    order: &[FunctionId],
    summaries: &Summaries,
    prototypes: &dyn Prototypes,
    data: &dyn Data,
    disabled: &[String],
    threads: usize,
    views: &mut [Interfaces],
    progress: &Progress,
    kept: &mut Kept,
) {
    let mut settling: Vec<Settling> = views
        .iter()
        .map(|_| Settling {
            work: order.iter().copied().collect(),
            ..Settling::default()
        })
        .collect();
    for _ in 0..ROUNDS {
        let work: Vec<FunctionId> = order
            .iter()
            .copied()
            .filter(|id| settling.iter().any(|view| view.work.contains(id)))
            .collect();
        if work.is_empty() {
            break;
        }
        progress.start(work.len());
        each_lifted(
            image,
            program,
            &work,
            summaries,
            disabled,
            threads,
            kept,
            |id, prepared| {
                progress.step();
                let Some(entry) = program.functions.get(id).map(|f| f.entry) else {
                    return;
                };
                let prepared = prepared.as_ref().ok();
                for (known, view) in views.iter_mut().zip(&mut settling) {
                    if !view.work.contains(&id) {
                        continue;
                    }
                    let found = prepared.and_then(|prepared| {
                        interface(image, prepared, prototypes, data, known).ok()
                    });
                    let before = view.clock;
                    let (interface, callees) = found.map_or((None, BTreeSet::new()), |found| {
                        (found.interface, found.callees)
                    });
                    if known.interfaces.get(&entry) != interface.as_ref() {
                        view.clock += 1;
                        view.changed.insert(entry, view.clock);
                        match interface {
                            Some(interface) => known.interfaces.insert(entry, interface),
                            None => known.interfaces.remove(&entry),
                        };
                    }
                    view.read.insert(id, (before, callees));
                }
            },
        );
        for view in &mut settling {
            view.work = order
                .iter()
                .copied()
                .filter(|id| {
                    view.read.get(id).is_some_and(|(at, callees)| {
                        callees
                            .iter()
                            .any(|callee| view.changed.get(callee).is_some_and(|&when| when > *at))
                    })
                })
                .collect();
        }
    }
}

/// Each function's L1 ([`decompile_l1`](super::decompile_l1)), kept from
/// one pass to the next: it reads only the summaries, never what a pass
/// finds, so a pass would lift it again the same.
type Kept = BTreeMap<FunctionId, Result<Prepared, String>>;

/// [`lifted`] for the passes of [`callers_for`]: each of `order` handed
/// to `visit` in that order, those `kept` from an earlier pass as kept,
/// the others lifted (on `threads` threads) and kept.
#[expect(
    clippy::too_many_arguments,
    reason = "lifted's arguments and what is kept"
)]
fn each_lifted(
    image: &Image<'_>,
    program: &Program,
    order: &[FunctionId],
    summaries: &Summaries,
    disabled: &[String],
    threads: usize,
    kept: &mut Kept,
    mut visit: impl FnMut(FunctionId, &Result<Prepared, String>),
) {
    let missing: Vec<FunctionId> = order
        .iter()
        .copied()
        .filter(|id| !kept.contains_key(id))
        .collect();
    // The next of `order` to visit: those kept before a function lifted
    // are visited first.
    let mut next = 0;
    lifted(
        image,
        program,
        &missing,
        summaries,
        disabled,
        threads,
        |id, prepared| {
            while let Some(&before) = order.get(next)
                && before != id
            {
                if let Some(prepared) = kept.get(&before) {
                    visit(before, prepared);
                }
                next += 1;
            }
            next += 1;
            visit(id, &prepared);
            kept.insert(id, prepared);
        },
    );
    for id in order.iter().skip(next) {
        if let Some(prepared) = kept.get(id) {
            visit(*id, prepared);
        }
    }
}

/// One view's progress through [`settle`].
#[derive(Default)]
struct Settling {
    /// The functions it finds again this round.
    work: BTreeSet<FunctionId>,
    /// When each function's interface last changed, by entry, on a clock
    /// counting the changes.
    changed: BTreeMap<u64, usize>,
    /// For each function found, the clock before it was, and the entries
    /// whose interfaces its lowering read.
    read: BTreeMap<FunctionId, (usize, BTreeSet<u64>)>,
    /// The clock.
    clock: usize,
}

/// The functions of those `found` (each function's [`Found`], by entry)
/// that return in the vector result register though their bodies say the
/// integer one, with that register: every exit writes both
/// ([`Found::alternative`]: `__scalbnf` works on the exponent in `eax`
/// down to its last instruction), some caller reads the vector register
/// after calling it ([`Found::strays`]: a register a call may change is
/// read only where the callee returns in it), and no caller is seen to
/// read the integer one, itself or through callers that return it on
/// ([`unread`] of the callers seen alone: a wrapper that jumps to it
/// returns whichever it returns). The body alone cannot tell such a
/// function from one that returns the integer and leaves a float it
/// compared; the callers can. [`settle`] then finds its interface, and
/// its callers', again.
fn preferred(program: &Program, found: &BTreeMap<u64, Found>) -> BTreeMap<u64, RegisterId> {
    let unseen = unread(program, BTreeSet::new(), found);
    found
        .iter()
        .filter_map(|(&entry, function)| {
            let register = function.alternative?.register;
            let read = found.values().any(|caller| caller.strays.contains(&entry));
            (read && unseen.contains(&entry)).then_some((entry, register))
        })
        .collect()
}

/// The top-down specialisation of the functions `found` (each function's
/// [`Found`], by entry): for each one not `whole`, the parameters other
/// than padding ([`Found::padding`]) every call to it passes one class at
/// ([`Found::arguments`], joined by
/// [`Argument::join`]), with the class. A caller whose calls to it give
/// no arguments (its solve refused, or a call typed otherwise than by
/// the callee's interface) blocks every parameter.
fn specialised(
    whole: &BTreeSet<u64>,
    found: &BTreeMap<u64, Found>,
) -> BTreeMap<u64, Vec<(Source, Class)>> {
    let mut joined: BTreeMap<u64, Option<Vec<(Source, Argument)>>> = BTreeMap::new();
    for function in found.values() {
        for &callee in function.passes.keys() {
            if whole.contains(&callee) {
                continue;
            }
            let passed = function.arguments.get(&callee);
            let slot = joined.entry(callee).or_insert_with(|| passed.cloned());
            let (Some(known), Some(passed)) = (slot.as_mut(), passed) else {
                *slot = None;
                continue;
            };
            for (source, argument) in known.iter_mut() {
                *argument = passed
                    .iter()
                    .find(|(at, _)| at == source)
                    .map_or(Argument::Unknown, |&(_, other)| argument.join(other));
            }
        }
    }
    joined
        .into_iter()
        .filter_map(|(callee, arguments)| {
            // A padding parameter takes what callers leave there.
            let padding = found.get(&callee)?.padding();
            let classes: Vec<(Source, Class)> = arguments?
                .into_iter()
                .filter(|(source, _)| match source {
                    Source::Register(piece) => !padding.contains(&piece.register),
                    Source::Stack { .. } => true,
                })
                .filter_map(|(source, argument)| Some((source, argument.class()?)))
                .collect();
            (!classes.is_empty()).then_some((callee, classes))
        })
        .collect()
}

/// The entries of the functions of `program` whose return value no caller
/// reads: of those `found` (each function's [`Found`], by entry), all but
/// the `whole` ones, those read ([`Read::Yes`]) and those whose callers
/// return their result where theirs is read ([`Read::Returned`]).
fn unread(
    program: &Program,
    mut kept: BTreeSet<u64>,
    found: &BTreeMap<u64, Found>,
) -> BTreeSet<u64> {
    // For each caller, the callees whose result it returns.
    let mut passes: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for (&caller, function) in found {
        for (&callee, &read) in &function.results {
            match read {
                Read::Yes => {
                    kept.insert(callee);
                }
                Read::Returned => passes.entry(caller).or_default().push(callee),
                Read::No => {}
            }
        }
    }
    let mut work: Vec<u64> = kept.iter().copied().collect();
    while let Some(caller) = work.pop() {
        for &callee in passes.get(&caller).map_or(&[][..], Vec::as_slice) {
            if kept.insert(callee) {
                work.push(callee);
            }
        }
    }
    program
        .functions
        .values()
        .map(|function| function.entry)
        .filter(|entry| !kept.contains(entry))
        .collect()
}

/// A function's parameter: its entry and register.
type Parameter = (u64, RegisterId);

/// The register parameters of `interface`, in order.
fn registers(interface: &Interface) -> Vec<RegisterId> {
    interface
        .parameters
        .iter()
        .filter_map(|source| match source {
            Source::Register(piece) => Some(piece.register),
            Source::Stack { .. } => None,
        })
        .collect()
}

/// Whether `interface` has stack parameters: then every integer argument
/// register is a parameter. Stack parameters are printed as scalars, and
/// C passes a scalar on the stack only after the integer argument
/// registers are taken, so a prototype with one names them all. (A struct
/// over 16 bytes or a `long double` goes on the stack without taking a
/// register; until such a parameter is placed, the registers before it
/// stay.)
fn stack(interface: &Interface) -> bool {
    interface
        .parameters
        .iter()
        .any(|source| matches!(source, Source::Stack { .. }))
}

/// The registers before `register` in `convention`'s order: its earlier
/// argument registers of the same kind, or where arguments take
/// registers by position, of earlier positions.
fn before(convention: &Convention, register: RegisterId) -> Vec<RegisterId> {
    let lists = [&convention.arguments, &convention.float_arguments];
    let mut earlier = Vec::new();
    for list in lists {
        let Some(position) = list.iter().position(|&r| r == register) else {
            continue;
        };
        if convention.positional {
            earlier.extend(lists.iter().flat_map(|list| list.iter().take(position)));
        } else {
            earlier.extend(list.iter().take(position));
        }
    }
    earlier
}

/// How a callee takes what a call passes in one register.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Takes {
    /// It may read it: it has no interface (its callers pass the
    /// convention's integer argument registers), it is a variadic one's
    /// argument past its named parameters, or a register other than an
    /// integer argument one its interface lacks ([`takes`]).
    Always,
    /// Where its parameter in that register is read.
    Parameter,
    /// Never: no call passes it.
    Never,
}

/// How a callee of `interface` (`None`: none) under `convention` takes
/// what a call passes in `register`. The interface is the one the sweep
/// found, before the drops; lowering again with fewer parameters
/// elsewhere never adds an integer argument register to it (a callee
/// without an interface took them all), but may a vector or other one a
/// cycle's convention did not pass, which is then taken as read.
fn takes(convention: &Convention, interface: Option<&Interface>, register: RegisterId) -> Takes {
    let integer = convention.arguments.contains(&register);
    let Some(interface) = interface else {
        return if integer { Takes::Always } else { Takes::Never };
    };
    if registers(interface).contains(&register) {
        Takes::Parameter
    } else if integer && !interface.variadic {
        Takes::Never
    } else {
        Takes::Always
    }
}

/// The register parameters of the functions `found` (each function's
/// [`Found`], by entry, its interface as the sweep found it) no run
/// reads, under `convention`, by entry (in order): those neither read
/// nor before a read one in the convention's order (nor, with stack
/// parameters, an integer argument register). A function's register is
/// read where its body reads it ([`Found::reads`]), passes it to a callee
/// that reads what it is given ([`Found::opaque`], [`Takes::Always`]), or
/// passes it to a function of the program at a parameter that is read
/// ([`Found::undeclared`], [`Found::passes`]): the least fixed point, so
/// what a cycle only passes around is read by none.
/// A function whose prototype is its own (debug information's, the
/// user's: [`Found::own_reads`]) reads only what its body reads or
/// computes from: what it passes on in place to a callee that may read it
/// the declaration says it takes nothing in.
/// With `assume`, a register a function only passes on is not read where
/// some call leaves it undefined ([`Found::passed_on`],
/// [`left_by_calls`]), and, if nothing says the callee reads it
/// ([`Found::forwarded`]; one with no interface, a variadic definition
/// past its named parameters), read only where a call sets it
/// ([`Reads::set_by_calls`]; to a fixed point with the rest); and a
/// function with a declaration that is not its own reads as one whose
/// prototype is ([`taken`]); and no register of the x87 unit is a
/// parameter ([`Convention::x87`]: no convention passes an argument
/// there).
fn unread_parameters(
    convention: &Convention,
    found: &BTreeMap<u64, Found>,
    assume: bool,
) -> BTreeMap<u64, Vec<RegisterId>> {
    let left = if assume {
        left_by_calls(found)
    } else {
        BTreeSet::new()
    };
    let mut reads = Reads::new(found, left, assume);
    // For each parameter, the registers of callers that pass their entry
    // value there.
    let mut passers: BTreeMap<Parameter, Vec<Parameter>> = BTreeMap::new();
    for (&entry, function) in found {
        if let Some(taken) = taken(function, assume) {
            for &register in taken {
                reads.read((entry, register));
            }
            // What it passes on its callees' reading makes it read no more.
            continue;
        }
        for &register in &function.reads {
            reads.read((entry, register));
        }
        for &register in &function.opaque {
            if !assume || !function.forwarded.contains(&register) {
                reads.mark((entry, register));
            }
        }
        for &callee in &function.undeclared {
            let interface = found.get(&callee).and_then(|f| f.interface.as_ref());
            for (&at, passed) in function.passes.get(&callee).into_iter().flatten() {
                let passing = passed.entries.iter().map(|&register| (entry, register));
                match takes(convention, interface, at) {
                    Takes::Always => {
                        // Assumed no argument unless a call sets it: its
                        // own register's entry value, as found, to code
                        // that states nothing of it (a stub jumping to
                        // an undeclared import; past the named
                        // parameters of a variadic definition with no
                        // format of its own).
                        let unstated = interface.is_none_or(|interface| {
                            interface.variadic && interface.format.is_none()
                        });
                        let found_so = assume
                            && unstated
                            && !passed.value
                            && passed.entries.iter().all(|&register| register == at);
                        for parameter in passing {
                            if found_so {
                                reads.unstated.insert(parameter);
                            } else {
                                reads.mark(parameter);
                            }
                        }
                    }
                    Takes::Parameter => passers.entry((callee, at)).or_default().extend(passing),
                    Takes::Never => {}
                }
            }
        }
    }
    loop {
        while let Some(parameter) = reads.work.pop() {
            for passer in passers.remove(&parameter).unwrap_or_default() {
                reads.mark(passer);
            }
        }
        if !assume {
            break;
        }
        reads.set_by_calls();
        if reads.work.is_empty() {
            break;
        }
    }
    let read = reads.read;
    let x87 = no_arguments(convention, assume);
    let mut unread = BTreeMap::new();
    for (&entry, function) in found {
        // A function that leaves for code it does not know has no
        // interface, but its prototype still says what it takes: of
        // the convention's argument registers, what it reads.
        let registers = match (&function.interface, taken(function, assume)) {
            (Some(interface), _) => registers(interface),
            (None, Some(_)) => convention
                .arguments
                .iter()
                .chain(&convention.float_arguments)
                .copied()
                .collect(),
            (None, None) => continue,
        };
        let mut kept: BTreeSet<RegisterId> = registers
            .iter()
            .copied()
            .filter(|&register| read.contains(&(entry, register)) && !x87.contains(&register))
            .collect();
        let earlier: Vec<RegisterId> = kept
            .iter()
            .flat_map(|&register| before(convention, register))
            .collect();
        kept.extend(earlier);
        if function.interface.as_ref().is_some_and(stack) {
            kept.extend(convention.arguments.iter().copied());
        }
        let dropped: Vec<RegisterId> = registers
            .into_iter()
            .filter(|register| !kept.contains(register))
            .collect();
        if !dropped.is_empty() {
            unread.insert(entry, dropped);
        }
    }
    unread
}

/// The registers that hold no argument under `assume`, the reading view's
/// x87 assumption: the x87 unit's ([`Convention::x87`]); none otherwise.
fn no_arguments(convention: &Convention, assume: bool) -> BTreeSet<RegisterId> {
    match &convention.x87 {
        Some(x87) if assume => x87.state().collect(),
        Some(_) | None => BTreeSet::new(),
    }
}

/// The registers `function`'s prototype says are all it takes, where
/// one says so: its own prototype's (debug information's, the user's:
/// [`Found::own_reads`]), or, with `assume`, those of a declaration that
/// is not its own (the type library's for the name it is exported under,
/// its mangling's: [`Found::declared_reads`]). Any other register it
/// only passes on: no parameter, whatever a callee reads or a caller
/// leaves there.
fn taken(function: &Found, assume: bool) -> Option<&BTreeSet<RegisterId>> {
    function.own_reads.as_ref().or(if assume {
        function.declared_reads.as_ref()
    } else {
        None
    })
}

/// The argument registers of the functions `found` that some call of the
/// program leaves undefined: at some call, on some path, the register
/// holds an undefined value ([`Passed::undefined`]: what an earlier call
/// left there), or the entry value of a register the caller only passes
/// on ([`Found::passed_on`]) that is itself left so (to a fixed point),
/// or of one the caller's prototype says it takes nothing in ([`taken`]).
/// C gives a function one prototype, so such a call shows the function
/// takes no argument there, whatever it passes the register on to.
fn left_by_calls(found: &BTreeMap<u64, Found>) -> BTreeSet<Parameter> {
    let mut left: BTreeSet<Parameter> = BTreeSet::new();
    loop {
        let mut grew = false;
        for (&caller, function) in found {
            let taken = taken(function, true);
            for (&callee, passes) in &function.passes {
                for (&at, passed) in passes {
                    let leaves = passed.undefined
                        || passed.entries.iter().any(|register| {
                            taken.is_some_and(|taken| !taken.contains(register))
                                || (function.passed_on.contains(register)
                                    && left.contains(&(caller, *register)))
                        });
                    grew |= leaves && left.insert((callee, at));
                }
            }
        }
        if !grew {
            return left;
        }
    }
}

/// The parameters read so far ([`unread_parameters`]).
struct Reads<'a> {
    /// Each function's [`Found`], by entry.
    found: &'a BTreeMap<u64, Found>,
    /// Those read.
    read: BTreeSet<Parameter>,
    /// Those read whose consequences are not drawn yet.
    work: Vec<Parameter>,
    /// Those some call of the program leaves undefined
    /// ([`left_by_calls`]): under the reading view's assumption only.
    left: BTreeSet<Parameter>,
    /// Those a call of the program sets ([`Self::set_by_calls`]).
    set: BTreeSet<Parameter>,
    /// Those their function only passes on as it found them to code that
    /// states nothing of them (a function with no interface, a variadic
    /// definition past its named parameters): under the reading view's
    /// assumption, read only where a call sets them.
    unstated: BTreeSet<Parameter>,
    /// The callee-saved registers their function keeps ([`Found::kept`]):
    /// under the reading view's assumption, never read.
    kept: BTreeSet<Parameter>,
}

impl<'a> Reads<'a> {
    /// None read yet of the functions `found`, whose calls leave `left`
    /// undefined; with `assume`, none of their kept registers ever.
    fn new(found: &'a BTreeMap<u64, Found>, left: BTreeSet<Parameter>, assume: bool) -> Self {
        let kept = if assume {
            found
                .iter()
                .flat_map(|(&entry, function)| {
                    function.kept.iter().map(move |&register| (entry, register))
                })
                .collect()
        } else {
            BTreeSet::new()
        };
        Self {
            found,
            read: BTreeSet::new(),
            work: Vec::new(),
            left,
            set: BTreeSet::new(),
            unstated: BTreeSet::new(),
            kept,
        }
    }

    /// `parameter` is read, whatever its callers pass: its function's
    /// body reads it, or its own prototype has it; never a register its
    /// function keeps, under the reading view's assumption.
    fn read(&mut self, parameter: Parameter) {
        if !self.kept.contains(&parameter) && self.read.insert(parameter) {
            self.work.push(parameter);
        }
    }

    /// Whether `parameter` holds no argument by what a call shows: its
    /// function only passes it on, and a call of the program leaves it
    /// undefined. A value another call leaves there is then taken for a
    /// stale one (what the register held for something else), not for
    /// an argument.
    fn left_undefined(&self, parameter: Parameter) -> bool {
        self.left.contains(&parameter)
            && self
                .found
                .get(&parameter.0)
                .is_some_and(|function| function.passed_on.contains(&parameter.1))
    }

    /// Whether `parameter` is a register its function's prototype says it
    /// takes nothing in ([`taken`], under the reading view's assumption):
    /// whatever a call leaves there is no argument.
    fn untaken(&self, parameter: Parameter) -> bool {
        self.found
            .get(&parameter.0)
            .and_then(|function| taken(function, true))
            .is_some_and(|taken| !taken.contains(&parameter.1))
    }

    /// What `parameter`'s function passes it on to reads it: it is read,
    /// unless a call shows it holds no argument
    /// ([`Self::left_undefined`]).
    fn mark(&mut self, parameter: Parameter) {
        if !self.left_undefined(parameter) {
            self.read(parameter);
        }
    }

    /// Finds the argument registers a call of the program sets: it
    /// passes a value there, or the entry value of a register of its
    /// caller that is read or itself set (to a fixed point: a value
    /// handed down a chain of functions that each only pass it on is set
    /// in each), and no call shows it holds none
    /// ([`Self::left_undefined`]) nor does its function's prototype
    /// ([`Self::untaken`]). Those of them a function only passes on
    /// where nothing says the callee reads it ([`Found::forwarded`],
    /// [`Self::unstated`]) hold an argument, then: read.
    fn set_by_calls(&mut self) {
        let found = self.found;
        loop {
            let mut grew = false;
            for (&caller, function) in found {
                for (&callee, passes) in &function.passes {
                    for (&at, passed) in passes {
                        let parameter = (callee, at);
                        let holds = |register: &RegisterId| {
                            let own = (caller, *register);
                            self.read.contains(&own) || self.set.contains(&own)
                        };
                        if self.set.contains(&parameter)
                            || self.left_undefined(parameter)
                            || self.untaken(parameter)
                            || !(passed.value || passed.entries.iter().any(holds))
                        {
                            continue;
                        }
                        self.set.insert(parameter);
                        grew = true;
                        if self.unstated.contains(&parameter)
                            || found
                                .get(&callee)
                                .is_some_and(|function| function.forwarded.contains(&at))
                        {
                            self.read(parameter);
                        }
                    }
                }
            }
            if !grew {
                break;
            }
        }
    }
}

/// The registers dropped from each function's interface of those `found`
/// (by entry, in the order of its interface): those no run reads
/// (`unread`, [`unread_parameters`]) and those every caller leaves
/// `garbage` in; of a function with no interface, those its own
/// prototype leaves unread.
fn dropped(
    found: &BTreeMap<u64, Found>,
    unread: &BTreeMap<u64, Vec<RegisterId>>,
    garbage: &BTreeMap<u64, Vec<RegisterId>>,
) -> BTreeMap<u64, Vec<RegisterId>> {
    found
        .iter()
        .filter_map(|(&entry, function)| {
            let unread = unread.get(&entry).map_or(&[][..], Vec::as_slice);
            let garbage = garbage.get(&entry).map_or(&[][..], Vec::as_slice);
            let dropped: Vec<RegisterId> = match &function.interface {
                Some(interface) => registers(interface)
                    .into_iter()
                    .filter(|register| unread.contains(register) || garbage.contains(register))
                    .collect(),
                None => unread.to_vec(),
            };
            (!dropped.is_empty()).then_some((entry, dropped))
        })
        .collect()
}

/// The parameter registers of the functions `found` (each function's
/// [`Found`], by entry) every caller leaves garbage in, under
/// `convention`, by entry, of those `unread` leaves ([`unread_parameters`]):
/// those of functions not `whole` that their body reads only to pass to
/// calls ([`Found::reads`]), that no call passes a value in
/// ([`Passed::value`]) or the entry value of a register its caller keeps,
/// and that no kept parameter after them in the convention's order keeps
/// (C passes arguments by position). The kept ones are the least fixed
/// point from those, so the dropped ones the most. (A caller's `unread`
/// register is passed on only where no parameter is read, so to none of
/// these.)
fn garbage(
    convention: &Convention,
    whole: &BTreeSet<u64>,
    found: &BTreeMap<u64, Found>,
    unread: &BTreeMap<u64, Vec<RegisterId>>,
) -> BTreeMap<u64, Vec<RegisterId>> {
    let mut fixed = Fixed::default();
    let mut parameters: BTreeMap<u64, Vec<RegisterId>> = BTreeMap::new();
    for (&entry, function) in found {
        let Some(interface) = &function.interface else {
            continue;
        };
        let unread = unread.get(&entry).map_or(&[][..], Vec::as_slice);
        let mut registers = registers(interface);
        registers.retain(|register| !unread.contains(register));
        let stack = stack(interface);
        if !whole.contains(&entry) {
            fixed.candidates.extend(
                registers
                    .iter()
                    .filter(|&register| {
                        !function.reads.contains(register)
                            && (!stack || !convention.arguments.contains(register))
                    })
                    .map(|&register| (entry, register)),
            );
        }
        parameters.insert(entry, registers);
    }
    for (&caller, function) in found {
        for (&callee, passed) in &function.passes {
            for &register in parameters.get(&callee).map_or(&[][..], Vec::as_slice) {
                fixed.passed(caller, (callee, register), passed.get(&register));
            }
        }
    }
    for (&entry, registers) in &parameters {
        for &register in registers {
            if !fixed.candidates.contains(&(entry, register)) {
                fixed.keep_before(convention, (entry, register));
            }
        }
    }
    while let Some(parameter) = fixed.work.pop() {
        fixed.keep_before(convention, parameter);
        for next in fixed.follows.remove(&parameter).unwrap_or_default() {
            fixed.keep(next);
        }
    }
    let mut garbage: BTreeMap<u64, Vec<RegisterId>> = BTreeMap::new();
    for (&entry, registers) in &parameters {
        let dropped: Vec<RegisterId> = registers
            .iter()
            .copied()
            .filter(|&register| {
                fixed.candidates.contains(&(entry, register))
                    && !fixed.kept.contains(&(entry, register))
            })
            .collect();
        if !dropped.is_empty() {
            garbage.insert(entry, dropped);
        }
    }
    garbage
}

/// The parameters kept so far ([`garbage`]).
#[derive(Default)]
struct Fixed {
    /// The parameters that may be garbage.
    candidates: BTreeSet<Parameter>,
    /// Those kept.
    kept: BTreeSet<Parameter>,
    /// Those kept whose consequences are not drawn yet.
    work: Vec<Parameter>,
    /// For each candidate, those a call passes its entry value to.
    follows: BTreeMap<Parameter, Vec<Parameter>>,
}

impl Fixed {
    /// Keeps `parameter`, if a candidate.
    fn keep(&mut self, parameter: Parameter) {
        if self.candidates.contains(&parameter) && self.kept.insert(parameter) {
            self.work.push(parameter);
        }
    }

    /// A call of `caller` passes `passed` (`None`: not known) where
    /// `parameter` is.
    fn passed(&mut self, caller: u64, parameter: Parameter, passed: Option<&Passed>) {
        let Some(passed) = passed.filter(|passed| !passed.value) else {
            self.keep(parameter);
            return;
        };
        for &register in &passed.entries {
            let forwarded = (caller, register);
            if self.candidates.contains(&forwarded) {
                self.follows.entry(forwarded).or_default().push(parameter);
            } else {
                self.keep(parameter);
            }
        }
    }

    /// Keeps the parameters of `parameter`'s function before it in
    /// `convention`'s order ([`before`]).
    fn keep_before(&mut self, convention: &Convention, (entry, register): Parameter) {
        for earlier in before(convention, register) {
            self.keep((entry, earlier));
        }
    }
}

/// No kept register ([`Found::kept`]) for the functions `found` whose
/// name (of `names`, by entry) is a Swift mangling (Swift 5's `$s`, 4's
/// `$S`, 3's `_T0`): Swift passes `self` and an async context in
/// callee-saved registers (`r13`/`x20`, `r14`/`x22`), which a function
/// using them too saves and restores, so they may hold arguments.
fn unkept_in_swift(found: &mut BTreeMap<u64, Found>, names: &BTreeMap<u64, String>) {
    for (entry, function) in found {
        let swift = names.get(entry).is_some_and(|name| {
            ["$s", "$S", "_T0"]
                .iter()
                .any(|prefix| name.starts_with(prefix))
        });
        if swift {
            function.kept.clear();
            if let Some(assumed) = function.assumed.as_mut() {
                assumed.kept.clear();
            }
        }
    }
}

/// The entries of the functions of `program` with callers we cannot see:
/// the entry point, exported functions, functions whose address is taken
/// (in code or in data), and functions no call or jump of another function
/// reaches.
fn visible(image: &Image<'_>, program: &Program, references: &References) -> BTreeSet<u64> {
    let exported = image
        .symbols
        .iter()
        .filter(|symbol| matches!(symbol.source, SymbolSource::Dynamic | SymbolSource::Export))
        .map(|symbol| symbol.address);
    let mut visible: BTreeSet<u64> = image.entry.into_iter().chain(exported).collect();
    for (id, function) in program.functions.iter() {
        let refs = references.to(function.entry);
        let taken = refs
            .iter()
            .any(|r| matches!(r.kind, Kind::Address | Kind::Pointer(_)));
        let reached = refs.iter().any(|r| {
            matches!(r.kind, Kind::Call | Kind::Jump) && r.function.is_some_and(|f| f != id)
        });
        if taken || !reached {
            visible.insert(function.entry);
        }
    }
    visible
}

/// The functions of `program`, each after those it calls or jumps to
/// ([`targets`]; but in cycles): [`callees_first`] with the functions a
/// function leaves for too, whose interface is as much what it returns
/// as a callee's is (a wrapper that jumps to `inner` returns what `inner`
/// does; found before it, it would take the convention's guess for it,
/// and its callers' reads of its result would be of the wrong register).
fn targets_first(program: &Program) -> Vec<FunctionId> {
    let next = |id: FunctionId| -> Vec<FunctionId> {
        targets(program, id)
            .into_iter()
            .filter_map(|target| program.function_at(target))
            .collect()
    };
    let mut order = Vec::new();
    let mut seen = BTreeSet::new();
    for id in callees_first(program) {
        if program.functions.get(id).is_none() || !seen.insert(id) {
            continue;
        }
        let mut stack = vec![(id, next(id), 0usize)];
        while let Some((at, list, index)) = stack.last_mut() {
            if let Some(&target) = list.get(*index) {
                *index += 1;
                if seen.insert(target) {
                    stack.push((target, next(target), 0));
                }
            } else {
                order.push(*at);
                stack.pop();
            }
        }
    }
    order
}

/// The entries of the functions that function `id` of `program` calls or
/// jumps to, by its recovered graph.
fn targets(program: &Program, id: FunctionId) -> BTreeSet<u64> {
    let Some(function) = program.functions.get(id) else {
        return BTreeSet::new();
    };
    function
        .blocks
        .iter()
        .filter_map(|&block| match program.blocks.get(block)?.exit {
            Exit::Call {
                callee: Destination::Address(target),
                ..
            }
            | Exit::Jump(Destination::Address(target))
            | Exit::Branch(Destination::Address(target)) => {
                let callee = program.function_at(target)?;
                (callee != id).then_some(target)
            }
            Exit::Call { .. }
            | Exit::Next
            | Exit::Jump(_)
            | Exit::Branch(_)
            | Exit::Return
            | Exit::Stop
            | Exit::Invalid
            | Exit::Limit => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use binbun_decompile::format::Family;
    use binbun_decompile::lower::{Interface, Passed};
    use binbun_decompile::mapping::Piece;
    use binbun_decompile::prototype::Format;

    use super::*;

    const CALLEE: u64 = 0x100;

    /// The first argument register's 64 bits.
    const FIRST: Source = Source::Register(Piece {
        register: RegisterId(7),
        offset: 0,
        width: 64,
    });

    /// A caller whose calls to [`CALLEE`] pass `argument` at [`FIRST`]
    /// (`None`: its solve gave nothing).
    fn caller(argument: Option<Argument>) -> Found {
        let mut found = Found::default();
        found
            .passes
            .insert(CALLEE, BTreeMap::from([(RegisterId(7), Passed::default())]));
        if let Some(argument) = argument {
            found.arguments.insert(CALLEE, vec![(FIRST, argument)]);
        }
        found
    }

    /// The specialisation of [`CALLEE`] (its one parameter [`FIRST`],
    /// which its body reads or, `padding`, only passes on) with `callers`,
    /// `whole` or not.
    fn specialise_with(
        callers: Vec<Option<Argument>>,
        whole: bool,
        padding: bool,
    ) -> Option<Vec<(Source, Class)>> {
        let mut found: BTreeMap<u64, Found> = (0x1000..)
            .zip(callers)
            .map(|(entry, argument)| (entry, caller(argument)))
            .collect();
        let mut callee = Found {
            interface: Some(Interface {
                parameters: vec![FIRST],
                ..Interface::default()
            }),
            ..Found::default()
        };
        if !padding {
            callee.reads.insert(RegisterId(7));
        }
        found.insert(CALLEE, callee);
        let whole: BTreeSet<u64> = whole.then_some(CALLEE).into_iter().collect();
        specialised(&whole, &found).remove(&CALLEE)
    }

    /// [`specialise_with`] a callee that reads its parameter.
    fn specialise(callers: Vec<Option<Argument>>, whole: bool) -> Option<Vec<(Source, Class)>> {
        specialise_with(callers, whole, false)
    }

    #[test]
    fn a_parameter_every_caller_passes_a_pointer_at_is_a_pointer() {
        let pointer = Argument::Class(Class::Pointer(None));
        let callers = vec![Some(pointer), Some(Argument::Zero), Some(pointer)];
        assert_eq!(
            specialise(callers, false),
            Some(vec![(FIRST, Class::Pointer(None))])
        );
    }

    #[test]
    fn one_disagreeing_or_unsolved_caller_blocks_it() {
        let pointer = Some(Argument::Class(Class::Pointer(None)));
        let code = Some(Argument::Class(Class::Code));
        assert_eq!(specialise(vec![pointer, code, pointer], false), None);
        // A non-zero integer constant is no pointer.
        assert_eq!(
            specialise(vec![pointer, Some(Argument::Integer)], false),
            None
        );
        assert_eq!(specialise(vec![pointer, None], false), None);
    }

    #[test]
    fn a_callee_with_callers_we_cannot_see_is_not_specialised() {
        let pointer = Some(Argument::Class(Class::Pointer(None)));
        assert_eq!(specialise(vec![pointer, pointer], true), None);
    }

    #[test]
    fn a_padding_parameter_is_not_specialised() {
        let pointer = Some(Argument::Class(Class::Pointer(None)));
        assert_eq!(specialise_with(vec![pointer, pointer], false, true), None);
    }

    /// System V's integer argument registers in [`convention`]: `rdi`,
    /// `rsi`, `rdx`, `rcx`, `r8`, `r9` as 7, 6, 2, 1, 8, 9; `xmm0` as 20.
    const ARGUMENTS: [u16; 6] = [7, 6, 2, 1, 8, 9];

    /// A System V-shaped convention ([`ARGUMENTS`], one vector argument
    /// register), not positional.
    fn convention() -> Convention {
        Convention {
            arguments: ARGUMENTS.map(RegisterId).to_vec(),
            float_arguments: vec![RegisterId(20)],
            ..Convention::default()
        }
    }

    /// The 64 bits of `register` as a parameter.
    fn whole(register: u16) -> Source {
        Source::Register(Piece {
            register: RegisterId(register),
            offset: 0,
            width: 64,
        })
    }

    /// A function taking the first `count` integer argument registers,
    /// reading `reads` itself.
    fn function(count: usize, reads: &[u16]) -> Found {
        Found {
            interface: Some(Interface {
                parameters: ARGUMENTS.iter().take(count).map(|&r| whole(r)).collect(),
                ..Interface::default()
            }),
            reads: reads.iter().copied().map(RegisterId).collect(),
            ..Found::default()
        }
    }

    /// A computed value in an argument register.
    fn value() -> Passed {
        Passed {
            value: true,
            ..Passed::default()
        }
    }

    /// `function` calls the function at `target` with no prototype,
    /// passing its own entry values of `registers` on in place.
    fn passes_on(function: &mut Found, target: u64, registers: &[u16]) {
        function.undeclared.insert(target);
        let passed = function.passes.entry(target).or_default();
        for &register in registers {
            passed.insert(
                RegisterId(register),
                Passed {
                    entries: BTreeSet::from([RegisterId(register)]),
                    ..Passed::default()
                },
            );
        }
    }

    /// The unread parameters of `found`, by entry, as register numbers.
    fn unread_of(found: &BTreeMap<u64, Found>) -> BTreeMap<u64, Vec<u16>> {
        unread_under(found, false)
    }

    /// [`unread_of`], under the reading view's assumption if `assume`.
    fn unread_under(found: &BTreeMap<u64, Found>, assume: bool) -> BTreeMap<u64, Vec<u16>> {
        unread_parameters(&convention(), found, assume)
            .into_iter()
            .map(|(entry, registers)| (entry, registers.iter().map(|r| r.0).collect()))
            .collect()
    }

    /// `open_like(path, flags)` reads both and passes `rdx` on as it
    /// found it past a variadic callee's named parameters.
    fn open_like() -> Found {
        let mut function = function(3, &[7, 6]);
        function.opaque.insert(RegisterId(2));
        function.forwarded.insert(RegisterId(2));
        function
    }

    #[test]
    fn a_register_only_passed_on_is_a_parameter_unless_assumed_not() {
        let found = BTreeMap::from([(0x100, open_like())]);
        // Sound: the callee may read it.
        assert_eq!(unread_of(&found), BTreeMap::new());
        // The reading view: no caller sets it.
        assert_eq!(
            unread_under(&found, true),
            BTreeMap::from([(0x100, vec![2])])
        );
    }

    #[test]
    fn a_register_only_passed_on_stays_where_a_call_sets_it() {
        // `caller` passes a value in `rdx`; `through` reads its own `rdx`
        // and passes it on in place: both set `open_like`'s.
        let mut caller = function(0, &[]);
        caller.undeclared.insert(0x100);
        caller
            .passes
            .entry(0x100)
            .or_default()
            .insert(RegisterId(2), value());
        let found = BTreeMap::from([(0x100, open_like()), (0x200, caller)]);
        assert_eq!(unread_under(&found, true), BTreeMap::new());
        let mut through = function(3, &[2]);
        passes_on(&mut through, 0x100, &[7, 6, 2]);
        let found = BTreeMap::from([(0x100, open_like()), (0x300, through)]);
        assert_eq!(unread_under(&found, true), BTreeMap::new());
        // One that only passes its own on in turn sets nothing.
        let mut chained = function(3, &[]);
        passes_on(&mut chained, 0x100, &[7, 6, 2]);
        chained.opaque.clear();
        let found = BTreeMap::from([(0x100, open_like()), (0x400, chained)]);
        assert_eq!(
            unread_under(&found, true),
            BTreeMap::from([(0x100, vec![2]), (0x400, vec![2])])
        );
    }

    #[test]
    fn a_value_handed_down_through_one_that_only_passes_it_on_is_an_argument() {
        // `caller` passes a value in `rdx` to `stub`, which reads nothing
        // and passes its three registers on in place to `open_like` (a
        // PLT stub of a function the image defines): the value reaches
        // `open_like`'s `rdx`, though `stub`'s is read only if that is.
        let mut caller = function(0, &[]);
        caller.undeclared.insert(0x300);
        caller
            .passes
            .entry(0x300)
            .or_default()
            .insert(RegisterId(2), value());
        let mut stub = function(3, &[]);
        passes_on(&mut stub, 0x100, &[7, 6, 2]);
        let found = BTreeMap::from([(0x100, open_like()), (0x200, caller), (0x300, stub)]);
        assert_eq!(unread_under(&found, true), BTreeMap::new());
    }

    #[test]
    fn a_register_a_call_leaves_undefined_is_no_argument_of_one_that_only_passes_it_on() {
        // `error(p, msg)` reads `p` and passes its three registers on in
        // place through a pointer.
        let mut error = function(3, &[7]);
        error.opaque.extend([RegisterId(6), RegisterId(2)]);
        error.passed_on.extend([RegisterId(6), RegisterId(2)]);
        let calls = |rdx: Passed| {
            let mut caller = function(0, &[]);
            caller.undeclared.insert(0x100);
            caller.passes.insert(
                0x100,
                BTreeMap::from([
                    (RegisterId(7), value()),
                    (RegisterId(6), value()),
                    (RegisterId(2), rdx),
                ]),
            );
            caller
        };
        let undefined = Passed {
            undefined: true,
            ..Passed::default()
        };
        // Every call seen leaves a value in `rdx`: it may be an argument.
        let found = BTreeMap::from([(0x100, error.clone()), (0x200, calls(value()))]);
        assert_eq!(unread_under(&found, true), BTreeMap::new());
        // One leaves it undefined: the other's value is a stale one.
        let found = BTreeMap::from([
            (0x100, error.clone()),
            (0x200, calls(value())),
            (0x300, calls(undefined.clone())),
        ]);
        assert_eq!(unread_of(&found), BTreeMap::new());
        assert_eq!(
            unread_under(&found, true),
            BTreeMap::from([(0x100, vec![2])])
        );
        // What its own code reads stays, whatever a call leaves there.
        error.reads.insert(RegisterId(2));
        error.passed_on.remove(&RegisterId(2));
        let found = BTreeMap::from([(0x100, error), (0x300, calls(undefined))]);
        assert_eq!(unread_under(&found, true), BTreeMap::new());
    }

    #[test]
    fn a_parameter_passed_only_to_a_callee_that_drops_it_is_unread() {
        // `f(a1..a6)` reads a1 and passes a1..a6 to `g(a1, a2)`, which
        // reads both: f's a3..a6 are read nowhere.
        let mut f = function(6, &[7]);
        passes_on(&mut f, 0x200, &ARGUMENTS);
        let g = function(2, &[7, 6]);
        let found = BTreeMap::from([(0x100, f), (0x200, g)]);
        assert_eq!(
            unread_of(&found),
            BTreeMap::from([(0x100, vec![2, 1, 8, 9])])
        );
    }

    /// `caller` passes a computed value in `register` to the function at
    /// `target`.
    fn setting(target: u64, register: u16) -> Found {
        let mut caller = function(0, &[]);
        caller.undeclared.insert(target);
        caller
            .passes
            .entry(target)
            .or_default()
            .insert(RegisterId(register), value());
        caller
    }

    #[test]
    fn a_register_passed_on_past_a_variadic_definitions_named_parameters_is_as_past_a_prototypes() {
        // `fail(msg)` reads `msg` and calls `message(fmt, kind, msg, ...)`,
        // a variadic definition of two named parameters, leaving `rcx`,
        // `r8` and `r9` as it found them (and setting `rsi`, `rdx`).
        let mut fail = function(6, &[7]);
        passes_on(&mut fail, 0x500, &[1, 8, 9]);
        fail.passed_on.extend([1, 8, 9].map(RegisterId));
        let mut message = function(2, &[7, 6]);
        if let Some(interface) = message.interface.as_mut() {
            interface.variadic = true;
        }
        let found = BTreeMap::from([(0x100, fail.clone()), (0x500, message.clone())]);
        // Sound: the definition saves every unnamed register and may
        // read the copy.
        assert_eq!(unread_of(&found), BTreeMap::new());
        // The reading view: no call sets them.
        assert_eq!(
            unread_under(&found, true),
            BTreeMap::from([(0x100, vec![6, 2, 1, 8, 9])])
        );
        // A call that sets `rcx` makes it an argument (and `rsi`, `rdx`
        // sit before it).
        let set = BTreeMap::from([
            (0x100, fail.clone()),
            (0x200, setting(0x100, 1)),
            (0x500, message.clone()),
        ]);
        assert_eq!(
            unread_under(&set, true),
            BTreeMap::from([(0x100, vec![8, 9])])
        );
        // A definition with a format of its own: what its callers pass
        // past its named parameters their format strings count, and
        // nothing here says these are not among them.
        if let Some(interface) = message.interface.as_mut() {
            interface.format = Some(Format {
                family: Family::Printf,
                string: 0,
                list: false,
            });
        }
        let found = BTreeMap::from([(0x100, fail), (0x500, message)]);
        assert_eq!(unread_under(&found, true), BTreeMap::new());
    }

    #[test]
    fn a_register_passed_on_to_a_function_with_no_interface_stays_where_a_call_sets_it() {
        // `through(a, b, c)` passes its three registers on in place to a
        // stub with no interface (it jumps to an undeclared import).
        let mut through = function(3, &[]);
        passes_on(&mut through, 0x300, &[7, 6, 2]);
        let stub = Found::default();
        let found = BTreeMap::from([(0x100, through.clone()), (0x300, stub.clone())]);
        assert_eq!(unread_of(&found), BTreeMap::new());
        // The reading view: no call sets them.
        assert_eq!(
            unread_under(&found, true),
            BTreeMap::from([(0x100, vec![7, 6, 2])])
        );
        // A call sets `rdx`: an argument, with those before it.
        let found = BTreeMap::from([(0x100, through), (0x200, setting(0x100, 2)), (0x300, stub)]);
        assert_eq!(unread_under(&found, true), BTreeMap::new());
    }

    /// `declared(a1)`, of a declaration not its own placing one
    /// parameter, with an interface of six registers.
    fn declared() -> Found {
        let mut declared = function(6, &[7]);
        declared.declared_reads = Some(BTreeSet::from([RegisterId(7)]));
        declared
    }

    #[test]
    fn a_declaration_not_its_own_is_assumed_to_say_all_a_function_takes() {
        // `declared(a1)` passes `rsi` to `r9` on through a pointer as it
        // found them.
        let mut wrapper = declared();
        wrapper.opaque.extend([6, 2, 1, 8, 9].map(RegisterId));
        wrapper.passed_on.extend([6, 2, 1, 8, 9].map(RegisterId));
        let found = BTreeMap::from([(0x100, wrapper)]);
        // Sound: the callee may read them, and the declaration may say
        // less than the definition takes.
        assert_eq!(unread_of(&found), BTreeMap::new());
        // The reading view: the declaration places nothing there.
        assert_eq!(
            unread_under(&found, true),
            BTreeMap::from([(0x100, vec![6, 2, 1, 8, 9])])
        );
    }

    #[test]
    fn no_call_sets_a_register_its_callees_declaration_places_nothing_in() {
        // `declared(a1)` passes `rcx` on past a variadic prototype's named
        // parameters as it found it, and a call leaves a value there.
        let mut wrapper = declared();
        wrapper.opaque.insert(RegisterId(1));
        wrapper.forwarded.insert(RegisterId(1));
        wrapper.passed_on.insert(RegisterId(1));
        let found = BTreeMap::from([(0x100, wrapper), (0x200, setting(0x100, 1))]);
        assert_eq!(
            unread_under(&found, true),
            BTreeMap::from([(0x100, vec![6, 2, 1, 8, 9])])
        );
    }

    #[test]
    fn what_a_function_passes_on_past_its_prototype_is_left_undefined() {
        // `inner(a1)` reads `a1` and passes `rcx` on through a pointer as
        // it found it; `outer(a1)`, whose prototype places one parameter,
        // passes its own `rcx` on to it in place.
        let mut inner = function(4, &[7]);
        inner.opaque.insert(RegisterId(1));
        inner.passed_on.insert(RegisterId(1));
        let passing = |mut outer: Found| {
            passes_on(&mut outer, 0x200, &[7, 1]);
            BTreeMap::from([(0x100, outer), (0x200, inner.clone())])
        };
        // No prototype: `outer`'s `rcx` may be an argument of both.
        assert_eq!(
            unread_under(&passing(function(4, &[7])), true),
            BTreeMap::new()
        );
        // Its own prototype says `outer` takes nothing in `rcx`, in both
        // views: what it passes on there shows `inner` takes nothing
        // there either, as the reading view assumes.
        let mut own = function(4, &[7]);
        own.own_reads = Some(BTreeSet::from([RegisterId(7)]));
        let found = passing(own);
        assert_eq!(unread_of(&found), BTreeMap::from([(0x100, vec![6, 2, 1])]));
        assert_eq!(
            unread_under(&found, true),
            BTreeMap::from([(0x100, vec![6, 2, 1]), (0x200, vec![6, 2, 1])])
        );
        // A declaration not its own: assumed to say so, in the reading
        // view only.
        let mut named = function(4, &[7]);
        named.declared_reads = Some(BTreeSet::from([RegisterId(7)]));
        let found = passing(named);
        assert_eq!(unread_of(&found), BTreeMap::new());
        assert_eq!(
            unread_under(&found, true),
            BTreeMap::from([(0x100, vec![6, 2, 1]), (0x200, vec![6, 2, 1])])
        );
    }

    #[test]
    fn reads_cascade_down_a_chain_and_keep_earlier_positions() {
        // `f` passes a1..a6 to `g`, which passes them to `h`, which reads
        // only a4 (rcx): every function keeps a1..a4 (a4 is read down the
        // chain, a1..a3 sit before it), none keeps a5 and a6.
        let mut f = function(6, &[]);
        passes_on(&mut f, 0x200, &ARGUMENTS);
        let mut g = function(6, &[]);
        passes_on(&mut g, 0x300, &ARGUMENTS);
        let h = function(4, &[1]);
        let found = BTreeMap::from([(0x100, f), (0x200, g), (0x300, h)]);
        assert_eq!(
            unread_of(&found),
            BTreeMap::from([(0x100, vec![8, 9]), (0x200, vec![8, 9])])
        );
    }

    #[test]
    fn recursion_alone_reads_nothing() {
        // `f` and `g` pass a1..a3 to each other, and `f` reads a1: a2 and
        // a3 go round the cycle without anyone reading them.
        let mut f = function(3, &[7]);
        passes_on(&mut f, 0x200, &ARGUMENTS[..3]);
        let mut g = function(3, &[]);
        passes_on(&mut g, 0x100, &ARGUMENTS[..3]);
        let found = BTreeMap::from([(0x100, f), (0x200, g)]);
        assert_eq!(
            unread_of(&found),
            BTreeMap::from([(0x100, vec![6, 2]), (0x200, vec![6, 2])])
        );
    }

    #[test]
    fn opaque_callees_and_callees_without_interfaces_read_everything() {
        // Passed to a declared or indirect callee ([`Found::opaque`]).
        let mut f = function(3, &[]);
        f.opaque.insert(RegisterId(2));
        // Passed to a function of the program without an interface.
        let mut g = function(2, &[]);
        passes_on(&mut g, 0x300, &ARGUMENTS[..2]);
        let h = Found::default();
        // Passed past a variadic interface's named parameters.
        let mut i = function(2, &[]);
        passes_on(&mut i, 0x500, &ARGUMENTS[..2]);
        let mut variadic = function(1, &[7]);
        if let Some(interface) = variadic.interface.as_mut() {
            interface.variadic = true;
        }
        let found = BTreeMap::from([
            (0x100, f),
            (0x200, g),
            (0x300, h),
            (0x400, i),
            (0x500, variadic),
        ]);
        assert_eq!(unread_of(&found), BTreeMap::new());
    }

    #[test]
    fn stack_parameters_keep_every_integer_argument_register() {
        let mut f = function(6, &[]);
        if let Some(interface) = f.interface.as_mut() {
            interface.parameters.push(Source::Stack {
                offset: 8,
                bytes: 8,
            });
        }
        let found = BTreeMap::from([(0x100, f)]);
        assert_eq!(unread_of(&found), BTreeMap::new());
    }

    #[test]
    fn both_rules_drop_and_the_garbage_rule_runs_on_what_reads_leave() {
        // `f(a1, a2, a3)` reads a1 and passes a2, a3 to `g(a1, a2)`, which
        // reads a1 only: f's a3 is unread (g never takes it) and g's a2 is
        // unread too (kept by nothing after it). `f`'s only caller passes
        // a value at a1, nothing at a2: f's a2 (not read: g drops it) is
        // unread; so the garbage rule has nothing left of f to drop.
        let mut caller = function(0, &[]);
        caller.undeclared.insert(0x200);
        caller
            .passes
            .insert(0x200, BTreeMap::from([(RegisterId(7), value())]));
        let mut f = function(3, &[7]);
        passes_on(&mut f, 0x300, &[6, 2]);
        let g = function(2, &[7]);
        // `h(a1, a2)` reads a1, passes a2 to an import (read), and its
        // only caller `f2` leaves garbage at a2: the garbage rule drops it.
        let mut f2 = function(0, &[]);
        f2.undeclared.insert(0x500);
        f2.passes.insert(
            0x500,
            BTreeMap::from([(RegisterId(7), value()), (RegisterId(6), Passed::default())]),
        );
        let mut h = function(2, &[7]);
        h.opaque.insert(RegisterId(6));
        let found = BTreeMap::from([
            (0x100, caller),
            (0x200, f),
            (0x300, g),
            (0x400, f2),
            (0x500, h),
        ]);
        let convention = convention();
        let unread = unread_parameters(&convention, &found, false);
        assert_eq!(
            unread,
            BTreeMap::from([
                (0x200, vec![RegisterId(6), RegisterId(2)]),
                (0x300, vec![RegisterId(6)])
            ])
        );
        let whole = BTreeSet::from([0x100, 0x400]);
        let garbage = garbage(&convention, &whole, &found, &unread);
        assert_eq!(garbage, BTreeMap::from([(0x500, vec![RegisterId(6)])]));
        assert_eq!(
            dropped(&found, &unread, &garbage),
            BTreeMap::from([
                (0x200, vec![RegisterId(6), RegisterId(2)]),
                (0x300, vec![RegisterId(6)]),
                (0x500, vec![RegisterId(6)])
            ])
        );
    }
}
