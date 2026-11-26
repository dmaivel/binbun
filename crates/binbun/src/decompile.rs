//! Recovered functions as C: each function's L1 lowered to L2, structured,
//! typed and printed, the passes on L1 and on L2 run by a pass manager per
//! function ([`binbun_semantics::core::pass`]), with the structure check
//! (L2's control flow against L1's CFG, [`validate::structure`]). Every
//! function reads the one interface of each function of the program,
//! found once for the whole program ([`callers`],
//! [`Callers::interfaces`]), so one function
//! decompiled alone and the whole program agree; the whole program is
//! decompiled callees first as [`stream`] hands the functions over, on
//! worker threads as the stream goes on ([`stream_parallel`],
//! [`threads`]).

mod callers;
mod stream;

use std::collections::{BTreeMap, BTreeSet};

use crate::cfg::{FunctionId, Program};
use binbun_ast::ir::{
    Block, CatchType, Escape, Function as Ast, HandlerKind, SehFilter, Stmt, StmtId,
};
use binbun_decompile::data::Data;
use binbun_decompile::itanium::{Action, CatchDispatch, Exceptions, Floor, TryRegions, Unknown};
use binbun_decompile::lower::{self as lowering, Context, Facts};
use binbun_decompile::mapping::Mapping;
use binbun_decompile::msvc::ExceptionCodes;
use binbun_decompile::names;
use binbun_decompile::pass::{self as l2, Feeds, L2Env};
use binbun_decompile::prototype::Prototypes;
use binbun_decompile::range::Indices;
use binbun_decompile::scopes::Scopes;
use binbun_decompile::simplify::coalesce::Coalesce;
use binbun_decompile::simplify::copies::{Narrow, Propagate, Prune};
use binbun_decompile::simplify::division::Divisions;
use binbun_decompile::simplify::fields::DeclaredFields;
use binbun_decompile::simplify::rules::Rewrite;
use binbun_decompile::simplify::signs::Signs;
use binbun_decompile::simplify::sink::Sink;
use binbun_decompile::structure::{
    ArrayLoops, CommonArms, Conditions, Exits, Forward, LoopHeads, Loops, Rotated, ShortCircuit,
    Structure, Switches,
};
use binbun_decompile::validate::{self, Link};
use binbun_loader::{CallSite, Catch, Clause, HandlerTable, Image, ScopeAction, TypeInfo};
use binbun_print::c::{Image as Printing, Opaque, Unknowns};
use binbun_print::layout;
use binbun_print::style::{IntSpelling, Naming, Placement, Spacing, Style};
use binbun_semantics::Declarations;
use binbun_semantics::core::pass::{Broken, Changed, Fuel, Manager, Pass, PassStats, Refusal};
use binbun_semantics::ir::RegisterId;
use binbun_ssa::constant::FoldBranches;
use binbun_ssa::float::{AssumeEmptyX87, AssumeFloatControls, AssumeFloatResults, Control};
use binbun_ssa::implied::FoldImplied;
use binbun_ssa::ir::Function;
use binbun_ssa::pass::{self as l1, L1Env};
use binbun_ssa::stack::{
    AssumeAligned, AssumeAuthenticated, AssumeCanonical, AssumeDereferenced, TailJumps,
};

use crate::data::ImageData;
use crate::funclets::catch_all;
use crate::lift::{ImageEnvironment, lift_function, lift_function_leaving};
use crate::memory::ImageMemory;
use crate::summary::Summaries;
use crate::target::{convention, setup};

pub use binbun_decompile::typing::Outcome;
pub use callers::{Callers, callers, callers_for};
pub use stream::{Interfaces, stream, stream_parallel};

/// The threads whole-program decompilation works on
/// ([`stream_parallel`]): `BINBUN_THREADS` if it is a positive number (1:
/// all on the calling thread, as [`stream`] hands functions over), else
/// as many as the process may run at once
/// ([`std::thread::available_parallelism`], which honours the CPU
/// affinity `taskset` sets), else one.
pub fn threads() -> usize {
    std::env::var("BINBUN_THREADS")
        .ok()
        .and_then(|threads| threads.parse().ok())
        .filter(|&threads| threads > 0)
        .or_else(|| std::thread::available_parallelism().ok().map(Into::into))
        .unwrap_or(1)
}

/// How functions are decompiled.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Options {
    /// The name of the style preset the C is laid out in; `None`: no C
    /// (L1 and L2 only).
    pub style: Option<String>,
    /// The passes not run, by name ([`passes`]).
    pub disabled: Vec<String>,
    /// Which view: exact, or the reading view.
    pub view: View,
    /// How the C spells integer types: fixed-width (`int32_t`, the
    /// default) or C's own names for the image's data model (`int`,
    /// `long`).
    pub types: IntSpelling,
    /// Where the C declares locals: in the blocks using them (the
    /// default), or all at the top.
    pub declarations: Placement,
    /// How the C names variables with no name of their own: by kind and
    /// number (`a1`, `v7`, the default), or by where the machine code kept
    /// them (`arg1`, `rax`, `var_58`).
    pub names: Naming,
    /// Whether empty lines part a block's statements into paragraphs
    /// (the default) or none do.
    pub spacing: Spacing,
}

/// Which C decompilation makes: the exact C or the reading view.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum View {
    /// What the machine code does, every fault it can take included.
    #[default]
    Exact,
    /// The reading view: a second L1 made under named assumptions
    /// ([`View::ASSUMPTIONS`]; [`reading_l1`]), lowered and structured
    /// again, so the checks the assumptions settle and their traps are
    /// gone and the loops they broke take their shapes. It hides, never
    /// lies: everything else (wrap-around, undefined values, the faults
    /// of other kinds) stays. Its structure is checked against the
    /// assumed L1 ([`Decompiled::l1`]), and it compiles as the exact C
    /// does but where it has instructions without semantics, which it
    /// prints as `__asm` blocks ([`Opaque::Asm`]); it differs
    /// from the exact C only on runs that take a fault the assumptions
    /// rule out, and in its types: what a pointer points to is C's type
    /// (`int32_t *`), which asks its alignment of the address, where
    /// the exact C's is one of alignment 1 (`binbun_i32_u *`).
    Reading,
}

impl View {
    /// The reading view's assumptions, as its C states them.
    pub const ASSUMPTIONS: &'static str = "every address a function dereferences (loads from, stores to, calls or jumps to) is canonical, and aligned for the type it is read or written as; the stack pointer is aligned at entry as the ABI says (AArch64); a return address signed with pointer authentication authenticates (AArch64); floating-point instructions run with the controls a process starts with (to nearest, every exception masked, no flush to zero, denormals as they are) unless the function loads the control register itself, a NaN is not told from another and a float converted to an integer is in its range; the x87 register stack is empty at a function's entry, TOP 0, and the x87 unit holds no argument (x86-64); a futex operation made of a constant and another value has the constant's command, the other value giving only its private and clock flags (Linux); no code steps back from an address of a function's stack frame that the function passes or stores to the frame's bytes below it (as container_of does); a register a function must keep, and saves and restores, holds no argument; an argument register a function only passes on as it found it holds no argument where the function's declaration places no parameter in it, where some call of the program leaves it undefined, or where it goes past a variadic function's named parameters, to an undeclared import, or to a call through a pointer after the last argument that call sets, and no call sets it";

    /// Whether the view assumes that an argument register a function
    /// only passes on as it found it holds no argument where the
    /// function's declaration places no parameter in it, where a call of
    /// the program leaves it undefined, or where nothing says the callee
    /// reads it (as after the last argument a call through a pointer
    /// sets) and no call sets it (the reading view; [`callers`] states
    /// the rules): the interfaces of the whole program are then found
    /// under it.
    pub const fn assumes_arguments_set(self) -> bool {
        matches!(self, Self::Reading)
    }

    /// How its C prints instructions without semantics: calls that
    /// compile (exact), `__asm` blocks (reading).
    pub const fn opaque(self) -> Opaque {
        match self {
            Self::Exact => Opaque::Calls,
            Self::Reading => Opaque::Asm,
        }
    }
}

/// The names of the passes, in the order they run: on L1, then (after
/// lowering) on L2.
pub fn passes() -> [&'static str; 26] {
    [
        TailJumps::default().name(),
        AssumeCanonical.name(),
        FoldBranches.name(),
        FoldImplied.name(),
        CatchDispatch::default().name(),
        ExceptionCodes.name(),
        Structure::default().name(),
        TryRegions.name(),
        Sink.name(),
        Propagate.name(),
        Coalesce.name(),
        Prune.name(),
        Narrow.name(),
        Rewrite::default().name(),
        Divisions.name(),
        ShortCircuit::default().name(),
        Exits::default().name(),
        CommonArms.name(),
        ArrayLoops::default().name(),
        Loops::default().name(),
        Switches.name(),
        DeclaredFields.name(),
        Signs.name(),
        Conditions.name(),
        Forward.name(),
        Scopes.name(),
    ]
}

/// Fuel per node of an L1 function (a block or an instruction) for the
/// passes its manager runs: each pass spends a unit per node it visits, so
/// this is 16 passes over the whole function (two run). A pass out of fuel
/// refuses and leaves the function as it was.
const FUEL: u64 = 16;

/// Fuel per node of an L2 function (a statement or an expression, as
/// lowered): structuring, the last dead code and loops (a pass each),
/// and [`ROUNDS`] rounds of the eight simplification passes (each
/// about a pass over the function, [`Rewrite`] up to two, [`Coalesce`]'s
/// liveness and values a few, more in nested loops), with room to spare.
/// At 64, libc's largest functions ran out before the last dead code.
const L2_FUEL: u64 = 128;

/// Rounds of the simplification passes ([`l2_passes`]) at most: each
/// round's copies, dead code and rewrites feed the next (a copy removed
/// makes a value read once, a rewrite makes a variable unread), and on
/// the fixture, bash and libc nearly every function is stable by the
/// third.
pub const ROUNDS: usize = 4;

/// The manager the L2 passes run under ([`l2_passes`]).
pub type L2Manager<'e> = Manager<Ast, L2Env<'e>>;

/// What a recording manager kept ([`Manager::record`]).
#[derive(Clone, Debug, Default)]
pub struct Recorded<F> {
    /// The function as each pass that changed it left it, with the pass's
    /// name, in order.
    pub stages: Vec<(&'static str, F)>,
    /// The refusals, in order, with the pass that refused.
    pub refusals: Vec<(&'static str, Refusal)>,
}

impl<F> Recorded<F> {
    /// What `manager` kept and its refusals.
    fn of<E>(manager: &mut Manager<F, E>) -> Self {
        Self {
            stages: manager.recorded(),
            refusals: manager.refusals().to_vec(),
        }
    }
}

/// The L2 passes after lowering, under one manager with L2's
/// verifier after each change, but the passes `disabled`:
///
/// 1. [`CatchDispatch`] (a landing pad's selector tests as its `Try`'s
///    handlers), [`ExceptionCodes`] (what an `__except` block receives
///    as the exception code), [`Structure`] (refused: the goto form, as
///    correct), then
///    [`TryRegions`] (the `Try`s of a landing pad as one, nested as the
///    exception tables say);
/// 2. to a fixed point (at most [`ROUNDS`] rounds), in order:
///    [`Sink`] (assignments with no effect but their write moved down to
///    their uses), [`Propagate`] (copies, values read once and call
///    results read once into their readers), [`Coalesce`] (the two
///    variables of a copy made one where they never differ while both
///    live), [`Prune`] (assignments nothing reads), [`Narrow`] (variables read
///    only in their low bits, or assigned only extensions), [`Rewrite`] (the
///    proved rules and constant
///    folding), [`Divisions`] (multiply-high sequences back to division
///    by a constant, which leaves the multiply-high's variables to the
///    next round's dead code), [`ShortCircuit`] (nested decisions to
///    `&&`/`||`, which the simplifications make possible where they
///    remove the code before an inner decision);
/// 3. [`Prune`] once more (what the fixed point's last round left:
///    coalescing's copies of a variable to itself);
///    then [`Exits`] (a `goto` to a small exit, at most three statements
///    ending in a `return` or a call that does not return, replaced by a
///    copy of it: after the fixed point, so that `&&`/`||` have merged
///    the decisions going to one exit and the exits are as small as they
///    get) and, if it copied one, the fixed point and [`Prune`] again
///    (what the copies make foldable: `v = 0; return v;`);
/// 4. [`CommonArms`] (the statements both arms of an `if` begin with
///    before it, those both end with after it: the guard of an inverted
///    `for` is then its loop's alone), [`ArrayLoops`] (pointer loops
///    through an array as loops of an index; then, if it rewrote one, the
///    fixed point and [`Prune`] again: the end pointers it leaves unread
///    go, a start read once moves into its reads, and their offsets fold),
///    then
///    [`Loops`] (`do`-`while`s guarded by their own condition as
///    `while`, `for` loops, proved exit conditions as `<`, counted rotated
///    loops as `for`);
///    then [`Switches`] (comparison chains on one value as `switch`);
/// 5. [`DeclaredFields`] (what is read and written through the thread
///    pointer, typed by the structure its platform declares);
/// 6. [`Signs`] (operations on values that read the same signed or
///    unsigned in the signedness of their operands' types; a local's own
///    signedness is the printer's choice);
/// 7. [`Conditions`] (an assignment into the condition after it that
///    reads it: `if ((v = f()) != 0)`, `while ((c = getc(s)) != -1)`;
///    last, so that no other pass sees an assignment expression) and,
///    if it moved one, [`ShortCircuit`] again (the `if` it leaves may be
///    all of its block's code now);
/// 8. [`Forward`] (the forward `goto`s the passes since [`Exits`] left
///    alone in an `if`'s arm beside the code they skip, folded into the
///    `if`: decisions with a load between them are one `&&` only now);
/// 9. [`Scopes`] (each local declared in the innermost block holding its
///    uses where no value flows in, its first assignment its
///    initializer, a `for`'s counter in its header; last, as the
///    others move statements).
///
/// Structuring comes first because the simplifications read the
/// structure (a value moves only forward within a block, into a loop only
/// if nothing in the loop changes what it reads). Decompilation
/// ([`decompile`]) and the corpus test both run this, so what is checked
/// is what is printed.
///
/// Returns the manager (its counts), why catch dispatch left each
/// landing pad's `Try`s on the goto floor ([`CatchDispatch::floors`]),
/// how many pointer loops became array loops ([`ArrayLoops::rewritten`])
/// and what became of the `do`-`while`s ([`Loops::rotated`]).
///
/// # Errors
///
/// A pass left the function failing its verifier.
pub fn l2_passes<'e>(
    l2: &mut Ast,
    env: &L2Env<'e>,
    disabled: &[String],
) -> Result<Passed<'e>, String> {
    l2_passes_recorded(l2, env, disabled, false)
}

/// [`l2_passes`], the manager recording ([`Manager::record`]: the
/// function after each pass that changed it, [`Passed::manager`]) if
/// `record`.
///
/// # Errors
///
/// As for [`l2_passes`].
pub(crate) fn l2_passes_recorded<'e>(
    l2: &mut Ast,
    env: &L2Env<'e>,
    disabled: &[String],
    record: bool,
) -> Result<Passed<'e>, String> {
    let mut manager =
        Manager::new(Fuel::new(L2_FUEL.saturating_mul(l2::size(l2)))).with_verifier(l2::verify);
    for name in disabled {
        manager.disable(name);
    }
    if record {
        manager.record();
    }
    let fails = |broken: Broken| fails("L2", &broken);
    let mut dispatch = CatchDispatch::default();
    manager.run(&mut dispatch, l2, env).map_err(fails)?;
    manager.run(&mut ExceptionCodes, l2, env).map_err(fails)?;
    manager
        .run(&mut Structure::default(), l2, env)
        .map_err(fails)?;
    manager.run(&mut TryRegions, l2, env).map_err(fails)?;
    let (mut rewrite, mut short) = (Rewrite::default(), ShortCircuit::default());
    let mut simplify = |manager: &mut L2Manager<'e>, l2: &mut Ast| {
        manager.fixpoint(
            &mut [
                &mut Sink,
                &mut Propagate,
                &mut Coalesce,
                &mut Prune,
                &mut Narrow,
                &mut rewrite,
                &mut Divisions,
                &mut short,
            ],
            ROUNDS,
            l2,
            env,
        )?;
        // The fixed point may end (at its last round) with what coalescing
        // left (a variable's copy to itself) or propagation made unread.
        manager.run(&mut Prune, l2, env)
    };
    simplify(&mut manager, l2).map_err(fails)?;
    if manager.run(&mut Exits::default(), l2, env).map_err(fails)? == Changed::Yes {
        simplify(&mut manager, l2).map_err(fails)?;
    }
    manager.run(&mut CommonArms, l2, env).map_err(fails)?;
    manager.run(&mut LoopHeads, l2, env).map_err(fails)?;
    let mut arrays = ArrayLoops::default();
    manager.run(&mut arrays, l2, env).map_err(fails)?;
    if arrays.rewritten() > 0 {
        // An end pointer only the rewritten tests read is dead; a start
        // read once moves into its reads, and their offsets fold (`(p +
        // 64) + 4·i - 64`).
        simplify(&mut manager, l2).map_err(fails)?;
    }
    let mut loops = Loops::default();
    manager.run(&mut loops, l2, env).map_err(fails)?;
    manager.run(&mut Switches, l2, env).map_err(fails)?;
    manager.run(&mut DeclaredFields, l2, env).map_err(fails)?;
    manager.run(&mut Signs, l2, env).map_err(fails)?;
    if manager.run(&mut Conditions, l2, env).map_err(fails)? == Changed::Yes {
        manager
            .run(&mut ShortCircuit::default(), l2, env)
            .map_err(fails)?;
    }
    manager.run(&mut Forward, l2, env).map_err(fails)?;
    manager.run(&mut Scopes, l2, env).map_err(fails)?;
    manager.run(&mut Indices, l2, env).map_err(fails)?;
    Ok(Passed {
        manager,
        floors: dispatch.floors,
        array_loops: arrays.rewritten(),
        rotated: loops.rotated().clone(),
        outcomes: loops.outcomes().clone(),
        rules: loops.applied().clone(),
    })
}

/// What the L2 passes ([`l2_passes`]) leave besides the function.
#[derive(Debug)]
pub struct Passed<'e> {
    /// The manager: each pass's and analysis's counts.
    pub manager: L2Manager<'e>,
    /// Why catch dispatch left each landing pad's `Try`s on the goto
    /// floor, by the pad's address.
    pub floors: BTreeMap<u64, Floor>,
    /// How many pointer loops became array loops.
    pub array_loops: usize,
    /// What became of the `do`-`while`s.
    pub rotated: BTreeMap<Rotated, usize>,
    /// What became of each `do`-`while`, by the statement that is the
    /// loop now ([`Loops::outcomes`]).
    pub outcomes: BTreeMap<StmtId, Rotated>,
    /// The loop rules applied to each loop, by the statement that is the
    /// loop now ([`Loops::applied`]).
    pub rules: BTreeMap<StmtId, BTreeSet<u8>>,
}

/// One function decompiled, or why it is not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    /// The function.
    pub id: FunctionId,
    /// Its entry.
    pub entry: u64,
    /// Its name, if the image has one (a symbol, or an import thunk's
    /// import).
    pub name: Option<String>,
    /// What it decompiled to, or why it did not.
    pub result: Result<Decompiled, String>,
}

/// A function decompiled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decompiled {
    /// Its L1 after the L1 passes ([`decompile_l1`]).
    pub l1: Function,
    /// Its L2 after the L2 passes ([`l2_passes`]), named.
    pub l2: Ast,
    /// How its L2 stands for its L1 (lowering's: parameters, returns and
    /// calls in L1's state), which running it reads.
    pub mapping: Mapping,
    /// Its C, if asked for ([`Options::style`]).
    pub c: Option<C>,
    /// Its counts.
    pub stats: Stats,
}

/// A function as a C file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C {
    /// The file: the function and the declarations it needs; it includes
    /// `binbun_defs.h` ([`binbun_print::c::HEADER`]).
    pub text: String,
    /// The casts it has.
    pub casts: usize,
    /// The conversions printed that its plan lacked
    /// ([`binbun_print::c::Counts::unplanned`]): 0 unless the plan is
    /// wrong.
    pub unplanned: usize,
    /// Its `__asm` blocks (the reading view's instructions without
    /// semantics, [`Opaque::Asm`]): with
    /// one, it is no C a compiler takes.
    pub asm: usize,
    /// The unknown values it prints, by where they come from: those the
    /// architecture leaves undefined are processor-dependent.
    pub unknowns: Unknowns,
}

/// Counts of one function.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Gotos and escapes in its L2 ([`count`]).
    pub counts: Counts,
    /// What became of its calls' declared format strings.
    pub formats: lowering::Formats,
    /// Where its control flow differs from L1's (the structure check), if
    /// it does.
    pub structure: Option<String>,
    /// Its `Try`s left on the goto floor (a landing handler), by why
    /// catch dispatch left their landing pad ([`l2_passes`]).
    pub floors: BTreeMap<Floor, usize>,
    /// How many of its pointer loops became array loops ([`l2_passes`]).
    pub array_loops: usize,
    /// What became of its `do`-`while`s ([`l2_passes`]).
    pub rotated: BTreeMap<Rotated, usize>,
    /// Each pass's counts, by name: L1's, then L2's.
    pub passes: Vec<(&'static str, PassStats)>,
    /// How many times each analysis was computed, by type name.
    pub analyses: Vec<(&'static str, usize)>,
    /// What the type solver did ([`Options::solver`]).
    pub typing: Outcome,
    /// Whether it is a variadic definition, recognised and declared.
    pub variadic: lowering::Variadic,
    /// How many of the frame's slots each rule of lowering's step 3 took.
    pub frames: lowering::Frames,
    /// What became of what debug information states about it.
    pub debug: lowering::DebugCounts,
    /// The checks the reading view assumed ([`View::Reading`]; none in
    /// the exact view).
    pub assumed: Assumed,
}

/// The checks the reading view assumed away ([`reading_l1`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Assumed {
    /// Each check, one each, in order: the canonical-address checks, the
    /// stack-alignment checks, the return addresses' authentications,
    /// then the instructions whose floating-point controls and whose
    /// floating-point results were assumed, and those reading the x87
    /// stack's state at entry; each by the address of the machine
    /// instruction it guards or is part of (where the exact C has the
    /// check).
    pub sites: Vec<u64>,
    /// How many of them are canonical-address checks
    /// ([`AssumeDereferenced`]), stack-alignment checks
    /// ([`AssumeAligned`]), return-address authentications
    /// ([`AssumeAuthenticated`]), instructions run under the default
    /// floating-point controls ([`AssumeFloatControls`]), instructions
    /// whose NaN or converted integer is the operation's own
    /// ([`AssumeFloatResults`]) and instructions reading an empty x87
    /// stack ([`AssumeEmptyX87`]), in that order.
    pub kinds: [usize; 6],
}

impl Assumed {
    /// Whether no check was assumed.
    pub fn is_empty(&self) -> bool {
        self.sites.is_empty()
    }
}

/// The C gotos, the escapes and the `Try`s of an L2 function.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    /// `goto` statements, and `break`s and `continue`s of a statement other
    /// than the innermost one C's would leave (which C says with a goto).
    pub gotos: usize,
    /// Escapes: what C cannot say ([`Escape`](binbun_ast::ir::Escape)).
    pub escapes: usize,
    /// `Try` statements.
    pub tries: usize,
    /// Their handlers, by kind.
    pub handlers: Handlers,
}

/// Counts of handlers by kind ([`HandlerKind`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Handlers {
    /// Landing handlers: the goto floor.
    pub landing: usize,
    /// Catches of a type.
    pub catch: usize,
    /// Catches of every exception.
    pub catch_all: usize,
    /// Cleanups.
    pub cleanup: usize,
    /// Exception specifications' handlers.
    pub unexpected: usize,
    /// `__except` handlers.
    pub except: usize,
    /// `__finally` handlers.
    pub finally: usize,
}

impl Handlers {
    /// Counts one handler of `kind`.
    fn add(&mut self, kind: &HandlerKind) {
        let slot = match kind {
            HandlerKind::Landing(_) => &mut self.landing,
            HandlerKind::Catch(_) => &mut self.catch,
            HandlerKind::CatchAll => &mut self.catch_all,
            HandlerKind::Cleanup => &mut self.cleanup,
            HandlerKind::Unexpected(_) => &mut self.unexpected,
            HandlerKind::Except(_) => &mut self.except,
            HandlerKind::Finally => &mut self.finally,
        };
        *slot += 1;
    }
}

/// The [`Counts`] of `function`.
pub fn count(function: &Ast) -> Counts {
    let mut counts = Counts::default();
    count_block(function, &function.body, None, None, &mut counts);
    counts
}

/// Counts in `block`, inside the innermost loop or switch `breakable` and
/// the innermost loop `loop_`.
fn count_block(
    function: &Ast,
    block: &Block,
    breakable: Option<StmtId>,
    loop_: Option<StmtId>,
    counts: &mut Counts,
) {
    for &id in block {
        let Some(stmt) = function.stmt(id) else {
            continue;
        };
        match stmt {
            Stmt::Goto(_) => counts.gotos += 1,
            // C says an atomic update: no escape.
            Stmt::Escape {
                kind: Escape::Update(_),
                ..
            } => {}
            Stmt::Escape { .. } => counts.escapes += 1,
            &Stmt::Break(target) if Some(target) != breakable => counts.gotos += 1,
            &Stmt::Continue(target) if Some(target) != loop_ => counts.gotos += 1,
            Stmt::While { .. } | Stmt::DoWhile { .. } | Stmt::For { .. } => {
                for inner in stmt.blocks() {
                    count_block(function, inner, Some(id), Some(id), counts);
                }
            }
            Stmt::Switch { .. } => {
                for inner in stmt.blocks() {
                    count_block(function, inner, Some(id), loop_, counts);
                }
            }
            Stmt::Try { handlers, .. } => {
                counts.tries += 1;
                for handler in handlers {
                    counts.handlers.add(&handler.kind);
                }
                for inner in stmt.blocks() {
                    count_block(function, inner, breakable, loop_, counts);
                }
            }
            Stmt::If { .. } => {
                for inner in stmt.blocks() {
                    count_block(function, inner, breakable, loop_, counts);
                }
            }
            Stmt::Assign { .. }
            | Stmt::Call { .. }
            | Stmt::Intrinsic { .. }
            | Stmt::Expr(_)
            | Stmt::Break(_)
            | Stmt::Continue(_)
            | Stmt::Label(_)
            | Stmt::Return(_)
            | Stmt::Trap(_)
            | Stmt::Unreachable
            | Stmt::VaStart { .. } => {}
        }
    }
}

/// What the pipeline is given of an image beside its code and the
/// interfaces of its functions.
pub struct ImageFacts<'f> {
    /// The declared prototypes.
    pub prototypes: &'f dyn Prototypes,
    /// The image's data.
    pub data: &'f ImageData<'f>,
    /// The image's exceptions ([`exceptions`]).
    pub exceptions: &'f Exceptions,
}

/// The `Try`s of `function` left with a landing handler (the goto floor),
/// counted by why catch dispatch left their pad (`reasons`, by pad; a
/// pad it gave no reason for, as when it did not run, is not counted).
fn floors(function: &Ast, reasons: &BTreeMap<u64, Floor>) -> BTreeMap<Floor, usize> {
    let mut floors = BTreeMap::new();
    let mut work = vec![&function.body];
    while let Some(block) = work.pop() {
        for stmt in block.iter().filter_map(|&id| function.stmt(id)) {
            work.extend(stmt.blocks());
            let Stmt::Try { handlers, .. } = stmt else {
                continue;
            };
            let reason = handlers.iter().find_map(|handler| match handler.kind {
                HandlerKind::Landing(pad) => reasons.get(&pad),
                HandlerKind::Catch(_)
                | HandlerKind::CatchAll
                | HandlerKind::Cleanup
                | HandlerKind::Unexpected(_)
                | HandlerKind::Except(_)
                | HandlerKind::Finally => None,
            });
            if let Some(&reason) = reason {
                *floors.entry(reason).or_default() += 1;
            }
        }
    }
    floors
}

impl std::fmt::Debug for ImageFacts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImageFacts")
            .field("exceptions", self.exceptions)
            .finish_non_exhaustive()
    }
}

/// The pipeline for a function `prepared` in L1 (of `image`, named
/// `name`), its callees' `interfaces` final: lowering with the declared
/// prototypes and the image's data (of `facts`), then the L2 passes
/// ([`l2_passes`]), the variables named from evidence ([`names::name`]),
/// then the check against L1's CFG, both knowing the image's exceptions;
/// then, under `options`, the C. In the reading view
/// ([`View::Reading`]) all of it starts from the reading view's L1
/// ([`reading_l1`]), and the C says how many checks it assumed.
///
/// # Errors
///
/// The image's code is not lifted, lowering fails, a pass leaves L2
/// failing its verifier, or the C cannot be printed (no such style
/// preset, or the printer refuses the function).
pub fn decompile(
    image: &Image<'_>,
    prepared: Prepared,
    name: Option<&str>,
    interfaces: &Interfaces,
    facts: &ImageFacts<'_>,
    options: &Options,
) -> Result<Decompiled, String> {
    let ImageFacts {
        prototypes,
        data,
        exceptions,
    } = *facts;
    let environment = ImageEnvironment::new(image, &[]).map_err(|e| e.0)?;
    let declarations = environment.declarations();
    let (prepared, assumed) = match options.view {
        View::Exact => (prepared, Assumed::default()),
        View::Reading => reading_l1(image, &prepared, &options.disabled)?,
    };
    let (mut l2, mapping, lowered) =
        lower_function(image, &prepared, interfaces, prototypes, data)?;
    l2.name = name.map(str::to_owned);
    let feeds = Feeds::new(&prepared.l1);
    let env = L2Env {
        declarations,
        exceptions,
        feeds: Some(&feeds),
    };
    let Passed {
        manager,
        floors: reasons,
        array_loops,
        rotated,
        ..
    } = l2_passes(&mut l2, &env, &options.disabled)?;
    names::name(&mut l2, prototypes);
    let structure = validate::structure(&prepared.l1, &l2, exceptions)
        .err()
        .map(|mismatch| mismatch.to_string());
    let stats = Stats {
        counts: count(&l2),
        formats: lowered.formats,
        structure,
        floors: floors(&l2, &reasons),
        array_loops,
        rotated,
        passes: prepared.passes.into_iter().chain(manager.stats()).collect(),
        analyses: prepared
            .analyses
            .into_iter()
            .chain(manager.computed())
            .collect(),
        typing: lowered.typing,
        variadic: lowered.variadic,
        frames: lowered.frames,
        debug: lowered.debug,
        assumed,
    };
    let c = match &options.style {
        Some(style) => {
            let style = Style::preset(style)
                .ok_or_else(|| format!("no style preset {style:?}"))?
                .with_int_spelling(options.types)
                .with_declarations(options.declarations)
                .with_naming(options.names)
                .with_spacing(options.spacing);
            let mut c = print(&l2, declarations, &style, data, options.view.opaque())?;
            if options.view == View::Reading && !stats.assumed.is_empty() {
                c.text.insert_str(0, &reading_comment(&stats.assumed));
            }
            Some(c)
        }
        None => None,
    };
    Ok(Decompiled {
        l1: prepared.l1,
        l2,
        mapping,
        c,
        stats,
    })
}

/// The error of a pass that left a function of `level` (L1, L2) failing
/// its verifier.
fn fails(level: &str, broken: &Broken) -> String {
    format!(
        "{level} after {} fails its verifier: {}",
        broken.pass, broken.message
    )
}

/// The line the reading view's C starts with when it assumed the checks
/// `assumed` (not empty): how many of each kind, singular for one.
pub fn reading_comment(assumed: &Assumed) -> String {
    let kinds = [
        ("canonical-address check", "canonical-address checks"),
        ("stack-alignment check", "stack-alignment checks"),
        (
            "return-address authentication",
            "return-address authentications",
        ),
        (
            "instruction's floating-point controls",
            "instructions' floating-point controls",
        ),
        (
            "instruction's floating-point result",
            "instructions' floating-point results",
        ),
        (
            "instruction's empty x87 stack",
            "instructions' empty x87 stack",
        ),
    ];
    let parts: Vec<String> = assumed
        .kinds
        .iter()
        .zip(kinds)
        .filter(|&(&count, _)| count > 0)
        .map(|(&count, (one, many))| format!("{count} {}", if count == 1 { one } else { many }))
        .collect();
    format!("/* Reading view: {} assumed. */\n", parts.join(", "))
}

/// The personality routines whose exception tables follow the Itanium C++
/// ABI's rule ([`binbun_decompile::itanium`]): C++'s, and C's (cleanups
/// only, `__attribute__((cleanup))`).
const ITANIUM_PERSONALITIES: [&str; 2] = ["__gxx_personality_v0", "__gcc_personality_v0"];

/// What decompilation knows about the exceptions of `image`: each landing
/// pad's action chain, where every call site unwinding to it lists the
/// same one under a personality routine following the Itanium C++ ABI's
/// rule (`__gxx_personality_v0`, `__gcc_personality_v0`)
/// (another routine's, or a damaged table's, pads stay landing pads);
/// the functions that resume unwinding: the import thunks (`thunks`:
/// entry and import name) of `_Unwind_Resume`; and the functions that
/// never throw: `nothrow`, the import thunks of the functions the type
/// library declares so ([`crate::prototypes::Imports::nothrow`]). A
/// function the image defines is not taken for one by its symbol (names
/// are not evidence of what code is: [`crate::prototypes`]).
///
/// Microsoft x64: an `__except` block's chain is its scope's filter; the
/// pads of the funclets built into their functions ([`crate::funclets`])
/// are entered for their try block's catch blocks (by type, in order,
/// selectors from 1) then the cleanup of the try's lowest state (an unwind
/// funclet, selector 0), or for a cleanup only (an unwind funclet, a
/// `__finally` block); a call to a function's exception handling data
/// (which no code calls: [`crate::funclets`]) resumes
/// unwinding.
pub fn exceptions<'n>(
    image: &Image<'_>,
    thunks: impl IntoIterator<Item = (u64, &'n str)>,
    nothrow: impl IntoIterator<Item = u64>,
) -> Exceptions {
    let unversioned = |name: &'n str| name.split('@').next().unwrap_or(name);
    let thunks: Vec<(u64, &str)> = thunks
        .into_iter()
        .map(|(entry, name)| (entry, unversioned(name)))
        .collect();
    let mut chains: BTreeMap<u64, Result<Vec<Action>, Unknown>> = BTreeMap::new();
    for table in &image.exception_tables {
        let itanium = table
            .personality
            .as_ref()
            .and_then(|routine| routine.symbol.as_deref())
            .is_some_and(|symbol| {
                let symbol = symbol.split('@').next().unwrap_or(symbol);
                ITANIUM_PERSONALITIES.contains(&symbol)
            });
        for site in &table.call_sites {
            let Some(pad) = site.landing_pad else {
                continue;
            };
            let chain = if itanium {
                actions(site).ok_or(Unknown::Damaged)
            } else {
                Err(Unknown::Personality)
            };
            chains
                .entry(pad)
                .and_modify(|known| {
                    if known.is_ok() && *known != chain {
                        *known = Err(chain.clone().err().unwrap_or(Unknown::Disagree));
                    }
                })
                .or_insert(chain);
        }
    }
    let resume = funclet_chains(image, &mut chains);
    // An `__except` block: entered for what its scope's filter takes.
    // Blocks of several scopes with different filters stay landing pads.
    for table in &image.frame_handlers {
        let HandlerTable::Scopes(scopes) = &table.table else {
            continue;
        };
        for scope in scopes {
            let ScopeAction::Except { filter, target } = scope.action else {
                continue;
            };
            let filter = match filter {
                binbun_loader::SehFilter::Constant(value) => SehFilter::Constant(value),
                binbun_loader::SehFilter::Funclet(funclet) => SehFilter::Funclet(funclet),
            };
            let chain = Ok(vec![Action {
                kind: HandlerKind::Except(filter),
                selector: 0,
            }]);
            chains
                .entry(target)
                .and_modify(|known| {
                    if known.is_ok() && *known != chain {
                        *known = Err(Unknown::Disagree);
                    }
                })
                .or_insert(chain);
        }
    }
    Exceptions {
        funclets: !image.frame_handlers.is_empty(),
        pads: chains
            .iter()
            .filter_map(|(&pad, chain)| Some((pad, chain.clone().ok()?)))
            .collect(),
        unknown: chains
            .iter()
            .filter_map(|(&pad, chain)| Some((pad, chain.clone().err()?)))
            .collect(),
        resume: thunks
            .iter()
            .filter(|&&(_, name)| name == "_Unwind_Resume")
            .map(|&(entry, _)| entry)
            .chain(resume)
            .collect(),
        nothrow: nothrow.into_iter().collect(),
    }
}

/// The action chain of call site `site`, if it is whole (a selector per
/// clause, at least one clause).
fn actions(site: &CallSite) -> Option<Vec<Action>> {
    if site.clauses.is_empty() || site.clauses.len() != site.selectors.len() {
        return None;
    }
    let catch_type = |info: &TypeInfo| CatchType {
        name: info.name.clone(),
        symbol: info.object.symbol.clone(),
        address: info.object.address,
    };
    let chain = site
        .clauses
        .iter()
        .zip(&site.selectors)
        .map(|(clause, &selector)| Action {
            kind: match clause {
                Clause::Catch(info) => HandlerKind::Catch(catch_type(info)),
                Clause::CatchAll => HandlerKind::CatchAll,
                Clause::Cleanup => HandlerKind::Cleanup,
                Clause::Filter(types) => {
                    HandlerKind::Unexpected(types.iter().map(catch_type).collect())
                }
            },
            selector,
        })
        .collect();
    Some(chain)
}

/// The action chains of the landing pads of the funclets built into their
/// functions ([`crate::funclets`]), into `chains`: a C++ try block's catch
/// blocks (selectors from 1, by type) up to its `catch (...)`
/// ([`catch_all`]: it takes every exception), or else then the unwind
/// funclet of the try's lowest state (a cleanup, 0); an unwind funclet
/// alone, a cleanup; a `__finally` block, its own kind. Returns the
/// addresses of the functions' exception handling data, a call to which
/// resumes unwinding.
fn funclet_chains(
    image: &Image<'_>,
    chains: &mut BTreeMap<u64, Result<Vec<Action>, Unknown>>,
) -> BTreeSet<u64> {
    let mut resume = BTreeSet::new();
    let alone = |chains: &mut BTreeMap<u64, Result<Vec<Action>, Unknown>>, pad, kind| {
        chains
            .entry(pad)
            .or_insert_with(|| Ok(vec![Action { kind, selector: 0 }]));
    };
    for table in &image.frame_handlers {
        resume.insert(table.data);
        let cxx = match &table.table {
            HandlerTable::Scopes(scopes) => {
                for scope in scopes {
                    if let ScopeAction::Finally(funclet) = scope.action {
                        alone(chains, funclet, HandlerKind::Finally);
                    }
                }
                continue;
            }
            HandlerTable::Cxx(cxx) => cxx,
        };
        for (state, entry) in cxx.unwind.iter().enumerate() {
            let Ok(state) = i32::try_from(state) else {
                continue;
            };
            let mut catches: Vec<&Catch> = cxx
                .tries
                .iter()
                .filter(|block| block.low == state)
                .flat_map(|block| &block.catches)
                .collect();
            let all = catches.iter().position(|catch| catch_all(catch));
            if let Some(all) = all {
                catches.truncate(all + 1);
            }
            let Some(pad) = all
                .and_then(|all| catches.get(all))
                .map(|catch| catch.funclet)
                .or(entry.action)
                .or_else(|| catches.first().map(|catch| catch.funclet))
            else {
                continue;
            };
            if catches.is_empty() {
                alone(chains, pad, HandlerKind::Cleanup);
                continue;
            }
            let mut chain: Vec<Action> = (1..)
                .zip(&catches)
                .map(|(selector, catch)| Action {
                    kind: match &catch.ty {
                        Some(info) if !catch_all(catch) => HandlerKind::Catch(CatchType {
                            name: info.name.clone(),
                            symbol: info.object.symbol.clone(),
                            address: info.object.address,
                        }),
                        Some(_) | None => HandlerKind::CatchAll,
                    },
                    selector,
                })
                .collect();
            if entry.action.is_some() && all.is_none() {
                chain.push(Action {
                    kind: HandlerKind::Cleanup,
                    selector: 0,
                });
            }
            chains.insert(pad, Ok(chain));
        }
    }
    resume
}

/// A function's L1 as decompilation starts from it ([`decompile_l1`]),
/// with what lowering reads and the counts of what made them.
#[derive(Clone, Debug)]
pub struct Prepared {
    /// The L1 function after the L1 passes.
    pub l1: Function,
    /// Its analyses, as the L1 passes left them, for lowering.
    pub facts: Facts,
    /// The counts of the L1 passes, by name.
    pub passes: Vec<(&'static str, PassStats)>,
    /// How many times each L1 analysis was computed, by type name.
    pub analyses: Vec<(&'static str, usize)>,
}

/// Function `id` of `program` (recovered from `image`) in L1, as
/// decompilation starts from it: [`lift_function_leaving`] (every computed
/// jump recovery has no table for, or resolved to code outside the
/// function, leaving the function); then the L1
/// passes under a manager (a verifier after each change, [`FUEL`] per
/// node), but those `disabled`: those leaves kept tail calls only where
/// the ABI's conditions for one hold, the others unresolved jumps
/// ([`TailJumps`]; disabled, every such jump is unresolved); under the
/// ABI's assumption that the stack and the
/// caller's return address are canonical, the branches on L0's checks
/// that they are made jumps ([`AssumeCanonical`]); then every branch
/// constant propagation over the image's read-only memory proves to go
/// one way made a jump ([`FoldBranches`]), and every branch on whether a
/// value is zero that an earlier test of the same value decides
/// ([`FoldImplied`]: `bsr` on a source tested first). So the blocks never
/// taken (a fault that cannot happen, a flag update that always does, a
/// register's old value kept for a zero source) are not decompiled.
/// Lowering, interfaces and the checks against L1 all use this
/// L1, so they agree, and lowering the analyses the passes left
/// ([`Facts::of`]).
///
/// # Errors
///
/// As for [`lift_function_leaving`], or a pass leaves L1 failing its
/// verifier.
pub fn decompile_l1(
    image: &Image<'_>,
    program: &Program,
    id: FunctionId,
    summaries: &Summaries,
    disabled: &[String],
) -> Result<Prepared, String> {
    let l1 = lift_l1(image, program, id, summaries, disabled)?;
    Ok(exact_l1(image, l1, disabled, false)?.0)
}

/// Function `id` of `program` (recovered from `image`) lifted as
/// decompilation lifts it: with the computed jumps recovery found no table
/// for, or resolved to code outside the function, leaving the function
/// ([`lift_function_leaving`]), for [`TailJumps`] to decide, unless that
/// pass is `disabled`.
///
/// # Errors
///
/// As for [`lift_function_leaving`].
pub(crate) fn lift_l1(
    image: &Image<'_>,
    program: &Program,
    id: FunctionId,
    summaries: &Summaries,
    disabled: &[String],
) -> Result<Function, String> {
    if tail_jumps(disabled) {
        lift_function_leaving(image, program, id, summaries)
    } else {
        lift_function(image, program, id, summaries)
    }
    .map_err(|e| e.0)
}

/// Whether [`TailJumps`] runs (it isn't among the passes `disabled`).
fn tail_jumps(disabled: &[String]) -> bool {
    !disabled
        .iter()
        .any(|name| name == TailJumps::default().name())
}

/// The L1 passes of [`decompile_l1`] on a function's `l1` as lifted (of
/// `image`, by [`lift_l1`]), those `disabled` not run; with what each pass
/// that changed it left if `record` ([`Manager::record`]).
///
/// # Errors
///
/// A pass leaves L1 failing its verifier.
pub(crate) fn exact_l1(
    image: &Image<'_>,
    mut l1: Function,
    disabled: &[String],
    record: bool,
) -> Result<(Prepared, Recorded<Function>), String> {
    let setting = L1Setting::new(image, l1.entry)?;
    let env = setting.env();
    let mut manager = l1_manager(&l1, disabled, record);
    if tail_jumps(disabled) {
        manager
            .run(
                &mut TailJumps::new(setting.link, setting.kept.clone()),
                &mut l1,
                &env,
            )
            .map_err(|broken| fails("L1", &broken))?;
    }
    manager
        .run(&mut AssumeCanonical, &mut l1, &env)
        .map_err(|broken| fails("L1", &broken))?;
    manager
        .run(&mut FoldBranches, &mut l1, &env)
        .map_err(|broken| fails("L1", &broken))?;
    manager
        .run(&mut FoldImplied, &mut l1, &env)
        .map_err(|broken| fails("L1", &broken))?;
    let facts = Facts::of(&mut manager, &l1, &env);
    let recorded = Recorded::of(&mut manager);
    let prepared = Prepared {
        l1,
        facts,
        passes: manager.stats().collect(),
        analyses: manager.computed().collect(),
    };
    Ok((prepared, recorded))
}

/// The manager the L1 passes of `l1` run under: [`FUEL`] per node, L1's
/// verifier after each change, the passes `disabled` not run, recording
/// if `record`.
fn l1_manager<'e>(
    l1: &Function,
    disabled: &[String],
    record: bool,
) -> Manager<Function, L1Env<'e>> {
    let mut manager =
        Manager::new(Fuel::new(FUEL.saturating_mul(l1::size(l1)))).with_verifier(l1::verify);
    for name in disabled {
        manager.disable(name);
    }
    if record {
        manager.record();
    }
    manager
}

/// The reading view's L1 ([`View::Reading`]) of a function `prepared` (of
/// `image`, by [`decompile_l1`]), the passes `disabled`: its L1 under the
/// reading view's assumptions ([`AssumeDereferenced`]: every branch on a
/// canonical-address check that guards an access goes the canonical
/// way; [`AssumeAligned`]: the stack pointer at entry is aligned as
/// AAPCS64 says, so its alignment checks pass; [`AssumeAuthenticated`],
/// where calls leave the return address in a register: a return address
/// signed with pointer authentication authenticates, as the one a call
/// left; [`AssumeFloatControls`]: the floating-point controls are what a
/// process starts with wherever the function has not loaded them;
/// [`AssumeFloatResults`]: a NaN is not told from another and a float
/// converted to an integer is in its range; [`AssumeEmptyX87`]: the x87
/// stack is empty at entry with TOP 0), then [`FoldBranches`]
/// again, with the facts lowering reads; and the checks it assumed
/// ([`Assumed`]). The interfaces stay the exact L1's.
///
/// Every run of the original L1 that takes no fault the first three
/// rule out runs the same in this L1 (a folded branch goes where it
/// went). The floating-point ones settle values too: a run under other
/// controls, or one that converts a float out of range, computes
/// something else, and a NaN this L1 gives is the operation's where the
/// original's is an operand's. L2 that agrees with this L1 agrees with
/// the original on the runs the assumptions hold for (NaNs alike): the
/// structure check and the differential compare the reading view with
/// this L1.
///
/// # Errors
///
/// A pass leaves L1 failing its verifier.
pub fn reading_l1(
    image: &Image<'_>,
    prepared: &Prepared,
    disabled: &[String],
) -> Result<(Prepared, Assumed), String> {
    let (reading, assumed, _) = reading_l1_recorded(image, prepared, disabled, false)?;
    Ok((reading, assumed))
}

/// [`reading_l1`], with what each pass that changed the L1 left if
/// `record` ([`Manager::record`]).
///
/// # Errors
///
/// As for [`reading_l1`].
pub(crate) fn reading_l1_recorded(
    image: &Image<'_>,
    prepared: &Prepared,
    disabled: &[String],
    record: bool,
) -> Result<(Prepared, Assumed, Recorded<Function>), String> {
    let mut l1 = prepared.l1.clone();
    let setting = L1Setting::new(image, l1.entry)?;
    let env = setting.env();
    let mut manager = l1_manager(&l1, disabled, record);
    let mut assume = AssumeDereferenced::default();
    manager
        .run(&mut assume, &mut l1, &env)
        .map_err(|broken| fails("L1", &broken))?;
    let mut aligned = AssumeAligned::default();
    manager
        .run(&mut aligned, &mut l1, &env)
        .map_err(|broken| fails("L1", &broken))?;
    let mut authenticated: Vec<u64> = Vec::new();
    if let Some(link) = setting.link {
        let mut authenticate = AssumeAuthenticated::new(link);
        manager
            .run(&mut authenticate, &mut l1, &env)
            .map_err(|broken| fails("L1", &broken))?;
        authenticated = authenticate.folded().to_vec();
    }
    let mut controls = AssumeFloatControls::new(setting.float_control.clone());
    manager
        .run(&mut controls, &mut l1, &env)
        .map_err(|broken| fails("L1", &broken))?;
    let mut results = AssumeFloatResults::default();
    manager
        .run(&mut results, &mut l1, &env)
        .map_err(|broken| fails("L1", &broken))?;
    let mut x87 = AssumeEmptyX87::new(setting.x87.clone());
    manager
        .run(&mut x87, &mut l1, &env)
        .map_err(|broken| fails("L1", &broken))?;
    manager
        .run(&mut FoldBranches, &mut l1, &env)
        .map_err(|broken| fails("L1", &broken))?;
    let facts = Facts::of(&mut manager, &l1, &env);
    let recorded = Recorded::of(&mut manager);
    let reading = Prepared {
        l1,
        facts,
        passes: prepared
            .passes
            .iter()
            .copied()
            .chain(manager.stats())
            .collect(),
        analyses: prepared
            .analyses
            .iter()
            .copied()
            .chain(manager.computed())
            .collect(),
    };
    let groups = [
        assume.folded(),
        aligned.folded(),
        &authenticated,
        controls.folded(),
        results.folded(),
        x87.folded(),
    ];
    let assumed = Assumed {
        sites: groups.concat(),
        kinds: groups.map(<[u64]>::len),
    };
    Ok((reading, assumed, recorded))
}

/// What the L1 passes of a function read of its image ([`L1Env`]).
struct L1Setting<'a> {
    memory: ImageMemory<'a>,
    declarations: &'static Declarations,
    stack_pointer: RegisterId,
    arguments: Vec<RegisterId>,
    return_slot: Option<i64>,
    /// The register calls leave the return address in, if not the stack.
    link: Option<RegisterId>,
    /// The registers a callee keeps, by the convention.
    kept: Vec<RegisterId>,
    thread_pointer: Option<RegisterId>,
    /// The floating-point control registers.
    float_control: Vec<Control>,
    /// The x87 stack's tag word and TOP, if the convention has the stack.
    x87: Vec<RegisterId>,
}

impl<'a> L1Setting<'a> {
    /// The setting of the function of `image` at `entry`.
    fn new(image: &'a Image<'a>, entry: u64) -> Result<Self, String> {
        let environment = ImageEnvironment::new(image, &[]).map_err(|e| e.0)?;
        let declarations = environment.declarations();
        let (return_slot, link) = match setup(image, entry)?.link {
            Link::Stack { .. } => (Some(0), None),
            Link::Register(register) => (None, Some(register)),
        };
        let convention = convention(image, declarations);
        Ok(Self {
            memory: ImageMemory::new(image),
            declarations,
            stack_pointer: environment.stack_pointer(),
            arguments: environment.arguments(),
            return_slot,
            link,
            kept: convention.callee_saved,
            thread_pointer: convention.thread_pointer,
            float_control: convention
                .float_control
                .iter()
                .map(|control| Control {
                    register: control.register,
                    status_bits: control.status_bits,
                    default: control.default,
                })
                .collect(),
            x87: convention
                .x87
                .iter()
                .flat_map(|x87| [x87.tags, x87.top])
                .collect(),
        })
    }

    fn env(&self) -> L1Env<'_> {
        L1Env {
            declarations: self.declarations,
            memory: &self.memory,
            stack_pointer: self.stack_pointer,
            arguments: &self.arguments,
            return_slot: self.return_slot,
            thread_pointer: self.thread_pointer,
        }
    }
}

/// The `prepared` L1 of a function of `image`, lowered to goto-only L2
/// ([`lowering::lower_counted`], with the analyses its passes left) under
/// the image's convention and [`setup`], the callees' `interfaces` and
/// declared `prototypes`, and the image's data; with its mapping and
/// counts.
///
/// # Errors
///
/// The image's code is not lifted, or lowering fails.
pub fn lower_function(
    image: &Image<'_>,
    prepared: &Prepared,
    interfaces: &Interfaces,
    prototypes: &dyn Prototypes,
    data: &dyn Data,
) -> Result<(Ast, Mapping, lowering::Counts), String> {
    with_context(
        image,
        prepared.l1.entry,
        interfaces,
        prototypes,
        data,
        |context| {
            lowering::lower_counted(&prepared.l1, &prepared.facts, context)
                .map_err(|e| e.to_string())
        },
    )
}

/// `f` of the lowering context of the function of `image` at `entry`
/// (the interfaces of the functions it may call, declared prototypes, the
/// image's data).
pub(crate) fn with_context<T>(
    image: &Image<'_>,
    entry: u64,
    interfaces: &Interfaces,
    prototypes: &dyn Prototypes,
    data: &dyn Data,
    f: impl FnOnce(&Context<'_>) -> Result<T, String>,
) -> Result<T, String> {
    let setup = setup(image, entry)?;
    let convention = convention(image, setup.declarations);
    let context = Context {
        fixed: &setup.fixed,
        prototypes,
        data,
        interfaces: &interfaces.interfaces,
        functions: &interfaces.functions,
        read_results: interfaces.callers.result_unread(entry).then_some(&[][..]),
        preferred_result: interfaces.callers.preferred(entry),
        dropped: interfaces.callers.dropped(entry),
        schemes: &interfaces.callers.schemes,
        specialised: interfaces.callers.specialised(entry),
        specialisations: &interfaces.callers.specialised,
        assume_futex: interfaces.callers.assume,
        assume_forward_reach: interfaces.callers.assume,
        ..Context::new(
            setup.declarations,
            setup.stack_pointer,
            setup.link,
            &convention,
        )
    };
    f(&context)
}

/// `l2` as a C file under `style`, functions and globals named,
/// and read-only data and instructions without semantics read, from
/// `image`; those instructions as `opaque` says.
///
/// # Errors
///
/// The printer refuses the function.
fn print(
    l2: &Ast,
    declarations: &Declarations,
    style: &Style,
    image: &dyn Printing,
    opaque: Opaque,
) -> Result<C, String> {
    let printed = binbun_print::c::function(l2, declarations, style, image, opaque)
        .map_err(|error| format!("cannot print: {error}"))?;
    Ok(C {
        text: layout::render(&printed.document, style),
        casts: printed.counts.casts,
        unplanned: printed.counts.unplanned,
        asm: printed.counts.asm,
        unknowns: printed.counts.unknowns,
    })
}
