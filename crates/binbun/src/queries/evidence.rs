//! Why each variable of a decompiled function has its printed type and
//! name ([`explain`]): its parameters, locals, frame variables, the
//! globals and environment registers it uses, and its return value.
//!
//! The type's source, by the evidence lowering recorded on the variable
//! ([`Evidence`]) and what decided it:
//!
//! - declared: debug information (the function's prototype or a frame
//!   variable it describes), the function's own declared prototype (the
//!   type library, a mangling), the platform (the thread pointer), a
//!   frame object promoted to the type a callee declares for its address;
//! - deduced: the type solver, with the bounds its type variables solved
//!   to ([`Explained`](binbun_decompile::typing::Explained), never fed
//!   back, so the C is unchanged), the strongest deciding: a callee's
//!   declared prototype (which call, which parameter or its result), a
//!   callee's scheme, what every caller passes, or the function's own
//!   operations and accesses;
//! - default: nothing but the width.
//!
//! Each clue carries the machine instructions it comes from, and the
//! bounds that lost a conflict are listed apart: the evidence the type
//! does not follow; each reads in C's words: its shape as C writes the
//! type ([`shape_c`]: `uint32_t`, `void *`), why as the C operation and
//! where (`zero extension of v12 at 1CC29`). Names come from debug
//! information, symbols (globals),
//! the convention (`va_list`'s `ap`), or the printer. A user's names and
//! types are the session's: it overlays them on this.

use std::collections::BTreeSet;

use binbun_ast::ir::{Function as Ast, NameOrigin, Node, Origin, VarId, VarKind, Variable};
use binbun_ast::types::Evidence;
use binbun_decompile::lower;
use binbun_decompile::prototype::Prototypes as _;
use binbun_decompile::typing::{BoundShape, Clue as SolverClue, Explained, Reason};
use binbun_print::c;
use binbun_print::document::{Doc, Document, Token, TokenKind};
use binbun_print::style::Style;
use binbun_ssa::ir::{Definition, Function, Op, Value};
use binbun_typeinfer::{Atom, Format};

use super::{Lowered, calls_through, constant, defined_at, lower as lower_function, values_of};
use crate::Database;
use crate::cfg::FunctionId;
use crate::decompile::{Interfaces, View, with_context};
use crate::user::UserTypes;

/// Where a variable is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Subject {
    /// Parameter `n` (from 0).
    Parameter(usize),
    /// A local (no address).
    Local,
    /// The stack frame at this offset from the entry stack pointer.
    Frame(i64),
    /// A global at this address.
    Global(u64),
    /// What the platform keeps in a register (the thread pointer).
    Environment,
    /// The return value.
    Return,
}

/// Where a type's evidence comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// The user's type (Set type): above every other evidence.
    User,
    /// Debug information.
    Debug,
    /// The function's own declared prototype (the type library, a
    /// mangling).
    Prototype,
    /// The platform's declaration (the thread pointer's type).
    Platform,
    /// A declaration of the global (debug information, the type
    /// library).
    Declaration,
    /// A frame object promoted to the type a callee declares for a
    /// pointer to it.
    Promoted,
    /// A callee's declared prototype.
    Callee(Callee),
    /// A callee's solved type (its scheme), deduced in the callee.
    Scheme(Callee),
    /// What every caller passes the parameter.
    Callers,
    /// The program's type of the global: every function's evidence
    /// joined ([`Database::global_type`](crate::Database::global_type)).
    Program,
    /// The type solver, from the function's own code.
    Solver,
    /// Nothing but its width.
    Default,
}

/// A call whose callee's evidence types a value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Callee {
    /// The calls (their instructions' addresses).
    pub calls: Vec<u64>,
    /// The callee's address, if constant.
    pub address: Option<u64>,
    /// Its name, if it has one.
    pub name: Option<String>,
    /// The parameter (from 0), or `None`: its result.
    pub parameter: Option<usize>,
}

/// Where a name comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NameSource {
    /// The user's rename.
    User,
    /// Debug information.
    Debug,
    /// The image's symbols (a global).
    Symbol,
    /// The calling convention (`va_list`'s `ap`).
    Convention,
    /// The function's declared prototype (a parameter's declared name).
    Declared,
    /// A callee's declared parameter the variable is passed as.
    Argument,
    /// The counter of a `for` loop (`i`, `j`, `k`).
    Counter,
    /// The one variable the function returns (`result`).
    Result,
    /// The printer's default, by where the variable is.
    Printer,
}

/// One bound of the solver, as evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Clue {
    /// Below the value (what flows in) or above it (what a use demands).
    pub lower: bool,
    /// What it is.
    pub shape: BoundShape,
    /// How strong (0 to 6: what an earlier pass deduced, callers'
    /// agreement, flags, operations, accesses, floating point,
    /// declarations).
    pub strength: u8,
    /// Why, in C's words: the operation and where
    /// (`zero extension of v12 at 1CC29`).
    pub reason: String,
    /// The reason's call, where it is a callee's evidence.
    pub callee: Option<Callee>,
    /// The machine instructions it comes from.
    pub addresses: Vec<u64>,
    /// The reasons it travelled through to the value, nearest first, in
    /// C's words.
    pub path: Vec<String>,
}

/// One variable (or the return value) with its evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    /// Where it is.
    pub subject: Subject,
    /// The L2 variable (none for the return value).
    pub var: Option<VarId>,
    /// Its printed name (the function's, for the return value).
    pub name: String,
    /// Where the name comes from.
    pub name_source: NameSource,
    /// Its printed type.
    pub ty: String,
    /// The strength lowering recorded.
    pub evidence: Evidence,
    /// What decided the type.
    pub source: Source,
    /// The solver's bounds, strongest first.
    pub clues: Vec<Clue>,
    /// The bounds that lost a conflict: evidence the type does not
    /// follow.
    pub conflicts: Vec<Clue>,
}

/// Every printed variable of a function, and its return value, with
/// their evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Explanation {
    /// The function's entry.
    pub entry: u64,
    /// The view.
    pub view: View,
    /// The variables in the order the C declares them (parameters,
    /// locals, globals), then the return value if any.
    pub items: Vec<Item>,
}

impl Explanation {
    /// The item named `name`.
    pub fn named(&self, name: &str) -> Option<&Item> {
        self.items.iter().find(|item| item.name == name)
    }
}

/// The most clues listed per item.
const CLUES: usize = 12;

/// Why function `id` of `database`, decompiled in `view`, types and
/// names its variables as the C (in the K&R preset) prints them.
///
/// # Errors
///
/// The function cannot be decompiled or printed.
pub fn explain(database: &Database<'_>, id: FunctionId, view: View) -> Result<Explanation, String> {
    let (lowered, interfaces) = lower_function(database, id, view, &[])?;
    explain_lowered(database, &lowered, &interfaces, view)
}

/// [`explain`] of `lowered`, with its callees' `interfaces`.
///
/// # Errors
///
/// The function cannot be printed.
pub fn explain_lowered(
    database: &Database<'_>,
    lowered: &Lowered,
    interfaces: &Interfaces,
    view: View,
) -> Result<Explanation, String> {
    let l1 = &lowered.prepared.l1;
    let l2 = &lowered.l2;
    let declarations = database
        .declarations()
        .ok_or_else(|| "the image's code is not lifted".to_owned())?;
    let style = Style::preset("kr").ok_or_else(|| "no K&R preset".to_owned())?;
    let printed = c::function(l2, declarations, &style, database.data(), view.opaque())
        .map_err(|error| format!("cannot print: {error}"))?;
    let segments = segments(&printed.document);
    let values: Vec<Value> = l2
        .variables
        .iter()
        .flat_map(|variable| values_of(l1, variable.kind, &variable.origins))
        .collect();
    let prototypes = database.prototypes();
    let explained = with_context(
        database.image(),
        lowered.entry,
        interfaces,
        &prototypes,
        database.data(),
        |context| {
            lower::explain(l1, &lowered.prepared.facts, context, &values)
                .map_err(|error| error.to_string())
        },
    )?
    .unwrap_or_default();
    let mut scratch = l2.types.clone();
    let debug =
        database.debug().is_some() && prototypes.debug(lowered.entry, &mut scratch).is_some();
    let user = prototypes.user_types();
    let context = Context {
        database,
        l1,
        l2,
        explained: &explained,
        debug,
        user,
    };
    let mut items = Vec::new();
    let mut seen = BTreeSet::new();
    for tokens in &segments {
        for token in tokens {
            if token.kind.is_variable()
                && let Some(Node::Var(var)) = token.node
                && seen.insert(var)
                && let Some(item) = context.item(var, tokens)
            {
                items.push(item);
            }
        }
    }
    if l2.returns.is_some() {
        items.push(context.returns(&printed.document));
    }
    Ok(Explanation {
        entry: lowered.entry,
        view,
        items,
    })
}

/// What [`explain_lowered`] reads for each item.
struct Context<'a> {
    database: &'a Database<'a>,
    l1: &'a Function,
    l2: &'a Ast,
    explained: &'a Explained,
    /// Whether debug information states the function's prototype.
    debug: bool,
    /// The user's types.
    user: &'a UserTypes,
}

impl Context<'_> {
    /// Whether the user states the type of variable `variable` (a
    /// parameter: the function's prototype).
    fn stated(&self, variable: &Variable) -> bool {
        let entry = self.l2.address;
        match variable.kind {
            VarKind::Parameter => self.user.prototype(entry).is_some(),
            VarKind::Global(address) => self.user.global(address).is_some(),
            VarKind::Frame(offset) => self.user.frame(entry, offset).is_some(),
            VarKind::Local => variable.origins.iter().any(|origin| match *origin {
                Origin::Value(value) => self.user.value(entry, [value.0]).is_some(),
                Origin::Slot(offset) => self.user.frame(entry, offset).is_some(),
                Origin::Instruction(_)
                | Origin::Register(_)
                | Origin::Held(_)
                | Origin::Block(_)
                | Origin::Absorbed(_)
                | Origin::Proved => false,
            }),
            VarKind::Environment(_) => false,
        }
    }

    /// The item of variable `var`, declared among `tokens`.
    fn item(&self, var: VarId, tokens: &[&Token]) -> Option<Item> {
        let variable = self.l2.var(var)?;
        let (name, ty) = declaration(tokens, var)?;
        let subject = match variable.kind {
            VarKind::Parameter => Subject::Parameter(
                self.l2
                    .parameters
                    .iter()
                    .position(|&p| p == var)
                    .unwrap_or_default(),
            ),
            VarKind::Local => Subject::Local,
            VarKind::Frame(offset) => Subject::Frame(offset),
            VarKind::Global(address) => Subject::Global(address),
            VarKind::Environment(_) => Subject::Environment,
        };
        let name_source = match (&variable.name, variable.kind) {
            (Some(_), _) if self.l2.va_list() == Some(var) => NameSource::Convention,
            (Some(_), VarKind::Global(_)) => NameSource::Symbol,
            (Some(name), _) => match name.origin {
                NameOrigin::User => NameSource::User,
                NameOrigin::Convention => NameSource::Convention,
                NameOrigin::Debug => NameSource::Debug,
                NameOrigin::Declared => NameSource::Declared,
                NameOrigin::Argument => NameSource::Argument,
                NameOrigin::Counter => NameSource::Counter,
                NameOrigin::Result => NameSource::Result,
            },
            (None, VarKind::Global(address)) if self.database.data_name(address).is_some() => {
                NameSource::Symbol
            }
            (None, _) => NameSource::Printer,
        };
        let solver: Vec<&SolverClue> = match variable.kind {
            VarKind::Global(address) => self
                .explained
                .globals
                .get(&address)
                .map(|clues| clues.iter().collect())
                .unwrap_or_default(),
            VarKind::Parameter | VarKind::Local | VarKind::Frame(_) | VarKind::Environment(_) => {
                values_of(self.l1, variable.kind, &variable.origins)
                    .iter()
                    .filter_map(|value| self.explained.values.get(value))
                    .flatten()
                    .collect()
            }
        };
        let (clues, conflicts) = self.clues(&solver);
        let source = match variable.evidence {
            Evidence::Default => Source::Default,
            Evidence::Declared if self.stated(variable) => Source::User,
            Evidence::Declared | Evidence::DeclaredPointer => match variable.kind {
                VarKind::Parameter if self.debug => Source::Debug,
                VarKind::Parameter => Source::Prototype,
                VarKind::Environment(_) => Source::Platform,
                VarKind::Global(_) => Source::Declaration,
                VarKind::Frame(_) if self.l2.promoted.contains(&var) => Source::Promoted,
                VarKind::Local | VarKind::Frame(_) => Source::Debug,
            },
            Evidence::Deduced => self.deciding(&solver),
        };
        Some(Item {
            subject,
            var: Some(var),
            name,
            name_source,
            ty,
            evidence: variable.evidence,
            source,
            clues,
            conflicts,
        })
    }

    /// The return value's item, its type from `document`'s signature.
    fn returns(&self, document: &Document) -> Item {
        let (name, ty) = signature(document);
        let solver: Vec<&SolverClue> = self.explained.returns.iter().collect();
        let (clues, conflicts) = self.clues(&solver);
        let source = match self.l2.returns_evidence {
            Evidence::Default => Source::Default,
            Evidence::Declared if self.user.prototype(self.l2.address).is_some() => Source::User,
            Evidence::Declared | Evidence::DeclaredPointer if self.debug => Source::Debug,
            Evidence::Declared | Evidence::DeclaredPointer => Source::Prototype,
            Evidence::Deduced => self.deciding(&solver),
        };
        Item {
            subject: Subject::Return,
            var: None,
            name,
            name_source: NameSource::Symbol,
            ty,
            evidence: self.l2.returns_evidence,
            source,
            clues,
            conflicts,
        }
    }

    /// What decided a deduced type: the strongest bound that did not
    /// lose, by its reason.
    fn deciding(&self, solver: &[&SolverClue]) -> Source {
        let Some(best) = solver
            .iter()
            .filter(|clue| !clue.lost)
            .max_by_key(|clue| clue.strength)
        else {
            return Source::Solver;
        };
        match best.reason {
            Some(Reason::Argument { call, index }) => {
                Source::Callee(self.callee(call, Some(index)))
            }
            Some(Reason::Result(call)) => Source::Callee(self.callee(call, None)),
            Some(Reason::Scheme(call)) => Source::Scheme(self.callee(call, None)),
            Some(Reason::Callers(_)) => Source::Callers,
            Some(Reason::Program(_)) => Source::Program,
            Some(Reason::Parameter(_)) => Source::Prototype,
            Some(Reason::User) => Source::User,
            Some(
                Reason::Phi(_)
                | Reason::Select(_)
                | Reason::Compare { .. }
                | Reason::Truth(_)
                | Reason::Division(_)
                | Reason::Shift(_)
                | Reason::Extend(_)
                | Reason::Copy(_)
                | Reason::Flag(_)
                | Reason::Float(_)
                | Reason::Access(_)
                | Reason::Slot(_)
                | Reason::Global(_)
                | Reason::AddressOf(_)
                | Reason::Called(_)
                | Reason::Function(_)
                | Reason::String(_)
                | Reason::Text(_)
                | Reason::Returned,
            )
            | None => Source::Solver,
        }
    }

    /// The call through `target`, its `parameter` (or result).
    fn callee(&self, target: Value, parameter: Option<usize>) -> Callee {
        let address = constant(self.l1, target);
        Callee {
            calls: calls_through(self.l1, target),
            address,
            name: address.and_then(|address| self.database.data_name(address)),
            parameter,
        }
    }

    /// `solver`'s clues as evidence, deduplicated: those that hold, then
    /// those that lost (at most [`CLUES`] each).
    fn clues(&self, solver: &[&SolverClue]) -> (Vec<Clue>, Vec<Clue>) {
        let mut kept: Vec<Clue> = Vec::new();
        let mut losing: Vec<Clue> = Vec::new();
        let mut sorted: Vec<&&SolverClue> = solver.iter().collect();
        sorted.sort_by_key(|clue| core::cmp::Reverse(clue.strength));
        for clue in sorted {
            let list = if clue.lost { &mut losing } else { &mut kept };
            if list.len() >= CLUES {
                continue;
            }
            let converted = self.clue(clue);
            if !list.iter().any(|other| {
                other.reason == converted.reason
                    && other.shape == converted.shape
                    && other.lower == converted.lower
            }) {
                list.push(converted);
            }
        }
        (kept, losing)
    }

    fn clue(&self, clue: &SolverClue) -> Clue {
        let callee = match clue.reason {
            Some(Reason::Argument { call, index }) => Some(self.callee(call, Some(index))),
            Some(Reason::Result(call) | Reason::Scheme(call) | Reason::Called(call)) => {
                Some(self.callee(call, None))
            }
            Some(_) | None => None,
        };
        let mut addresses = clue
            .reason
            .map(|reason| reason_addresses(self.l1, reason))
            .unwrap_or_default();
        if let Some(callee) = &callee {
            addresses.extend(&callee.calls);
        }
        addresses.sort_unstable();
        addresses.dedup();
        Clue {
            lower: clue.lower,
            shape: clue.shape,
            strength: clue.strength,
            reason: clue.reason.map_or_else(
                || "unrecorded".to_owned(),
                |reason| reason_c(self.l1, reason),
            ),
            callee,
            addresses,
            path: clue
                .path
                .iter()
                .map(|&reason| reason_c(self.l1, reason))
                .collect(),
        }
    }
}

/// A bound's shape as C writes the type (`uint32_t`, `char`, `double`,
/// `void *`); what is no type in C, in words (`a struct`).
pub fn shape_c(shape: BoundShape) -> String {
    let integer = |signed: bool, width: u16| {
        let u = if signed { "" } else { "u" };
        match width {
            8 | 16 | 32 | 64 => format!("{u}int{width}_t"),
            128 if signed => "__int128".to_owned(),
            128 => "unsigned __int128".to_owned(),
            _ if signed => format!("_BitInt({width})"),
            _ => format!("unsigned _BitInt({width})"),
        }
    };
    match shape {
        // Nothing known but the width, or not the sign: as the printer
        // writes such an integer.
        BoundShape::Atom(Atom::Bits(width) | Atom::Unsigned(width)) => integer(false, width),
        BoundShape::Atom(Atom::Int(width) | Atom::Signed(width)) => integer(true, width),
        BoundShape::Atom(Atom::Enum { width, signed, .. }) => {
            format!("an enumeration ({})", integer(signed, width))
        }
        BoundShape::Atom(Atom::Bool(_)) => "bool".to_owned(),
        BoundShape::Atom(Atom::Char { .. }) => "char".to_owned(),
        BoundShape::Atom(Atom::Float(format)) => match format {
            Format::Half => "_Float16",
            Format::Single => "float",
            Format::Double => "double",
            Format::Extended => "long double",
        }
        .to_owned(),
        BoundShape::Pointer => "void *".to_owned(),
        BoundShape::Record => "a struct".to_owned(),
        BoundShape::Code => "a function".to_owned(),
        BoundShape::Other => "another value's type".to_owned(),
    }
}

/// Why `reason` says what it says, in C's words: the operation of `l1`
/// it is (`zero extension of v12`, `dereference`, `argument 2 of a
/// call`) and the instruction it is at (` at 1CC29`, hexadecimal as the
/// listing writes addresses).
fn reason_c(l1: &Function, reason: Reason) -> String {
    let of = |what: &str, v: Value| format!("{what} of v{}", v.0);
    let text = match reason {
        Reason::Phi(v) => of("paths joining", v),
        Reason::Select(v) => of("?: arm", v),
        Reason::Compare { at, signed } => of(
            if signed {
                "signed comparison"
            } else {
                "unsigned comparison"
            },
            at,
        ),
        Reason::Truth(v) => format!("comparison result v{}", v.0),
        Reason::Division(v) => of("division (/, %)", v),
        Reason::Shift(v) => of("right shift (>>)", v),
        Reason::Extend(v) => {
            let op = match l1.value(v).map(|info| &info.definition) {
                Some(&Definition::Result { inst, .. }) => l1.inst(inst).map(|i| &i.op),
                Some(Definition::Parameter { .. }) | None => None,
            };
            let signed = if let Some(&Op::Extend { signed, .. }) = op {
                Some(signed)
            } else {
                None
            };
            let what = match signed {
                Some(true) => "sign extension",
                Some(false) => "zero extension",
                None => "extension",
            };
            of(what, v)
        }
        Reason::Copy(v) => format!("v{} unchanged (x | 0)", v.0),
        Reason::Flag(v) => of("carry or overflow test", v),
        Reason::Float(v) => of("floating-point arithmetic", v),
        Reason::Access(_) => "dereference (*p)".to_owned(),
        Reason::Slot(_) => "local variable".to_owned(),
        Reason::Global(_) => "global variable".to_owned(),
        Reason::AddressOf(v) => format!("&local (v{})", v.0),
        Reason::Argument { index, .. } => format!("argument {} of a call", index + 1),
        Reason::Result(_) => "result of a call".to_owned(),
        Reason::Scheme(_) => "the callee's types at a call".to_owned(),
        Reason::Called(v) => format!("call through v{} (v{}())", v.0, v.0),
        Reason::Function(v) => format!("function address (&f) v{}", v.0),
        Reason::String(v) => format!("string literal address v{}", v.0),
        Reason::Text(v) => format!("tested only for characters v{}", v.0),
        Reason::Parameter(index) => format!("declared parameter {}", index + 1),
        Reason::Callers(index) => format!("every caller's argument {}", index + 1),
        Reason::Program(address) => format!("the program's type of the global at {address:X}"),
        Reason::Returned => "return value".to_owned(),
        Reason::User => "your type".to_owned(),
    };
    match reason_addresses(l1, reason).first() {
        Some(address) => format!("{text} at {address:X}"),
        None => text,
    }
}

/// The machine instructions `reason` names.
fn reason_addresses(l1: &Function, reason: Reason) -> Vec<u64> {
    let value = match reason {
        Reason::Phi(value)
        | Reason::Select(value)
        | Reason::Compare { at: value, .. }
        | Reason::Truth(value)
        | Reason::Division(value)
        | Reason::Shift(value)
        | Reason::Extend(value)
        | Reason::Copy(value)
        | Reason::Flag(value)
        | Reason::Float(value)
        | Reason::AddressOf(value)
        | Reason::Function(value)
        | Reason::String(value)
        | Reason::Text(value) => value,
        Reason::Access(inst) | Reason::Slot(inst) | Reason::Global(inst) => {
            return l1.inst(inst).map(|inst| inst.address).into_iter().collect();
        }
        Reason::Argument { call, .. }
        | Reason::Result(call)
        | Reason::Scheme(call)
        | Reason::Called(call) => return calls_through(l1, call),
        Reason::Parameter(_)
        | Reason::Callers(_)
        | Reason::Program(_)
        | Reason::Returned
        | Reason::User => {
            return Vec::new();
        }
    };
    defined_at(l1, value).into_iter().collect()
}

/// The document's tokens in segments: each top-level item, and each item
/// of a braced block, apart (braces are no tokens, so a block's first
/// declaration would otherwise run on from what precedes it).
fn segments(document: &Document) -> Vec<Vec<&Token>> {
    /// Tokens with their place in the document.
    type Segment<'d> = Vec<(usize, &'d Token)>;
    fn walk<'d>(
        doc: &'d Doc,
        place: &mut usize,
        current: &mut Segment<'d>,
        out: &mut Vec<Segment<'d>>,
    ) {
        match doc {
            Doc::Token(token) => {
                current.push((*place, token));
                *place += 1;
            }
            Doc::Group(items) | Doc::Nest(items) | Doc::Outdent(items) => {
                for item in items {
                    walk(item, place, current, out);
                }
            }
            Doc::Block { body, .. } => {
                for item in body {
                    let mut inner = Vec::new();
                    walk(item, place, &mut inner, out);
                    out.push(inner);
                }
            }
            Doc::Space
            | Doc::Line
            | Doc::SoftLine
            | Doc::HardLine
            | Doc::BlankLine
            | Doc::AfterBlock => {}
        }
    }
    let mut out = Vec::new();
    let mut place = 0;
    for item in &document.items {
        let mut current = Vec::new();
        walk(item, &mut place, &mut current, &mut out);
        out.push(current);
    }
    // In the order the C reads: a segment is pushed after the blocks
    // inside it, so order them by their first token's place.
    out.retain(|segment| !segment.is_empty());
    out.sort_by_key(|segment| segment.first().map(|&(place, _)| place));
    out.into_iter()
        .map(|segment| segment.into_iter().map(|(_, token)| token).collect())
        .collect()
}

/// The printed name and type of `var`: its first declaration among
/// `tokens` (a segment: the signature's parameters, the locals, the
/// globals' `extern`s), the declarator's tokens around the name joined:
/// back to a separator outside parentheses or the `(` opening a
/// function's parameter list (one after a name), and on to a separator
/// outside them or the `)` closing that list (`int (*f)(int)` whole).
fn declaration(tokens: &[&Token], var: VarId) -> Option<(String, String)> {
    let at = tokens
        .iter()
        .position(|token| token.kind.is_variable() && token.node == Some(Node::Var(var)))?;
    let name = tokens.get(at)?.text.clone();
    let stop = |token: &Token, depth: usize| {
        matches!(token.kind, TokenKind::Comment)
            || (token.kind == TokenKind::Punctuation
                && depth == 0
                && matches!(token.text.as_str(), ";" | "," | "{" | "}" | "="))
            || (token.kind == TokenKind::Keyword && token.text == "extern")
    };
    let mut start = at;
    let mut depth = 0usize;
    // The `(`s before the name it is inside (`int (*f)`).
    let mut open = 0usize;
    while let Some(previous) = start.checked_sub(1).and_then(|i| tokens.get(i)) {
        if stop(previous, depth) {
            break;
        }
        match previous.text.as_str() {
            ")" => depth += 1,
            "(" if depth == 0 => {
                let after_name = start
                    .checked_sub(2)
                    .and_then(|i| tokens.get(i))
                    .is_none_or(|before| before.kind.is_name());
                if after_name {
                    break;
                }
                open += 1;
            }
            "(" => depth -= 1,
            _ => {}
        }
        start -= 1;
    }
    let mut end = at + 1;
    let mut depth = 0usize;
    while let Some(next) = tokens.get(end) {
        if stop(next, depth) {
            break;
        }
        match next.text.as_str() {
            "(" => depth += 1,
            ")" if depth == 0 && open > 0 => open -= 1,
            ")" if depth == 0 => break,
            ")" => depth -= 1,
            _ => {}
        }
        end += 1;
    }
    let before = tokens.get(start..at).unwrap_or_default();
    let after = tokens.get(at + 1..end).unwrap_or_default();
    Some((name, join(before.iter().chain(after))))
}

/// The function's printed name and return type, from its signature.
fn signature(document: &Document) -> (String, String) {
    let head = match document.items.last() {
        Some(Doc::Group(definition)) => definition.first(),
        _ => None,
    };
    let mut tokens = Vec::new();
    if let Some(head) = head {
        flatten(head, &mut tokens);
    }
    let at = tokens
        .windows(2)
        .position(|pair| {
            matches!(pair, [name, open] if name.kind == TokenKind::Function
                && name.node.is_none() && open.text == "(")
        })
        .unwrap_or(tokens.len());
    let name = tokens
        .get(at)
        .map(|token| token.text.clone())
        .unwrap_or_default();
    (name, join(tokens.get(..at).unwrap_or_default().iter()))
}

fn flatten<'d>(doc: &'d Doc, out: &mut Vec<&'d Token>) {
    match doc {
        Doc::Token(token) => out.push(token),
        Doc::Group(items)
        | Doc::Nest(items)
        | Doc::Outdent(items)
        | Doc::Block { body: items, .. } => {
            for item in items {
                flatten(item, out);
            }
        }
        Doc::Space
        | Doc::Line
        | Doc::SoftLine
        | Doc::HardLine
        | Doc::BlankLine
        | Doc::AfterBlock => {}
    }
}

/// Tokens as a type: a space between two words, before a `*` or `(`
/// after one, and after a comma.
fn join<'t>(tokens: impl Iterator<Item = &'t &'t Token>) -> String {
    let mut out = String::new();
    let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    for token in tokens {
        let text = token.text.as_str();
        let last = out.chars().last();
        let first = text.chars().next();
        let space = match (last, first) {
            (Some(l), Some(f)) => (word(l) && (word(f) || f == '*' || f == '(')) || l == ',',
            _ => false,
        };
        if space {
            out.push(' ');
        }
        out.push_str(text);
    }
    out
}

#[cfg(test)]
mod tests {
    use binbun_decompile::typing::{BoundShape, Reason};
    use binbun_ssa::ir::{Definition, Function, Inst, InstId, Op, Type, Unknown, Value, ValueInfo};
    use binbun_typeinfer::{Atom, Format};

    use super::{reason_c, shape_c};

    #[test]
    fn every_shape_is_spelled_as_c_writes_the_type() {
        let spelled = [
            (BoundShape::Atom(Atom::Unsigned(32)), "uint32_t"),
            (BoundShape::Atom(Atom::Bits(64)), "uint64_t"),
            (BoundShape::Atom(Atom::Signed(8)), "int8_t"),
            (BoundShape::Atom(Atom::Int(16)), "int16_t"),
            (BoundShape::Atom(Atom::Signed(128)), "__int128"),
            (BoundShape::Atom(Atom::Unsigned(24)), "unsigned _BitInt(24)"),
            (BoundShape::Atom(Atom::Bool(8)), "bool"),
            (
                BoundShape::Atom(Atom::Enum {
                    id: 3,
                    width: 32,
                    signed: false,
                }),
                "an enumeration (uint32_t)",
            ),
            (BoundShape::Atom(Atom::Char { signed: true }), "char"),
            (BoundShape::Atom(Atom::Float(Format::Double)), "double"),
            (
                BoundShape::Atom(Atom::Float(Format::Extended)),
                "long double",
            ),
            (BoundShape::Pointer, "void *"),
        ];
        for (shape, c) in spelled {
            assert_eq!(shape_c(shape), c, "{shape:?}");
        }
        // No Rust debug text in any of them.
        for shape in [BoundShape::Record, BoundShape::Code, BoundShape::Other] {
            let c = shape_c(shape);
            assert!(!c.contains(['(', ')']) && !c.contains("Record"), "{c}");
        }
    }

    #[test]
    fn a_reason_reads_as_the_c_operation_and_where_it_is() {
        // v0 is an argument; v1 its zero extension at 0x1cc29, v2 its sign
        // extension at 0x1cc30.
        let inst = |op, result, address| Inst {
            op,
            results: vec![Value(result)],
            address,
        };
        let value = |definition| ValueInfo {
            ty: Type::Bits(64),
            definition,
        };
        let extend = |signed| Op::Extend {
            signed,
            value: Value(0),
            width: 64,
        };
        let l1 = Function {
            entry: 0x1cc00,
            blocks: Vec::new(),
            insts: vec![
                inst(Op::Undefined(Unknown::Unwritten, Vec::new()), 0, 0x1cc20),
                inst(extend(false), 1, 0x1cc29),
                inst(extend(true), 2, 0x1cc30),
            ],
            values: (0..3)
                .map(|i| {
                    value(Definition::Result {
                        inst: InstId(i),
                        index: 0,
                    })
                })
                .collect(),
            ..Function::default()
        };
        assert_eq!(
            reason_c(&l1, Reason::Extend(Value(1))),
            "zero extension of v1 at 1CC29"
        );
        assert_eq!(
            reason_c(&l1, Reason::Extend(Value(2))),
            "sign extension of v2 at 1CC30"
        );
        assert_eq!(
            reason_c(
                &l1,
                Reason::Compare {
                    at: Value(0),
                    signed: true
                }
            ),
            "signed comparison of v0 at 1CC20"
        );
        assert_eq!(
            reason_c(&l1, Reason::Access(InstId(1))),
            "dereference (*p) at 1CC29"
        );
        // Nowhere in the code: no address.
        assert_eq!(reason_c(&l1, Reason::Parameter(0)), "declared parameter 1");
        assert_eq!(reason_c(&l1, Reason::User), "your type");
    }
}
