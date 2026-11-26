//! Calls and the function's own signature: each call's callee (its
//! arguments and result, from a declared prototype, else the callee's
//! [`Interface`](super::Interface), else the convention, unknown), the
//! return value, and what each call's results are.
//!
//! The arguments past a prototype's parameters (it is variadic), and all
//! of an unknown callee's, are not declared. A declared format string
//! ([`Prototype::format`](crate::prototype::Prototype::format)) that is a
//! constant string in read-only data and parses
//! ([`format::parse`](crate::format::parse)) gives them exactly, with
//! their types. Otherwise they are the convention's remaining integer
//! argument registers up to the last one the call may pass something in:
//! a register whose value at the call is undefined on every path (a
//! previous call's clobber) passes nothing a callee could depend on. A
//! register holding the caller's own entry value untouched is kept: it may
//! be the caller's parameter passed on in place, and nothing in the caller
//! says it is not. That is the known limit: without a format string, an
//! untouched argument register stays an argument (and so the caller's
//! parameter). Only the caller's callers know whether they set it, and
//! they are lowered after it; a second pass informed by them could drop a
//! parameter no caller ever sets. The reading view's first assumption
//! does (`callers` in `binbun::decompile`), for registers a call passes
//! where nothing says the callee reads them (`Lowering::forwarded_reads`).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;

use binbun_ast::types::{Evidence, Signature, Type, TypeId, Types};
use binbun_semantics::Declarations;
use binbun_semantics::bits::Bits;
use binbun_semantics::ir::{Binary, Format as FloatFormat, LaneOp, RegisterId};
use binbun_ssa::ir::{Definition, InstId, Op, Terminator, Unknown, Value, ValueInfo};
use binbun_ssa::stack::top_byte_view;

use super::facts::{Kind, Lowering, Site};
use super::frame::Home;
use super::{Aggregates, Context, Convention, Interface, Passed, Read};
use crate::format::{self, Argument, Integer, Refusal, Scalar};
use crate::mapping::{Piece, Source};
use crate::prototype::{AllocSize, Format, Prototype, Prototypes};

/// A call's callee, as the call passes arguments and gets its result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Callee {
    /// The address called, if it is a constant.
    pub(super) target: Option<u64>,
    /// The slot of the import called, if the call goes through a slot
    /// that holds its import from the start and never changes
    /// ([`Data::fixed_import`](crate::data::Data::fixed_import)): a call
    /// of the import ([`AstCallee::Import`](binbun_ast::ir::Callee::Import)),
    /// not of the value loaded.
    pub(super) import: Option<u64>,
    /// A jump into the body of another function: a `ForeignJump` escape,
    /// not a tail call.
    pub(super) foreign: bool,
    /// Where each argument is, in the state at the call.
    pub(super) arguments: Vec<Source>,
    /// Where its return value is after the call, low bits first.
    pub(super) results: Vec<Piece>,
    /// Its type (a `Code` type).
    pub(super) signature: TypeId,
    /// The types of the arguments past the signature's parameters, from a
    /// parsed format string (empty: none).
    pub(super) variadic: Vec<TypeId>,
    /// What became of its declared format string, if it has one.
    pub(super) format: Option<Formatting>,
    /// Whether its arguments and result are its [`Interface`](super::Interface)'s (a
    /// function of the program with no prototype): its scheme, if any,
    /// types them ([`crate::typing`]).
    pub(super) interfaced: bool,
    /// Whether its arguments and result are a declared prototype's: the
    /// declaration, not an interface of the program, says what it reads.
    pub(super) declared: bool,
    /// The parameters its declaration says give the size of the object
    /// it returns, if it says.
    pub(super) alloc_size: Option<AllocSize>,
    /// The format string its declaration says describes the `va_list`
    /// parameter after it (C's `v` functions: [`Format::list`]), if it
    /// says.
    pub(super) list_format: Option<Format>,
}

/// What became of a call's declared format string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Formatting {
    /// Parsed: it gives the arguments.
    Parsed,
    /// Not a constant string in read-only data, nor the result of a
    /// translation of such strings that agree
    /// ([`Prototype::format_arg`]).
    NotConstant,
    /// A constant string the parser refuses.
    Refused(Refusal),
    /// Parsed, but its arguments' types cannot be placed (a `long` of
    /// unknown width, an argument the convention cannot pass).
    Unplaced,
}

/// The function's own signature.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Returns {
    /// Where its return value is at a return, low bits first (empty: none).
    pub(super) pieces: Vec<Piece>,
    /// The return value's type.
    pub(super) ty: Option<TypeId>,
    /// From a declared prototype: its parameters, where, of what type
    /// and on what evidence ([`Evidence::Declared`], or
    /// [`Evidence::DeclaredPointer`] for one declared only a pointer:
    /// [`Prototype::open`]).
    pub(super) declared: Option<Vec<(Source, TypeId, Evidence)>>,
    /// Whether the declared prototype states the return value (if not,
    /// [`pieces`](Self::pieces) and [`ty`](Self::ty) are what every exit
    /// writes, as without a declaration).
    pub(super) stated: bool,
    /// Whether the stated return value is declared only a pointer.
    pub(super) open: bool,
}

/// A declared signature placed in the convention's registers and stack.
pub(super) struct Placed {
    pub(super) parameters: Vec<(Source, TypeId)>,
    pub(super) returns: Vec<Piece>,
    /// The signature these are the places of, where it is not the
    /// declared one: an aggregate in two registers or returned in memory
    /// has no one place ([`Placer::place`]).
    pub(super) lowered: Option<TypeId>,
    /// Where each declared parameter is, in the declared order: several
    /// places where it is a struct or union passed in parts.
    pub(super) declared: Vec<Vec<Source>>,
    /// Whether each declared parameter is the parameter of its position
    /// in the lowered signature too: none takes its place first (the
    /// address of a result returned in memory) and none is in parts or
    /// moved after the registers; a struct or union is one value in its
    /// place (a pointer or an integer, [`Placer::one_slot`], or one
    /// register). What a declaration counts by position (a format string,
    /// a size) is then where it counts it.
    pub(super) kept: bool,
}

/// How a convention passes an aggregate by value.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Passing {
    /// In registers, one per eightbyte: whether each is a vector one.
    Registers(Vec<bool>),
    /// In memory.
    Memory,
}

/// What a call calls, as far as its target value says.
#[derive(Clone, Copy, Debug)]
enum Called {
    /// Code at a constant address.
    Address(u64),
    /// The address loaded from the pointer at a constant address (a
    /// slot an import's prototype may be known through).
    Through(u64),
    /// A computed address.
    Computed,
}

/// The most values one search through block parameters looks at.
const STEPS: usize = 4096;

/// How many extensions and extractions [`Lowering::immediate`] looks
/// through.
const FITS: usize = 8;

/// How many operations [`Lowering::vacant_part`] looks through: a
/// register a `movsd` loaded and three scalar instructions then wrote
/// (`mulsd`, `cvtsd2ss`, `cvtss2sd`, each keeping what was above its
/// result) is nine deep above its low lane.
const VACANT: usize = 16;

/// The widest scalar (in bits) a variable of the image's data, an element
/// of one, or a parameter or result of a function referred to by its
/// address may be: C's widest integer. A wider access (a vector's) stays
/// an access at its address, and a function taking vectors a number.
pub(crate) const MAX_SCALAR: u16 = 128;

impl<'c> Lowering<'_, 'c> {
    /// Each call's callee. A callee known only by its address gets one
    /// signature for all the function's calls to it: the argument
    /// registers any of them may pass something in ([`unknown`](Self::unknown)).
    pub(super) fn resolve_calls(&mut self) {
        let mut sites = Vec::new();
        for (id, block) in self.blocks() {
            for &inst in &block.insts {
                if let Some(Op::Call { target, .. }) = self.l1.inst(inst).map(|i| &i.op) {
                    sites.push((Site::Call(inst), *target, false));
                }
            }
            if let Terminator::Leave { address, .. } = block.terminator {
                sites.push((Site::Tail(id), address, true));
            }
        }
        let sites: Vec<(Site, Called, bool)> = sites
            .into_iter()
            .map(|(site, target, tail)| (site, self.called(target), tail))
            .collect();
        let mut widest: BTreeMap<u64, usize> = BTreeMap::new();
        for &(site, target, _) in &sites {
            let key = match target {
                Called::Address(address) => Some(address),
                Called::Through(_) => self.fixed_slot(target),
                Called::Computed => None,
            };
            if let Some(address) = key {
                let passed = self.passed(site, 0).len();
                let entry = widest.entry(address).or_default();
                *entry = (*entry).max(passed);
            }
        }
        for (site, target, tail) in sites {
            let mut callee = self.callee(site, target, tail, &widest);
            if callee.target.is_none() && !callee.foreign {
                callee.import = self.fixed_slot(target);
            }
            self.callees.insert(site, callee);
        }
    }

    /// The slot of the fixed import `target` calls through, if it does
    /// ([`Data::fixed_import`](crate::data::Data::fixed_import)).
    fn fixed_slot(&self, target: Called) -> Option<u64> {
        match target {
            Called::Through(slot) if self.cx.data.fixed_import(slot, self.pointer / 8) => {
                Some(slot)
            }
            Called::Through(_) | Called::Address(_) | Called::Computed => None,
        }
    }

    /// The slot of the fixed import load `inst` reads, if it reads one.
    pub(super) fn fixed_slot_of(&self, inst: InstId) -> Option<u64> {
        self.fixed_slot(Called::Through(self.slot(inst)?))
    }

    /// The system calls whose number (in the convention's first system
    /// call register) is a constant the declarations know
    /// ([`Prototypes::system_call`](crate::prototype::Prototypes::system_call)).
    pub(super) fn resolve_system_calls(&mut self) {
        let Some(number) = self.cx.convention.system_call.first() else {
            return;
        };
        let mut found = BTreeMap::new();
        let mut unsettled = false;
        for (_, block) in self.blocks() {
            for &inst in &block.insts {
                let Some(Op::SystemCall { registers, .. }) = self.l1.inst(inst).map(|i| &i.op)
                else {
                    continue;
                };
                let Some(&value) = registers.get(usize::from(number.0)) else {
                    continue;
                };
                if let Kind::Const(bits) = self.kind(value)
                    && bits.width() <= 64
                    && let Some(call) = self.cx.prototypes.system_call(bits.low_u64())
                {
                    let mut call = call;
                    // `futex` reads as many arguments as its operation
                    // takes: its command, wherever its bits are known (a
                    // constant, or a flag or-ed or masked in).
                    if call.name == "futex"
                        && let Some(&op) = self
                            .cx
                            .convention
                            .system_call
                            .get(2)
                            .and_then(|register| registers.get(usize::from(register.0)))
                    {
                        let settled = self.futex_count(op, FUTEX_DEPTH);
                        unsettled |= settled.is_none();
                        let arguments = settled.or_else(|| {
                            self.cx
                                .assume_futex
                                .then(|| self.futex_assumed(op))
                                .flatten()
                        });
                        if let Some(arguments) = arguments {
                            call.arguments = call.arguments.min(arguments);
                        }
                    }
                    found.insert(inst, call);
                }
            }
        }
        self.system_calls = found;
        self.unsettled_futex = unsettled;
    }

    /// The registers system call `inst` reads: the convention's number
    /// register, then its argument registers, only as many as the call
    /// takes where its number is known ([`Self::resolve_system_calls`]),
    /// else all of them.
    pub(super) fn system_call_registers(&self, inst: InstId) -> &'c [RegisterId] {
        let all = self.cx.convention.system_call.as_slice();
        self.system_calls
            .get(&inst)
            .and_then(|call| all.get(..=call.arguments))
            .unwrap_or(all)
    }

    /// What a call to `target` calls. An AArch64 target is its value's
    /// branch-target view ([`top_byte_view`]): of a pointer loaded from a
    /// slot (an import's, `adrp`, `ldr`, `blr` through the IAT or the GOT),
    /// the pointer itself, a function's address whose top byte is 0.
    fn called(&self, target: Value) -> Called {
        let target = top_byte_view(self.l1, target).unwrap_or(target);
        match self.kind(target) {
            Kind::Const(bits) => Called::Address(bits.low_u64()),
            Kind::Load(inst) => self.slot(inst).map_or(Called::Computed, Called::Through),
            Kind::None
            | Kind::Undefined(..)
            | Kind::Address(_)
            | Kind::Entry(_)
            | Kind::Phi
            | Kind::Pure(_)
            | Kind::Result(_)
            | Kind::CallView { .. } => Called::Computed,
        }
    }

    /// The constant address load `inst` reads a pointer from, if it does
    /// and the address may be one of the image's (computed, or the image
    /// is at a fixed address: [`Data::relocatable`](crate::data::Data::relocatable)).
    fn slot(&self, inst: InstId) -> Option<u64> {
        let &Op::Load { address, bytes, .. } = &self.l1.inst(inst)?.op else {
            return None;
        };
        if self.cx.data.relocatable() && self.immediate(address) {
            return None;
        }
        match self.kind(address) {
            Kind::Const(bits) if bytes.saturating_mul(8) == self.pointer => Some(bits.low_u64()),
            Kind::Const(_)
            | Kind::None
            | Kind::Undefined(..)
            | Kind::Address(_)
            | Kind::Entry(_)
            | Kind::Phi
            | Kind::Pure(_)
            | Kind::Load(_)
            | Kind::Result(_)
            | Kind::CallView { .. } => None,
        }
    }

    /// The callee at `target`, called or (`tail`) jumped to at `site`;
    /// `widest`: how many argument registers the function's calls to each
    /// address may pass something in, at most.
    fn callee(
        &mut self,
        site: Site,
        target: Called,
        tail: bool,
        widest: &BTreeMap<u64, usize>,
    ) -> Callee {
        let cx = self.cx;
        let (address, prototype) = match target {
            Called::Address(address) => (Some(address), cx.prototypes.of(address, &mut self.types)),
            Called::Through(slot) => (None, cx.prototypes.through(slot, &mut self.types)),
            Called::Computed => (None, None),
        };
        if let Some(prototype) = prototype
            && let Some(signature) = self.types.signature(prototype.signature).cloned()
            && let Some(placed) = self.place_declared(&prototype, &signature)
        {
            return self.declared(site, address, &prototype, &signature, placed);
        }
        if let Some(address) = address {
            if let Some(interface) = cx.interfaces.get(&address) {
                let signature = interface_signature(interface, &mut self.types);
                let mut signature = classed(
                    &mut self.types,
                    cx.convention,
                    signature,
                    &interface.parameters,
                    &interface.returns,
                );
                if interface.alloc_size.is_some() {
                    signature = allocating(&mut self.types, signature);
                }
                let mut callee = Callee {
                    target: Some(address),
                    import: None,
                    foreign: false,
                    arguments: interface.parameters.clone(),
                    results: interface.returns.clone(),
                    signature,
                    variadic: Vec::new(),
                    format: None,
                    interfaced: true,
                    declared: false,
                    alloc_size: interface.alloc_size,
                    list_format: None,
                };
                if interface.variadic {
                    self.interfaced_variadic(site, interface, &mut callee);
                }
                return callee;
            }
            if tail && !cx.functions.is_empty() && !cx.functions.contains(&address) {
                let signature = self.types.intern(Type::Code(Signature::default()));
                return Callee {
                    target: Some(address),
                    import: None,
                    foreign: true,
                    arguments: Vec::new(),
                    results: Vec::new(),
                    signature,
                    variadic: Vec::new(),
                    format: None,
                    interfaced: false,
                    declared: false,
                    alloc_size: None,
                    list_format: None,
                };
            }
        }
        let passed = address
            .or_else(|| self.fixed_slot(target))
            .and_then(|address| widest.get(&address).copied());
        self.unknown(site, address, passed.unwrap_or(0))
    }

    /// The callee at `address` (if constant) of declared `prototype`
    /// (whose signature is `signature`, placed as `placed`), called at
    /// `site`: its parameters, then the arguments its format string gives,
    /// or if it has none that parses, the convention's integer argument
    /// registers after its parameters the call may pass something in
    /// ([`passed`](Self::passed)).
    fn declared(
        &mut self,
        site: Site,
        address: Option<u64>,
        prototype: &Prototype,
        signature: &Signature,
        placed: Placed,
    ) -> Callee {
        let mut callee = Callee {
            target: address,
            import: None,
            foreign: false,
            arguments: placed
                .parameters
                .iter()
                .map(|&(source, _)| source)
                .collect(),
            results: placed.returns,
            signature: placed.lowered.unwrap_or(prototype.signature),
            variadic: Vec::new(),
            format: None,
            interfaced: false,
            declared: true,
            alloc_size: prototype.alloc_size,
            list_format: prototype.format.filter(|format| format.list),
        };
        if !signature.variadic {
            return callee;
        }
        if let Some(format) = prototype.format.filter(|format| !format.list) {
            match self.formatted(site, format, signature, &placed.parameters) {
                Ok((arguments, variadic)) => {
                    callee.arguments = arguments;
                    callee.variadic = variadic;
                    callee.format = Some(Formatting::Parsed);
                    return callee;
                }
                Err(formatting) => callee.format = Some(formatting),
            }
        }
        // Unnamed arguments on the stack are as many as the format says;
        // without one, none is known.
        if self.cx.convention.variadic_on_stack {
            return callee;
        }
        let integers = &self.cx.convention.arguments;
        let used = callee
            .arguments
            .iter()
            .filter(
                |source| matches!(source, Source::Register(piece) if integers.contains(&piece.register)),
            )
            .count();
        let extra = self.passed(site, used);
        callee.arguments.extend(extra);
        callee
    }

    /// The arguments past the parameters of `interface` (of a variadic
    /// function of the program, as `callee` has them) at call `site`:
    /// those its own format string gives ([`Interface::format`]), or, if
    /// it has none that parses, the convention's integer argument
    /// registers after its parameters the call may pass something in
    /// ([`passed`](Self::passed)), then its vector ones
    /// ([`passed_vectors`](Self::passed_vectors)).
    fn interfaced_variadic(&mut self, site: Site, interface: &Interface, callee: &mut Callee) {
        if let Some(format) = interface.format
            && let Some(signature) = self.types.signature(callee.signature).cloned()
        {
            let parameters: Vec<(Source, TypeId)> = interface
                .parameters
                .iter()
                .copied()
                .zip(signature.parameters.iter().copied())
                .collect();
            match self.formatted(site, format, &signature, &parameters) {
                Ok((arguments, variadic)) => {
                    callee.arguments = arguments;
                    callee.variadic = variadic;
                    callee.format = Some(Formatting::Parsed);
                    return;
                }
                Err(formatting) => callee.format = Some(formatting),
            }
        }
        if self.cx.convention.variadic_on_stack {
            return;
        }
        // A named `double` takes a vector register, no integer one.
        let integers = &self.cx.convention.arguments;
        let used = callee
            .arguments
            .iter()
            .filter(
                |source| matches!(source, Source::Register(piece) if integers.contains(&piece.register)),
            )
            .count();
        let extra = self.passed(site, used);
        callee.arguments.extend(extra);
        let vectors = self.passed_vectors(site, &callee.arguments);
        callee.arguments.extend(vectors);
    }

    /// The arguments past the declared parameters that format string
    /// `format` of a function of `signature` (its parameters placed at
    /// `parameters`) gives at call `site`, with their types; why not, if
    /// it does not.
    fn formatted(
        &mut self,
        site: Site,
        format: Format,
        signature: &Signature,
        parameters: &[(Source, TypeId)],
    ) -> Result<(Vec<Source>, Vec<TypeId>), Formatting> {
        let &(source, ty) = parameters
            .get(format.string)
            .ok_or(Formatting::NotConstant)?;
        let Source::Register(piece) = source else {
            return Err(Formatting::NotConstant);
        };
        let &value = self
            .site_registers(site)
            .get(usize::from(piece.register.0))
            .ok_or(Formatting::NotConstant)?;
        let strings = self.format_strings(value).ok_or(Formatting::NotConstant)?;
        let mut parsed: Option<Vec<Argument>> = None;
        for bytes in strings {
            let arguments = format::parse(format.family, &bytes).map_err(Formatting::Refused)?;
            if parsed.as_ref().is_some_and(|first| *first != arguments) {
                return Err(Formatting::NotConstant);
            }
            parsed = Some(arguments);
        }
        let arguments = parsed.ok_or(Formatting::NotConstant)?;
        let character = match self.types.get(ty) {
            Some(&Type::Pointer(Some(character))) => character,
            Some(_) | None => self.types.intern(Type::Char { signed: true }),
        };
        let variadic = arguments
            .into_iter()
            .map(|argument| self.format_type(argument, character))
            .collect::<Option<Vec<_>>>()
            .ok_or(Formatting::Unplaced)?;
        let mut extended = signature.clone();
        extended.parameters.extend(variadic.iter().copied());
        let placed = self
            .place_named(&extended, signature.parameters.len())
            .ok_or(Formatting::Unplaced)?;
        let arguments = placed
            .parameters
            .iter()
            .map(|&(source, _)| source)
            .collect();
        Ok((arguments, variadic))
    }

    /// The bytes (before the NUL) of the format strings `value` stands
    /// for: the constant string in read-only data it is, or, where it is
    /// the return value of a call to a declared translation
    /// ([`Prototype::format_arg`], as `dcgettext`), the constant strings
    /// that call passes at those parameters, every one (GNU gettext's
    /// documented contract, which GCC's format checking relies on: a
    /// translation keeps its message's conversions). `None` where any is
    /// not such a string.
    fn format_strings(&mut self, value: Value) -> Option<Vec<Vec<u8>>> {
        let inst = match self.kind(value) {
            Kind::Const(_) => return Some(vec![self.constant_string(value)?]),
            Kind::Result(inst) => inst,
            Kind::None
            | Kind::Undefined(..)
            | Kind::Address(_)
            | Kind::Entry(_)
            | Kind::Phi
            | Kind::Pure(_)
            | Kind::Load(_)
            | Kind::CallView { .. } => return None,
        };
        let &Op::Call { target, .. } = &self.l1.inst(inst)?.op else {
            return None;
        };
        let cx = self.cx;
        let prototype = match self.called(target) {
            Called::Address(address) => cx.prototypes.of(address, &mut self.types),
            Called::Through(slot) => cx.prototypes.through(slot, &mut self.types),
            Called::Computed => None,
        }?;
        if prototype.format_arg.is_empty() {
            return None;
        }
        let signature = self.types.signature(prototype.signature).cloned()?;
        let placed = self.place_declared(&prototype, &signature)?;
        let [returned] = placed.returns[..] else {
            return None;
        };
        if returned.offset != 0
            || returned.width != self.pointer
            || self.call_register(inst, value) != Some(returned.register)
        {
            return None;
        }
        let registers = self.site_registers(Site::Call(inst));
        prototype
            .format_arg
            .iter()
            .map(|&parameter| {
                let &(Source::Register(piece), _) = placed.parameters.get(parameter)? else {
                    return None;
                };
                let &argument = registers.get(usize::from(piece.register.0))?;
                self.constant_string(argument)
            })
            .collect()
    }

    /// The bytes (before the NUL) of the constant string in read-only data
    /// at the address `value` is, if it is one.
    fn constant_string(&self, value: Value) -> Option<Vec<u8>> {
        let Kind::Const(bits) = self.kind(value) else {
            return None;
        };
        let data = self.cx.data;
        if data.relocatable() && self.immediate(value) {
            return None;
        }
        let address = bits.low_u64();
        data.string(address)
            .and_then(|length| data.constant(address, length))
    }

    /// The L2 type of a format string's `argument` under the convention's
    /// data model, `character` its plain `char`; `None` where the model
    /// does not say (`long` of unknown width).
    fn format_type(&mut self, argument: Argument, character: TypeId) -> Option<TypeId> {
        let scalar = match argument {
            Argument::Value(scalar) | Argument::Pointer(scalar) => scalar,
        };
        let ty = match scalar {
            Scalar::Integer { rank, signed } => {
                let width = match rank {
                    Integer::Char => 8,
                    Integer::Short => 16,
                    Integer::Int => 32,
                    Integer::Long => Some(self.cx.convention.long).filter(|&w| w > 0)?,
                    Integer::LongLong | Integer::IntMax => 64,
                    Integer::Size | Integer::PtrDiff => self.pointer,
                };
                self.types.intern(if signed {
                    Type::Int(width)
                } else {
                    Type::UInt(width)
                })
            }
            Scalar::Float => self.types.intern(Type::Float(FloatFormat::Single)),
            Scalar::Double => self.types.intern(Type::Float(FloatFormat::Double)),
            Scalar::Char => character,
            Scalar::VoidPointer => self.types.intern(Type::Pointer(None)),
        };
        Some(match argument {
            Argument::Value(_) => ty,
            Argument::Pointer(_) => self.types.intern(Type::Pointer(Some(ty))),
        })
    }

    /// The convention's integer argument registers after the first `used`
    /// that call `site` may pass something in: up to the last whose value
    /// at the call is not undefined on every path. An undefined value
    /// (another call's clobber) passes nothing the callee can depend on; the
    /// caller's own entry value untouched is kept, since in-place
    /// forwarding of its parameter looks the same.
    fn passed(&self, site: Site, used: usize) -> Vec<Source> {
        let registers = self.site_registers(site);
        let candidates: Vec<RegisterId> = self
            .cx
            .convention
            .arguments
            .iter()
            .skip(used)
            .copied()
            .collect();
        let kept = candidates
            .iter()
            .rposition(|register| {
                registers
                    .get(usize::from(register.0))
                    .is_some_and(|&value| !self.undefined(value))
            })
            .map_or(0, |last| last + 1);
        candidates
            .iter()
            .take(kept)
            .map(|&register| self.whole(register))
            .collect()
    }

    /// The vector argument registers after those among `named` that call
    /// `site` passes a variadic function something in, where the
    /// convention passes unnamed arguments in them: under System V, whose
    /// `al` counts them ("the number of vector registers used", an upper
    /// bound, which the callee's prologue tests before it saves any),
    /// those the count at the call covers if it is a constant; else, and
    /// under AAPCS64 (no count), up to the last whose value is not
    /// undefined on every path. Each is the 16 bytes a variadic callee
    /// saves of it (psABI §3.5.7, the register save area; AAPCS64's
    /// `__vr_top` area).
    fn passed_vectors(&self, site: Site, named: &[Source]) -> Vec<Source> {
        let convention = self.cx.convention;
        let count = match convention.va_list {
            super::VaList::SystemV { count } => Some(count),
            // No count register: the vector registers up to the last not
            // undefined, as without a constant count.
            super::VaList::Aapcs64 => None,
            super::VaList::Unknown | super::VaList::Pointer => return Vec::new(),
        };
        let registers = self.site_registers(site);
        let at = |register: RegisterId| registers.get(usize::from(register.0)).copied();
        let used = named
            .iter()
            .filter(|source| {
                matches!(source, Source::Register(piece) if convention.float_arguments.contains(&piece.register))
            })
            .count();
        let candidates = convention.float_arguments.get(used..).unwrap_or(&[]);
        let counted = count.and_then(at).and_then(|value| self.low_byte(value));
        let kept = counted.map_or_else(
            || {
                candidates
                    .iter()
                    .rposition(|&register| at(register).is_some_and(|value| !self.undefined(value)))
                    .map_or(0, |last| last + 1)
            },
            |counted| counted.saturating_sub(used),
        );
        candidates
            .iter()
            .take(kept)
            .map(|&register| {
                Source::Register(Piece {
                    register,
                    offset: 0,
                    width: 128.min(self.register_width(register)),
                })
            })
            .collect()
    }

    /// The low byte of `value`, if it is a constant: of a constant, or of
    /// what has one below other bits (`mov al, 2` leaves the rest of
    /// `rax` as it was) or extended.
    fn low_byte(&self, value: Value) -> Option<usize> {
        let mut value = self.canonical(value);
        for _ in 0..STEPS {
            if let Kind::Const(bits) = self.kind(value) {
                return Some(usize::from(bits.low_u64().to_le_bytes()[0]));
            }
            let lower = match *self.defining(value)?.1 {
                Op::Concat { low, .. } => low,
                Op::Extend { value, .. } => value,
                Op::Const(_)
                | Op::Undefined(..)
                | Op::Unary(..)
                | Op::Binary(..)
                | Op::Flag(..)
                | Op::Extract { .. }
                | Op::Select { .. }
                | Op::Lanes { .. }
                | Op::Float { .. }
                | Op::Load { .. }
                | Op::Store { .. }
                | Op::Intrinsic { .. }
                | Op::Call { .. }
                | Op::SystemCall { .. }
                | Op::Landing { .. } => return None,
            };
            if self.width(lower) < 8 {
                return None;
            }
            value = self.canonical(lower);
        }
        None
    }

    /// Whether `value` is undefined on every path (through block
    /// parameters).
    fn undefined(&self, value: Value) -> bool {
        let mut seen = BTreeSet::new();
        let mut work = vec![self.canonical(value)];
        while let Some(value) = work.pop() {
            if !seen.insert(value) {
                continue;
            }
            if seen.len() > STEPS {
                return false;
            }
            match self.kind(value) {
                Kind::Undefined(..) => {}
                Kind::Phi => {
                    let Some(&ValueInfo {
                        definition: Definition::Parameter { block, index },
                        ..
                    }) = self.l1.value(value)
                    else {
                        return false;
                    };
                    for (_, argument) in self.incoming(block, index as usize) {
                        work.push(self.canonical(argument));
                    }
                }
                Kind::None
                | Kind::Const(_)
                | Kind::Address(_)
                | Kind::Entry(_)
                | Kind::Pure(_)
                | Kind::Load(_)
                | Kind::Result(_)
                | Kind::CallView { .. } => return false,
            }
        }
        true
    }

    /// A callee known only by its address: the convention's integer
    /// argument registers the call may pass something in
    /// ([`passed`](Self::passed)), at least the first `passed` (what the
    /// function's other calls to it pass: one callee, one signature), and
    /// its first result register, each untyped (`bits`, which no type pass
    /// takes as evidence). The signature lists exactly the arguments
    /// passed, so C declares it with a prototype (C23 has no unprototyped
    /// `T f()`).
    fn unknown(&mut self, site: Site, target: Option<u64>, passed: usize) -> Callee {
        let convention = self.cx.convention;
        let mut arguments = self.passed(site, 0);
        let more: Vec<Source> = convention
            .arguments
            .iter()
            .take(passed)
            .skip(arguments.len())
            .map(|&register| self.whole(register))
            .collect();
        arguments.extend(more);
        let results: Vec<Piece> = convention
            .results
            .first()
            .map(|&register| self.piece(register))
            .into_iter()
            .collect();
        let signature = untyped_signature(&arguments, &results, &mut self.types);
        Callee {
            target,
            import: None,
            foreign: false,
            arguments,
            results,
            signature,
            variadic: Vec::new(),
            format: None,
            interfaced: false,
            declared: false,
            alloc_size: None,
            list_format: None,
        }
    }

    /// The type of the code at `address` (a function's entry), interned
    /// into `types`, as calls to it have it: its declared prototype's,
    /// else its interface's, else the convention's whole integer argument
    /// set and first result register, untyped; with whether it is that
    /// guess (no prototype or interface states it: it says only that the
    /// address is code).
    fn code_type(&self, address: u64, types: &mut Types) -> (TypeId, bool) {
        let cx = self.cx;
        stated_code_type(cx.prototypes, cx.interfaces, address, types)
            .map_or_else(|| (unknown_signature(cx, types), true), |ty| (ty, false))
    }

    /// [`Self::code_type`] where it is a type C can refer to a function
    /// by: its parameters and result all scalars C has (at most
    /// [`MAX_SCALAR`] bits).
    pub(super) fn scalar_code_type(&self, address: u64, types: &mut Types) -> Option<TypeId> {
        self.guessed_scalar_code_type(address, types)
            .map(|(ty, _)| ty)
    }

    /// [`Self::scalar_code_type`], and whether it is the convention's
    /// guess ([`Self::code_type`]).
    pub(super) fn guessed_scalar_code_type(
        &self,
        address: u64,
        types: &mut Types,
    ) -> Option<(TypeId, bool)> {
        let (ty, guessed) = self.code_type(address, types);
        scalar_code(types, ty).then_some((ty, guessed))
    }

    /// Whether value `v` is an immediate: a constant operand, through
    /// extensions and extractions (or a block parameter: not computed
    /// either), rather than computed by an operation or loaded. In
    /// position-independent code only a computed constant can be one of
    /// the image's addresses.
    pub(super) fn immediate(&self, v: Value) -> bool {
        let mut v = self.canonical(v);
        for _ in 0..FITS {
            match self.defining(v).map(|(_, op)| op) {
                Some(&(Op::Extend { value, .. } | Op::Extract { value, .. })) => {
                    v = self.canonical(value);
                }
                Some(Op::Const(_)) | None => return true,
                Some(_) => return false,
            }
        }
        true
    }

    /// The whole of register `register`.
    fn piece(&self, register: RegisterId) -> Piece {
        Piece {
            register,
            offset: 0,
            width: self.register_width(register),
        }
    }

    /// How many bits an argument may have in register `register`, a
    /// vector (`float`) or integer argument register: a vector one's
    /// [`float_bits`](super::Convention::float_bits) where the convention
    /// limits them, else the whole register.
    pub(super) fn argument_width(&self, register: RegisterId, float: bool) -> u16 {
        let full = self.register_width(register);
        match self.cx.convention.float_bits {
            bits if float && bits > 0 => full.min(bits),
            _ => full,
        }
    }

    /// The whole of register `register`, as a source.
    fn whole(&self, register: RegisterId) -> Source {
        Source::Register(self.piece(register))
    }

    /// The type of `width` bits.
    pub(super) fn bits(&mut self, width: u16) -> TypeId {
        self.types.intern(Type::Bits(width))
    }

    /// What places a declared signature by this function's convention.
    fn placer(&mut self) -> Placer<'_> {
        Placer {
            types: &mut self.types,
            convention: self.cx.convention,
            declarations: self.cx.declarations,
            pointer: self.pointer,
            link: self.cx.link_bytes(),
        }
    }

    /// [`Placer::place`].
    fn place(&mut self, signature: &Signature) -> Option<Placed> {
        self.placer().place(signature)
    }

    /// [`Placer::place_named`].
    fn place_named(&mut self, signature: &Signature, named: usize) -> Option<Placed> {
        self.placer().place_named(signature, named)
    }

    /// Where the convention places declared `prototype`, of `signature`
    /// ([`Placer::place`]). Not a lowered one that moves parameters
    /// ([`Placed::kept`]) where the declaration counts them (a format
    /// string's, a size's, a pointer's it does not describe): they are no
    /// longer where it counts them.
    fn place_declared(&mut self, prototype: &Prototype, signature: &Signature) -> Option<Placed> {
        let placed = match prototype.wide_result {
            // Returned in memory, or not placed.
            Some(wide) => {
                let mut returning = signature.clone();
                returning.returns = Some(wide);
                self.place(&returning)?
            }
            None => self.place(signature)?,
        };
        let counted = prototype.format.is_some()
            || !prototype.format_arg.is_empty()
            || prototype.alloc_size.is_some()
            || !prototype.open.parameters.is_empty();
        (placed.lowered.is_none() || placed.kept || !counted).then_some(placed)
    }
}

/// What places a declared signature: a convention, the registers it
/// names, and the types the signature and its lowered form are of.
pub(super) struct Placer<'a> {
    pub(super) types: &'a mut Types,
    pub(super) convention: &'a Convention,
    pub(super) declarations: &'a Declarations,
    /// A pointer's bits.
    pub(super) pointer: u16,
    /// The bytes of the return address on the stack at a function's
    /// entry.
    pub(super) link: u16,
}

impl Placer<'_> {
    /// The bits of register `register`.
    fn register_width(&self, register: RegisterId) -> u16 {
        self.declarations
            .info(register)
            .map_or(0, |info| info.width)
    }

    /// The whole of register `register`.
    fn piece(&self, register: RegisterId) -> Piece {
        Piece {
            register,
            offset: 0,
            width: self.register_width(register),
        }
    }

    /// The whole of register `register`, as a source.
    fn whole(&self, register: RegisterId) -> Source {
        Source::Register(self.piece(register))
    }

    /// The type of `width` bits.
    fn bits(&mut self, width: u16) -> TypeId {
        self.types.intern(Type::Bits(width))
    }

    /// How many bits an argument may have in register `register`
    /// ([`Lowering::argument_width`]).
    fn argument_width(&self, register: RegisterId, float: bool) -> u16 {
        let full = self.register_width(register);
        match self.convention.float_bits {
            bits if float && bits > 0 => full.min(bits),
            _ => full,
        }
    }

    /// Where the convention passes the parameters of `signature` and
    /// returns its result: scalars in the integer or vector registers in
    /// order (by position where the convention is
    /// [`positional`](super::Convention::positional)), then on the stack
    /// in 8-byte (pointer) slots past the return address and the
    /// [`shadow`](super::Convention::shadow) space; `None` where it cannot
    /// say (values wider than their register's argument, aggregates the
    /// convention's rule does not place: [`Self::aggregate`]).
    ///
    /// A struct or union by value has no one place where it takes two
    /// registers or comes back through memory, and an argument of one is
    /// made of bits, which C converts to no struct. So the signature
    /// placed is then a lowered one ([`Placed::lowered`]) that C's
    /// convention places the same: a parameter is a scalar per eightbyte
    /// in a register, or per 8 bytes on the stack (where the convention
    /// passes every argument in one register or slot, the integer of its
    /// size or a pointer to a copy of it: [`Self::one_slot`]); a result in
    /// memory is a pointer result, with the pointer the caller passes as
    /// a new first parameter. C would pass the 8-byte scalars of one on
    /// the stack in the integer registers left, so with one the lowered
    /// signature has the parameters in registers first, then one for
    /// each integer argument register left (which no caller sets), then
    /// those on the stack, in their order. A result in registers stays
    /// one value of the struct's type (of 1, 2, 4, 8 or 16 bytes: what C
    /// reads the bits of).
    pub(super) fn place(&mut self, signature: &Signature) -> Option<Placed> {
        self.place_named(signature, signature.parameters.len())
    }

    /// [`Self::place`], the parameters from the `named`th on being the
    /// unnamed arguments of a variadic call: on the stack where the
    /// convention passes them there
    /// ([`variadic_on_stack`](super::Convention::variadic_on_stack)).
    fn place_named(&mut self, signature: &Signature, named: usize) -> Option<Placed> {
        let convention = self.convention;
        let slot = i64::from(self.pointer / 8);
        let mut integer = convention.arguments.iter();
        let mut vector = convention.float_arguments.iter();
        let mut stack = i64::from(self.link) + i64::from(convention.shadow);
        let mut parameters = Vec::new();
        let mut declared_places = Vec::new();
        let mut lowered = false;
        // Whether a struct or union is on the stack, as 8-byte scalars.
        let mut spilled = false;
        // A result in memory: its address is the first integer argument.
        let mut hidden = None;
        if let Some(ty) = signature.returns
            && self.is_aggregate(ty)
            && self.aggregate(ty)? == Passing::Memory
        {
            let &register = integer.next()?;
            let pointer = self.types.intern(Type::Pointer(Some(ty)));
            parameters.push((self.whole(register), pointer));
            hidden = Some(pointer);
            lowered = true;
        }
        // By position, the hidden first argument has the first.
        let shift = usize::from(hidden.is_some());
        for (position, &declared) in signature.parameters.iter().enumerate() {
            let ty = self.one_slot(declared).unwrap_or(declared);
            if self.is_aggregate(declared) {
                if convention.variadic_on_stack && position >= named {
                    return None;
                }
                lowered = true;
            }
            if self.is_aggregate(ty) {
                let pieces = self.aggregate_parts(ty, &mut integer, &mut vector, &mut stack)?;
                spilled |= pieces
                    .iter()
                    .any(|(source, _)| matches!(source, Source::Stack { .. }));
                declared_places.push(pieces.iter().map(|&(source, _)| source).collect());
                parameters.extend(pieces);
                continue;
            }
            let width = self.types.value_width(ty)?;
            let float = matches!(self.types.get(ty), Some(Type::Float(_)));
            if !float && width > self.pointer {
                return None;
            }
            let register = match (convention.positional, float) {
                _ if convention.variadic_on_stack && position >= named => None,
                (true, true) => convention.float_arguments.get(position + shift),
                (true, false) => convention.arguments.get(position + shift),
                (false, true) => vector.next(),
                (false, false) => integer.next(),
            };
            let source = match register {
                Some(&register) if width <= self.argument_width(register, float) => {
                    Source::Register(Piece {
                        register,
                        offset: 0,
                        width,
                    })
                }
                Some(_) => return None,
                None => {
                    let bytes = width.div_ceil(8);
                    let source = Source::Stack {
                        offset: stack,
                        bytes,
                    };
                    stack += (i64::from(bytes) + slot - 1) / slot * slot;
                    source
                }
            };
            declared_places.push(vec![source]);
            parameters.push((source, ty));
        }
        if spilled {
            let left = (!signature.variadic).then_some(integer.as_slice())?;
            parameters = self.stack_last(parameters, left);
        }
        let returns = self.placed_returns(signature.returns, hidden.is_some())?;
        let lowered = lowered.then(|| {
            self.types.intern(Type::Code(Signature {
                parameters: parameters.iter().map(|&(_, ty)| ty).collect(),
                returns: hidden.or(signature.returns),
                variadic: signature.variadic,
            }))
        });
        let kept =
            hidden.is_none() && !spilled && declared_places.iter().all(|places| places.len() == 1);
        Some(Placed {
            parameters,
            returns,
            lowered,
            declared: declared_places,
            kept,
        })
    }

    /// Where a function returning `returns` leaves it: nothing for none;
    /// the first result register, which holds the address the caller
    /// passed, where it is returned in memory (`hidden`); else its
    /// registers ([`Self::result_pieces`]).
    fn placed_returns(&self, returns: Option<TypeId>, hidden: bool) -> Option<Vec<Piece>> {
        Some(match returns {
            None => Vec::new(),
            Some(_) if hidden => self
                .convention
                .results
                .first()
                .map(|&register| self.piece(register))
                .into_iter()
                .collect(),
            Some(ty) => self.result_pieces(ty)?,
        })
    }

    /// `parameters` with those on the stack last, after those in
    /// registers and one for each of the integer argument registers
    /// `left` ([`Self::place`]: what C then passes on the stack too).
    fn stack_last(
        &mut self,
        parameters: Vec<(Source, TypeId)>,
        left: &[RegisterId],
    ) -> Vec<(Source, TypeId)> {
        let (mut first, on_stack): (Vec<_>, Vec<_>) = parameters
            .into_iter()
            .partition(|(source, _)| matches!(source, Source::Register(_)));
        let word = self.bits(self.pointer);
        first.extend(left.iter().map(|&register| (self.whole(register), word)));
        first.extend(on_stack);
        first
    }

    /// What the convention passes in one register or stack slot for a
    /// struct or union of type `ty` by value: under
    /// [`Aggregates::Microsoft`], the integer of its size where that is 1,
    /// 2, 4 or 8 bytes, else a pointer to it (to a copy the caller makes);
    /// under [`Aggregates::Aapcs64`], a pointer to it where it is larger
    /// than 16 bytes. `None` for another convention, another type, a
    /// smaller one under AAPCS64, or one of no known size.
    fn one_slot(&mut self, ty: TypeId) -> Option<TypeId> {
        if !self.is_aggregate(ty) {
            return None;
        }
        let width = self.types.width(ty)?;
        match self.convention.aggregates {
            Aggregates::Microsoft => Some(match u16::try_from(width) {
                Ok(width @ (8 | 16 | 32 | 64)) => self.bits(width),
                Ok(_) | Err(_) => self.types.intern(Type::Pointer(Some(ty))),
            }),
            Aggregates::Aapcs64 if width > 128 => Some(self.types.intern(Type::Pointer(Some(ty)))),
            Aggregates::Aapcs64 | Aggregates::Unknown | Aggregates::SystemV => None,
        }
    }

    /// Where the convention passes a struct or union of type `ty` by
    /// value, as scalars ([`Self::place`]): one per eightbyte in the
    /// next registers of `integer` and `vector` where it is passed in
    /// registers and they are left for all of it, else one per 8 bytes
    /// on the stack from `stack`.
    fn aggregate_parts(
        &mut self,
        ty: TypeId,
        integer: &mut core::slice::Iter<'_, RegisterId>,
        vector: &mut core::slice::Iter<'_, RegisterId>,
        stack: &mut i64,
    ) -> Option<Vec<(Source, TypeId)>> {
        let bytes = u16::try_from(self.types.width(ty)? / 8).ok()?;
        let mut parts = Vec::new();
        match self.aggregate(ty)? {
            Passing::Registers(classes)
                if classes.iter().filter(|&&sse| sse).count() <= vector.as_slice().len()
                    && classes.iter().filter(|&&sse| !sse).count() <= integer.as_slice().len() =>
            {
                let mut left = bytes.saturating_mul(8);
                for sse in classes {
                    let &register = if sse { vector.next()? } else { integer.next()? };
                    let width = match left.min(64) {
                        width @ (8 | 16 | 32 | 64) => width,
                        _ => 64,
                    };
                    left = left.saturating_sub(64);
                    let bits = self.bits(width);
                    let part = if sse {
                        vector_class(self.types, bits)
                    } else {
                        bits
                    };
                    let piece = Piece {
                        register,
                        offset: 0,
                        width,
                    };
                    parts.push((Source::Register(piece), part));
                }
            }
            Passing::Registers(_) | Passing::Memory => {
                let word = self.bits(64);
                for _ in 0..bytes.div_ceil(8) {
                    let source = Source::Stack {
                        offset: *stack,
                        bytes: 8,
                    };
                    parts.push((source, word));
                    *stack += 8;
                }
            }
        }
        Some(parts)
    }

    /// Where the convention returns a value of type `ty` in registers:
    /// a struct or union of 1, 2, 4, 8 or 16 bytes in a register per
    /// eightbyte by its class; a scalar in the integer result registers,
    /// low part first, or the first vector one. `None` where it does
    /// not, or cannot say.
    fn result_pieces(&self, ty: TypeId) -> Option<Vec<Piece>> {
        let convention = self.convention;
        let mut left = self.types.value_width(ty)?;
        let mut pieces = Vec::new();
        if self.is_aggregate(ty) {
            let Passing::Registers(classes) = self.aggregate(ty)? else {
                return None;
            };
            if !matches!(left, 8 | 16 | 32 | 64 | 128) {
                return None;
            }
            let mut integer = convention.results.iter();
            let mut vector = convention.float_results.iter();
            for sse in classes {
                let &register = if sse { vector.next()? } else { integer.next()? };
                let width = left.min(64);
                left -= width;
                pieces.push(Piece {
                    register,
                    offset: 0,
                    width,
                });
            }
            return Some(pieces);
        }
        let float = matches!(self.types.get(ty), Some(Type::Float(_)));
        let registers = if float {
            &convention.float_results
        } else {
            &convention.results
        };
        for &register in registers {
            if left == 0 {
                break;
            }
            let take = left.min(self.register_width(register));
            pieces.push(Piece {
                register,
                offset: 0,
                width: take,
            });
            left -= take;
            if float {
                break;
            }
        }
        (left == 0).then_some(pieces)
    }

    /// Whether `ty` is a struct, a union or an array: passed by the
    /// convention's rule for aggregates.
    fn is_aggregate(&self, ty: TypeId) -> bool {
        matches!(
            self.types.get(ty),
            Some(Type::Struct(_) | Type::Union(_) | Type::Array { .. })
        )
    }

    /// How the convention passes a value of aggregate type `ty`
    /// ([`Aggregates`](super::Aggregates)); `None` where it has no rule
    /// known, or the type's layout does not say (no size, a field of a
    /// type with no class here: `long double`, a vector, a 16-byte
    /// integer; 8 bytes no field is in).
    fn aggregate(&self, ty: TypeId) -> Option<Passing> {
        match self.convention.aggregates {
            // AAPCS64's larger ones are pointers by now (`one_slot`).
            Aggregates::Unknown | Aggregates::Aapcs64 => None,
            Aggregates::SystemV => {
                let bytes = self.types.width(ty)? / 8;
                if bytes == 0 {
                    return None;
                }
                let mut classes = vec![None; usize::try_from(bytes.div_ceil(8)).ok()?];
                let aligned = self.eightbytes(ty, 0, &mut classes, FITS)?;
                if bytes > 16 || !aligned {
                    return Some(Passing::Memory);
                }
                classes
                    .into_iter()
                    .collect::<Option<Vec<bool>>>()
                    .map(Passing::Registers)
            }
            Aggregates::Microsoft => Some(match self.types.width(ty)? {
                8 | 16 | 32 | 64 => Passing::Registers(vec![false]),
                _ => Passing::Memory,
            }),
        }
    }

    /// Merges into `classes` (per eightbyte: whether it is a vector
    /// one, `None` while nothing is in it) the classes of the scalars of
    /// a value of type `ty` at byte `offset` of an aggregate, System V's
    /// way: an eightbyte is an integer one if anything in it is an
    /// integer or a pointer, a vector one if all is `float` or `double`.
    /// `false` where a scalar is not at a multiple of its size (the
    /// aggregate is then in memory); `None` where a type has no class
    /// here, or types nest deeper than `depth`.
    fn eightbytes(
        &self,
        ty: TypeId,
        offset: u64,
        classes: &mut [Option<bool>],
        depth: usize,
    ) -> Option<bool> {
        let depth = depth.checked_sub(1)?;
        let sse = match self.types.get(ty)? {
            Type::Struct(aggregate) | Type::Union(aggregate) => {
                for field in &aggregate.fields {
                    let at = offset.checked_add(field.offset)?;
                    if !self.eightbytes(field.ty, at, classes, depth)? {
                        return Some(false);
                    }
                }
                return Some(true);
            }
            &Type::Array { element, length } => {
                let size = self.types.width(element)? / 8;
                for index in 0..length? {
                    let at = offset.checked_add(index.checked_mul(size)?)?;
                    if !self.eightbytes(element, at, classes, depth)? {
                        return Some(false);
                    }
                }
                return Some(true);
            }
            Type::Float(FloatFormat::Single | FloatFormat::Double) => true,
            Type::Float(_) | Type::Vector { .. } => return None,
            Type::Bits(_)
            | Type::Int(_)
            | Type::UInt(_)
            | Type::Char { .. }
            | Type::Bool(_)
            | Type::Pointer(_)
            | Type::Code(_)
            | Type::Enum(_) => false,
        };
        let size = self.types.width(ty)? / 8;
        // A scalar of 16 bytes would align what holds it to 16 on the
        // stack: not placed.
        if !matches!(size, 1 | 2 | 4 | 8) {
            return None;
        }
        if !offset.is_multiple_of(size) {
            return Some(false);
        }
        let class = classes.get_mut(usize::try_from(offset / 8).ok()?)?;
        *class = Some(class.unwrap_or(true) && sse);
        Some(true)
    }
}

impl Lowering<'_, '_> {
    /// The function's return value: its declared prototype's, else the
    /// convention's first result register where every exit writes it
    /// (also where the prototype does not state its return value: its
    /// parameters are still the declared ones).
    pub(super) fn find_returns(&mut self) {
        let cx = self.cx;
        if let Some(prototype) = cx.prototypes.of(self.l1.entry, &mut self.types)
            && let Some(signature) = self.types.signature(prototype.signature).cloned()
            && let Some(placed) = self.place_declared(&prototype, &signature)
        {
            let returns = match placed.lowered {
                Some(lowered) => self.types.signature(lowered).and_then(|code| code.returns),
                None => signature.returns,
            };
            let declared = placed
                .parameters
                .into_iter()
                .enumerate()
                .map(|(position, (source, ty))| {
                    let evidence = if prototype.open.parameters.contains(&position) {
                        Evidence::DeclaredPointer
                    } else {
                        Evidence::Declared
                    };
                    (source, ty, evidence)
                })
                .collect();
            if prototype.returns_stated {
                self.returns = Returns {
                    pieces: placed.returns,
                    ty: returns,
                    declared: Some(declared),
                    stated: true,
                    open: prototype.open.returns,
                };
                return;
            }
            self.returns.declared = Some(declared);
        }
        let Some(&register) = cx.convention.results.first() else {
            return;
        };
        if cx
            .read_results
            .is_some_and(|read| !read.contains(&register))
        {
            return;
        }
        let Some(narrow) = self.result_narrow(register) else {
            return;
        };
        let full = self.register_width(register);
        let width = if narrow { full.min(32) } else { full };
        self.returns.pieces = vec![Piece {
            register,
            offset: 0,
            width,
        }];
        self.returns.ty = Some(self.bits(width));
    }

    /// The function's return value where it is in the convention's first
    /// vector result register, after [`find_needed`](Self::find_needed):
    /// no prototype states the return value, callers may read the
    /// register ([`Context::read_results`]), no integer result is defined
    /// at an exit (none found, or what every exit leaves there is
    /// undefined on every path: another call's leftovers), and every exit
    /// writes the register ([`Self::vector_written`]) or returns what a
    /// callee returns there. Its width is the widest write, as a `float`,
    /// a `double` or a whole vector. Returns whether it found one (what is
    /// needed then changes).
    pub(super) fn find_vector_returns(&mut self) -> bool {
        let cx = self.cx;
        if self.returns.stated {
            return false;
        }
        let Some(&register) = cx.convention.float_results.first() else {
            return false;
        };
        if cx
            .read_results
            .is_some_and(|read| !read.contains(&register))
        {
            return false;
        }
        // Where the callers read this register after their calls and none
        // the integer one ([`Context::preferred_result`]), what every
        // exit leaves in the integer register is what the function
        // computed with, not what it returns.
        let preferred = cx.preferred_result == Some(register);
        if !self.returns.pieces.is_empty() && !self.returns_undefined() && !preferred {
            return false;
        }
        let Some(width) = self.vector_result(register) else {
            return false;
        };
        self.returns.pieces = vec![Piece {
            register,
            offset: 0,
            width,
        }];
        let ty = self.bits(width);
        self.returns.ty = Some(vector_class(&mut self.types, ty));
        true
    }

    /// The vector result register's low lane, where the return value
    /// found is in an integer register (not stated by a prototype) and
    /// every exit writes a scalar to the vector one too
    /// ([`Found::alternative`](super::Found::alternative)), after
    /// [`find_needed`](Self::find_needed).
    pub(super) fn alternative_result(&self) -> Option<Piece> {
        let convention = self.cx.convention;
        let &register = convention.float_results.first()?;
        if self.returns.stated
            || self.returns.pieces.is_empty()
            || self
                .returns
                .pieces
                .iter()
                .any(|piece| !convention.results.contains(&piece.register))
        {
            return None;
        }
        let width = self.vector_result(register).filter(|&width| width <= 64)?;
        Some(Piece {
            register,
            offset: 0,
            width,
        })
    }

    /// The callees at a constant address after a call to which the
    /// function reads the vector result register, though the callee's
    /// interface returns nothing there
    /// ([`Found::strays`](super::Found::strays)): the value the call left
    /// is needed by the function's own code, or passed on in place to a
    /// callee a declaration or a format string says takes an argument
    /// there (`printf("%f", f(x))`). Passing it on to another callee is
    /// no read: that one's parameters may be the convention's guess, and
    /// the register then holds whatever was there (`pxor xmm0, xmm0` in a
    /// callee that clears a struct).
    pub(super) fn stray_reads(&self) -> BTreeSet<u64> {
        let Some(&register) = self.cx.convention.float_results.first() else {
            return BTreeSet::new();
        };
        let needed = self.needed_apart_from_arguments();
        let needed = |value: Value| {
            needed
                .get(self.canonical(value).0 as usize)
                .copied()
                .unwrap_or(false)
        };
        let passed = |value: Value| {
            self.callees.iter().any(|(&site, taking)| {
                taking.declared
                    && taking.arguments.iter().any(
                        |source| matches!(source, Source::Register(piece) if piece.register == register),
                    )
                    && self
                        .site_registers(site)
                        .get(usize::from(register.0))
                        .is_some_and(|&given| self.canonical(given) == self.canonical(value))
            })
        };
        let mut strays = BTreeSet::new();
        for (&site, callee) in &self.callees {
            let (Site::Call(inst), Some(target)) = (site, callee.target) else {
                continue;
            };
            let Some(i) = self.l1.inst(inst) else {
                continue;
            };
            let Op::Call { changes, .. } = &i.op else {
                continue;
            };
            if callee
                .results
                .iter()
                .any(|piece| piece.register == register)
            {
                continue;
            }
            let read = changes
                .iter()
                .zip(i.results.iter().skip(1))
                .any(|(&changed, &value)| changed == register && (needed(value) || passed(value)));
            if read {
                strays.insert(target);
            }
        }
        strays
    }

    /// Whether the return value found is undefined on every path at
    /// every return, and no exit returns a callee's.
    fn returns_undefined(&self) -> bool {
        self.blocks().all(|(_, block)| match &block.terminator {
            Terminator::Return { state, .. } => self.returns.pieces.iter().all(|piece| {
                state
                    .registers
                    .get(usize::from(piece.register.0))
                    .is_some_and(|&value| self.undefined(value))
            }),
            Terminator::Leave { returns: true, .. } => false,
            Terminator::Jump(_)
            | Terminator::Branch { .. }
            | Terminator::Invoke { .. }
            | Terminator::IndirectJump { .. }
            | Terminator::Leave { returns: false, .. }
            | Terminator::Trap(_)
            | Terminator::Stop
            | Terminator::Open => true,
        })
    }

    /// How many low bits of vector register `register` hold a result at
    /// every exit (`None` if one leaves there what is no result, none
    /// writes one, or none returns): 32, 64, or a whole vector's, the
    /// widest of what the returns write ([`Self::vector_written`]) and
    /// what the callees of tail calls return there; 64 where all that is
    /// written is zeros (`pxor xmm0, xmm0`, which says no width: `0.0` is
    /// the commonest). Where some path writes a scalar with nothing above
    /// it, the widest such scalar: a function has one return type, and
    /// what another path leaves above its scalar is then what it
    /// computed with (`__j0_finite` evaluates its polynomials two lanes
    /// at a time and returns the low one).
    fn vector_result(&self, register: RegisterId) -> Option<u16> {
        let mut exits = 0usize;
        let mut width = 0u16;
        let mut scalar = 0u16;
        let mut written = false;
        let stored = self.stored_values();
        for (id, block) in self.blocks() {
            match &block.terminator {
                Terminator::Return { state, .. } => {
                    let value = *state.registers.get(usize::from(register.0))?;
                    let (wrote, low, lane) = self.vector_written(value, register, &stored)?;
                    written |= wrote;
                    width = width.max(low);
                    scalar = scalar.max(lane);
                    exits += 1;
                }
                Terminator::Leave { returns: true, .. } => {
                    let callee = self.callees.get(&Site::Tail(id))?;
                    if callee.foreign {
                        continue;
                    }
                    let [piece] = callee.results[..] else {
                        return None;
                    };
                    if piece.register != register || piece.offset != 0 {
                        return None;
                    }
                    width = width.max(piece.width);
                    if piece.width <= 64 {
                        scalar = scalar.max(piece.width);
                    }
                    written = true;
                    exits += 1;
                }
                Terminator::Jump(_)
                | Terminator::Branch { .. }
                | Terminator::Invoke { .. }
                | Terminator::IndirectJump { .. }
                | Terminator::Leave { returns: false, .. }
                | Terminator::Trap(_)
                | Terminator::Stop
                | Terminator::Open => {}
            }
        }
        let full = self.argument_width(register, true);
        let width = if scalar > 0 { scalar } else { width };
        let width = if width == 0 { 64 } else { width.max(32) };
        (exits > 0 && written).then(|| width.next_power_of_two().min(full))
    }

    /// Whether a path writes vector register `register`'s value `value`
    /// at a return as a result, how many low bits the widest such write
    /// is (0: zeros alone) and how many the widest of 64 bits or less is
    /// (0: none), through block parameters: the low part
    /// of each concatenation whose high part is 0, undefined, or the
    /// register's own entry bits there (`addsd` keeps the bits above its
    /// sum, `movq` clears them). A path that leaves the register's entry
    /// value writes nothing and is no objection (`return a < b ? a : b +
    /// 1.0` returns its first argument where it found it). `None` where a
    /// path leaves an undefined value there, or one the function stores
    /// to memory (`stored`, [`Self::stored_values`]): a copy that goes
    /// through the register (`movq xmm0, [rsi]; movq [rdi], xmm0`) leaves
    /// no result in it, while a value loaded or computed into it that
    /// goes nowhere else is one, whatever else is computed from it (a
    /// sum a loop adds to, and in the exact L1 every operand of the next
    /// operation's exception test). That is for a scalar, the low 32 or
    /// 64 bits; a whole vector left there that anything else needs is
    /// taken for a temporary (the induction vector of a loop that fills
    /// memory, `png_build_grayscale_palette`'s), since functions return
    /// scalars far more often than vectors. A call's result there counts
    /// as written.
    fn vector_written(
        &self,
        value: Value,
        register: RegisterId,
        stored: &BTreeSet<Value>,
    ) -> Option<(bool, u16, u16)> {
        let mut seen = BTreeSet::new();
        let mut work = vec![(self.canonical(value), self.width(value))];
        let mut width = 0u16;
        let mut scalar = 0u16;
        let mut written = false;
        while let Some((mut value, mut within)) = work.pop() {
            if !seen.insert(value) {
                continue;
            }
            if seen.len() > STEPS {
                return None;
            }
            // The part written: under what is left of the register, the
            // low bits of what they are extracted from.
            for _ in 0..FITS {
                if !matches!(self.kind(value), Kind::Pure(_)) {
                    break;
                }
                let low = match self.defining(value).map(|(_, op)| op) {
                    Some(&Op::Concat { high, low })
                        if self.vacant(high, register, self.width(low)) =>
                    {
                        low
                    }
                    Some(
                        &(Op::Extend {
                            signed: false,
                            value: low,
                            ..
                        }
                        | Op::Extract {
                            value: low,
                            offset: 0,
                            ..
                        }),
                    ) => low,
                    Some(_) | None => break,
                };
                within = within.min(self.width(value));
                value = self.canonical(low);
            }
            within = within.min(self.width(value));
            if self.entry_bits_of(value, register) {
                continue;
            }
            // What a callee returned there is as wide as its return
            // value: the rest of the register after the call is nothing
            // (`return f(x)` after more work returns `f`'s `double`).
            if let Kind::CallView {
                offset: 0,
                width: lane,
                ..
            } = self.kind(value)
            {
                within = within.min(lane);
            }
            if matches!(self.kind(value), Kind::Const(bits) if bits.is_zero()) {
                written = true;
                continue;
            }
            // What a bitwise operation leaves above a low lane is not
            // written either (`xorps` with a sign mask keeps the rest),
            // where the lane itself is written (a whole argument moved
            // there, `movaps xmm0, xmm1`, says no width).
            let whole = self.width(value);
            let vacant = |offset: u16, width: u16| {
                self.vacant_part(
                    value,
                    (offset, width),
                    register,
                    offset,
                    VACANT,
                    &mut Vec::new(),
                )
            };
            if let Some(low) = [32u16, 64, 128]
                .into_iter()
                .find(|&low| low < within && vacant(low, whole - low) && !vacant(0, low))
            {
                within = low;
            }
            if self.copied(value, stored)
                || (within > 64 && self.needed_otherwise(value))
                || self.undefined(value)
            {
                return None;
            }
            if self.kind(value) == Kind::Phi {
                let &ValueInfo {
                    definition: Definition::Parameter { block, index },
                    ..
                } = self.l1.value(value)?
                else {
                    return None;
                };
                for (_, argument) in self.incoming(block, index as usize) {
                    work.push((self.canonical(argument), within));
                }
                continue;
            }
            width = width.max(within);
            if within <= 64 {
                scalar = scalar.max(within);
            }
            written = true;
        }
        Some((written, width, scalar))
    }

    /// Whether `value` is one the function stores (`stored`), or bits of
    /// one (an extraction from one, an extension of one), or has one as
    /// its low part (under whatever the register kept above it): what is
    /// left in a register of a value that went to memory (the low lane of
    /// a vector that was stored).
    fn copied(&self, value: Value, stored: &BTreeSet<Value>) -> bool {
        let mut value = self.canonical(value);
        for _ in 0..FITS {
            if stored.contains(&value) {
                return true;
            }
            if !matches!(self.kind(value), Kind::Pure(_)) {
                return false;
            }
            match self.defining(value).map(|(_, op)| op) {
                Some(&(Op::Extract { value: whole, .. } | Op::Extend { value: whole, .. })) => {
                    value = self.canonical(whole);
                }
                Some(&Op::Concat { low, .. }) => value = self.canonical(low),
                Some(_) | None => return false,
            }
        }
        false
    }

    /// Whether `value` is needed, or bits of a value that is (an
    /// extraction from one, an extension of one).
    fn needed_otherwise(&self, value: Value) -> bool {
        let mut value = self.canonical(value);
        for _ in 0..FITS {
            if self.is_needed(value) {
                return true;
            }
            if !matches!(self.kind(value), Kind::Pure(_)) {
                return false;
            }
            match self.defining(value).map(|(_, op)| op) {
                Some(&(Op::Extract { value: whole, .. } | Op::Extend { value: whole, .. })) => {
                    value = self.canonical(whole);
                }
                Some(_) | None => return false,
            }
        }
        false
    }

    /// The values the function stores to memory (not to the slots of its
    /// frame that are its locals, where a value only waits), and those
    /// they are bits of or made of: extractions, extensions and
    /// concatenations are the same value in a register.
    fn stored_values(&self) -> BTreeSet<Value> {
        let mut stored = BTreeSet::new();
        let mut work = Vec::new();
        for (_, block) in self.blocks() {
            for &inst in &block.insts {
                let Some(&Op::Store { value, .. }) = self.l1.inst(inst).map(|i| &i.op) else {
                    continue;
                };
                let local = self
                    .frame
                    .accesses
                    .get(&inst)
                    .is_some_and(|&slot| self.home(slot) != Home::Frame);
                if !local && !self.frame.pushes.contains(&inst) {
                    work.push((self.canonical(value), FITS));
                }
            }
        }
        while let Some((value, depth)) = work.pop() {
            if !stored.insert(value) || depth == 0 || !matches!(self.kind(value), Kind::Pure(_)) {
                continue;
            }
            match self.defining(value).map(|(_, op)| op) {
                Some(&(Op::Extract { value: whole, .. } | Op::Extend { value: whole, .. })) => {
                    work.push((self.canonical(whole), depth - 1));
                }
                Some(&Op::Concat { high, low }) => {
                    work.push((self.canonical(high), depth - 1));
                    work.push((self.canonical(low), depth - 1));
                }
                Some(_) | None => {}
            }
        }
        stored
    }

    /// Whether `high`, the part of register `register` from bit `from`
    /// up, holds nothing written: 0, an undefined value, or the
    /// register's entry bits there.
    fn vacant(&self, high: Value, register: RegisterId, from: u16) -> bool {
        let part = (0, self.width(high));
        self.vacant_part(high, part, register, from, VACANT, &mut Vec::new())
    }

    /// Whether bits `offset..offset + width` (`part`) of `value`, which
    /// are register `register`'s from bit `from`, hold nothing written:
    /// 0, an undefined value, or the entry bits there of the register or
    /// of another vector argument register (`addsd xmm1, xmm2; movapd
    /// xmm0, xmm1` moves what the caller left above the second argument
    /// along with the sum: nothing the function computed);
    /// through extractions, concatenations and zero extensions (`pxor
    /// xmm0, xmm0; cvtsi2sd xmm0, edi` leaves the zeros above the
    /// double), through a bitwise operation with a constant that leaves
    /// those bits as they are (`xorps`, `andps` with a mask of the low
    /// lane) or clears them, and through block parameters whose
    /// arguments all do (`seen`: those being looked at; a loop's holds
    /// nothing written if its other arguments do not), `depth`
    /// operations deep. What a call leaves of a register outside its
    /// return value is undefined too.
    fn vacant_part(
        &self,
        value: Value,
        (offset, width): (u16, u16),
        register: RegisterId,
        from: u16,
        depth: usize,
        seen: &mut Vec<Value>,
    ) -> bool {
        let value = self.canonical(value);
        match self.kind(value) {
            Kind::Const(bits) => bits.extract(offset, width).is_zero(),
            Kind::Undefined(..) => true,
            Kind::CallView {
                offset: first,
                width: lane,
                ..
            } => offset >= first.saturating_add(lane) || offset.saturating_add(width) <= first,
            Kind::Entry(entry) => {
                offset == from
                    && (entry == register || self.cx.convention.float_arguments.contains(&entry))
            }
            Kind::Phi => {
                let Some(&ValueInfo {
                    definition: Definition::Parameter { block, index },
                    ..
                }) = self.l1.value(value)
                else {
                    return false;
                };
                let Some(depth) = depth.checked_sub(1) else {
                    return false;
                };
                if seen.contains(&value) {
                    return true;
                }
                seen.push(value);
                self.incoming(block, index as usize)
                    .into_iter()
                    .all(|(_, argument)| {
                        self.vacant_part(argument, (offset, width), register, from, depth, seen)
                    })
            }
            Kind::Pure(_) => {
                let Some(depth) = depth.checked_sub(1) else {
                    return false;
                };
                self.vacant_through(value, (offset, width), register, from, depth, seen)
            }
            Kind::None | Kind::Address(_) | Kind::Load(_) | Kind::Result(_) => false,
        }
    }

    /// [`Self::vacant_part`] of the result of a pure operation, by its
    /// operands.
    fn vacant_through(
        &self,
        value: Value,
        (offset, width): (u16, u16),
        register: RegisterId,
        from: u16,
        depth: usize,
        seen: &mut Vec<Value>,
    ) -> bool {
        let mut vacant = |value, offset, width, from| {
            self.vacant_part(value, (offset, width), register, from, depth, seen)
        };
        match self.defining(value).map(|(_, op)| op) {
            Some(&Op::Extract {
                value: inner,
                offset: first,
                ..
            }) => vacant(inner, offset.saturating_add(first), width, from),
            Some(&Op::Concat { high, low }) => {
                let below = self.width(low);
                if offset >= below {
                    vacant(high, offset - below, width, from)
                } else if offset.saturating_add(width) <= below {
                    vacant(low, offset, width, from)
                } else {
                    let part = below - offset;
                    vacant(low, offset, part, from)
                        && vacant(high, 0, width - part, from.saturating_add(part))
                }
            }
            Some(&Op::Extend {
                signed: false,
                value: inner,
                ..
            }) => {
                let within = self.width(inner);
                offset >= within || vacant(inner, offset, width.min(within - offset), from)
            }
            // Either is vacant: what AArch64's FPCR.NEP chooses above a
            // scalar result, the source register's bits or zeros.
            Some(&Op::Select {
                then, otherwise, ..
            }) => vacant(then, offset, width, from) && vacant(otherwise, offset, width, from),
            Some(
                &(Op::Binary(op @ (Binary::And | Binary::Or | Binary::Xor), a, b)
                | Op::Lanes {
                    op: LaneOp::Binary(op @ (Binary::And | Binary::Or | Binary::Xor)),
                    operands: [a, b, _],
                    ..
                }),
            ) => {
                let masked = [(a, b), (b, a)].into_iter().any(|(kept, mask)| {
                    let Some(bits) = self.mask(mask) else {
                        return false;
                    };
                    let part = bits.extract(offset, width);
                    let cleared = op == Binary::And && part.is_zero();
                    let left = if op == Binary::And {
                        part == Bits::ones(width)
                    } else {
                        part.is_zero()
                    };
                    cleared || (left && vacant(kept, offset, width, from))
                });
                // Zeros and-ed with anything are zeros, and or-ed with
                // nothing written leave it (`andps` and `orps` of
                // registers a `movss` cleared above their floats).
                let zero = |value| self.zero_part(value, (offset, width), depth);
                masked
                    || if op == Binary::And {
                        zero(a) || zero(b)
                    } else {
                        (zero(a) && vacant(b, offset, width, from))
                            || (zero(b) && vacant(a, offset, width, from))
                    }
            }
            Some(_) | None => false,
        }
    }

    /// Whether bits `offset..offset + width` (`part`) of `value` are
    /// zeros: a constant's, those a zero extension adds, those of an
    /// and with zeros or of an or of zeros, `depth` operations deep.
    fn zero_part(&self, value: Value, (offset, width): (u16, u16), depth: usize) -> bool {
        let value = self.canonical(value);
        if let Some(bits) = self.mask(value) {
            return bits.extract(offset, width).is_zero();
        }
        let Some(depth) = depth.checked_sub(1) else {
            return false;
        };
        if !matches!(self.kind(value), Kind::Pure(_)) {
            return false;
        }
        let zero = |value, offset, width| self.zero_part(value, (offset, width), depth);
        match self.defining(value).map(|(_, op)| op) {
            Some(&Op::Extract {
                value: inner,
                offset: first,
                ..
            }) => zero(inner, offset.saturating_add(first), width),
            Some(&Op::Concat { high, low }) => {
                let below = self.width(low);
                if offset >= below {
                    zero(high, offset - below, width)
                } else if offset.saturating_add(width) <= below {
                    zero(low, offset, width)
                } else {
                    let part = below - offset;
                    zero(low, offset, part) && zero(high, 0, width - part)
                }
            }
            Some(&Op::Extend {
                signed: false,
                value: inner,
                ..
            }) => {
                let within = self.width(inner);
                offset >= within || zero(inner, offset, width.min(within - offset))
            }
            Some(
                &(Op::Binary(op @ (Binary::And | Binary::Or | Binary::Xor), a, b)
                | Op::Lanes {
                    op: LaneOp::Binary(op @ (Binary::And | Binary::Or | Binary::Xor)),
                    operands: [a, b, _],
                    ..
                }),
            ) => {
                if op == Binary::And {
                    zero(a, offset, width) || zero(b, offset, width)
                } else {
                    zero(a, offset, width) && zero(b, offset, width)
                }
            }
            Some(_) | None => false,
        }
    }

    /// The bits of `value` where it is a constant: one, or a load of
    /// bytes the program cannot change at a constant address (the masks
    /// compilers keep in read-only data: `andps xmm1, [sign]`).
    fn mask(&self, value: Value) -> Option<Bits> {
        match self.kind(value) {
            Kind::Const(bits) => Some(bits),
            Kind::Load(inst) => {
                let Some(&Op::Load { address, .. }) = self.l1.inst(inst).map(|i| &i.op) else {
                    return None;
                };
                let Kind::Const(address) = self.kind(address) else {
                    return None;
                };
                let width = self.width(value);
                let bytes = self
                    .cx
                    .data
                    .constant(address.low_u64(), u64::from(width / 8))?;
                Some(Bits::from_le_bytes(width, &bytes))
            }
            Kind::None
            | Kind::Undefined(..)
            | Kind::Address(_)
            | Kind::Entry(_)
            | Kind::Phi
            | Kind::Pure(_)
            | Kind::Result(_)
            | Kind::CallView { .. } => None,
        }
    }

    /// Whether `value` is the entry value of register `register`, or its
    /// low bits.
    fn entry_bits_of(&self, value: Value, register: RegisterId) -> bool {
        self.kind(value) == Kind::Entry(register)
            || matches!(
                self.defining(self.canonical(value)).map(|(_, op)| op),
                Some(&Op::Extract { value: whole, offset: 0, .. })
                    if self.kind(value) != Kind::Phi && self.kind(whole) == Kind::Entry(register)
            )
    }

    /// Whether every exit writes `register` (`None` if one does not, or
    /// none does), and whether every one writes 32 bits or less,
    /// zero-extended. A tail call to code that never returns is no exit:
    /// what it leaves in `register` is never returned.
    fn result_narrow(&self, register: RegisterId) -> Option<bool> {
        let mut exits = 0usize;
        let mut narrow = true;
        for (id, block) in self.blocks() {
            match &block.terminator {
                Terminator::Return { state, .. } => {
                    let value = *state.registers.get(usize::from(register.0))?;
                    if self.kind(value) == Kind::Entry(register) {
                        return None;
                    }
                    narrow &= self.returned_width(value, register)?;
                    exits += 1;
                }
                Terminator::Leave { returns: true, .. } => {
                    let callee = self.callees.get(&Site::Tail(id))?;
                    if callee.foreign {
                        continue;
                    }
                    let piece = callee.results.first()?;
                    if piece.register != register {
                        return None;
                    }
                    narrow &= callee.results.len() == 1 && piece.width <= 32;
                    exits += 1;
                }
                Terminator::Jump(_)
                | Terminator::Branch { .. }
                | Terminator::Invoke { .. }
                | Terminator::IndirectJump { .. }
                | Terminator::Leave { returns: false, .. }
                | Terminator::Trap(_)
                | Terminator::Stop
                | Terminator::Open => {}
            }
        }
        (exits > 0).then_some(narrow)
    }

    /// Whether `value`'s bits from 32 up are zero or undefined on every
    /// path through block parameters. A path carrying `register`'s
    /// unchanged entry value gives no inferred return when that register
    /// is not also an argument register. Argument-bearing result registers
    /// may return a real input on that path and stay. An incomplete
    /// traversal keeps the full result rather than removing an uncertain
    /// value.
    fn returned_width(&self, value: Value, register: RegisterId) -> Option<bool> {
        let argument = self.cx.convention.arguments.contains(&register)
            || self.cx.convention.float_arguments.contains(&register);
        let mut seen = BTreeSet::new();
        let mut work = vec![self.canonical(value)];
        let mut narrow = true;
        while let Some(value) = work.pop() {
            if !seen.insert(value) {
                continue;
            }
            if seen.len() > STEPS {
                return Some(false);
            }
            let ok = match self.kind(value) {
                Kind::Entry(entry) if entry == register && !argument => return None,
                Kind::Const(bits) => {
                    bits.width() <= 32 || bits.extract(32, bits.width() - 32).is_zero()
                }
                // Bits the architecture leaves undefined are not chosen
                // to be zero.
                Kind::Undefined(_, unknown) => !unknown.architectural(),
                Kind::CallView { offset, width, .. } => offset == 0 && width <= 32,
                Kind::Phi => {
                    let Some(&ValueInfo {
                        definition: Definition::Parameter { block, index },
                        ..
                    }) = self.l1.value(value)
                    else {
                        return Some(false);
                    };
                    for (_, argument) in self.incoming(block, index as usize) {
                        work.push(self.canonical(argument));
                    }
                    true
                }
                Kind::Pure(_) => matches!(
                    self.defining(value).map(|(_, op)| op),
                    Some(&Op::Extend { signed: false, value: inner, .. }) if self.width(inner) <= 32
                ),
                Kind::None
                | Kind::Address(_)
                | Kind::Entry(_)
                | Kind::Load(_)
                | Kind::Result(_) => false,
            };
            narrow &= ok;
        }
        Some(narrow)
    }

    /// The kinds of calls' results: a register the callee returns in is
    /// its result (a view of it where the return value is not the whole
    /// register); another register it changes is undefined.
    pub(super) fn call_results(&mut self) {
        let mut kinds = Vec::new();
        for (&site, callee) in &self.callees {
            let Site::Call(inst) = site else {
                continue;
            };
            let Some(i) = self.l1.inst(inst) else {
                continue;
            };
            let Op::Call { changes, .. } = &i.op else {
                continue;
            };
            for (&register, &value) in changes.iter().zip(i.results.iter().skip(1)) {
                let width = self.width(value);
                let kind = match callee.results.iter().find(|p| p.register == register) {
                    Some(piece) if piece.offset == 0 && piece.width == width => Kind::Result(inst),
                    Some(piece) => Kind::CallView {
                        inst,
                        offset: piece.offset,
                        width: piece.width,
                    },
                    None => Kind::Undefined(
                        width,
                        Unknown::Call {
                            address: i.address,
                            register,
                        },
                    ),
                };
                kinds.push((value, kind));
            }
        }
        for (value, kind) in kinds {
            self.set_kind(value, kind);
        }
    }

    /// The register `value` is after call `inst`, if it is one of the
    /// registers the call changes.
    pub(super) fn call_register(&self, inst: InstId, value: Value) -> Option<RegisterId> {
        let i = self.l1.inst(inst)?;
        let Op::Call { changes, .. } = &i.op else {
            return None;
        };
        let index = i
            .results
            .iter()
            .skip(1)
            .position(|&result| result == value)?;
        changes.get(index).copied()
    }

    /// The registers of the state at call site `site`: `Op::Call`'s, or a
    /// tail call's state.
    pub(super) fn site_registers(&self, site: Site) -> &[Value] {
        let l1 = self.l1;
        match site {
            Site::Call(inst) => match l1.inst(inst).map(|i| &i.op) {
                Some(Op::Call { registers, .. }) => registers,
                _ => &[],
            },
            Site::Tail(block) => match l1.block(block).map(|b| &b.terminator) {
                Some(Terminator::Leave { state, .. }) => &state.registers,
                _ => &[],
            },
        }
    }

    /// How the function reads the return value of each callee at a
    /// constant address, over its calls to it ([`Read`]), after
    /// [`signature`](Self::signature): a call's result values needed
    /// without the function's own return value are read; needed only with
    /// it, or passed on by a tail call that returns, only returned.
    pub(super) fn result_reads(&mut self) -> BTreeMap<u64, Read> {
        let returned: Vec<(u64, Vec<Value>)> = self
            .callees
            .iter()
            .filter_map(|(&site, callee)| {
                let Site::Call(inst) = site else {
                    return None;
                };
                let i = self.l1.inst(inst)?;
                let Op::Call { changes, .. } = &i.op else {
                    return None;
                };
                let values = changes
                    .iter()
                    .zip(i.results.iter().skip(1))
                    .filter(|&(register, _)| callee.results.iter().any(|p| p.register == *register))
                    .map(|(_, &value)| value)
                    .collect();
                Some((callee.target?, values))
            })
            .collect();
        let with: Vec<bool> = returned
            .iter()
            .map(|(_, values)| values.iter().any(|&value| self.is_needed(value)))
            .collect();
        let pieces = core::mem::take(&mut self.returns.pieces);
        let own = !pieces.is_empty();
        if own {
            self.find_needed();
        }
        let mut reads: BTreeMap<u64, Read> = BTreeMap::new();
        for ((target, values), with) in returned.iter().zip(with) {
            let read = if values.iter().any(|&value| self.is_needed(value)) {
                Read::Yes
            } else if with {
                Read::Returned
            } else {
                Read::No
            };
            let entry = reads.entry(*target).or_default();
            *entry = (*entry).max(read);
        }
        self.returns.pieces = pieces;
        if own {
            self.find_needed();
        }
        for (id, block) in self.blocks() {
            let Terminator::Leave { returns, .. } = block.terminator else {
                continue;
            };
            let Some(target) = self.callees.get(&Site::Tail(id)).and_then(|c| c.target) else {
                continue;
            };
            let read = if returns { Read::Returned } else { Read::No };
            let entry = reads.entry(target).or_default();
            *entry = (*entry).max(read);
        }
        reads
    }

    /// Where the function is an allocator wrapper
    /// ([`Interface::alloc_size`]), which of `parameters` (its interface's)
    /// give the size of what it returns: every value it returns in one
    /// whole register, at each return and each tail call that returns, is
    /// the result of a call that allocates (its callee's `alloc_size`,
    /// declared or itself a wrapper's), directly or through block
    /// parameters, the size (and count) arguments of each the entry value
    /// of the same register parameters. A path where the result is null
    /// may call what does not return, or return that null.
    pub(super) fn allocation(&self, parameters: &[Source]) -> Option<AllocSize> {
        let [piece] = self.returns.pieces.as_slice() else {
            return None;
        };
        let mut found = None;
        let mut agree = |size: AllocSize| {
            let same = found.is_none_or(|was| was == size);
            found = Some(size);
            same
        };
        for (id, block) in self.blocks() {
            let size = match &block.terminator {
                Terminator::Return { state, .. } => {
                    let value = *state.registers.get(usize::from(piece.register.0))?;
                    self.allocated(value, *piece, parameters)?
                }
                Terminator::Leave { returns: true, .. } => {
                    let callee = self.callees.get(&Site::Tail(id))?;
                    self.sized(Site::Tail(id), callee, *piece, parameters)?
                }
                Terminator::Leave { .. }
                | Terminator::Jump(_)
                | Terminator::Branch { .. }
                | Terminator::IndirectJump { .. }
                | Terminator::Invoke { .. }
                | Terminator::Trap(_)
                | Terminator::Stop
                | Terminator::Open => continue,
            };
            if !agree(size) {
                return None;
            }
        }
        found
    }

    /// The parameters of the function giving the size of the allocation
    /// `value` is ([`Self::allocation`]), in the register of `piece`.
    fn allocated(&self, value: Value, piece: Piece, parameters: &[Source]) -> Option<AllocSize> {
        let mut found = None;
        let mut seen = BTreeSet::new();
        let mut work = vec![self.canonical(value)];
        while let Some(value) = work.pop() {
            if !seen.insert(value) {
                continue;
            }
            if seen.len() > STEPS {
                return None;
            }
            let size = match self.kind(value) {
                Kind::Phi => {
                    let &ValueInfo {
                        definition: Definition::Parameter { block, index },
                        ..
                    } = self.l1.value(value)?
                    else {
                        return None;
                    };
                    for (_, argument) in self.incoming(block, index as usize) {
                        work.push(self.canonical(argument));
                    }
                    continue;
                }
                Kind::Result(inst) => {
                    let i = self.l1.inst(inst)?;
                    let Op::Call { changes, .. } = &i.op else {
                        return None;
                    };
                    let at = i.results.iter().skip(1).position(|&r| r == value)?;
                    if changes.get(at) != Some(&piece.register) {
                        return None;
                    }
                    let callee = self.callees.get(&Site::Call(inst))?;
                    self.sized(Site::Call(inst), callee, piece, parameters)?
                }
                Kind::None
                | Kind::Const(_)
                | Kind::Undefined(..)
                | Kind::Address(_)
                | Kind::Entry(_)
                | Kind::Pure(_)
                | Kind::Load(_)
                | Kind::CallView { .. } => return None,
            };
            if found.is_some_and(|was| was != size) {
                return None;
            }
            found = Some(size);
        }
        found
    }

    /// The parameters of the function (of `parameters`) that `callee`'s
    /// allocation at `site` takes its size (and count) from, where it
    /// allocates, returns in `piece`'s register alone, and passes them as
    /// it found them at its entry.
    fn sized(
        &self,
        site: Site,
        callee: &Callee,
        piece: Piece,
        parameters: &[Source],
    ) -> Option<AllocSize> {
        let alloc = callee.alloc_size?;
        if callee.results.as_slice() != [piece] {
            return None;
        }
        let registers = self.site_registers(site);
        let parameter = |argument: usize| {
            let &Source::Register(passed) = callee.arguments.get(argument)? else {
                return None;
            };
            let value = *registers.get(usize::from(passed.register.0))?;
            let held = self.held(value);
            let mut entries = held.entries.iter();
            let (Some(&register), None) = (entries.next(), entries.next()) else {
                return None;
            };
            if held.value || held.undefined {
                return None;
            }
            parameters.iter().position(|source| {
                matches!(source, Source::Register(own) if own.register == register && own.offset == 0)
            })
        };
        Some(AllocSize {
            size: parameter(alloc.size)?,
            count: match alloc.count {
                Some(count) => Some(parameter(count)?),
                None => None,
            },
        })
    }

    /// What the function's calls pass each callee at a constant address
    /// ([`Found::passes`](super::Found::passes)): per register of the
    /// convention's argument registers and the call's arguments, what it
    /// holds at the calls.
    pub(super) fn passes(&self) -> BTreeMap<u64, BTreeMap<RegisterId, Passed>> {
        let convention = self.cx.convention;
        let mut passes: BTreeMap<u64, BTreeMap<RegisterId, Passed>> = BTreeMap::new();
        for (&site, callee) in &self.callees {
            let Some(target) = callee.target else {
                continue;
            };
            let registers = self.site_registers(site);
            let candidates = convention
                .arguments
                .iter()
                .chain(&convention.float_arguments)
                .copied()
                .chain(callee.arguments.iter().filter_map(|source| match source {
                    Source::Register(piece) => Some(piece.register),
                    Source::Stack { .. } => None,
                }));
            let to_target = passes.entry(target).or_default();
            for register in candidates {
                let Some(&value) = registers.get(usize::from(register.0)) else {
                    continue;
                };
                to_target
                    .entry(register)
                    .or_default()
                    .add(&self.held(value));
            }
        }
        passes
    }

    /// Whether `callee` is a function of the program called with no
    /// prototype: by its interface, or by the convention's registers where
    /// it has none (yet). What it reads of its arguments is then its
    /// interface's to say ([`Found::undeclared`](super::Found::undeclared)).
    fn undeclared(&self, callee: &Callee) -> bool {
        !callee.declared
            && !callee.foreign
            && callee
                .target
                .is_some_and(|target| callee.interfaced || self.cx.functions.contains(&target))
    }

    /// The functions of the program the function calls or jumps to with
    /// no prototype ([`Found::undeclared`](super::Found::undeclared)).
    pub(super) fn undeclared_callees(&self) -> BTreeSet<u64> {
        self.callees
            .values()
            .filter(|callee| self.undeclared(callee))
            .filter_map(|callee| callee.target)
            .collect()
    }

    /// The registers whose entry value the function's other calls (those
    /// not [`undeclared`](Self::undeclared)) may pass as a register
    /// argument ([`Found::opaque`](super::Found::opaque)): a declared
    /// prototype's parameters, a call through a pointer, to an address no
    /// function of the program starts at; the callee may read them. And
    /// those any call's argument is computed from
    /// ([`computed_reads`](Self::computed_reads)): the callee reads what
    /// is computed.
    pub(super) fn opaque_reads(&self) -> BTreeSet<RegisterId> {
        let mut reads = self.computed_reads();
        for (&site, callee) in &self.callees {
            if callee.foreign || self.undeclared(callee) {
                continue;
            }
            let registers = self.site_registers(site);
            for source in &callee.arguments {
                let Source::Register(piece) = source else {
                    continue;
                };
                if let Some(&value) = registers.get(usize::from(piece.register.0)) {
                    reads.extend(self.held(value).entries);
                }
            }
        }
        reads
    }

    /// The registers whose entry value the function only passes on in
    /// place where no declaration says a callee reads it
    /// ([`Found::forwarded`](super::Found::forwarded)): at every call
    /// that may pass one, the register holds, on every path, its own
    /// entry value or an undefined one, and is an argument past a
    /// variadic prototype's named parameters (none counted by a format
    /// string) or of a callee at a constant address, or behind an
    /// import's slot, that has neither a declaration nor code in the
    /// program, or of a call through a pointer after the last argument it
    /// sets ([`Self::after_last_set`]). A register a call's argument is
    /// computed from, or passed in another register or at a declared
    /// parameter, is none.
    pub(super) fn forwarded_reads(&self) -> BTreeSet<RegisterId> {
        self.only_passed_on(false)
    }

    /// The registers whose entry value the function only passes on in
    /// place to callees no declaration states the parameters of
    /// ([`Found::passed_on`](super::Found::passed_on)): as
    /// [`Self::forwarded_reads`], and also to a function of the program
    /// with no prototype and through a pointer.
    pub(super) fn passed_on_reads(&self) -> BTreeSet<RegisterId> {
        self.only_passed_on(true)
    }

    /// [`Self::forwarded_reads`]; where `anywhere`,
    /// [`Self::passed_on_reads`].
    fn only_passed_on(&self, anywhere: bool) -> BTreeSet<RegisterId> {
        let mut forwarded = BTreeSet::new();
        let mut read = self.computed_reads();
        for (&site, callee) in &self.callees {
            let stated = callee.foreign || self.undeclared(callee);
            if stated && !anywhere {
                continue;
            }
            // The arguments from this one on are not declared.
            let named = if stated {
                0
            } else if callee.declared {
                match callee.format {
                    Some(Formatting::Parsed) => usize::MAX,
                    Some(_) | None => self
                        .types
                        .signature(callee.signature)
                        .map_or(usize::MAX, |signature| signature.parameters.len()),
                }
            } else if anywhere || callee.target.is_some() || self.through_import(site) {
                0
            } else {
                self.after_last_set(site, callee)
            };
            let registers = self.site_registers(site);
            for (index, source) in callee.arguments.iter().enumerate() {
                let Source::Register(piece) = source else {
                    continue;
                };
                let Some(&value) = registers.get(usize::from(piece.register.0)) else {
                    continue;
                };
                let held = self.held(value);
                let in_place = !held.value && held.entries.iter().all(|&r| r == piece.register);
                if index >= named && in_place {
                    forwarded.extend(held.entries);
                } else {
                    read.extend(held.entries);
                }
            }
        }
        forwarded.retain(|register| !read.contains(register));
        forwarded
    }

    /// For a call through a pointer, the index of its arguments after the
    /// last one it sets (one not in place: computed, another register's
    /// entry value, or undefined), whose registers the function's code
    /// left alone, so passes on as its callers left them; `usize::MAX`
    /// where it sets none (a dispatch handing on its own arguments).
    /// Register classes are not told apart: the vector registers follow
    /// the integer ones, so a call setting one leaves no integer register
    /// after it.
    fn after_last_set(&self, site: Site, callee: &Callee) -> usize {
        let registers = self.site_registers(site);
        callee
            .arguments
            .iter()
            .enumerate()
            .filter(|(_, source)| {
                let Source::Register(piece) = source else {
                    return false;
                };
                registers
                    .get(usize::from(piece.register.0))
                    .is_some_and(|&value| {
                        let held = self.held(value);
                        held.value
                            || held.entries.is_empty()
                            || held.entries.iter().any(|&r| r != piece.register)
                    })
            })
            .last()
            .map_or(usize::MAX, |(index, _)| index + 1)
    }

    /// Whether the call at `site` goes through an import's pointer slot
    /// ([`Data::import_slot`](crate::data::Data::import_slot)).
    fn through_import(&self, site: Site) -> bool {
        let target = match site {
            Site::Call(inst) => match self.l1.inst(inst).map(|i| &i.op) {
                Some(&Op::Call { target, .. }) => target,
                Some(_) | None => return false,
            },
            Site::Tail(block) => match self.l1.block(block).map(|b| &b.terminator) {
                Some(&Terminator::Leave { address, .. }) => address,
                Some(_) | None => return false,
            },
        };
        matches!(self.called(target), Called::Through(slot) if self.cx.data.import_slot(slot))
    }

    /// Where the function's prototype is its own, its definition's
    /// ([`Prototype::own`]: debug information's, the user's), placed and
    /// not variadic: its declared parameters' registers and those whose
    /// entry value it reads or computes a call's argument from
    /// ([`Self::computed_reads`]). Its other registers it only passes on, in
    /// place, to its calls (`PyModule_GetState(m, a2, …)`, the callee's
    /// prototype unknown): the declaration says it takes nothing there.
    pub(super) fn own_reads(&mut self) -> Option<BTreeSet<RegisterId>> {
        self.placed_prototype(true).then(|| self.computed_reads())
    }

    /// Where the function's prototype is a declaration that is not its
    /// own (the type library's for the name it is exported under, its
    /// mangling's), placed and not variadic: its declared parameters'
    /// registers, those whose entry value it reads or computes a call's
    /// argument from ([`Self::computed_reads`]), and those it passes to a
    /// call in another register
    /// ([`Found::declared_reads`](super::Found::declared_reads)). Its
    /// other registers it only passes on to its calls as it found them.
    pub(super) fn declared_reads(&mut self) -> Option<BTreeSet<RegisterId>> {
        if !self.placed_prototype(false) {
            return None;
        }
        let mut reads = self.computed_reads();
        for (&site, callee) in &self.callees {
            if callee.foreign {
                continue;
            }
            let registers = self.site_registers(site);
            for source in &callee.arguments {
                let Source::Register(piece) = source else {
                    continue;
                };
                if let Some(&value) = registers.get(usize::from(piece.register.0)) {
                    let moved = self.held(value).entries;
                    reads.extend(moved.into_iter().filter(|&r| r != piece.register));
                }
            }
        }
        Some(reads)
    }

    /// Whether the function has a declared prototype lowering placed,
    /// not variadic, that is its own (`own`) or not.
    fn placed_prototype(&mut self, own: bool) -> bool {
        if self.returns.declared.is_none() {
            return false;
        }
        let cx = self.cx;
        cx.prototypes
            .of(self.l1.entry, &mut self.types)
            .filter(|prototype| prototype.own == own)
            .and_then(|prototype| self.types.signature(prototype.signature))
            .is_some_and(|signature| !signature.variadic)
    }

    /// The values `value` is on some path (through block parameters) other
    /// than undefined ones and entry values of registers: the computations
    /// it may pass on. Past [`STEPS`] values, `value` itself.
    pub(super) fn computed(&self, value: Value) -> Vec<Value> {
        let mut computed = Vec::new();
        let mut seen = BTreeSet::new();
        let mut work = vec![self.canonical(value)];
        while let Some(value) = work.pop() {
            if !seen.insert(value) {
                continue;
            }
            if seen.len() > STEPS {
                return vec![value];
            }
            match self.kind(value) {
                Kind::Undefined(..) | Kind::Entry(_) => {}
                Kind::Phi => match self.l1.value(value) {
                    Some(&ValueInfo {
                        definition: Definition::Parameter { block, index },
                        ..
                    }) => {
                        for (_, argument) in self.incoming(block, index as usize) {
                            work.push(self.canonical(argument));
                        }
                    }
                    _ => computed.push(value),
                },
                Kind::None
                | Kind::Const(_)
                | Kind::Address(_)
                | Kind::Pure(_)
                | Kind::Load(_)
                | Kind::Result(_)
                | Kind::CallView { .. } => computed.push(value),
            }
        }
        computed
    }

    /// What `value` is on every path (through block parameters): undefined,
    /// the entry value of registers, or another value. Past [`STEPS`]
    /// values, another value or the entry value of any register.
    fn held(&self, value: Value) -> Passed {
        let mut held = Passed::default();
        let mut seen = BTreeSet::new();
        let mut work = vec![self.canonical(value)];
        while let Some(value) = work.pop() {
            if !seen.insert(value) {
                continue;
            }
            if seen.len() > STEPS {
                held.value = true;
                let count = u16::try_from(self.cx.declarations.registers.len()).unwrap_or(u16::MAX);
                held.entries.extend((0..count).map(RegisterId));
                return held;
            }
            match self.kind(value) {
                Kind::Undefined(..) => held.undefined = true,
                Kind::Entry(register) => {
                    held.entries.insert(register);
                }
                Kind::Phi => {
                    let Some(&ValueInfo {
                        definition: Definition::Parameter { block, index },
                        ..
                    }) = self.l1.value(value)
                    else {
                        held.value = true;
                        return held;
                    };
                    for (_, argument) in self.incoming(block, index as usize) {
                        work.push(self.canonical(argument));
                    }
                }
                Kind::None
                | Kind::Const(_)
                | Kind::Address(_)
                | Kind::Pure(_)
                | Kind::Load(_)
                | Kind::Result(_)
                | Kind::CallView { .. } => held.value = true,
            }
        }
        held
    }
}

/// How deep [`Lowering::futex_count`] and [`Lowering::known_bits`] look.
const FUTEX_DEPTH: usize = 8;

/// The bits of a `futex` operation that choose its command: all but
/// `FUTEX_PRIVATE_FLAG` and `FUTEX_CLOCK_REALTIME` (of the 32 the kernel
/// reads).
const FUTEX_COMMAND: u64 = 0xffff_fe7f;

impl Lowering<'_, '_> {
    /// How many arguments a `futex` call whose operation is `op` reads, on
    /// every run: the most of its alternatives (a select's, a block
    /// parameter's), each by its command where its command bits are
    /// known ([`Self::known_bits`]); `None` if one is not.
    fn futex_count(&self, op: Value, depth: usize) -> Option<usize> {
        let depth = depth.checked_sub(1)?;
        let alternatives: Vec<Value> = match self.l1.value(op)?.definition {
            Definition::Parameter { block, index } => self
                .incoming(block, index as usize)
                .into_iter()
                .map(|(_, argument)| argument)
                .collect(),
            Definition::Result { .. } => {
                if let Some(&Op::Select {
                    then, otherwise, ..
                }) = self.defining(op).map(|(_, op)| op)
                {
                    vec![then, otherwise]
                } else {
                    let (known, value) = self.known_bits(op, depth);
                    return (known & FUTEX_COMMAND == FUTEX_COMMAND)
                        .then(|| futex_arguments(value))
                        .flatten();
                }
            }
        };
        alternatives
            .into_iter()
            .map(|alternative| self.futex_count(alternative, depth))
            .try_fold(0, |most, count| Some(most.max(count?)))
    }

    /// How many arguments a `futex` call whose operation is `op` reads
    /// under [`Context::assume_futex`](crate::lower::Context::assume_futex):
    /// the command of the constant `op` is made of with another value by
    /// `xor` or `or` (through extensions and the low part a narrower write
    /// leaves: `xor $0x81,%sil`), where the assumption takes it.
    fn futex_assumed(&self, op: Value) -> Option<usize> {
        let mut v = op;
        for _ in 0..FUTEX_DEPTH {
            match *self.defining(v)?.1 {
                // The low bits the kernel reads are the extended value's.
                Op::Extend { value, .. }
                | Op::Extract {
                    value, offset: 0, ..
                }
                | Op::Concat { low: value, .. } => v = value,
                Op::Binary(binary @ (Binary::Xor | Binary::Or), a, b) => {
                    let constant = |x: Value| {
                        let mask = match self.width(x) {
                            width if width >= 32 => 0xffff_ffff,
                            width => (1u64 << width) - 1,
                        };
                        let (known, value) = self.known_bits(x, FUTEX_DEPTH);
                        (known & mask == mask).then_some(value)
                    };
                    let c = constant(b).or_else(|| constant(a))?;
                    let command = c & FUTEX_COMMAND;
                    let taken = command != 0 || (binary == Binary::Xor && c & 0x80 != 0);
                    return taken.then(|| futex_arguments(c)).flatten();
                }
                Op::Const(_)
                | Op::Undefined(..)
                | Op::Unary(..)
                | Op::Binary(..)
                | Op::Flag(..)
                | Op::Extract { .. }
                | Op::Select { .. }
                | Op::Lanes { .. }
                | Op::Float { .. }
                | Op::Load { .. }
                | Op::Store { .. }
                | Op::Intrinsic { .. }
                | Op::Call { .. }
                | Op::SystemCall { .. }
                | Op::Landing { .. } => return None,
            }
        }
        None
    }

    /// Which of the low 32 bits of `v` every run gives the same, and those
    /// bits' values: through constants, `and`, `or`, `xor`, zero extensions,
    /// extractions from bit 0 and concatenations (`depth` deep at most).
    fn known_bits(&self, v: Value, depth: usize) -> (u64, u64) {
        const LOW: u64 = 0xffff_ffff;
        let Some(depth) = depth.checked_sub(1) else {
            return (0, 0);
        };
        let width_mask = |width: u16| {
            if width >= 64 {
                u64::MAX
            } else {
                (1u64 << width) - 1
            }
        };
        let known = match self.defining(v).map(|(_, op)| op) {
            Some(Op::Const(bits)) => (u64::MAX, bits.low_u64()),
            // A bit known 0 on either side is 0.
            Some(&Op::Binary(Binary::And, a, b)) => {
                let ((ka, va), (kb, vb)) = (self.known_bits(a, depth), self.known_bits(b, depth));
                let zeros = (ka & !va) | (kb & !vb);
                let ones = ka & kb & va & vb;
                (zeros | ones, ones)
            }
            // A bit known 1 on either side is 1.
            Some(&Op::Binary(Binary::Or, a, b)) => {
                let ((ka, va), (kb, vb)) = (self.known_bits(a, depth), self.known_bits(b, depth));
                let ones = (ka & va) | (kb & vb);
                let zeros = ka & kb & !va & !vb;
                (zeros | ones, ones)
            }
            Some(&Op::Binary(Binary::Xor, a, b)) => {
                let ((ka, va), (kb, vb)) = (self.known_bits(a, depth), self.known_bits(b, depth));
                (ka & kb, (va ^ vb) & ka & kb)
            }
            Some(&Op::Extend {
                signed: false,
                value,
                ..
            }) => {
                let inner = width_mask(self.width(value));
                let (k, val) = self.known_bits(value, depth);
                ((k & inner) | !inner, val & inner)
            }
            // The bits above a sign extension's source are its top bit.
            Some(&Op::Extend {
                signed: true,
                value,
                ..
            }) => {
                let width = self.width(value);
                let inner = width_mask(width);
                let (k, val) = self.known_bits(value, depth);
                let top = 1u64
                    .checked_shl(u32::from(width.saturating_sub(1)))
                    .unwrap_or(0);
                if k & top == 0 {
                    (k & inner, val & inner)
                } else if val & top == 0 {
                    ((k & inner) | !inner, val & inner)
                } else {
                    ((k & inner) | !inner, (val & inner) | !inner)
                }
            }
            Some(&Op::Extract {
                value, offset: 0, ..
            }) => self.known_bits(value, depth),
            Some(&Op::Concat { high, low }) => {
                let shift = u32::from(self.width(low));
                let low_mask = width_mask(self.width(low));
                let (kl, vl) = self.known_bits(low, depth);
                let (kh, vh) = self.known_bits(high, depth);
                let (kh, vh) = (
                    kh.checked_shl(shift).unwrap_or(0),
                    vh.checked_shl(shift).unwrap_or(0),
                );
                ((kl & low_mask) | kh, (vl & low_mask) | vh)
            }
            _ => (0, 0),
        };
        (known.0 & LOW, known.1 & known.0 & LOW)
    }
}

/// How many of its arguments Linux reads of a `futex` call whose
/// operation (its second argument) is `op` (the kernel's `do_futex`):
/// counted by position, so an argument an operation ignores before one it
/// reads is read; `None` for an operation it does not have. The private
/// and realtime-clock flags (`FUTEX_PRIVATE_FLAG`, `FUTEX_CLOCK_REALTIME`)
/// do not change it.
fn futex_arguments(op: u64) -> Option<usize> {
    Some(match op & 0xffff_fe7f {
        // FUTEX_UNLOCK_PI, FUTEX_TRYLOCK_PI: the word alone.
        7 | 8 => 2,
        // FUTEX_WAKE: and how many to wake.
        1 => 3,
        // FUTEX_WAIT, FUTEX_LOCK_PI, FUTEX_LOCK_PI2: and the timeout.
        0 | 6 | 13 => 4,
        // FUTEX_REQUEUE (a count in the timeout's place, the second word),
        // FUTEX_WAIT_REQUEUE_PI (the second word).
        3 | 11 => 5,
        // FUTEX_CMP_REQUEUE, FUTEX_WAKE_OP, FUTEX_CMP_REQUEUE_PI: all six;
        // FUTEX_WAIT_BITSET, FUTEX_WAKE_BITSET: the bitset is the sixth.
        4 | 5 | 9 | 10 | 12 => 6,
        _ => return None,
    })
}

/// Whether code type `ty`'s parameters and result are all scalars C
/// has (at most [`MAX_SCALAR`] bits).
pub(crate) fn scalar_code(types: &Types, ty: TypeId) -> bool {
    types.signature(ty).is_some_and(|signature| {
        signature
            .parameters
            .iter()
            .chain(&signature.returns)
            .all(|&ty| {
                types
                    .value_width(ty)
                    .is_some_and(|width| width <= MAX_SCALAR)
            })
    })
}

/// The type of the code at `address` (a function's entry) as a
/// prototype of `prototypes` or an interface of `interfaces` states it
/// (the prototype's, else the interface's, untyped), interned into
/// `types`; `None` where neither does.
pub(crate) fn stated_code_type(
    prototypes: &dyn Prototypes,
    interfaces: &BTreeMap<u64, Interface>,
    address: u64,
    types: &mut Types,
) -> Option<TypeId> {
    if let Some(prototype) = prototypes.of(address, types) {
        return Some(prototype.signature);
    }
    let interface = interfaces.get(&address)?;
    Some(interface_signature(interface, types))
}

/// `signature` (an interface's: untyped, or typed by the callee's
/// scheme) with, at each parameter in a vector register of `parameters`
/// and at a result in one of `returns`, the type C passes there
/// ([`vector_class`]), and at each in another register one C passes
/// there ([`integer_class`]): the declaration then places them where
/// the definition has them.
pub(super) fn classed(
    types: &mut Types,
    convention: &Convention,
    signature: TypeId,
    parameters: &[Source],
    returns: &[Piece],
) -> TypeId {
    let Some(mut code) = types.signature(signature).cloned() else {
        return signature;
    };
    for (ty, source) in code.parameters.iter_mut().zip(parameters) {
        if let Source::Register(piece) = source {
            *ty = if convention.float_arguments.contains(&piece.register) {
                vector_class(types, *ty)
            } else {
                integer_class(types, *ty)
            };
        }
    }
    if let ([piece], Some(ty)) = (returns, code.returns.as_mut()) {
        *ty = if convention.float_results.contains(&piece.register) {
            vector_class(types, *ty)
        } else {
            integer_class(types, *ty)
        };
    }
    types.intern(Type::Code(code))
}

/// The type C passes in an integer register for a value of type `ty`
/// there: `ty` unless it is a floating-point type, which C would pass in
/// a vector register (what types it so is a guess: its bits made of an
/// integer's, as `scalbnf` makes a `float` of its exponent); then the
/// bits.
pub(super) fn integer_class(types: &mut Types, ty: TypeId) -> TypeId {
    match types.get(ty) {
        Some(&Type::Float(format)) => types.intern(Type::Bits(format.width())),
        Some(_) | None => ty,
    }
}

/// The type C passes in a vector register for a value of type `ty`
/// there: `ty` if it is a floating-point or a vector type, else `double`
/// or `float` for 64 or 32 bits and two 64-bit lanes for 128 (C passes an
/// integer or a pointer in integer registers, so the bits in a vector
/// register are those of a floating-point value or a vector to it); `ty`
/// at other widths (256 and 512 bits print as vectors).
pub(super) fn vector_class(types: &mut Types, ty: TypeId) -> TypeId {
    if matches!(types.get(ty), Some(Type::Float(_) | Type::Vector { .. })) {
        return ty;
    }
    match types.value_width(ty) {
        Some(32) => types.intern(Type::Float(FloatFormat::Single)),
        Some(64) => types.intern(Type::Float(FloatFormat::Double)),
        Some(128) => {
            let element = types.intern(Type::Bits(64));
            types.intern(Type::Vector { lanes: 2, element })
        }
        Some(_) | None => ty,
    }
}

/// The width in bits of what `source` names.
pub(super) fn source_width(source: Source) -> u16 {
    match source {
        Source::Register(piece) => piece.width,
        Source::Stack { bytes, .. } => bytes.saturating_mul(8),
    }
}

/// The type of code with `interface`, untyped: its parameters' and
/// return value's widths (variadic if it is).
fn interface_signature(interface: &Interface, types: &mut Types) -> TypeId {
    let ty = untyped_signature(&interface.parameters, &interface.returns, types);
    if !interface.variadic {
        return ty;
    }
    let Some(mut signature) = types.signature(ty).cloned() else {
        return ty;
    };
    signature.variadic = true;
    types.intern(Type::Code(signature))
}

/// Code type `signature` returning `void *` where it returns a pointer-wide
/// value: an allocator wrapper's ([`Interface::alloc_size`]), whose
/// allocation is any object's.
fn allocating(types: &mut Types, signature: TypeId) -> TypeId {
    let Some(mut code) = types.signature(signature).cloned() else {
        return signature;
    };
    let pointer = types.pointer_width();
    if code.returns.and_then(|ty| types.value_width(ty)) != Some(pointer) {
        return signature;
    }
    code.returns = Some(types.intern(Type::Pointer(None)));
    types.intern(Type::Code(code))
}

/// The type of code taking `parameters` and returning in `returns`,
/// untyped: their widths.
fn untyped_signature(parameters: &[Source], returns: &[Piece], types: &mut Types) -> TypeId {
    let parameters = parameters
        .iter()
        .map(|&source| types.intern(Type::Bits(source_width(source))))
        .collect();
    let width: u16 = returns.iter().map(|piece| piece.width).sum();
    let returns = (width > 0).then(|| types.intern(Type::Bits(width)));
    types.intern(Type::Code(Signature {
        parameters,
        returns,
        variadic: false,
    }))
}

/// The type of code known only by its address under `cx`'s convention:
/// its whole integer argument registers and its first result register,
/// untyped.
fn unknown_signature(cx: &Context<'_>, types: &mut Types) -> TypeId {
    let width = |register: RegisterId| cx.declarations.info(register).map_or(0, |info| info.width);
    let convention = cx.convention;
    let parameters = convention
        .arguments
        .iter()
        .map(|&register| types.intern(Type::Bits(width(register))))
        .collect();
    let returns = convention
        .results
        .first()
        .map(|&register| width(register))
        .filter(|&bits| bits > 0)
        .map(|bits| types.intern(Type::Bits(bits)));
    types.intern(Type::Code(Signature {
        parameters,
        returns,
        variadic: false,
    }))
}
