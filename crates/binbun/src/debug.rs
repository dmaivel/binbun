//! Debug information as input: where a binary has DWARF or PDB
//! ([`binbun_debuginfo::info`]), its names and types are the strongest
//! evidence there is, asserted over the solver.
//!
//! - **Prototypes**: a function's debug entry is its declared prototype
//!   (above the type library, manglings and schemes), with its parameters'
//!   names, only where the convention places its parameters where the
//!   debug information says they are at the entry
//!   ([`DebugInfo::unplaced`]): a parameter of a type no register holds
//!   (`long double`; a structure or union by value that the convention
//!   has no rule for, or of a unit not C's, whose language may pass it
//!   otherwise), a stated register or
//!   incoming stack slot other than the convention's (a clone whose
//!   parameters the compiler removed or changed: GCC's `.isra`,
//!   `.constprop`), or (PDB) a type stating other parameters than the
//!   symbols, and the prototype is ignored and counted. A stated place in
//!   the function's own frame (below the entry stack pointer) says
//!   nothing about the entry: unoptimised code's parameters are stated
//!   in their spill slots for the whole function.
//! - **Names**: a function without a symbol takes its debug name where
//!   no symbol and no other debug entry has it (C has one name per
//!   function in a file).
//! - **Frame variables**: a local variable that lives in one stack slot
//!   for all its stated ranges is at that offset from the entry stack
//!   pointer ([`cfa_to_entry`]), named and typed in lowering.
//!
//! Types convert to L2's as declarations do (`crate::prototypes`):
//! typedefs looked through, enumerations as their integer, structures
//! and unions with their byte-aligned fields, a parameter of array type
//! a pointer to its element.

use std::collections::{BTreeMap, BTreeSet};

use binbun_ast::types::{Aggregate, Field, Signature, Type, TypeId, Types};
use binbun_debuginfo::info::DebugModel;
use binbun_debuginfo::info::model::{
    CompositeKind, Encoding, Function, Language, Place, Type as DebugType, TypeId as DebugTypeId,
};
use binbun_decompile::lower::{Aggregates, Convention, places};
use binbun_decompile::mapping::Source;
use binbun_decompile::prototype::{DebugStated, Local, Open, Prototype, Unplaced};
use binbun_loader::{Image, Machine};
use binbun_semantics::Declarations;
use binbun_semantics::ir::Format;

use crate::target::{convention, setup};

/// The canonical frame address minus the entry stack pointer: added to a
/// [`Place::Stack`] offset it gives an offset from the entry stack
/// pointer (L2's [`Origin::Slot`](binbun_ast::ir::Origin::Slot)).
/// x86-64's call pushes the return address, AArch64's leaves it in the
/// link register.
pub const fn cfa_to_entry(machine: Machine) -> i64 {
    match machine {
        Machine::X86_64 | Machine::X86 => 8,
        Machine::Aarch64 | Machine::Arm | Machine::Other => 0,
    }
}

/// An image's debug information as the decompiler's input.
#[derive(Debug)]
pub struct DebugInfo {
    model: DebugModel,
    /// [`cfa_to_entry`] of the image.
    cfa_to_entry: i64,
    /// Why each function's debug prototype is not taken, by entry
    /// (absent: taken).
    unplaced: BTreeMap<u64, Unplaced>,
}

impl DebugInfo {
    /// `model`, the debug information of `image`, with each function's
    /// prototype checked against `image`'s convention.
    pub fn new(model: DebugModel, image: &Image<'_>) -> Self {
        let cfa = cfa_to_entry(image.machine);
        let unplaced = setup(image, 0).map_or_else(
            |_| {
                model
                    .functions
                    .keys()
                    .map(|&entry| (entry, Unplaced::Location))
                    .collect()
            },
            |setup| {
                let declarations = setup.declarations;
                let convention = convention(image, declarations);
                let pointer = declarations
                    .info(setup.stack_pointer)
                    .map_or(64, |info| u64::from(info.width));
                let placement = Placement {
                    model: &model,
                    declarations,
                    convention: &convention,
                    pointer: pointer / 8,
                    cfa,
                };
                model
                    .functions
                    .iter()
                    .filter_map(|(&entry, function)| {
                        placement.check(function).err().map(|why| (entry, why))
                    })
                    .collect()
            },
        );
        Self {
            model,
            cfa_to_entry: cfa,
            unplaced,
        }
    }

    /// The debug information.
    pub fn model(&self) -> &DebugModel {
        &self.model
    }

    /// Why the debug prototype of the function at `entry` is not taken,
    /// if it has one and it is not.
    pub fn unplaced(&self, entry: u64) -> Option<Unplaced> {
        self.unplaced.get(&entry).copied()
    }

    /// The debug names of functions and globals that may name them: C
    /// identifiers no symbol in `taken` and no other function or global
    /// of the debug information has (C has one name per external object
    /// in a program; two `static` ones of different files would print
    /// alike). Code that only a public symbol names (a public PDB's, as
    /// symbol servers serve) takes that name, unless a function or global
    /// of the debug information has it.
    pub fn names<'s>(&'s self, taken: &BTreeSet<&str>) -> Vec<(u64, &'s str)> {
        let records = self
            .model
            .functions
            .iter()
            .filter_map(|(&entry, function)| Some((entry, function.name.as_deref()?)))
            .chain(
                self.model
                    .globals
                    .iter()
                    .map(|(&address, global)| (address, global.name.as_str())),
            );
        let stated: BTreeSet<&str> = records.clone().map(|(_, name)| name).collect();
        let named = records.chain(
            self.model
                .publics
                .iter()
                .filter(|&(address, name)| {
                    !stated.contains(name.as_str())
                        && self
                            .model
                            .functions
                            .get(address)
                            .is_none_or(|function| function.name.is_none())
                })
                .map(|(&address, name)| (address, name.as_str())),
        );
        let mut uses: BTreeMap<&str, usize> = BTreeMap::new();
        for (_, name) in named.clone() {
            *uses.entry(name).or_default() += 1;
        }
        named
            .filter(|(_, name)| {
                uses.get(name) == Some(&1) && !taken.contains(name) && is_identifier(name)
            })
            .collect()
    }

    /// The globals with a size, as objects: (address, size in bytes).
    pub fn objects(&self) -> Vec<(u64, u64)> {
        self.model
            .globals
            .iter()
            .filter_map(|(&address, global)| {
                Some((
                    address,
                    self.model.size(global.ty).filter(|&size| size > 0)?,
                ))
            })
            .collect()
    }

    /// The type of the global at `address`, interned into `types`, where
    /// L2 can say it.
    pub fn global(&self, address: u64, types: &mut Types) -> Option<TypeId> {
        let global = self.model.globals.get(&address)?;
        self.convert(types).any(global.ty)
    }

    /// The debug prototype of the function at `entry`, its types interned
    /// into `types`, where it is taken.
    pub fn prototype(&self, entry: u64, types: &mut Types) -> Option<Prototype> {
        if self.unplaced.contains_key(&entry) {
            return None;
        }
        let function = self.model.functions.get(&entry)?;
        let mut convert = self.convert(types);
        let (signature, wide_result) = convert.declared(function)?;
        Some(Prototype {
            name: function.name.clone(),
            signature: types.intern(Type::Code(signature)),
            returns_stated: true,
            own: true,
            open: Open::default(),
            noreturn: false,
            format: None,
            format_arg: Vec::new(),
            alloc_size: None,
            wide_result,
        })
    }

    /// What the debug information states about the body of the function
    /// at `entry`, its types interned into `types`.
    pub fn facts(&self, entry: u64, types: &mut Types) -> Option<DebugStated> {
        let function = self.model.functions.get(&entry)?;
        let unplaced = self.unplaced(entry);
        // A struct or union by value is passed in parts or through a
        // pointer: the parameters lowering gives are not the stated ones,
        // one for one.
        let parameters = if unplaced.is_none() && !by_value(&self.model, function) {
            function
                .parameters
                .iter()
                .map(|parameter| parameter.name.clone())
                .collect()
        } else {
            Vec::new()
        };
        let mut convert = self.convert(types);
        let locals = function
            .locals
            .iter()
            .filter_map(|local| {
                let name = local.name.clone()?;
                let slot = local.stack_slot()?;
                let bytes = self.model.size(local.ty).filter(|&bytes| bytes > 0)?;
                Some(Local {
                    offset: slot.checked_add(self.cfa_to_entry)?,
                    bytes,
                    name,
                    ty: convert.any(local.ty),
                })
            })
            .collect();
        let registers = function
            .locals
            .iter()
            .filter(|local| {
                !local.location.is_empty()
                    && local
                        .location
                        .iter()
                        .all(|span| matches!(span.place, Place::Register(_)))
            })
            .count();
        Some(DebugStated {
            parameters,
            unplaced,
            locals,
            registers,
        })
    }

    fn convert<'t>(&'t self, types: &'t mut Types) -> Convert<'t> {
        Convert {
            model: &self.model,
            types,
            seen: BTreeMap::new(),
        }
    }
}

/// Whether `name` is a C identifier (a C++ debug name, `operator new` or
/// `std::vector<int>::push_back`, is not).
fn is_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Whether `function` passes or returns a struct or union by value.
fn by_value(model: &DebugModel, function: &Function) -> bool {
    let record = |id: DebugTypeId| matches!(model.ty(model.resolve(id)), DebugType::Composite(_));
    record(function.returns)
        || function
            .parameters
            .iter()
            .any(|parameter| record(parameter.ty))
}

/// How deep [`Placement::whole`] follows a type's members.
const WHOLE_DEPTH: u32 = 16;

/// The check that the convention places a debug prototype's parameters
/// where the debug information says they are at the entry.
struct Placement<'p> {
    model: &'p DebugModel,
    declarations: &'p Declarations,
    convention: &'p Convention,
    /// The width of a pointer (and of a stack argument slot) in bytes.
    pointer: u64,
    /// [`cfa_to_entry`].
    cfa: i64,
}

impl Placement<'_> {
    /// `Ok` where `function`'s prototype is placed as stated.
    fn check(&self, function: &Function) -> Result<(), Unplaced> {
        if function
            .arity
            .is_some_and(|arity| arity != function.parameters.len())
        {
            return Err(Unplaced::Arity);
        }
        if by_value(self.model, function) {
            return self.check_by_value(function);
        }
        if !matches!(
            self.model.ty(self.model.resolve(function.returns)),
            DebugType::Void
        ) {
            self.scalar(function.returns, false).ok_or(Unplaced::Type)?;
        }
        let convention = self.convention;
        let mut integer = convention.arguments.iter();
        let mut vector = convention.float_arguments.iter();
        let link = u64::try_from(self.cfa).unwrap_or(0);
        let mut stack = link + u64::from(convention.shadow);
        for (position, parameter) in function.parameters.iter().enumerate() {
            let (float, bytes) = self.scalar(parameter.ty, true).ok_or(Unplaced::Type)?;
            if !float && bytes > self.pointer {
                return Err(Unplaced::Type);
            }
            let register = match (convention.positional, float) {
                (true, true) => convention.float_arguments.get(position),
                (true, false) => convention.arguments.get(position),
                (false, true) => vector.next(),
                (false, false) => integer.next(),
            };
            let placed = if let Some(&register) = register {
                Placed::Register {
                    name: self
                        .declarations
                        .info(register)
                        .map(|info| register_key(info.name)),
                    home: (convention.shadow > 0)
                        .then(|| link + self.pointer * u64::try_from(position).unwrap_or(0)),
                }
            } else {
                let at = stack;
                stack += bytes.div_ceil(self.pointer) * self.pointer;
                Placed::Stack(at)
            };
            let stated = parameter.place_at(function.entry);
            let agrees = match (stated, placed) {
                (Some(Place::Register(stated)), Placed::Register { name, .. }) => {
                    name.as_deref() == Some(register_key(stated).as_str())
                }
                (Some(&Place::Stack(cfa)), placed) => {
                    let entry = cfa.saturating_add(self.cfa);
                    // Below the entry stack pointer is the function's own
                    // frame: no place at the entry.
                    match (u64::try_from(entry), placed) {
                        (Err(_), _) => true,
                        (Ok(at), Placed::Stack(slot)) => at == slot,
                        (Ok(at), Placed::Register { home, .. }) => home == Some(at),
                    }
                }
                (Some(Place::Register(_)), Placed::Stack(_)) => false,
                (Some(Place::Relative { .. } | Place::Other) | None, _) => true,
            };
            if !agrees {
                return Err(Unplaced::Location);
            }
        }
        Ok(())
    }

    /// [`Self::check`] of a function that passes or returns a struct or
    /// union by value: placed by the convention's rule for those
    /// ([`places`], as lowering places a declaration), where it has one,
    /// the function is C's (another language may pass one otherwise:
    /// [`Language`]) and L2's type of each has all of it
    /// ([`Self::whole`]: the rule goes by the fields).
    fn check_by_value(&self, function: &Function) -> Result<(), Unplaced> {
        let c = function
            .unit
            .and_then(|unit| self.model.unit(unit))
            .is_some_and(|unit| unit.language == Language::C);
        let stated = core::iter::once(function.returns)
            .chain(function.parameters.iter().map(|parameter| parameter.ty));
        let whole = stated
            .filter(|&id| !matches!(self.model.ty(self.model.resolve(id)), DebugType::Void))
            .all(|id| self.whole(id, WHOLE_DEPTH));
        if !c || !whole || self.convention.aggregates == Aggregates::Unknown {
            return Err(Unplaced::Type);
        }
        let pointer = u16::try_from(self.pointer * 8).unwrap_or(64);
        let mut types = Types::new(pointer);
        let mut convert = Convert {
            model: self.model,
            types: &mut types,
            seen: BTreeMap::new(),
        };
        let (mut signature, wide) = convert.declared(function).ok_or(Unplaced::Type)?;
        signature.returns = signature.returns.or(wide);
        let link = u16::try_from(self.cfa).unwrap_or(0);
        let placed = places(
            &mut types,
            self.convention,
            self.declarations,
            pointer,
            link,
            &signature,
        )
        .ok_or(Unplaced::Type)?;
        let agree = function
            .parameters
            .iter()
            .zip(&placed.parameters)
            .all(|(parameter, sources)| self.agrees(parameter.place_at(function.entry), sources));
        if agree {
            Ok(())
        } else {
            Err(Unplaced::Location)
        }
    }

    /// Whether a parameter `stated` to be there at the entry is where the
    /// convention places it, at `sources` (as [`Self::check`] compares a
    /// scalar's: a place in the function's own frame, a place of several
    /// pieces or none says nothing).
    fn agrees(&self, stated: Option<&Place>, sources: &[Source]) -> bool {
        match (stated, sources) {
            (Some(Place::Register(stated)), [Source::Register(piece)]) => self
                .declarations
                .info(piece.register)
                .is_some_and(|info| register_key(info.name) == register_key(stated)),
            (Some(Place::Register(_)), _) => false,
            (Some(&Place::Stack(cfa)), sources) => {
                let Ok(at) = u64::try_from(cfa.saturating_add(self.cfa)) else {
                    return true;
                };
                match sources.first() {
                    Some(&Source::Stack { offset, .. }) => u64::try_from(offset) == Ok(at),
                    Some(Source::Register(piece)) => self.home(piece.register) == Some(at),
                    None => false,
                }
            }
            (Some(Place::Relative { .. } | Place::Other) | None, _) => true,
        }
    }

    /// The home slot of argument register `register` (from the entry
    /// stack pointer), where the convention gives its register arguments
    /// one.
    fn home(&self, register: binbun_semantics::ir::RegisterId) -> Option<u64> {
        let convention = self.convention;
        if convention.shadow == 0 {
            return None;
        }
        let position = [&convention.arguments, &convention.float_arguments]
            .into_iter()
            .find_map(|registers| registers.iter().position(|&other| other == register))?;
        let link = u64::try_from(self.cfa).unwrap_or(0);
        Some(link + self.pointer * u64::try_from(position).ok()?)
    }

    /// Whether L2's type of a value of type `id` has all of it, so that
    /// the convention's rule for a struct or union, which goes by the
    /// fields, sees every one: no bit-field (L2's structures have none),
    /// no member of a type L2 does not say, to `depth` levels.
    fn whole(&self, id: DebugTypeId, depth: u32) -> bool {
        let Some(depth) = depth.checked_sub(1) else {
            return false;
        };
        match self.model.ty(self.model.resolve(id)) {
            &DebugType::Base {
                bytes, encoding, ..
            } => match encoding {
                Encoding::Float => matches!(bytes, 4 | 8),
                Encoding::Other => false,
                Encoding::Signed | Encoding::Unsigned | Encoding::Char { .. } | Encoding::Bool => {
                    true
                }
            },
            DebugType::Pointer { .. } | DebugType::Enum { .. } => true,
            &DebugType::Array { element, count } => count.is_some() && self.whole(element, depth),
            DebugType::Composite(composite) => {
                composite.size.is_some()
                    && composite
                        .fields
                        .iter()
                        .all(|field| field.bits.is_none() && self.whole(field.ty, depth))
            }
            DebugType::Void
            | DebugType::Typedef { .. }
            | DebugType::Function { .. }
            | DebugType::Unknown => false,
        }
    }

    /// Whether a value of type `id` is floating-point, and its bytes,
    /// where a register holds it (a parameter of array type is a pointer
    /// where `parameter`).
    fn scalar(&self, id: DebugTypeId, parameter: bool) -> Option<(bool, u64)> {
        match self.model.ty(self.model.resolve(id)) {
            &DebugType::Base {
                bytes, encoding, ..
            } => match encoding {
                Encoding::Float if bytes <= 8 => Some((true, bytes)),
                Encoding::Float | Encoding::Other => None,
                Encoding::Signed | Encoding::Unsigned | Encoding::Char { .. } | Encoding::Bool => {
                    Some((false, bytes))
                }
            },
            &(DebugType::Pointer { bytes, .. } | DebugType::Enum { bytes, .. }) => {
                Some((false, bytes))
            }
            DebugType::Array { .. } if parameter => Some((false, self.pointer)),
            DebugType::Void
            | DebugType::Array { .. }
            | DebugType::Composite(_)
            | DebugType::Typedef { .. }
            | DebugType::Function { .. }
            | DebugType::Unknown => None,
        }
    }
}

/// Where the convention places a parameter.
#[derive(Clone, Debug)]
enum Placed {
    /// In a register (by its name, [`register_key`]), with its home slot
    /// (from the entry stack pointer) where the convention gives one.
    Register {
        name: Option<String>,
        home: Option<u64>,
    },
    /// In the stack, this far from the entry stack pointer.
    Stack(u64),
}

/// A register's name as debug information and the lifter both say it:
/// lower case, x86's `zmm`/`ymm` as `xmm`, AArch64's `q`/`d`/`s`/`h`/`b`
/// views as `v`.
fn register_key(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    if let Some(rest) = lower
        .strip_prefix("zmm")
        .or_else(|| lower.strip_prefix("ymm"))
    {
        return format!("xmm{rest}");
    }
    let mut chars = lower.chars();
    if let Some(first) = chars.next()
        && matches!(first, 'q' | 'd' | 's' | 'h' | 'b')
        && !chars.as_str().is_empty()
        && chars.as_str().chars().all(|c| c.is_ascii_digit())
    {
        return format!("v{}", chars.as_str());
    }
    lower
}

/// A conversion of debug information's types into one function's
/// [`Types`].
struct Convert<'t> {
    model: &'t DebugModel,
    types: &'t mut Types,
    /// Structures and unions converted so far (a recursive one refers to
    /// itself through a pointer).
    seen: BTreeMap<DebugTypeId, TypeId>,
}

impl Convert<'_> {
    /// `function`'s signature, if L2 can state its parameters' and return
    /// value's types: scalars, pointers, and structs and unions by value
    /// (as a declaration's are: `crate::prototypes`), with the one it
    /// returns where no value holds one so wide
    /// ([`Prototype::wide_result`]): the signature then returns none. A
    /// definition stated variadic with no fixed parameter is C's
    /// unprototyped `f()` (as PDB states it; C11 has no `f(...)`): it
    /// takes none.
    fn declared(&mut self, function: &Function) -> Option<(Signature, Option<TypeId>)> {
        let parameters = function
            .parameters
            .iter()
            .map(|parameter| self.passed(parameter.ty, true))
            .collect::<Option<Vec<_>>>()?;
        // A parameter no value holds is in no code type.
        if parameters
            .iter()
            .any(|&ty| self.types.value_width(ty).is_none())
        {
            return None;
        }
        let void = matches!(
            self.model.ty(self.model.resolve(function.returns)),
            DebugType::Void
        );
        let (returns, wide) = if void {
            (None, None)
        } else {
            let ty = self.passed(function.returns, false)?;
            if self.types.value_width(ty).is_some() {
                (Some(ty), None)
            } else {
                (None, Some(ty))
            }
        };
        Some((
            Signature {
                parameters,
                returns,
                variadic: function.variadic && !function.parameters.is_empty(),
            },
            wide,
        ))
    }

    /// The type of what is passed for a parameter (where `parameter`) or
    /// returned, of type `id`: a value's, or a struct or union.
    fn passed(&mut self, id: DebugTypeId, parameter: bool) -> Option<TypeId> {
        let resolved = self.model.resolve(id);
        if matches!(self.model.ty(resolved), DebugType::Composite(_)) {
            self.record(resolved)
        } else if parameter {
            self.parameter(id)
        } else {
            self.value(id)
        }
    }

    /// A return type: `None` for `void`; an error where L2 holds it in no
    /// value.
    fn returns(&mut self, id: DebugTypeId) -> Result<Option<TypeId>, Unplaced> {
        if matches!(self.model.ty(self.model.resolve(id)), DebugType::Void) {
            return Ok(None);
        }
        self.value(id).map(Some).ok_or(Unplaced::Type)
    }

    /// A parameter's type: an array is a pointer to its element (C11
    /// 6.7.6.3p7).
    fn parameter(&mut self, id: DebugTypeId) -> Option<TypeId> {
        if let &DebugType::Array { element, .. } = self.model.ty(self.model.resolve(id)) {
            let pointer = Type::Pointer(self.any(element));
            return Some(self.types.intern(pointer));
        }
        self.value(id)
    }

    /// `id` as a type a value can have: a scalar or a pointer.
    fn value(&mut self, id: DebugTypeId) -> Option<TypeId> {
        match self.model.ty(self.model.resolve(id)) {
            DebugType::Base { .. } | DebugType::Pointer { .. } | DebugType::Enum { .. } => {
                self.any(id)
            }
            DebugType::Void
            | DebugType::Array { .. }
            | DebugType::Composite(_)
            | DebugType::Typedef { .. }
            | DebugType::Function { .. }
            | DebugType::Unknown => None,
        }
    }

    /// `id` as any L2 type, if L2 can say it.
    fn any(&mut self, id: DebugTypeId) -> Option<TypeId> {
        let id = self.model.resolve(id);
        let ty = match self.model.ty(id) {
            &DebugType::Base {
                ref name,
                bytes,
                encoding,
            } => {
                let bits = u16::try_from(bytes.checked_mul(8)?).ok()?;
                match encoding {
                    // C's plain `char` is a type of its own; `signed
                    // char` and `unsigned char` are integers.
                    Encoding::Char { signed } if bytes == 1 && name == "char" => {
                        Type::Char { signed }
                    }
                    Encoding::Signed | Encoding::Char { signed: true } => Type::Int(bits),
                    Encoding::Unsigned | Encoding::Char { signed: false } => Type::UInt(bits),
                    Encoding::Bool => Type::Bool(bits),
                    Encoding::Float => Type::Float(match bytes {
                        2 => Format::Half,
                        4 => Format::Single,
                        8 => Format::Double,
                        // x87's `long double` is no type the C output
                        // prints yet (nor is IEEE quad L2's).
                        _ => return None,
                    }),
                    Encoding::Other => return None,
                }
            }
            &DebugType::Enum { bytes, signed, .. } => {
                let bits = u16::try_from(bytes.checked_mul(8)?).ok()?;
                if signed {
                    Type::Int(bits)
                } else {
                    Type::UInt(bits)
                }
            }
            &DebugType::Pointer { target, .. } => {
                let resolved = self.model.resolve(target);
                if let DebugType::Function {
                    returns,
                    parameters,
                    variadic,
                } = self.model.ty(resolved)
                {
                    let (returns, parameters, variadic) = (*returns, parameters.clone(), *variadic);
                    let signature = (|| {
                        Some(Signature {
                            parameters: parameters
                                .iter()
                                .map(|&parameter| self.parameter(parameter))
                                .collect::<Option<Vec<_>>>()?,
                            returns: self.returns(returns).ok()?,
                            variadic,
                        })
                    })();
                    signature.map_or(Type::Pointer(None), Type::Code)
                } else {
                    Type::Pointer(self.any(target))
                }
            }
            &DebugType::Array { element, count } => Type::Array {
                element: self.any(element)?,
                length: count,
            },
            DebugType::Composite(_) => return self.record(id),
            DebugType::Void
            | DebugType::Typedef { .. }
            | DebugType::Function { .. }
            | DebugType::Unknown => return None,
        };
        Some(self.types.intern(ty))
    }

    /// A structure or union with its byte-aligned fields, if its size is
    /// stated. A named one the function's types already hold (converted
    /// for another variable, or a declaration's) is that one: C has one
    /// type per tag. The members of an anonymous union or structure that
    /// PDB states flattened (overlapping in a structure, past the start
    /// in a union) are its first: a field overlapping an earlier one of a
    /// structure, or not at the start of a union, is none of L2's.
    fn record(&mut self, id: DebugTypeId) -> Option<TypeId> {
        if let Some(&seen) = self.seen.get(&id) {
            return Some(seen);
        }
        let DebugType::Composite(composite) = self.model.ty(id) else {
            return None;
        };
        let size = composite.size?;
        let union = composite.kind == CompositeKind::Union;
        if let Some(name) = &composite.name
            && let Some(existing) = self.types.iter().find_map(|(existing, ty)| {
                let (Type::Struct(aggregate) | Type::Union(aggregate)) = ty else {
                    return None;
                };
                let same = aggregate.name.as_ref() == Some(name)
                    && aggregate.size == size
                    && matches!(ty, Type::Union(_)) == union;
                same.then_some(existing)
            })
        {
            self.seen.insert(id, existing);
            return Some(existing);
        }
        let shell = Aggregate {
            name: composite.name.clone(),
            size,
            fields: Vec::new(),
        };
        let converted = self.types.intern(if union {
            Type::Union(shell)
        } else {
            Type::Struct(shell)
        });
        self.seen.insert(id, converted);
        let mut fields: Vec<Field> = Vec::new();
        let mut end = 0;
        for field in composite.fields.iter().filter(|field| field.bits.is_none()) {
            let Some(ty) = self.any(field.ty) else {
                continue;
            };
            // A flexible array member has no width: no field of L2's.
            let Some(bytes) = self.types.width(ty).map(|width| width / 8) else {
                continue;
            };
            let field_end = field.offset.saturating_add(bytes);
            let placed = if union {
                field.offset == 0
            } else {
                field.offset >= end
            };
            if !placed || field_end > size {
                continue;
            }
            end = end.max(field_end);
            fields.push(Field {
                offset: field.offset,
                ty,
                name: field.name.clone(),
            });
        }
        if let Some(aggregate) = self.types.aggregate_mut(converted) {
            aggregate.fields = fields;
        }
        Some(converted)
    }
}
