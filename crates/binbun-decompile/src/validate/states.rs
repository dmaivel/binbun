//! Random entry states ([`random_states`]) and states shaped by the
//! function's types ([`shaped_states`]), the memory and intrinsic answers
//! both runs share ([`Oracle`]), the processor they run on if one
//! ([`OnProcessor`]), and the machine each run records its writes on.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::iter::repeat;

use binbun_ast::ir::{Function as Ast, VarId};
use binbun_ast::types::{Type, TypeId, Types};
use binbun_semantics::Declarations;
use binbun_semantics::bits::Bits;
use binbun_semantics::interpret::{Fault, Machine, Value};
use binbun_semantics::ir::{IntrinsicId, RegisterId, SiteId};
use binbun_semantics::profile::{Choices, Profile};

use crate::mapping::{Mapping, Source};
use crate::range::{Ranges, Term};

/// Where functions return to in random states: canonical, and no
/// function's address.
pub const RETURN_ADDRESS: u64 = 0x7fff_0000_1000;

/// Where a call leaves the return address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Link {
    /// Pushed: `bytes` bytes at the callee's entry stack pointer (x86).
    Stack {
        /// Its size.
        bytes: u16,
    },
    /// In a register (AArch64's link register).
    Register(RegisterId),
}

/// The architecture and convention the checks run under, and their
/// budget.
#[derive(Clone, Debug)]
pub struct Setup<'a> {
    /// The architecture's registers and intrinsics.
    pub declarations: &'a Declarations,
    /// The stack pointer.
    pub stack_pointer: RegisterId,
    /// Where the return address is on entry.
    pub link: Link,
    /// Registers with a fixed value on entry (a program counter, a flag
    /// the convention keeps clear), by id.
    pub fixed: Vec<(RegisterId, u64)>,
    /// The blocks L1 may enter per run; L2 may take
    /// [`L2_FUEL`](super::L2_FUEL) times as many steps.
    pub fuel: u64,
    /// How many bytes below the entry stack pointer are the function's
    /// own stack: writes there are dead at its exits and visible to calls
    /// only through L2's frame variables, so only those bytes compare.
    pub frame: u64,
    /// How many bytes just above the return address are the function's
    /// own too, like those below the entry stack pointer: the space the
    /// convention has the caller reserve for it (Microsoft x64's home
    /// space; 0 elsewhere).
    pub shadow: u64,
}

/// One entry state: every register, the return address, and the memory
/// it sets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    /// Every register's value, in register order.
    pub registers: Vec<Value>,
    /// Where the function returns to.
    pub return_address: u64,
    /// Memory the state sets before the run, as regions (each its first
    /// address and bytes, every bit defined); every other byte is the
    /// [`Oracle`]'s. Random states set none; shaped ones
    /// ([`shaped_states`]) the objects their parameters point to.
    pub memory: Vec<(u64, Vec<u8>)>,
}

impl State {
    /// The stack pointer on entry.
    pub fn stack(&self, setup: &Setup<'_>) -> Option<u64> {
        self.registers
            .get(usize::from(setup.stack_pointer.0))
            .and_then(Value::known)
            .map(|bits| bits.low_u64())
    }
}

/// A deterministic xorshift generator.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    /// A random byte.
    fn byte(&mut self) -> u8 {
        self.next().to_le_bytes()[0]
    }

    /// A random byte other than zero.
    fn non_zero_byte(&mut self) -> u8 {
        self.byte().max(1)
    }

    /// A register value: often an edge value of 8 to 64 bits (as the CPU
    /// oracle draws them), a small number or a pointer-like one.
    fn value(&mut self) -> u64 {
        match self.below(13) {
            0 => 0,
            1 => u64::MAX,
            2 => 1,
            3 => 1 << self.below(64),
            4 => (1 << self.below(64)) - 1,
            5 => self.below(64),
            6 => 0x7f | (self.next() & !0xff),
            7 => 0x8000_0000 | (self.next() & !0xffff_ffff),
            8 => self.below(0x1_0000),
            9 | 10 => 0x5555_0000_0000 + self.below(0x1_0000_0000) * 8,
            _ => self.next(),
        }
    }
}

/// `count` random entry states from `seed`: registers with edge, small,
/// pointer-like or random values (1-bit registers random), `setup.fixed`
/// as given, the stack pointer in a stack-like place (16-byte aligned
/// before the call; minus the pushed return address for
/// [`Link::Stack`]), and the return address [`RETURN_ADDRESS`] (in the
/// link register for [`Link::Register`]).
pub fn random_states(setup: &Setup<'_>, count: usize, seed: u64) -> Vec<State> {
    let mut rng = Rng(seed | 1);
    (0..count)
        .map(|_| {
            let registers = setup
                .declarations
                .registers
                .iter()
                .enumerate()
                .map(|(index, info)| {
                    let id = RegisterId(u16::try_from(index).unwrap_or(u16::MAX));
                    let value = if id == setup.stack_pointer {
                        let aligned = 0x7ffe_0000_0000 + rng.below(0x10_0000) * 16;
                        match setup.link {
                            Link::Stack { bytes } => aligned - u64::from(bytes),
                            Link::Register(_) => aligned,
                        }
                    } else if setup.link == Link::Register(id) {
                        RETURN_ADDRESS
                    } else if let Some(&(_, fixed)) =
                        setup.fixed.iter().find(|(fixed, _)| *fixed == id)
                    {
                        fixed
                    } else if info.width == 1 {
                        rng.below(2)
                    } else {
                        rng.value()
                    };
                    Value::defined(Bits::from_u64(info.width, value))
                })
                .collect();
            State {
                registers,
                return_address: RETURN_ADDRESS,
                memory: Vec::new(),
            }
        })
        .collect()
}

/// Where [`shaped_states`] places the objects parameters point to:
/// canonical, above any image and below [`random_states`]' stacks.
const HEAP: u64 = 0x6000_0000_0000;

/// How deep [`shaped_states`] follows pointers within the objects it
/// makes (a pointer deeper than that is a random value).
const DEPTH: u32 = 2;

/// The most elements before the terminator of a vector or string
/// [`shaped_states`] makes, and the largest count it gives an integer
/// parameter.
const LENGTH: u64 = 16;

/// The most bytes of one object [`shaped_states`] makes (a larger struct
/// or array is cut there; the oracle's bytes follow).
const OBJECT: u64 = 1 << 12;

/// `count` entry states of the function `l2` (whose parameters are where
/// `mapping` says) shaped by its parameters' types, from `seed`: random
/// states ([`random_states`], of a seed of their own) whose register
/// parameters point to objects of their type, with random contents in
/// that shape, and whose integer parameters are small counts:
///
/// - a pointer to `char` or another integer: an array of up to
///   [`LENGTH`] non-zero elements and a terminating zero (a string, a
///   zero-terminated vector);
/// - a pointer to a pointer: a vector of up to [`LENGTH`] pointers, each
///   to an object of its type, and a null pointer after them;
/// - a pointer to a struct or a fixed array: an object its size (up to
///   [`OBJECT`] bytes), random but where its pointer fields point to
///   objects of their type;
/// - a pointer to another type: [`LENGTH`] random elements;
/// - a signed or unsigned integer, or any parameter a counted loop's
///   bound is ([`Ranges`]: `for (i = 0; i < n; i++)`): up to [`LENGTH`]
///   (so a count or a bound ends a loop over the objects).
///
/// Pointers are followed [`DEPTH`] deep. Untyped parameters (bits only,
/// or a pointer to nothing known, no loop's bound) and stack parameters
/// stay random.
/// The registers [`random_states`] sets for the call (the stack pointer,
/// the link register, the fixed ones) keep their values even where L2
/// takes them as parameters: the link register is where the function
/// returns to (a state's [`State::return_address`]), which the exact
/// view's `return` goes to whatever its value; another value there is
/// no call of the function with that parameter but one returning
/// elsewhere.
/// Random memory rarely holds a terminator, so a loop scanning a random
/// state's memory runs to its fuel and the state is skipped; these end.
/// Any state is one the function may be started from, so a shaped state
/// is as sound a check as a random one: it adds states, never weakens
/// one. None when no parameter has a shape.
pub fn shaped_states(
    setup: &Setup<'_>,
    l2: &Ast,
    mapping: &Mapping,
    count: usize,
    seed: u64,
) -> Vec<State> {
    let types = &l2.types;
    let bounds: BTreeSet<VarId> = Ranges::of(l2)
        .counters()
        .filter_map(|(_, counted)| match counted.bound {
            Term::Var(var) => Some(var),
            Term::Const(_) => None,
        })
        .collect();
    let parameters: Vec<(RegisterId, TypeId)> = l2
        .parameters
        .iter()
        .zip(&mapping.parameters)
        .filter_map(|(&parameter, source)| match source {
            Source::Register(piece)
                if piece.offset == 0
                    && piece.register != setup.stack_pointer
                    && setup.link != Link::Register(piece.register)
                    && !setup
                        .fixed
                        .iter()
                        .any(|&(fixed, _)| fixed == piece.register) =>
            {
                let ty = l2.var(parameter)?.ty;
                (shaped(types, ty) || bounds.contains(&parameter)).then_some((piece.register, ty))
            }
            Source::Register(_) | Source::Stack { .. } => None,
        })
        .collect();
    if parameters.is_empty() {
        return Vec::new();
    }
    let mut rng = Rng(mix(seed) | 1);
    let mut states = random_states(setup, count, mix(seed ^ HEAP));
    for state in &mut states {
        let mut heap = Heap {
            next: HEAP + rng.below(1 << 20) * 0x1000,
            regions: Vec::new(),
        };
        for &(register, ty) in &parameters {
            let value = match types.get(ty) {
                Some(&Type::Pointer(Some(target))) => heap.object(types, target, &mut rng, DEPTH),
                _ => rng.below(LENGTH + 1),
            };
            if let Some(slot) = state.registers.get_mut(usize::from(register.0)) {
                *slot = Value::defined(Bits::from_u64(slot.width(), value));
            }
        }
        state.memory = heap.regions;
    }
    states
}

/// Whether [`shaped_states`] shapes a parameter of type `ty`.
fn shaped(types: &Types, ty: TypeId) -> bool {
    matches!(
        types.get(ty),
        Some(Type::Pointer(Some(_)) | Type::Int(_) | Type::UInt(_))
    )
}

/// The objects one shaped state sets ([`shaped_states`]), placed one after
/// the other from `next`.
struct Heap {
    /// Where the next object goes.
    next: u64,
    /// The objects so far: first address and bytes.
    regions: Vec<(u64, Vec<u8>)>,
}

impl Heap {
    /// A new object of type `ty` (in `types`), `depth` more pointers deep
    /// followed: its address.
    fn object(&mut self, types: &Types, ty: TypeId, rng: &mut Rng, depth: u32) -> u64 {
        let bytes = |id: TypeId| types.width(id).map_or(8, |bits| bits.div_ceil(8).max(1));
        let mut object: Vec<u8> = Vec::new();
        // Pointers to fill in once the object has its place: offset, width
        // and target.
        let mut pointers: Vec<(u64, u64, Option<TypeId>)> = Vec::new();
        match types.get(ty) {
            Some(
                Type::Char { .. } | Type::Int(_) | Type::UInt(_) | Type::Bits(_) | Type::Bool(_),
            ) => {
                let width = bytes(ty);
                for _ in 0..rng.below(LENGTH + 1) {
                    // Non-zero: its low byte is.
                    object.push(rng.non_zero_byte());
                    object.extend((1..width).map(|_| rng.byte()));
                }
                let terminated = object
                    .len()
                    .saturating_add(usize::try_from(width).unwrap_or(0));
                object.resize(terminated, 0);
            }
            Some(&Type::Pointer(target)) => {
                let width = bytes(ty);
                let length = rng.below(LENGTH + 1);
                for at in 0..length {
                    pointers.push((at * width, width, target));
                }
                object.resize(usize::try_from((length + 1) * width).unwrap_or(0), 0);
            }
            Some(Type::Struct(aggregate)) => {
                let size = aggregate.size.clamp(1, OBJECT);
                object.extend((0..size).map(|_| rng.byte()));
                for field in &aggregate.fields {
                    if let Some(&Type::Pointer(target)) = types.get(field.ty) {
                        let width = bytes(field.ty);
                        if field.offset + width <= size {
                            pointers.push((field.offset, width, target));
                        }
                    }
                }
            }
            Some(&Type::Array {
                element,
                length: Some(length),
            }) => {
                let size = bytes(element).saturating_mul(length).clamp(1, OBJECT);
                object.extend((0..size).map(|_| rng.byte()));
            }
            _ => {
                let size = bytes(ty).saturating_mul(LENGTH).clamp(1, OBJECT);
                object.extend((0..size).map(|_| rng.byte()));
            }
        }
        let address = self.next;
        // Aligned for any scalar, with a gap so objects do not touch.
        self.next = (address + object.len() as u64 + 16).next_multiple_of(16);
        for (offset, width, target) in pointers {
            let value = match target {
                Some(target) if depth > 0 => self.object(types, target, rng, depth - 1),
                _ => rng.value(),
            };
            let start = usize::try_from(offset).unwrap_or(usize::MAX);
            let end = start.saturating_add(usize::try_from(width).unwrap_or(0));
            if let Some(slot) = object.get_mut(start..end) {
                for (byte, value) in slot.iter_mut().zip(value.to_le_bytes()) {
                    *byte = value;
                }
            }
        }
        self.regions.push((address, object));
        address
    }
}

/// What both runs see: memory before the run and intrinsics' answers. The
/// same question must get the same answer, whoever asks and in whatever
/// order.
pub trait Oracle {
    /// The byte at `address` before the run, or `None` if reading it
    /// faults.
    fn byte(&self, address: u64) -> Option<u8>;

    /// The outputs (`outputs` bits wide) of `intrinsic` on `inputs`.
    fn intrinsic(&self, intrinsic: IntrinsicId, inputs: &[Value], outputs: &[u16]) -> Vec<Value>;

    /// The processor the runs are on: its profile gives the values the
    /// architecture leaves undefined at sites. By default none: those
    /// values are unknown.
    fn profile(&self) -> Option<&Profile> {
        None
    }
}

/// `oracle`'s memory and intrinsics, on `profile`'s processor.
#[derive(Clone, Copy)]
pub struct OnProcessor<'a> {
    /// The memory and intrinsics.
    pub oracle: &'a dyn Oracle,
    /// The processor.
    pub profile: &'a Profile,
}

impl Oracle for OnProcessor<'_> {
    fn byte(&self, address: u64) -> Option<u8> {
        self.oracle.byte(address)
    }

    fn intrinsic(&self, intrinsic: IntrinsicId, inputs: &[Value], outputs: &[u16]) -> Vec<Value> {
        self.oracle.intrinsic(intrinsic, inputs, outputs)
    }

    fn profile(&self) -> Option<&Profile> {
        Some(self.profile)
    }
}

impl core::fmt::Debug for OnProcessor<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OnProcessor")
            .field("profile", &self.profile.id)
            .finish_non_exhaustive()
    }
}

/// The default [`Oracle`]: bytes below 0x1000 fault, every other byte is
/// a hash of its address; an intrinsic's outputs are a hash of it and its
/// inputs' defined bits.
#[derive(Clone, Copy, Debug, Default)]
pub struct Hashed;

/// A 64-bit mix (the finalizer of `SplitMix64`).
fn mix(mut x: u64) -> u64 {
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

impl Oracle for Hashed {
    fn byte(&self, address: u64) -> Option<u8> {
        (address >= 0x1000).then(|| mix(address).to_le_bytes()[0])
    }

    fn intrinsic(&self, intrinsic: IntrinsicId, inputs: &[Value], outputs: &[u16]) -> Vec<Value> {
        let mut state = mix(u64::from(intrinsic.0) + 1);
        for input in inputs {
            let known = input.bits.and(&input.undefined.invert());
            for byte in known.to_le_bytes() {
                state = mix(state ^ u64::from(byte));
            }
        }
        outputs
            .iter()
            .map(|&width| {
                let bytes: Vec<u8> = (0..width.div_ceil(8))
                    .map(|_| {
                        state = mix(state);
                        state.to_le_bytes()[0]
                    })
                    .collect();
                Value::defined(Bits::from_le_bytes(width, &bytes))
            })
            .collect()
    }
}

/// The machine of one run: the oracle's memory under the entry state (the
/// pushed return address) and the run's writes, each byte with its
/// undefined bits; and for L2's run, the entry state's registers, which
/// its environment variables read. On a processor ([`Oracle::profile`]),
/// L1's run records the profile's values at the sites, and L2's takes
/// them where it lacks a site's inputs ([`Recorder::with_choices`]).
pub(super) struct Recorder<'a> {
    oracle: &'a dyn Oracle,
    /// The registers [`Machine::read`] answers (none for L1's runs, which
    /// keep their registers themselves).
    registers: &'a [Value],
    /// Bytes the entry state sets and bytes the run wrote: value and
    /// undefined bits.
    pub(super) written: BTreeMap<u64, (u8, u8)>,
    /// The bytes the run wrote (not the entry state's).
    pub(super) writes: BTreeSet<u64>,
    /// The profile's values at the sites: given (L1's run), or to take
    /// (L2's).
    pub(super) choices: Choices,
    /// Whether [`Self::choices`] are another run's, to take.
    replaying: bool,
}

impl<'a> Recorder<'a> {
    /// The memory of `state` under `setup`.
    pub(super) fn new(oracle: &'a dyn Oracle, setup: &Setup<'_>, state: &State) -> Self {
        let mut written = BTreeMap::new();
        for (start, bytes) in &state.memory {
            for (offset, &byte) in (0u64..).zip(bytes) {
                written.insert(start.wrapping_add(offset), (byte, 0));
            }
        }
        if let (Link::Stack { bytes }, Some(stack)) = (setup.link, state.stack(setup)) {
            for (offset, byte) in state
                .return_address
                .to_le_bytes()
                .into_iter()
                .chain(repeat(0))
                .take(usize::from(bytes))
                .enumerate()
            {
                written.insert(stack.wrapping_add(offset as u64), (byte, 0));
            }
        }
        Self {
            oracle,
            registers: &[],
            written,
            writes: BTreeSet::new(),
            choices: Choices::default(),
            replaying: false,
        }
    }

    /// The same machine, answering register reads with `registers`.
    pub(super) fn with_registers(self, registers: &'a [Value]) -> Self {
        Self { registers, ..self }
    }

    /// The same machine, taking the profile's values at sites whose
    /// inputs its run lacks from `choices` (another run's from the same
    /// state).
    pub(super) fn with_choices(self, choices: Choices) -> Self {
        Self {
            choices,
            replaying: true,
            ..self
        }
    }

    /// The byte at `address` and its undefined bits, or `None` if it
    /// faults.
    pub(super) fn byte(&self, address: u64) -> Option<(u8, u8)> {
        match self.written.get(&address) {
            Some(&byte) => Some(byte),
            None => self.oracle.byte(address).map(|byte| (byte, 0)),
        }
    }
}

impl Machine for Recorder<'_> {
    /// The register's value in the entry state (L2's environment
    /// variables; the interpreters keep the others themselves).
    fn read(&mut self, register: RegisterId) -> Value {
        self.registers
            .get(usize::from(register.0))
            .copied()
            .unwrap_or_else(|| Value::unknown(1))
    }

    /// Unused: both interpreters keep registers themselves.
    fn write(&mut self, _register: RegisterId, _value: Value) {}

    fn load(&mut self, address: u64, bytes: u16) -> Result<Value, Fault> {
        let fault = Fault {
            address,
            write: false,
        };
        let mut values = Vec::with_capacity(usize::from(bytes));
        let mut undefined = Vec::with_capacity(usize::from(bytes));
        for offset in 0..u64::from(bytes) {
            let at = address.checked_add(offset).ok_or(fault)?;
            let (value, mask) = self.byte(at).ok_or(fault)?;
            values.push(value);
            undefined.push(mask);
        }
        let width = bytes * 8;
        Ok(Value {
            bits: Bits::from_le_bytes(width, &values),
            undefined: Bits::from_le_bytes(width, &undefined),
        })
    }

    fn store(&mut self, address: u64, value: Value) -> Result<(), Fault> {
        let bytes = u64::from(value.width() / 8);
        let fault = Fault {
            address,
            write: true,
        };
        // The oracle says which bytes exist; a store faults where a load
        // would.
        for offset in 0..bytes {
            let at = address.checked_add(offset).ok_or(fault)?;
            self.byte(at).ok_or(fault)?;
        }
        let pairs = value.bits.to_le_bytes().zip(value.undefined.to_le_bytes());
        for (offset, (bits, undefined)) in (0..bytes).zip(pairs) {
            let at = address.wrapping_add(offset);
            self.written.insert(at, (bits & !undefined, undefined));
            self.writes.insert(at);
        }
        Ok(())
    }

    fn intrinsic(
        &mut self,
        intrinsic: IntrinsicId,
        inputs: &[Value],
        outputs: &[u16],
    ) -> Vec<Value> {
        self.oracle.intrinsic(intrinsic, inputs, outputs)
    }

    fn undefined_at(&mut self, address: u64, site: SiteId, inputs: &[Value], width: u16) -> Value {
        let Some(profile) = self.oracle.profile() else {
            return Value::unknown(width);
        };
        if self.replaying {
            return self.choices.choose(profile, address, site, inputs, width);
        }
        let value = profile.value(site, inputs, width);
        self.choices.record(address, site, value);
        value
    }
}
