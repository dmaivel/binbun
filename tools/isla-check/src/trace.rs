//! One isla path read as binbun sees state: what it assumes (its path
//! condition), which of its reads are binbun's initial state, how it ends
//! (an exception, or binbun's registers, the next PC, BTYPE and memory).
//!
//! Events before isla's `cycle` marker are the reset; only their SMT
//! definitions matter. After it:
//! - the first value Sail sees of a mapped register (or `PSTATE` field) is
//!   linked to binbun's initial value of it;
//! - writes give final values; a write to an exception syndrome register
//!   marks an exception path; writes to registers neither mapped nor
//!   bookkeeping are collected ([`Trace::unmapped`]);
//! - memory starts as binbun's initial memory: each read's value is linked
//!   to the bytes there, each write stores into it. Memory is indexed by
//!   the virtual address as the instruction computes it, tag included:
//!   top-byte-ignore belongs to the memory system, which both sides hand
//!   the same addresses (equal accesses then behave alike under any
//!   aliasing).

use std::collections::{BTreeMap, BTreeSet};

use isla_lib::bitvector::BV;
use isla_lib::bitvector::b129::B129;
use isla_lib::ir::Val;
use isla_lib::smt::{Accessor, Event};

use crate::context::{self, BOOKKEEPING, PSTATE_FIELDS, SYNDROMES, SYSTEM_REGISTERS};
use crate::model::{Model, Path};
use crate::sexp::{self, Types};

/// The sort of memory, as `binbun_semantics::smt` declares it.
pub const MEMORY_SORT: &str = "(Array (_ BitVec 64) (_ BitVec 8))";

/// A path, as SMT-LIB terms over binbun's initial state.
#[derive(Clone, Debug, Default)]
pub struct Trace {
    /// isla's declarations and definitions, and the path condition
    /// (assertions), as commands.
    pub commands: Vec<String>,
    /// Booleans tying Sail's view of the initial state to binbun's.
    pub links: Vec<String>,
    /// The exception the path takes, if it takes one.
    pub exception: Option<Exception>,
    /// Final values of the binbun registers the path writes, by name.
    pub writes: BTreeMap<String, String>,
    /// Where execution continues if no exception is taken.
    pub next_pc: String,
    /// The BTYPE the instruction sets for the next one (`BTypeNext`), if it
    /// sets one.
    pub btype_next: Option<String>,
    /// Memory at the end.
    pub memory: String,
    /// The reads: address and size.
    pub loads: Vec<(String, u32)>,
    /// The writes, alike.
    pub stores: Vec<(String, u32)>,
    /// Sail registers (or `PSTATE` fields) written that binbun does not
    /// map.
    pub unmapped: BTreeSet<String>,
    /// The binbun registers whose initial value Sail reads.
    pub reads: BTreeSet<String>,
    /// Calls of the overrides' abstract functions standing for binbun's
    /// intrinsics (`binbun_compute_pac`): the intrinsic's name, the
    /// arguments and the result, as terms.
    pub intrinsics: Vec<(String, Vec<String>, String)>,
}

/// An exception taken.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exception {
    /// The syndrome register written.
    pub register: String,
    /// Its value, when concrete.
    pub syndrome: Option<u64>,
}

impl Exception {
    /// The exception class (`ESR_ELx.EC`), when known.
    pub fn class(&self) -> Option<u64> {
        self.syndrome.map(|syndrome| (syndrome >> 26) & 0x3f)
    }
}

/// binbun's initial state, by register name, and its initial memory.
#[derive(Clone, Debug)]
pub struct Initial {
    /// Initial values of binbun's registers.
    pub registers: BTreeMap<String, String>,
    /// Initial memory.
    pub memory: String,
}

struct Reader<'a, 'ir> {
    model: &'a Model<'ir>,
    initial: &'a Initial,
    trace: Trace,
    types: Types,
    /// binbun registers written so far (later reads see the writes).
    written: BTreeSet<String>,
    /// binbun registers already linked to their initial value.
    linked: BTreeSet<String>,
    memories: usize,
}

/// Reads `path` (of an instruction at `pc`) against `initial`.
///
/// # Errors
///
/// If the path has no `cycle` marker, calls an abstracted function, or has
/// terms the SMT printer does not support.
pub fn read(model: &Model<'_>, path: &Path, initial: &Initial, pc: u64) -> Result<Trace, String> {
    let cycle = path
        .iter()
        .rposition(|event| matches!(event, Event::Cycle))
        .ok_or("the path has no cycle marker")?;
    let mut reader = Reader {
        model,
        initial,
        trace: Trace {
            next_pc: format!("(_ bv{} 64)", pc.wrapping_add(4)),
            memory: initial.memory.clone(),
            ..Trace::default()
        },
        types: Types::default(),
        written: BTreeSet::new(),
        linked: BTreeSet::new(),
        memories: 0,
    };
    for (index, event) in path.iter().enumerate() {
        if let Event::Smt(def, ..) = event {
            let commands = reader.types.define(def)?;
            reader.trace.commands.extend(commands);
        } else if index > cycle {
            reader.event(event)?;
        }
    }
    Ok(reader.trace)
}

impl Reader<'_, '_> {
    fn event(&mut self, event: &Event<B129>) -> Result<(), String> {
        match event {
            Event::ReadReg(name, _, value) => {
                self.read_register(&self.model.identifier(*name), value)
            }
            Event::WriteReg(name, accessors, value) => {
                self.write_register(&self.model.identifier(*name), accessors, value)
            }
            Event::ReadMem {
                value,
                address,
                bytes,
                ..
            } => {
                let address = self.address(address)?;
                let loaded = (0..*bytes)
                    .rev()
                    .map(|index| {
                        format!("(select {} {})", self.trace.memory, offset(&address, index))
                    })
                    .collect::<Vec<_>>();
                let loaded = if loaded.len() == 1 {
                    loaded.concat()
                } else {
                    format!("(concat {})", loaded.join(" "))
                };
                self.trace
                    .links
                    .push(format!("(= {} {loaded})", sexp::val(value)?));
                self.trace.loads.push((address, *bytes));
                Ok(())
            }
            Event::WriteMem {
                address,
                data,
                bytes,
                ..
            } => {
                let address = self.address(address)?;
                let data = sexp::val(data)?;
                let mut memory = self.trace.memory.clone();
                for index in 0..*bytes {
                    memory = format!(
                        "(store {memory} {} ((_ extract {} {}) {data}))",
                        offset(&address, index),
                        index * 8 + 7,
                        index * 8
                    );
                }
                self.memories += 1;
                let name = format!("|isla.memory.{}|", self.memories);
                self.trace
                    .commands
                    .push(format!("(define-fun {name} () {MEMORY_SORT} {memory})"));
                self.trace.memory = name;
                self.trace.stores.push((address, *bytes));
                Ok(())
            }
            Event::Abstract {
                name,
                primitive: false,
                ..
            } => Err(format!(
                "the path calls the abstracted {}",
                self.model.identifier(*name)
            )),
            Event::Abstract {
                name,
                primitive: true,
                args,
                return_value,
            } if self.model.identifier(*name).starts_with("binbun_") => {
                let identifier = self.model.identifier(*name);
                let intrinsic = identifier.trim_start_matches("binbun_").to_owned();
                let args = args.iter().map(sexp::val).collect::<Result<Vec<_>, _>>()?;
                let result = sexp::val(return_value)?;
                self.trace.intrinsics.push((intrinsic, args, result));
                Ok(())
            }
            // The model's announcements to a memory model
            // (`sail_take_exception`, `sail_barrier`, …) carry no state.
            Event::Abstract {
                primitive: true, ..
            }
            | Event::Smt(..)
            | Event::Fork(..)
            | Event::Function { .. }
            | Event::AssumeReg(..)
            | Event::MarkReg { .. }
            | Event::AddressAnnounce { .. }
            | Event::Branch { .. }
            | Event::Cycle
            | Event::Instr(_)
            | Event::Assume(_)
            | Event::AssumeFun { .. }
            | Event::UseFunAssumption { .. } => Ok(()),
        }
    }

    /// A memory access's address, named.
    fn address(&mut self, address: &Val<B129>) -> Result<String, String> {
        let address = sexp::val(address)?;
        self.memories += 1;
        let name = format!("|isla.address.{}|", self.memories);
        self.trace
            .commands
            .push(format!("(define-fun {name} () (_ BitVec 64) {address})"));
        Ok(name)
    }

    /// Links `binbun`'s initial value to `value` unless it was written or
    /// linked already.
    fn link(&mut self, binbun: &str, value: &Val<B129>) -> Result<(), String> {
        if self.written.contains(binbun) || !self.linked.insert(binbun.to_owned()) {
            return Ok(());
        }
        let initial = self
            .initial
            .registers
            .get(binbun)
            .ok_or_else(|| format!("binbun declares no register {binbun}"))?;
        self.trace
            .links
            .push(format!("(= {} {initial})", sexp::val(value)?));
        self.trace.reads.insert(binbun.to_owned());
        Ok(())
    }

    /// Links the `PSTATE` fields of `pstate` not yet written.
    fn link_pstate(&mut self, pstate: &Val<B129>) -> Result<(), String> {
        let Val::Struct(fields) = pstate else {
            return Err("PSTATE is not a structure".into());
        };
        for (sail, binbun) in PSTATE_FIELDS {
            let name = self.model.name(sail).ok_or("no PSTATE field name")?;
            let value = fields
                .get(&name)
                .ok_or_else(|| format!("PSTATE has no field {sail}"))?;
            self.link(binbun, value)?;
        }
        Ok(())
    }

    fn read_register(&mut self, sail: &str, value: &Val<B129>) -> Result<(), String> {
        if sail == "PSTATE" {
            return self.link_pstate(value);
        }
        // A register binbun reads through `system_register`: the value Sail
        // sees is the intrinsic's on its encoding.
        if let Some(&(_, encoding)) = SYSTEM_REGISTERS.iter().find(|(name, _)| *name == sail) {
            let bits = if let Val::Struct(fields) = value {
                self.model
                    .name("bits")
                    .and_then(|name| fields.get(&name))
                    .ok_or_else(|| format!("{sail} has no bits"))?
            } else {
                value
            };
            self.trace.intrinsics.push((
                "system_register".into(),
                vec![format!("(_ bv{encoding} 16)")],
                sexp::val(bits)?,
            ));
            return Ok(());
        }
        match context::binbun_register(sail) {
            Some(binbun) => self.link(&binbun, value),
            None => Ok(()),
        }
    }

    fn write_register(
        &mut self,
        sail: &str,
        accessors: &[Accessor],
        value: &Val<B129>,
    ) -> Result<(), String> {
        if sail == "PSTATE" {
            return self.write_pstate(accessors, value);
        }
        if let Some(binbun) = context::binbun_register(sail) {
            self.written.insert(binbun.clone());
            self.trace.writes.insert(binbun, sexp::val(value)?);
        } else if sail == "_PC" {
            self.trace.next_pc = sexp::val(value)?;
        } else if sail == "BTypeNext" {
            self.trace.btype_next = Some(sexp::val(value)?);
        } else if SYNDROMES.contains(&sail) {
            self.trace.exception = Some(Exception {
                register: sail.to_owned(),
                syndrome: self.syndrome(value),
            });
        } else if !BOOKKEEPING.contains(&sail) {
            self.trace.unmapped.insert(sail.to_owned());
        }
        Ok(())
    }

    fn syndrome(&self, value: &Val<B129>) -> Option<u64> {
        let bits = match value {
            Val::Struct(fields) => fields.get(&self.model.name("bits")?)?,
            Val::Symbolic(_)
            | Val::I64(_)
            | Val::I128(_)
            | Val::Bool(_)
            | Val::Bits(_)
            | Val::MixedBits(_)
            | Val::String(_)
            | Val::Unit
            | Val::Vector(_)
            | Val::List(_)
            | Val::Enum(_)
            | Val::Ctor(..)
            | Val::SymbolicCtor(..)
            | Val::Ref(_)
            | Val::Poison => value,
        };
        match bits {
            Val::Bits(bits) => Some(bits.lower_u64()),
            Val::Symbolic(_)
            | Val::I64(_)
            | Val::I128(_)
            | Val::Bool(_)
            | Val::MixedBits(_)
            | Val::String(_)
            | Val::Unit
            | Val::Vector(_)
            | Val::List(_)
            | Val::Enum(_)
            | Val::Struct(_)
            | Val::Ctor(..)
            | Val::SymbolicCtor(..)
            | Val::Ref(_)
            | Val::Poison => None,
        }
    }

    fn write_pstate(&mut self, accessors: &[Accessor], value: &Val<B129>) -> Result<(), String> {
        // The structure holds the new value of the field written and the
        // current values of the others.
        self.link_pstate(value)?;
        let Val::Struct(fields) = value else {
            return Err("PSTATE is not a structure".into());
        };
        let [Accessor::Field(field)] = accessors else {
            self.trace.unmapped.insert("PSTATE".into());
            return Ok(());
        };
        let field = self.model.identifier(*field);
        let Some((_, binbun)) = PSTATE_FIELDS.iter().find(|(sail, _)| *sail == field) else {
            self.trace.unmapped.insert(format!("PSTATE.{field}"));
            return Ok(());
        };
        let name = self.model.name(&field).ok_or("no PSTATE field name")?;
        let new = fields.get(&name).ok_or("PSTATE lacks the field written")?;
        self.written.insert((*binbun).to_owned());
        self.trace
            .writes
            .insert((*binbun).to_owned(), sexp::val(new)?);
        Ok(())
    }
}

fn offset(address: &str, index: u32) -> String {
    if index == 0 {
        address.to_owned()
    } else {
        format!("(bvadd {address} (_ bv{index} 64))")
    }
}
