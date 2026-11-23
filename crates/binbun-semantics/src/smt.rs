//! L0 as SMT-LIB 2: what a [`Semantics`] does, as terms over its initial
//! state, for an SMT solver (z3, cvc5) to prove things about: equivalence
//! with a specification, or of two instruction sequences, or a rewrite
//! rule.
//!
//! - A [`Script`] collects declarations, definitions and assertions;
//!   [`Script::initial_state`] declares a [`State`] (every register as a
//!   bit vector, memory as an array from addresses to bytes) and
//!   [`Script::encode`] defines the [`Final`] state a semantics leaves,
//!   with when it traps, where it continues, and which bytes it reads and
//!   writes. Encoding one semantics from another's final state composes
//!   them.
//! - Paths are merged, not enumerated: a write under an `if` makes the
//!   register `(ite condition new old)`.
//! - Every intermediate value is a `define-fun`, so shared subterms stay
//!   shared.
//! - [`Expr::Undefined`] is a fresh constant per occurrence (per encoding):
//!   a property proved holds for every choice of undefined values.
//! - Loops are unrolled [`Options::unroll`] times; [`Final::exhausted`]
//!   holds when that did not suffice.
//! - Intrinsics are uninterpreted functions of their inputs (one per
//!   output), shared by all encodings of a script: two semantics calling
//!   one on the same inputs get the same outputs.
//!   An opaque intrinsic's (an instruction without semantics) outputs are
//!   fresh constants instead, as undefined values are.
//! - IEEE operations ([`Expr::Float`]) are uninterpreted functions too, for
//!   now; integer lane operations ([`Expr::Lanes`]) are exact.
//!
//! The result is plain SMT-LIB 2 (`QF_ABV` plus uninterpreted functions);
//! running a solver is the caller's business.

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use crate::bits::{Bits, MAX_WIDTH};
use crate::ir::{
    Binary, Declarations, Expr, ExprId, Flag, FloatOp, FloatOutput, Format, IntrinsicId, LaneOp,
    Local, RegisterId, Semantics, Stmt, Trap, Unary, View,
};

/// An SMT-LIB term: a symbol, a literal or an application.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Term(String);

impl Term {
    /// A term from its SMT-LIB text.
    pub fn new(text: impl Into<String>) -> Self {
        Self(text.into())
    }

    /// Its SMT-LIB text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether it is a symbol or a literal (worth no definition of its own).
    fn is_atom(&self) -> bool {
        !self.0.starts_with('(')
    }
}

impl fmt::Display for Term {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The Boolean `true`.
pub fn top() -> Term {
    Term::new("true")
}

/// The Boolean `false`.
pub fn bottom() -> Term {
    Term::new("false")
}

/// The conjunction of `terms` (`true` for none).
pub fn and(terms: &[Term]) -> Term {
    let parts: Vec<&Term> = terms.iter().filter(|term| term.0 != "true").collect();
    if parts.iter().any(|term| term.0 == "false") {
        return bottom();
    }
    match parts.as_slice() {
        [] => top(),
        [one] => (*one).clone(),
        _ => Term(format!("(and {})", join(&parts))),
    }
}

/// The disjunction of `terms` (`false` for none).
pub fn or(terms: &[Term]) -> Term {
    let parts: Vec<&Term> = terms.iter().filter(|term| term.0 != "false").collect();
    if parts.iter().any(|term| term.0 == "true") {
        return top();
    }
    match parts.as_slice() {
        [] => bottom(),
        [one] => (*one).clone(),
        _ => Term(format!("(or {})", join(&parts))),
    }
}

/// The negation of `term`.
pub fn not(term: &Term) -> Term {
    match term.0.as_str() {
        "true" => bottom(),
        "false" => top(),
        _ => Term(format!("(not {term})")),
    }
}

/// `a` implies `b`.
pub fn implies(a: &Term, b: &Term) -> Term {
    Term(format!("(=> {a} {b})"))
}

/// Whether `a` and `b` (of the same sort) are equal.
pub fn eq(a: &Term, b: &Term) -> Term {
    if a == b {
        return top();
    }
    Term(format!("(= {a} {b})"))
}

/// `then` if `condition` holds, else `otherwise`.
pub fn ite(condition: &Term, then: &Term, otherwise: &Term) -> Term {
    match condition.0.as_str() {
        "true" => then.clone(),
        "false" => otherwise.clone(),
        _ if then == otherwise => then.clone(),
        _ => Term(format!("(ite {condition} {then} {otherwise})")),
    }
}

/// The Boolean a 1-bit value stands for.
pub fn holds(bit: &Term) -> Term {
    match bit.0.as_str() {
        "#b1" => top(),
        "#b0" => bottom(),
        _ => Term(format!("(= {bit} #b1)")),
    }
}

/// The sort of `width`-bit values.
pub fn sort(width: u16) -> String {
    format!("(_ BitVec {width})")
}

/// The sort of memory: bytes indexed by `address_width`-bit addresses.
pub fn memory_sort(address_width: u16) -> String {
    format!("(Array {} {})", sort(address_width), sort(8))
}

/// `name` as a quoted symbol (`|` and `\`, which a quoted symbol cannot
/// hold, become `_`).
pub fn symbol(name: &str) -> Term {
    let clean: String = name
        .chars()
        .map(|c| if c == '|' || c == '\\' { '_' } else { c })
        .collect();
    Term(format!("|{clean}|"))
}

/// `bits` as a literal: hexadecimal when the width is a multiple of 4,
/// binary otherwise.
pub fn constant(bits: &Bits) -> Term {
    let width = bits.width();
    let mut text = String::with_capacity(usize::from(width) + 2);
    if width.is_multiple_of(4) {
        text.push_str("#x");
        for nibble in (0..width / 4).rev() {
            let value = (0..4).fold(0u32, |acc, bit| {
                acc | (u32::from(bits.bit(nibble * 4 + bit)) << bit)
            });
            text.push(char::from_digit(value, 16).unwrap_or('0'));
        }
    } else {
        text.push_str("#b");
        for bit in (0..width).rev() {
            text.push(if bits.bit(bit) { '1' } else { '0' });
        }
    }
    Term(text)
}

/// A literal `value` of `width` bits.
pub fn literal(width: u16, value: u64) -> Term {
    constant(&Bits::from_u64(width, value))
}

/// Parses a bit-vector literal as a solver prints it in a model (`#x…`,
/// `#b…`, or `(_ bvN W)`).
pub fn parse_literal(text: &str) -> Option<Bits> {
    let text = text.trim();
    let (width, digits, radix) = if let Some(hex) = text.strip_prefix("#x") {
        (hex.len().checked_mul(4)?, hex, 16)
    } else if let Some(binary) = text.strip_prefix("#b") {
        (binary.len(), binary, 2)
    } else {
        let inner = text.strip_prefix("(_ bv")?.strip_suffix(')')?;
        let (value, width) = inner.split_once(' ')?;
        let width: u16 = width.trim().parse().ok()?;
        let value: u128 = value.parse().ok()?;
        return (usize::from(width) <= 128).then(|| Bits::from_u128(width, value));
    };
    let width = u16::try_from(width).ok()?;
    if width == 0 || width > MAX_WIDTH {
        return None;
    }
    let shift = if radix == 16 { 4 } else { 1 };
    let mut bytes = vec![0u8; usize::from(width).div_ceil(8)];
    for (position, digit) in digits.chars().rev().enumerate() {
        let value = digit.to_digit(radix)?;
        for bit in 0..shift {
            if value >> bit & 1 == 1 {
                let index = position * shift + bit;
                *bytes.get_mut(index / 8)? |= 1 << (index % 8);
            }
        }
    }
    Some(Bits::from_le_bytes(width, &bytes))
}

fn join(terms: &[&Term]) -> String {
    let mut text = String::new();
    for (index, term) in terms.iter().enumerate() {
        if index > 0 {
            text.push(' ');
        }
        text.push_str(&term.0);
    }
    text
}

/// What encodings need to know beyond the semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options {
    /// The width of addresses (memory's index sort, jump targets).
    pub address_width: u16,
    /// How many times loops are unrolled.
    pub unroll: u32,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            address_width: 64,
            unroll: 16,
        }
    }
}

/// Why a semantics could not be encoded (it does not pass the verifier,
/// or does not fit the [`Options`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmtError(pub String);

impl fmt::Display for SmtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Machine state as terms: each register (indexed by [`RegisterId`]) and
/// memory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    /// The registers, in [`RegisterId`] order.
    pub registers: Vec<Term>,
    /// Memory: an array from addresses to bytes.
    pub memory: Term,
}

impl State {
    /// Register `id`.
    pub fn register(&self, id: RegisterId) -> Option<&Term> {
        self.registers.get(usize::from(id.0))
    }
}

/// A memory access: under which condition it happens, where, and how many
/// bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Access {
    /// Boolean: whether the access happens.
    pub condition: Term,
    /// The address.
    pub address: Term,
    /// The number of bytes.
    pub bytes: u16,
}

/// What a semantics does, as terms over the state it starts from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Final {
    /// The state it leaves (meaningless when it traps: exceptions are
    /// precise, so the state is then the initial one).
    pub state: State,
    /// Boolean: whether it traps.
    pub trap: Term,
    /// Each trap statement's kind and the condition under which it runs
    /// (at most one runs).
    pub traps: Vec<(Trap, Term)>,
    /// Boolean: whether it transfers control (jump, call or return).
    pub transferred: Term,
    /// Where it transfers control to, if it does.
    pub target: Term,
    /// Boolean: whether it enters the operating system.
    pub system_call: Term,
    /// The loads it performs, in order.
    pub loads: Vec<Access>,
    /// The stores it performs, in order.
    pub stores: Vec<Access>,
    /// Boolean: whether a loop needed more than [`Options::unroll`]
    /// iterations (the encoding is then incomplete).
    pub exhausted: Term,
}

/// Boolean: whether `address` lies in one of the `accesses` that happen.
pub fn touches(accesses: &[Access], address: &Term, address_width: u16) -> Term {
    let parts: Vec<Term> = accesses
        .iter()
        .map(|access| {
            let last = literal(address_width, u64::from(access.bytes.saturating_sub(1)));
            let within = Term(format!(
                "(bvule (bvsub {address} {}) {last})",
                access.address
            ));
            and(&[access.condition.clone(), within])
        })
        .collect();
    or(&parts)
}

/// Boolean: whether `a` and `b` end alike: both trap, or neither does and
/// they leave the same registers (but `ignored`) and memory, transfer
/// control alike and enter the operating system alike.
pub fn same_outcome(a: &Final, b: &Final, ignored: &[RegisterId]) -> Term {
    let mut parts = Vec::new();
    for (index, (x, y)) in a.state.registers.iter().zip(&b.state.registers).enumerate() {
        let id = RegisterId(u16::try_from(index).unwrap_or(u16::MAX));
        if !ignored.contains(&id) {
            parts.push(eq(x, y));
        }
    }
    parts.push(eq(&a.state.memory, &b.state.memory));
    parts.push(eq(&a.transferred, &b.transferred));
    parts.push(implies(&a.transferred, &eq(&a.target, &b.target)));
    parts.push(eq(&a.system_call, &b.system_call));
    let completes = and(&parts);
    and(&[eq(&a.trap, &b.trap), or(&[a.trap.clone(), completes])])
}

/// An SMT-LIB 2 script under construction.
#[derive(Clone, Debug, Default)]
pub struct Script {
    text: String,
    declared: BTreeSet<String>,
    /// What was declared at each open `push`.
    scopes: Vec<BTreeSet<String>>,
    fresh: u32,
}

impl Script {
    /// An empty script.
    pub fn new() -> Self {
        Self::default()
    }

    /// The script's text so far.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Appends a command (`(check-sat)`, `(push 1)`, …) as is.
    pub fn command(&mut self, command: &str) {
        self.text.push_str(command);
        self.text.push('\n');
    }

    /// Opens a scope (`(push 1)`): what is declared, defined and asserted
    /// until the matching [`Script::pop`] is forgotten then.
    pub fn push(&mut self) {
        self.scopes.push(self.declared.clone());
        self.command("(push 1)");
    }

    /// Closes the innermost scope (`(pop 1)`); nothing if none is open.
    pub fn pop(&mut self) {
        if let Some(declared) = self.scopes.pop() {
            self.declared = declared;
            self.command("(pop 1)");
        }
    }

    /// Declares the constant `name` of `sort` (once: later declarations of
    /// the same name are skipped) and returns it.
    pub fn declare(&mut self, name: &str, sort: &str) -> Term {
        self.declare_function(name, &[], sort)
    }

    /// Declares the function `name` (once) and returns its symbol.
    pub fn declare_function(&mut self, name: &str, arguments: &[String], result: &str) -> Term {
        let symbol = symbol(name);
        if self.declared.insert(symbol.0.clone()) {
            self.command(&format!(
                "(declare-fun {symbol} ({}) {result})",
                arguments.join(" ")
            ));
        }
        symbol
    }

    /// Defines the constant `name` of `sort` as `value` and returns it.
    pub fn define(&mut self, name: &str, sort: &str, value: &Term) -> Term {
        let symbol = symbol(name);
        self.command(&format!("(define-fun {symbol} () {sort} {value})"));
        symbol
    }

    /// Asserts the Boolean `condition`.
    pub fn assert(&mut self, condition: &Term) {
        self.command(&format!("(assert {condition})"));
    }

    /// `value` itself if it is atomic, else a new constant `prefix.N`
    /// defined as it.
    pub fn name(&mut self, prefix: &str, sort: &str, value: Term) -> Term {
        if value.is_atom() {
            return value;
        }
        self.fresh += 1;
        let name = format!("{prefix}.{}", self.fresh);
        self.define(&name, sort, &value)
    }

    /// Declares a state for `declarations`: register `r` is `prefix` +
    /// `r`'s name, memory `prefix` + `memory`.
    pub fn initial_state(
        &mut self,
        declarations: &Declarations,
        prefix: &str,
        options: &Options,
    ) -> State {
        let registers = declarations
            .registers
            .iter()
            .map(|register| {
                self.declare(&format!("{prefix}{}", register.name), &sort(register.width))
            })
            .collect();
        let memory = self.declare(
            &format!("{prefix}memory"),
            &memory_sort(options.address_width),
        );
        State { registers, memory }
    }

    /// Defines what `semantics` does from `initial`; its definitions are
    /// named `prefix.N` and its undefined values `prefix` +
    /// `undefined.N` (a prefix per encoding keeps them apart).
    ///
    /// # Errors
    ///
    /// If `semantics` does not pass the verifier for `declarations` (as far
    /// as encoding notices), or an address is not
    /// [`Options::address_width`] bits wide.
    pub fn encode(
        &mut self,
        semantics: &Semantics,
        declarations: &Declarations,
        initial: &State,
        prefix: &str,
        options: &Options,
    ) -> Result<Final, SmtError> {
        if initial.registers.len() != declarations.registers.len() {
            return Err(SmtError(format!(
                "{} initial registers for {} declared",
                initial.registers.len(),
                declarations.registers.len()
            )));
        }
        let mut encoder = Encoder {
            script: self,
            semantics,
            declarations,
            prefix,
            options: *options,
            registers: initial.registers.clone(),
            memory: initial.memory.clone(),
            locals: vec![None; semantics.locals.len()],
            cache: vec![None; semantics.exprs.len()],
            generation: 0,
            guard: top(),
            running: top(),
            loops: Vec::new(),
            traps: Vec::new(),
            transferred: bottom(),
            target: literal(options.address_width, 0),
            system_call: bottom(),
            loads: Vec::new(),
            stores: Vec::new(),
            exhausted: bottom(),
        };
        encoder.block(&semantics.body)?;
        Ok(encoder.finish())
    }
}

struct Encoder<'a> {
    script: &'a mut Script,
    semantics: &'a Semantics,
    declarations: &'a Declarations,
    prefix: &'a str,
    options: Options,
    registers: Vec<Term>,
    memory: Term,
    locals: Vec<Option<Term>>,
    /// Terms of expressions, with the generation they were computed in:
    /// locals change only between loop iterations, which start a new
    /// generation.
    cache: Vec<Option<(u32, Term)>>,
    generation: u32,
    /// The conditions of the enclosing `if`s.
    guard: Term,
    /// No trap has run.
    running: Term,
    /// Per enclosing loop: no `break` has run in this iteration.
    loops: Vec<Term>,
    traps: Vec<(Trap, Term)>,
    transferred: Term,
    target: Term,
    system_call: Term,
    loads: Vec<Access>,
    stores: Vec<Access>,
    exhausted: Term,
}

fn error(message: String) -> SmtError {
    SmtError(message)
}

impl Encoder<'_> {
    fn finish(self) -> Final {
        let trap = or(&self
            .traps
            .iter()
            .map(|(_, condition)| condition.clone())
            .collect::<Vec<_>>());
        Final {
            state: State {
                registers: self.registers,
                memory: self.memory,
            },
            trap,
            traps: self.traps,
            transferred: self.transferred,
            target: self.target,
            system_call: self.system_call,
            loads: self.loads,
            stores: self.stores,
            exhausted: self.exhausted,
        }
    }

    fn name(&mut self, sort: &str, value: Term) -> Term {
        self.script.name(self.prefix, sort, value)
    }

    fn boolean(&mut self, value: Term) -> Term {
        self.name("Bool", value)
    }

    /// Whether the current statement runs.
    fn enabled(&mut self) -> Term {
        let mut parts = vec![self.guard.clone(), self.running.clone()];
        parts.extend(self.loops.iter().cloned());
        let value = and(&parts);
        self.boolean(value)
    }

    fn block(&mut self, statements: &[Stmt]) -> Result<(), SmtError> {
        statements.iter().try_for_each(|stmt| self.statement(stmt))
    }

    fn statement(&mut self, stmt: &Stmt) -> Result<(), SmtError> {
        match stmt {
            Stmt::Read { local, view } => {
                let value = self.read(*view)?;
                self.set(*local, value)
            }
            Stmt::Write { view, value } => self.write(*view, *value),
            Stmt::Load {
                local,
                address,
                bytes,
            } => self.load(*local, *address, *bytes),
            Stmt::Store { address, value } => self.store(*address, *value),
            Stmt::If {
                condition,
                then,
                otherwise,
            } => self.branch(*condition, then, otherwise),
            Stmt::Loop(body) => self.unroll(body),
            Stmt::Break => {
                let enabled = self.enabled();
                let current = self
                    .loops
                    .pop()
                    .ok_or_else(|| error("break outside a loop".into()))?;
                let continuing = self.boolean(and(&[current, not(&enabled)]));
                self.loops.push(continuing);
                Ok(())
            }
            Stmt::Trap(trap) => {
                let enabled = self.enabled();
                self.running = self.boolean(and(&[self.running.clone(), not(&enabled)]));
                self.traps.push((*trap, enabled));
                Ok(())
            }
            Stmt::Jump { target } | Stmt::Call { target, .. } | Stmt::Return { target } => {
                self.transfer(*target)
            }
            Stmt::Atomic(body) => self.block(body),
            Stmt::SystemCall => {
                let enabled = self.enabled();
                self.system_call = self.boolean(or(&[self.system_call.clone(), enabled]));
                Ok(())
            }
            Stmt::Intrinsic {
                intrinsic,
                inputs,
                outputs,
            } => self.intrinsic(*intrinsic, inputs, outputs),
        }
    }

    fn set(&mut self, local: Local, value: Term) -> Result<(), SmtError> {
        let slot = self
            .locals
            .get_mut(local.0 as usize)
            .ok_or_else(|| error(format!("no local l{}", local.0)))?;
        *slot = Some(value);
        Ok(())
    }

    fn register(&self, view: View) -> Result<(usize, u16), SmtError> {
        let info = self
            .declarations
            .info(view.register)
            .ok_or_else(|| error(format!("no register {}", view.register.0)))?;
        if u32::from(view.offset) + u32::from(view.width) > u32::from(info.width) || view.width == 0
        {
            return Err(error(format!("view outside {}", info.name)));
        }
        Ok((usize::from(view.register.0), info.width))
    }

    fn read(&mut self, view: View) -> Result<Term, SmtError> {
        let (index, width) = self.register(view)?;
        let whole = self
            .registers
            .get(index)
            .cloned()
            .ok_or_else(|| error("register out of range".into()))?;
        if view.offset == 0 && view.width == width {
            return Ok(whole);
        }
        let value = Term(extract(&whole, view.offset, view.width));
        Ok(self.name(&sort(view.width), value))
    }

    fn write(&mut self, view: View, value: ExprId) -> Result<(), SmtError> {
        let (index, width) = self.register(view)?;
        if self.semantics.width(value) != view.width {
            return Err(error(format!(
                "write of e{} to a {}-bit view",
                value.0, view.width
            )));
        }
        let value = self.eval(value)?;
        let old = self
            .registers
            .get(index)
            .cloned()
            .ok_or_else(|| error("register out of range".into()))?;
        let mut parts = Vec::new();
        let top_bit = view.offset + view.width;
        if top_bit < width {
            parts.push(extract(&old, top_bit, width - top_bit));
        }
        parts.push(value.0);
        if view.offset > 0 {
            parts.push(extract(&old, 0, view.offset));
        }
        let new = Term(concat(parts));
        let enabled = self.enabled();
        let merged = ite(&enabled, &new, &old);
        let merged = self.name(&sort(width), merged);
        if let Some(slot) = self.registers.get_mut(index) {
            *slot = merged;
        }
        Ok(())
    }

    fn address(&mut self, id: ExprId) -> Result<Term, SmtError> {
        let width = self.semantics.width(id);
        if width != self.options.address_width {
            return Err(error(format!(
                "a {width}-bit address (addresses are {} bits)",
                self.options.address_width
            )));
        }
        self.eval(id)
    }

    fn byte_address(&self, address: &Term, index: u16) -> String {
        if index == 0 {
            address.0.clone()
        } else {
            format!(
                "(bvadd {address} {})",
                literal(self.options.address_width, u64::from(index))
            )
        }
    }

    fn load(&mut self, local: Local, address: ExprId, bytes: u16) -> Result<(), SmtError> {
        if bytes == 0 {
            return Err(error("a load of no bytes".into()));
        }
        let address = self.address(address)?;
        let parts = (0..bytes)
            .rev()
            .map(|index| {
                format!(
                    "(select {} {})",
                    self.memory,
                    self.byte_address(&address, index)
                )
            })
            .collect();
        let value = Term(concat(parts));
        let value = self.name(&sort(bytes.saturating_mul(8)), value);
        let condition = self.enabled();
        self.loads.push(Access {
            condition,
            address,
            bytes,
        });
        self.set(local, value)
    }

    fn store(&mut self, address: ExprId, value: ExprId) -> Result<(), SmtError> {
        let width = self.semantics.width(value);
        if !width.is_multiple_of(8) {
            return Err(error(format!("a store of {width} bits")));
        }
        let bytes = width / 8;
        let address = self.address(address)?;
        let value = self.eval(value)?;
        let mut memory = self.memory.0.clone();
        for index in 0..bytes {
            memory = format!(
                "(store {memory} {} {})",
                self.byte_address(&address, index),
                extract(&value, index * 8, 8)
            );
        }
        let enabled = self.enabled();
        let merged = ite(&enabled, &Term(memory), &self.memory);
        self.memory = self.name(&memory_sort(self.options.address_width), merged);
        self.stores.push(Access {
            condition: enabled,
            address,
            bytes,
        });
        Ok(())
    }

    fn branch(
        &mut self,
        condition: ExprId,
        then: &[Stmt],
        otherwise: &[Stmt],
    ) -> Result<(), SmtError> {
        if self.semantics.width(condition) != 1 {
            return Err(error(format!("condition e{} is not 1 bit", condition.0)));
        }
        let condition = self.eval(condition)?;
        let condition = holds(&condition);
        let outer = self.guard.clone();
        self.guard = self.boolean(and(&[outer.clone(), condition.clone()]));
        self.block(then)?;
        self.guard = self.boolean(and(&[outer.clone(), not(&condition)]));
        self.block(otherwise)?;
        self.guard = outer;
        Ok(())
    }

    fn unroll(&mut self, body: &[Stmt]) -> Result<(), SmtError> {
        self.loops.push(top());
        for _ in 0..self.options.unroll {
            self.generation += 1;
            self.block(body)?;
        }
        let enabled = self.enabled();
        self.exhausted = self.boolean(or(&[self.exhausted.clone(), enabled]));
        self.loops.pop();
        self.generation += 1;
        Ok(())
    }

    fn transfer(&mut self, target: ExprId) -> Result<(), SmtError> {
        let target = self.address(target)?;
        let enabled = self.enabled();
        let merged = ite(&enabled, &target, &self.target);
        self.target = self.name(&sort(self.options.address_width), merged);
        self.transferred = self.boolean(or(&[self.transferred.clone(), enabled]));
        Ok(())
    }

    fn intrinsic(
        &mut self,
        intrinsic: IntrinsicId,
        inputs: &[ExprId],
        outputs: &[Local],
    ) -> Result<(), SmtError> {
        let info = *self
            .declarations
            .intrinsic(intrinsic)
            .ok_or_else(|| error(format!("no intrinsic {}", intrinsic.0)))?;
        if info.opaque {
            // Unknown values: a fresh constant per output, as for
            // `Expr::Undefined`.
            for &input in inputs {
                self.eval(input)?;
            }
            for &local in outputs {
                let width = self.semantics.locals.get(local.0 as usize).copied();
                let width = width.ok_or_else(|| error(format!("no local l{}", local.0)))?;
                let name = format!("{}{}.l{}", self.prefix, info.name, local.0);
                let value = self.script.declare(&name, &sort(width));
                self.set(local, value)?;
            }
            return Ok(());
        }
        if inputs.len() != info.inputs.len() || outputs.len() != info.outputs.len() {
            return Err(error(format!("{} with the wrong arity", info.name)));
        }
        let arguments = inputs
            .iter()
            .map(|&input| self.eval(input))
            .collect::<Result<Vec<_>, _>>()?;
        let sorts: Vec<String> = info.inputs.iter().map(|&width| sort(width)).collect();
        for (index, (&local, &width)) in outputs.iter().zip(info.outputs).enumerate() {
            let name = format!("intrinsic.{}.{index}", info.name);
            let function = self.script.declare_function(&name, &sorts, &sort(width));
            let value = if arguments.is_empty() {
                function
            } else {
                let refs: Vec<&Term> = arguments.iter().collect();
                Term(format!("({function} {})", join(&refs)))
            };
            let value = self.name(&sort(width), value);
            self.set(local, value)?;
        }
        Ok(())
    }

    fn eval(&mut self, id: ExprId) -> Result<Term, SmtError> {
        let index = id.0 as usize;
        if let Some(Some((generation, term))) = self.cache.get(index)
            && *generation == self.generation
        {
            return Ok(term.clone());
        }
        let (expr, width) = self
            .semantics
            .expr(id)
            .ok_or_else(|| error(format!("no expression e{}", id.0)))?;
        let text = self.expression(expr, width)?;
        let term = self.name(&sort(width), Term(text));
        if let Some(slot) = self.cache.get_mut(index) {
            *slot = Some((self.generation, term.clone()));
        }
        Ok(term)
    }

    fn operand(&mut self, id: ExprId) -> Result<(Term, u16), SmtError> {
        Ok((self.eval(id)?, self.semantics.width(id)))
    }

    fn expression(&mut self, expr: Expr, width: u16) -> Result<String, SmtError> {
        Ok(match expr {
            Expr::Const(bits) => constant(&bits).0,
            Expr::Local(local) => {
                self.locals
                    .get(local.0 as usize)
                    .cloned()
                    .flatten()
                    .ok_or_else(|| error(format!("l{} used before its definition", local.0)))?
                    .0
            }
            Expr::Undefined { width, serial } => {
                let name = format!("{}undefined.{serial}", self.prefix);
                self.script.declare(&name, &sort(width)).0
            }
            Expr::Unary(op, a) => {
                let (a, w) = self.operand(a)?;
                unary(op, &a, w)?
            }
            Expr::Binary(op, a, b) => {
                let (a, w) = self.operand(a)?;
                let (b, _) = self.operand(b)?;
                binary(op, &a, &b, w)
            }
            Expr::Flag(op, a, b, c) => {
                let (a, w) = self.operand(a)?;
                let (b, _) = self.operand(b)?;
                let (c, _) = self.operand(c)?;
                flag(op, &a, &b, &c, w)
            }
            Expr::Extract {
                value,
                offset,
                width,
            } => extract(&self.eval(value)?, offset, width),
            Expr::Concat { high, low } => concat(vec![self.eval(high)?.0, self.eval(low)?.0]),
            Expr::Extend {
                signed,
                value,
                width,
            } => {
                let (value, from) = self.operand(value)?;
                extend(signed, &value, from, width)
            }
            Expr::Select {
                condition,
                then,
                otherwise,
            } => select(
                &self.eval(condition)?,
                &self.eval(then)?,
                &self.eval(otherwise)?,
            ),
            Expr::Lanes {
                lanes,
                op,
                operands,
            } => self.lanes(lanes, op, operands)?,
            Expr::Float {
                op,
                format,
                lanes,
                output,
                rounding,
                operands,
            } => self.float(op, format, lanes, output, rounding, operands, width)?,
        })
    }

    fn lanes(&mut self, lanes: u16, op: LaneOp, operands: [ExprId; 3]) -> Result<String, SmtError> {
        if lanes == 0 {
            return Err(error("no lanes".into()));
        }
        let values = operands
            .iter()
            .take(op.arity())
            .map(|&id| self.operand(id))
            .collect::<Result<Vec<_>, _>>()?;
        let mut parts = Vec::new();
        for lane in (0..lanes).rev() {
            let lane_values: Vec<(Term, u16)> = values
                .iter()
                .map(|(value, width)| {
                    let lane_width = width / lanes;
                    (
                        Term(extract(value, lane * lane_width, lane_width)),
                        lane_width,
                    )
                })
                .collect();
            let text = match (op, lane_values.as_slice()) {
                (LaneOp::Unary(unary_op), [(a, w), ..]) => unary(unary_op, a, *w)?,
                (LaneOp::Binary(binary_op), [(a, w), (b, _), ..]) => binary(binary_op, a, b, *w),
                (LaneOp::Extract { offset, width }, [(a, _), ..]) => extract(a, offset, width),
                (LaneOp::Extend { signed, width }, [(a, w), ..]) => extend(signed, a, *w, width),
                (LaneOp::Select, [(c, _), (t, _), (e, _)]) => select(c, t, e),
                (
                    LaneOp::Unary(_)
                    | LaneOp::Binary(_)
                    | LaneOp::Extract { .. }
                    | LaneOp::Extend { .. }
                    | LaneOp::Select,
                    _,
                ) => return Err(error("lanes with too few operands".into())),
            };
            parts.push(text);
        }
        Ok(concat(parts))
    }

    #[expect(clippy::too_many_arguments, reason = "the fields of Expr::Float")]
    fn float(
        &mut self,
        op: FloatOp,
        format: Format,
        lanes: u16,
        output: FloatOutput,
        rounding: ExprId,
        operands: [ExprId; 3],
        width: u16,
    ) -> Result<String, SmtError> {
        let mut arguments = vec![self.operand(rounding)?];
        for &id in operands.iter().take(op.arity()) {
            arguments.push(self.operand(id)?);
        }
        let sorts: Vec<String> = arguments.iter().map(|(_, w)| sort(*w)).collect();
        let widths: Vec<String> = arguments.iter().map(|(_, w)| format!("{w}")).collect();
        let name = format!(
            "float.{op:?}.{format:?}.{lanes}.{output:?}.{}",
            widths.join(".")
        );
        let function = self.script.declare_function(&name, &sorts, &sort(width));
        let terms: Vec<&Term> = arguments.iter().map(|(term, _)| term).collect();
        Ok(format!("({function} {})", join(&terms)))
    }
}

/// `width` bits of `value` from bit `offset`.
fn extract(value: &Term, offset: u16, width: u16) -> String {
    format!(
        "((_ extract {} {offset}) {value})",
        offset + width.saturating_sub(1)
    )
}

/// The parts, highest first, side by side.
fn concat(mut parts: Vec<String>) -> String {
    if parts.len() == 1 {
        return parts.pop().unwrap_or_default();
    }
    format!("(concat {})", parts.join(" "))
}

fn extend(signed: bool, value: &Term, from: u16, to: u16) -> String {
    if to <= from {
        return value.0.clone();
    }
    let kind = if signed { "sign_extend" } else { "zero_extend" };
    format!("((_ {kind} {}) {value})", to - from)
}

fn select(condition: &Term, then: &Term, otherwise: &Term) -> String {
    format!("(ite (= {condition} #b1) {then} {otherwise})")
}

fn bit_of(value: &Term, index: u16) -> String {
    format!("((_ extract {index} {index}) {value})")
}

fn unary(op: Unary, a: &Term, width: u16) -> Result<String, SmtError> {
    Ok(match op {
        Unary::Not => format!("(bvnot {a})"),
        Unary::Neg => format!("(bvneg {a})"),
        Unary::Popcount => {
            if width == 1 {
                return Ok(a.0.clone());
            }
            let bits: Vec<String> = (0..width)
                .map(|index| format!("((_ zero_extend {}) {})", width - 1, bit_of(a, index)))
                .collect();
            format!("(bvadd {})", bits.join(" "))
        }
        Unary::LeadingZeros => {
            let mut text = literal(width, u64::from(width)).0;
            for index in 0..width {
                let count = literal(width, u64::from(width - 1 - index));
                text = format!("(ite (= {} #b1) {count} {text})", bit_of(a, index));
            }
            text
        }
        Unary::TrailingZeros => {
            let mut text = literal(width, u64::from(width)).0;
            for index in (0..width).rev() {
                let count = literal(width, u64::from(index));
                text = format!("(ite (= {} #b1) {count} {text})", bit_of(a, index));
            }
            text
        }
        Unary::ByteSwap => {
            if !width.is_multiple_of(8) {
                return Err(error(format!("byte swap of {width} bits")));
            }
            concat((0..width / 8).map(|byte| extract(a, byte * 8, 8)).collect())
        }
        Unary::EvenParity8 => {
            let bits: Vec<String> = (0..width.min(8)).map(|index| bit_of(a, index)).collect();
            if bits.len() == 1 {
                format!("(bvnot {})", bits.concat())
            } else {
                format!("(bvnot (bvxor {}))", bits.join(" "))
            }
        }
    })
}

fn bit(condition: &str) -> String {
    format!("(ite {condition} #b1 #b0)")
}

fn binary(op: Binary, a: &Term, b: &Term, width: u16) -> String {
    let function = match op {
        Binary::Add => "bvadd",
        Binary::Sub => "bvsub",
        Binary::Mul => "bvmul",
        Binary::UDiv => "bvudiv",
        Binary::URem => "bvurem",
        Binary::SRem => "bvsrem",
        Binary::And => "bvand",
        Binary::Or => "bvor",
        Binary::Xor => "bvxor",
        Binary::Shl => "bvshl",
        Binary::LShr => "bvlshr",
        Binary::AShr => "bvashr",
        Binary::SDiv => {
            // SMT-LIB's quotient of a negative dividend by 0 is 1; L0's is
            // all ones.
            return format!(
                "(ite (= {b} {}) {} (bvsdiv {a} {b}))",
                literal(width, 0),
                constant(&Bits::ones(width))
            );
        }
        Binary::Rol | Binary::Ror => {
            let size = literal(width, u64::from(width));
            let count = format!("(bvurem {b} {size})");
            let (first, second) = if op == Binary::Rol {
                ("bvshl", "bvlshr")
            } else {
                ("bvlshr", "bvshl")
            };
            return format!("(bvor ({first} {a} {count}) ({second} {a} (bvsub {size} {count})))");
        }
        Binary::Eq => return bit(&format!("(= {a} {b})")),
        Binary::Ne => return bit(&format!("(not (= {a} {b}))")),
        Binary::ULt => return bit(&format!("(bvult {a} {b})")),
        Binary::ULe => return bit(&format!("(bvule {a} {b})")),
        Binary::SLt => return bit(&format!("(bvslt {a} {b})")),
        Binary::SLe => return bit(&format!("(bvsle {a} {b})")),
    };
    format!("({function} {a} {b})")
}

/// A flag computation, as [`crate::expand`] defines it.
fn flag(op: Flag, a: &Term, b: &Term, c: &Term, width: u16) -> String {
    let top = width.saturating_sub(1);
    match op {
        Flag::AddCarry => bit(&format!(
            "(or (bvult (bvadd {a} {b}) {a}) (bvult (bvadd {a} {b} {c}) (bvadd {a} {b})))"
        )),
        Flag::SubBorrow => bit(&format!("(or (bvult {a} {b}) (bvult (bvsub {a} {b}) {c}))")),
        Flag::AddOverflow => {
            let result = format!("(bvadd {a} {b} {c})");
            format!("((_ extract {top} {top}) (bvand (bvxor {a} {result}) (bvxor {b} {result})))")
        }
        Flag::SubOverflow => {
            let result = format!("(bvsub (bvsub {a} {b}) {c})");
            format!("((_ extract {top} {top}) (bvand (bvxor {a} {b}) (bvxor {a} {result})))")
        }
        Flag::NibbleCarry => {
            if width <= 4 {
                "#b0".into()
            } else {
                format!("((_ extract 4 4) (bvxor {a} {b} {c}))")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals_round_trip() {
        for (width, value) in [(1, 1), (3, 5), (8, 0xa5), (64, u64::MAX), (13, 0x1abc)] {
            let bits = Bits::from_u64(width, value);
            assert_eq!(parse_literal(constant(&bits).as_str()), Some(bits));
        }
        assert_eq!(constant(&Bits::from_u64(8, 0xa5)).as_str(), "#xa5");
        assert_eq!(constant(&Bits::from_u64(3, 5)).as_str(), "#b101");
        assert_eq!(parse_literal("(_ bv300 16)"), Some(Bits::from_u64(16, 300)));
        assert_eq!(parse_literal("#xz"), None);
    }

    #[test]
    fn combinators_simplify_constants() {
        let x = Term::new("x");
        assert_eq!(and(&[top(), x.clone()]), x);
        assert_eq!(and(&[bottom(), x.clone()]), bottom());
        assert_eq!(or(&[top(), x.clone()]), top());
        assert_eq!(or(&[]), bottom());
        assert_eq!(ite(&top(), &x, &Term::new("y")), x);
        assert_eq!(not(&not(&top())), top());
        assert_eq!(symbol("a|b").as_str(), "|a_b|");
    }
}
