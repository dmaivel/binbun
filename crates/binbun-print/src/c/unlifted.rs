//! Instructions without semantics: an architecture's `lift_opaque`, an
//! [opaque](binbun_semantics::ir::IntrinsicInfo::opaque) intrinsic in L2,
//! printed by the listing's text ([`Image::unlifted`]), as a call of
//! `binbun_defs.h`'s ([`Opaque::Calls`]) or in `__asm` blocks
//! ([`Opaque::Asm`]). Their inputs are not printed (the text names what
//! they read); of their outputs only those later code reads are.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use binbun_ast::ir::{Expr, ExprId, Function, Node, Origin, Place, Stmt, StmtId, VarId, VarKind};
use binbun_ast::types::{Type, TypeId};
use binbun_semantics::Declarations;

use super::memory::string_literal;
use super::types::container;
use super::{Image, PrintError, Printer, error};
use crate::document::{BlockKind, Braces, Doc, TokenKind};

/// How instructions without semantics print.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Opaque {
    /// Each one a call of `binbun_defs.h`'s carrying its text, which gives what
    /// later code reads of it: `v41 = unlifted_u32("kmovd eax, k1");`,
    /// `unlifted("vmovdqu64 ymm17, ymmword ptr [rsi]");` where nothing is
    /// read, `unlifted("vcomisd xmm16, xmm17", &t0, &t1);` where several
    /// values are. The C compiles, but does not compute them: to the
    /// compiler they are unknown values, and memory may change.
    #[default]
    Calls,
    /// Consecutive ones in a block as one `__asm { … }` block, an
    /// instruction a line, and what later code reads of them as variables
    /// named after the register as the code reads it (`_EAX`, `_K1`,
    /// `_ZMM17`), declared as the other locals are. No
    /// compiler takes it. The reading view's: a local merged from several
    /// paths is also left unassigned where it would take what a call left
    /// (`unknown::unassigned`).
    Asm,
}

/// An instruction without semantics, as the listing shows it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Unlifted {
    /// Its text (x86-64: Intel syntax, as XED prints it).
    pub text: String,
    /// What each of its outputs is called, in order: `(width, name)` pairs
    /// (lower case), narrowest first, each a part of the output from its
    /// first bit (`eax`'s output: `al`, `ax`, `eax`); empty for an output
    /// that is no register (a value it stores).
    pub outputs: Vec<Vec<(u16, String)>>,
}

impl Unlifted {
    /// What output `index` is called where `width` bits of it are read:
    /// the first name at least that wide, else the widest.
    pub fn name(&self, index: usize, width: u16) -> Option<&str> {
        let names = self.outputs.get(index)?;
        names
            .iter()
            .find(|&&(wide, _)| wide >= width)
            .or_else(|| names.last())
            .map(|(_, name)| name.as_str())
    }
}

/// Whether `stmt` is an instruction without semantics (of `declarations`).
pub(super) fn is_unlifted(stmt: &Stmt, declarations: &Declarations) -> bool {
    matches!(stmt, Stmt::Intrinsic { intrinsic, .. }
        if declarations.intrinsic(*intrinsic).is_some_and(|info| info.opaque))
}

/// What the printed code of a function reads ([`printed_reads`]).
#[derive(Debug, Default)]
pub(super) struct Reads {
    /// The variables the printed code reads.
    pub vars: BTreeSet<VarId>,
    /// The assignments not printed: to locals whose values only
    /// instructions without semantics read (through other such
    /// assignments), computed without loads or calls.
    pub unprinted: BTreeSet<StmtId>,
}

/// Whether expression `id` of `f` has no loads, calls, assignments or
/// exception values in it: printed twice or not at all, it means the same.
pub(super) fn pure(f: &Function, id: ExprId) -> bool {
    let mut work = vec![id];
    let mut seen = BTreeSet::new();
    while let Some(id) = work.pop() {
        if !seen.insert(id) {
            continue;
        }
        match f.expr(id) {
            None
            | Some(
                Expr::Load { .. } | Expr::Call(_) | Expr::Assign { .. } | Expr::Exception { .. },
            ) => return false,
            Some(expr) => work.extend(expr.operands(f)),
        }
    }
    true
}

/// The local `stmt` assigns a [`pure`] value, and the value: an
/// assignment that may go unprinted.
fn pure_assignment(f: &Function, stmt: &Stmt) -> Option<(VarId, ExprId)> {
    let &Stmt::Assign {
        place: Place::Var(var),
        value,
    } = stmt
    else {
        return None;
    };
    (f.var(var)?.kind == VarKind::Local && pure(f, value)).then_some((var, value))
}

/// The variables the expressions `roots` read (as values or by address),
/// into `vars`, and for each one newly read the values `assigned` gives
/// it (removed from `assigned`), to a fixed point.
fn reads_from(
    f: &Function,
    roots: Vec<ExprId>,
    assigned: &mut BTreeMap<VarId, Vec<(StmtId, ExprId)>>,
    vars: &mut BTreeSet<VarId>,
) {
    let mut work = roots;
    let mut visited = vec![false; f.exprs.len()];
    while let Some(id) = work.pop() {
        let (Some(slot), Some(expr)) = (visited.get_mut(id.0 as usize), f.expr(id)) else {
            continue;
        };
        if core::mem::replace(slot, true) {
            continue;
        }
        if let Expr::Var(var) | Expr::AddressOf(var) = *expr
            && vars.insert(var)
            && let Some(values) = assigned.remove(&var)
        {
            work.extend(values.into_iter().map(|(_, value)| value));
        }
        work.extend(expr.operands(f));
    }
}

/// What the printed code of `f` reads: what its body's statements read,
/// but for the inputs of the instructions without semantics, which their
/// text stands for, and for the assignments of locals only those inputs
/// read (through others such), which are not printed.
pub(super) fn printed_reads(f: &Function, declarations: &Declarations) -> Reads {
    let mut seen = vec![false; f.stmts.len()];
    let mut blocks = vec![&f.body];
    let mut printed = Vec::new();
    let mut opaque = Vec::new();
    let mut assigned: BTreeMap<VarId, Vec<(StmtId, ExprId)>> = BTreeMap::new();
    while let Some(block) = blocks.pop() {
        for &id in block {
            let (Some(slot), Some(stmt)) = (seen.get_mut(id.0 as usize), f.stmt(id)) else {
                continue;
            };
            if core::mem::replace(slot, true) {
                continue;
            }
            if let Stmt::Intrinsic {
                results, inputs, ..
            } = stmt
                && is_unlifted(stmt, declarations)
            {
                printed.extend(results.iter().filter_map(|place| match *place {
                    Place::Memory { address, .. } => Some(address),
                    Place::Var(_) => None,
                }));
                opaque.extend(inputs.iter().copied());
            } else if let Some((var, value)) = pure_assignment(f, stmt) {
                assigned.entry(var).or_default().push((id, value));
            } else {
                printed.extend(stmt.roots());
            }
            blocks.extend(stmt.blocks());
        }
    }
    // The locals only instructions without semantics may read: the others'
    // assignments are printed as any statement.
    let mut fed = BTreeSet::new();
    let mut feeding = assigned.clone();
    reads_from(f, opaque, &mut feeding, &mut fed);
    let mut candidates = BTreeMap::new();
    for (var, values) in assigned {
        if fed.contains(&var) {
            candidates.insert(var, values);
        } else {
            printed.extend(values.into_iter().map(|(_, value)| value));
        }
    }
    let mut vars = BTreeSet::new();
    reads_from(f, printed, &mut candidates, &mut vars);
    let unprinted = candidates
        .into_values()
        .flatten()
        .map(|(id, _)| id)
        .collect();
    Reads { vars, unprinted }
}

/// The instruction statement `id` of `f` stands for, by its text and
/// outputs as `image` lists them; else its address (or none) and no
/// names.
fn listed(f: &Function, image: &dyn Image, id: StmtId) -> Unlifted {
    let address = f
        .provenance
        .stmt(id)
        .iter()
        .find_map(|origin| match *origin {
            Origin::Instruction(address) => Some(address),
            Origin::Value(_)
            | Origin::Register(_)
            | Origin::Held(_)
            | Origin::Slot(_)
            | Origin::Block(_)
            | Origin::Absorbed(_)
            | Origin::Proved => None,
        });
    address
        .and_then(|address| image.unlifted(address))
        .unwrap_or_else(|| Unlifted {
            text: address.map_or_else(
                || String::from("(an instruction)"),
                |address| format!("(the instruction at {address:#x})"),
            ),
            outputs: Vec::new(),
        })
}

/// The name of a register as code reads it: `_` and upper case.
fn register_name(name: &str) -> String {
    format!("_{}", name.to_ascii_uppercase())
}

/// For [`Opaque::Asm`]: the locals of `f` that hold an output of an
/// instruction without semantics the printed code reads (`reads`), and
/// the name of the register as it reads them (the variable's width); the
/// first such output a variable holds names it, unless the variable has a
/// name of its own.
pub(super) fn register_names(
    f: &Function,
    declarations: &Declarations,
    image: &dyn Image,
    reads: &BTreeSet<VarId>,
) -> BTreeMap<VarId, String> {
    let mut names = BTreeMap::new();
    for (index, stmt) in (0u32..).zip(&f.stmts) {
        let Stmt::Intrinsic { results, .. } = stmt else {
            continue;
        };
        if !is_unlifted(stmt, declarations) {
            continue;
        }
        let mut listing = None;
        for (output, place) in results.iter().enumerate() {
            let &Place::Var(var) = place else { continue };
            let Some(variable) = f.var(var) else { continue };
            if variable.kind != VarKind::Local
                || variable.name.is_some()
                || !reads.contains(&var)
                || names.contains_key(&var)
            {
                continue;
            }
            let width = f
                .types
                .width(variable.ty)
                .and_then(|width| u16::try_from(width).ok())
                .unwrap_or(0);
            let listing = listing.get_or_insert_with(|| listed(f, image, StmtId(index)));
            if let Some(name) = listing.name(output, width) {
                names.insert(var, register_name(name));
            }
        }
    }
    names
}

impl Printer<'_> {
    /// Whether statement `id` is an instruction without semantics.
    pub(super) fn unlifted_at(&self, id: StmtId) -> bool {
        self.f
            .stmt(id)
            .is_some_and(|stmt| is_unlifted(stmt, self.declarations))
    }

    /// Whether `place`, a result of an instruction without semantics, is
    /// printed: a store, or a variable the printed code reads.
    pub(super) fn printed(&self, place: &Place) -> bool {
        match *place {
            Place::Memory { .. } => true,
            Place::Var(var) => {
                self.printed_reads.contains(&var)
                    || self.f.var(var).is_some_and(|variable| {
                        matches!(variable.kind, VarKind::Frame(_) | VarKind::Global(_))
                    })
            }
        }
    }

    /// The L2 type `binbun_defs.h`'s helper returns for an output of `width`
    /// bits, and the helper's name: `unlifted_bool` for 1 bit, else
    /// `unlifted_u8` to `unlifted_u128` by the C integer holding it, and
    /// `unlifted_u256` and `unlifted_u512` (a `u64x4`, a `u64x8`).
    fn unlifted_helper(&mut self, width: u16) -> Result<(TypeId, String), PrintError> {
        let ty = self.types.intern(Type::UInt(width));
        if width == 1 {
            return Ok((ty, String::from("unlifted_bool")));
        }
        if matches!(width, 256 | 512) {
            return Ok((ty, format!("unlifted_u{width}")));
        }
        let bits = container(width)
            .ok_or_else(|| self.unsupported(self.node, "unlifted values over 128 bits"))?;
        Ok((ty, format!("unlifted_u{bits}")))
    }

    /// The width of `place`.
    fn place_width(&self, place: &Place) -> Result<u16, PrintError> {
        let ty = match *place {
            Place::Var(var) => self
                .f
                .var(var)
                .map(|variable| variable.ty)
                .ok_or_else(|| error(Some(Node::Var(var)), "no such variable"))?,
            Place::Memory { ty, .. } => ty,
        };
        self.type_width(ty)
    }

    /// The text of statement `id`, an instruction without semantics, as a
    /// string literal token.
    fn unlifted_literal(&self, id: StmtId) -> Doc {
        let text = listed(self.f, self.image, id).text;
        Doc::string(string_literal(text.as_bytes()), self.node)
    }

    /// [`Opaque::Calls`]: the instruction without semantics being printed
    /// (an intrinsic with `results`) as a call of `binbun_defs.h`'s with its
    /// text, giving the outputs printed code reads: `unlifted("…");`, `x =
    /// unlifted_u32("…");`, or `unlifted("…", &t0, &t1);` then the places
    /// from the temporaries.
    pub(super) fn unlifted_call(&mut self, results: &[Place]) -> Result<Vec<Doc>, PrintError> {
        let Some(Node::Stmt(id)) = self.node else {
            return Err(error(self.node, "an instruction outside a statement"));
        };
        self.counts.unlifted += 1;
        let literal = vec![self.unlifted_literal(id)];
        let read: Vec<&Place> = results.iter().filter(|place| self.printed(place)).collect();
        if let [place] = read.as_slice() {
            let width = self.place_width(place)?;
            let (ty, helper) = self.unlifted_helper(width)?;
            let (doc, _) = self.call_doc(vec![self.helper_name(&helper)], vec![literal], 0);
            let mut value = self.named(String::new(), ty)?;
            value.doc = doc;
            value.lvalue = false;
            value.loads = true;
            return self.distribute(&[**place], ty, value);
        }
        let mut arguments = vec![literal];
        let mut temps = Vec::new();
        for place in &read {
            let width = self.place_width(place)?;
            let ty = self.types.intern(Type::UInt(width));
            let temp = self.temp(ty);
            arguments.push(vec![Doc::op("&", self.node), self.temp_name(temp.clone())]);
            temps.push((temp, ty, **place));
        }
        let (doc, _) = self.call_doc(vec![self.helper_name("unlifted")], arguments, 0);
        let mut out = vec![self.line(doc)];
        for (temp, ty, place) in temps {
            let (lhs, place_ty) = self.place(&place)?;
            let value = self.named(temp, ty)?;
            let tokens = self.store(lhs, place_ty, value)?;
            out.push(self.line(tokens));
        }
        Ok(out)
    }

    /// A `binbun_defs.h` helper's name as a token.
    pub(super) fn helper_name(&self, name: &str) -> Doc {
        Doc::macro_name(name, self.node)
    }

    /// [`Opaque::Asm`]: the instructions without semantics `run` (statements
    /// of one block, in order) as one `__asm { … }` block, an instruction a
    /// line; then, for each output the printed code reads that is not its
    /// own register-named variable, `place = _EAX;` from a variable named
    /// after the register.
    pub(super) fn asm_block(&mut self, run: &[StmtId]) -> Result<Vec<Doc>, PrintError> {
        let saved = self.node;
        let mut lines = Vec::new();
        let mut after = Vec::new();
        for &id in run {
            self.node = Some(Node::Stmt(id));
            let listing = listed(self.f, self.image, id);
            lines.push(Doc::Group(self.asm_tokens(&listing.text)));
            self.counts.unlifted += 1;
            let Some(Stmt::Intrinsic { results, .. }) = self.f.stmt(id).cloned() else {
                continue;
            };
            for (output, place) in results.iter().enumerate() {
                if !self.printed(place) {
                    continue;
                }
                if let Place::Var(var) = *place
                    && self.register_vars.contains_key(&var)
                {
                    self.used.insert(var);
                    continue;
                }
                let width = self.place_width(place)?;
                let ty = self.types.intern(Type::UInt(width));
                let base = listing
                    .name(output, width)
                    .map_or_else(|| format!("_OUT{output}"), register_name);
                let name = self.names.fresh(&base);
                self.temps.push((name.clone(), ty));
                let (lhs, place_ty) = self.place(place)?;
                let value = self.named(name, ty)?;
                let tokens = self.store(lhs, place_ty, value)?;
                after.push(self.line(tokens));
            }
        }
        self.node = run.first().map(|&id| Node::Stmt(id));
        self.counts.asm += 1;
        let block = Doc::Group(vec![
            Doc::keyword("__asm", self.node),
            Doc::Block {
                kind: BlockKind::Statement,
                braces: Braces::Required,
                body: lines,
                node: self.node,
            },
        ]);
        self.node = saved;
        let mut out = vec![block];
        out.extend(after);
        Ok(out)
    }

    /// An instruction's text as tokens: its words, separated by spaces (a
    /// token holds no whitespace), the mnemonic a keyword, the numbers
    /// numbers, the rest (registers, sizes, addresses) punctuation.
    fn asm_tokens(&self, text: &str) -> Vec<Doc> {
        let mut out = Vec::new();
        for (position, word) in text.split_whitespace().enumerate() {
            if position > 0 {
                out.push(Doc::Space);
            }
            let digits = word.trim_end_matches(',');
            let kind = if position == 0 {
                TokenKind::Keyword
            } else if digits.starts_with(|c: char| c.is_ascii_digit()) {
                TokenKind::Number
            } else {
                TokenKind::Punctuation
            };
            out.push(Doc::token(kind, word, self.node));
        }
        out
    }
}
