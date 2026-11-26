//! The solver's types ([`crate::typing`]): the
//! read-only view of lowering its generation reads, solving after
//! folding, each value's sort for coalescing, rounding after coalescing
//! (emit applies the rounded types).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;

use binbun_ast::types::{Evidence, Types};
use binbun_semantics::ir::LaneOp;
use binbun_ssa::condition::{Relation, comparison};
use binbun_ssa::ir::{BlockId, Definition, InstId, Op, Terminator, Value, ValueInfo};

use super::facts::{Kind, Lowering, Site};
use super::frame::Home;
use super::needed::Role;
use crate::mapping::Source;
use crate::typing::{
    self, Arguments, Call, Declared, Evolutions, Explained, Members, Parameter, Returns, Shape,
    Sort, Summary, View,
};

impl Lowering<'_, '_> {
    /// Generation and solving (after folding).
    pub(super) fn solve_types(&mut self) {
        let solved = typing::solve(&self.typing_view());
        match solved {
            Ok(solved) => self.solved = Some(solved),
            Err(outcome) => self.typing = outcome,
        }
    }

    /// The scheme of what [`Self::solve_types`] solved (nothing unless
    /// solved, or past [`typing::SCHEME_SIZE`]).
    pub(super) fn summary(&self) -> Option<Summary> {
        let solved = self.solved.as_ref()?;
        typing::summary(&self.typing_view(), solved)
    }

    /// Why what [`Self::solve_types`] solved types `values` as it does
    /// (`None` unless solved).
    pub(super) fn explained(&self, values: &[Value]) -> Option<Explained> {
        let solved = self.solved.as_ref()?;
        Some(typing::explained(solved, values))
    }

    /// What the calls pass their callees by what [`Self::solve_types`]
    /// solved ([`typing::Arguments`]; nothing unless solved).
    pub(super) fn arguments(&self) -> Arguments {
        let Some(solved) = self.solved.as_ref() else {
            return Arguments::new();
        };
        let mut types = self.types.clone();
        let view = self.rounding_view(&mut types);
        typing::arguments(&view, solved, &mut types)
    }

    /// What [`Self::solve_types`] solved adds to the program's synthesised
    /// structs ([`typing::Contribution`]; nothing unless solved), with the
    /// declared structs its roots point to where the function has debug
    /// information ([`Self::declared_roots`]).
    pub(super) fn structs(&self) -> typing::Contribution {
        let Some(solved) = self.solved.as_ref() else {
            return typing::Contribution::default();
        };
        let mut types = self.types.clone();
        let view = self.rounding_view(&mut types);
        let mut contribution = typing::contribution(&view, solved, &mut types);
        if self.debug.is_some() {
            let roots = self.declared_roots(&view);
            typing::declare(
                solved,
                &roots,
                self.cx.prototypes,
                &mut types,
                &mut contribution,
            );
        }
        contribution
    }

    /// The roots whose type a declaration states (debug information's
    /// where the function has it): the parameters and the return value of
    /// a declared prototype, the arguments of calls to the program's
    /// functions with a declared prototype, and the frame slots of the
    /// debug information's typed variables.
    fn declared_roots(&self, view: &View<'_>) -> Vec<Declared> {
        let mut roots = Vec::new();
        for parameter in &view.parameters {
            if parameter.evidence != Evidence::Declared {
                continue;
            }
            roots.extend(
                parameter
                    .values
                    .iter()
                    .map(|&value| Declared::Value(value, parameter.ty)),
            );
            if let Some(slot) = parameter.slot {
                roots.push(Declared::Slot(slot, parameter.ty));
            }
        }
        if view.returns.evidence == Some(Evidence::Declared)
            && let Some(ty) = view.returns.ty
        {
            roots.extend(
                view.returns
                    .values
                    .iter()
                    .map(|&value| Declared::Value(value, ty)),
            );
        }
        for call in &view.calls {
            let defined = view
                .constant(call.target)
                .is_some_and(|target| view.functions.contains(&target.cast_unsigned()));
            let Some(signature) = view.types.signature(call.signature) else {
                continue;
            };
            if call.callee.is_some() || !defined {
                continue;
            }
            for (values, &ty) in call.arguments.iter().zip(&signature.parameters) {
                roots.extend(values.iter().map(|&value| Declared::Value(value, ty)));
            }
            if let Some(ty) = signature.returns {
                roots.extend(call.result.iter().map(|&value| Declared::Value(value, ty)));
            }
        }
        if let Some(debug) = &self.debug {
            for (index, slot) in self.frame.slots.iter().enumerate() {
                let typed = debug.locals.iter().find_map(|local| {
                    (local.offset == slot.offset && local.bytes == slot.bytes())
                        .then_some(local.ty)
                        .flatten()
                });
                if let Some(ty) = typed {
                    roots.push(Declared::Slot(index, ty));
                }
            }
        }
        roots
    }

    /// Per L1 value: what [`Self::solve_types`] solved rounds it to alone,
    /// where it is a pointer-wide variable (nothing unless solved), for
    /// coalescing.
    pub(super) fn sorts(&self) -> Vec<Option<Sort>> {
        let Some(solved) = self.solved.as_ref() else {
            return Vec::new();
        };
        let mut types = self.types.clone();
        let view = self.rounding_view(&mut types);
        typing::sorts(&view, solved, &mut types)
    }

    /// Rounding of what [`Self::solve_types`] solved, for the classes
    /// coalescing made.
    pub(super) fn round_types(&mut self) {
        let Some(solved) = self.solved.take() else {
            return;
        };
        // A class of the low lane of wider values
        // ([`Self::var_width`]) holds those values' low parts: what is
        // known of them is the variable's type (a `double` in the 512
        // bits of `zmm0`).
        let parts = self.low_parts();
        let members: Vec<Members> = self
            .classes
            .sets
            .iter()
            .map(|class| Members {
                values: class
                    .members
                    .iter()
                    .flat_map(|&value| {
                        if class.parameter.is_none() && self.width(value) > class.width {
                            self.parts(value, class.width, &parts)
                        } else {
                            vec![value]
                        }
                    })
                    .collect(),
                width: class.width,
                parameter: class.parameter,
            })
            .collect();
        let mut types = self.types.clone();
        let view = self.rounding_view(&mut types);
        let (rounded, outcome) = typing::round(&view, &solved, &members, &mut types);
        self.types = types;
        self.typed = Some(rounded);
        self.typing = outcome;
    }

    /// What rounding reads: [`Self::typing_view`] with the code types of
    /// the functions whose addresses are kept constants (interned in
    /// `types`), each with whether it is the convention's guess.
    fn rounding_view(&self, types: &mut Types) -> View<'_> {
        let mut view = self.typing_view();
        view.codes = view
            .shapes
            .iter()
            .filter_map(|shape| match shape {
                Some(Shape::Const(bits)) if self.cx.functions.contains(&bits.low_u64()) => {
                    Some(bits.low_u64())
                }
                Some(_) | None => None,
            })
            .filter_map(|address| Some((address, self.guessed_scalar_code_type(address, types)?)))
            .collect();
        view
    }

    /// What typing reads of this lowering.
    fn typing_view(&self) -> View<'_> {
        let slots = self
            .frame
            .slots
            .iter()
            .map(|slot| {
                let bits = u16::try_from(slot.bytes().saturating_mul(8)).ok()?;
                (slot.shape || slot.home == Home::Local).then_some(bits)
            })
            .collect();
        let parts = self.low_parts();
        let shapes = self.shapes();
        let nulls = self.null_arguments(&shapes);
        let returns = self.typing_returns(&parts, &nulls);
        View {
            l1: self.l1,
            constants: self.constants,
            types: &self.types,
            data: self.cx.data,
            functions: self.cx.functions,
            canon: &self.canon,
            shapes,
            nulls,
            evolutions: Evolutions::new(
                self.l1,
                self.dominators,
                &self.canon,
                self.constants,
                |block, index| self.incoming(block, index),
            ),
            variables: (0..self.l1.values.len())
                .map(|index| {
                    let v = Value(u32::try_from(index).unwrap_or(u32::MAX));
                    matches!(self.role(v), Role::Var | Role::Parameter(_))
                })
                .collect(),
            slots,
            reached: self.frame.slots.iter().map(|slot| slot.reached).collect(),
            dominators: self.dominators,
            slot_of: &self.frame.accesses,
            stores: self.lowered_stores(),
            conditions: self.conditions(),
            calls: self.typing_calls(&parts),
            parameters: self.typing_parameters(&parts),
            returns,
            codes: BTreeMap::new(),
            schemes: self.cx.schemes,
            specialised: self.cx.specialised,
            specialisations: self.cx.specialisations,
            user_values: self
                .user
                .values
                .iter()
                .map(|&(value, ty)| (self.canonical(Value(value)), ty))
                .collect(),
            user_slots: self
                .frame
                .slots
                .iter()
                .enumerate()
                .filter_map(|(index, slot)| {
                    let ty = self.user.at(slot.offset)?;
                    let wide = self.types.width(ty) == slot.bytes().checked_mul(8);
                    wide.then_some((index, ty))
                })
                .collect(),
        }
    }

    /// What each kept canonical value is.
    fn shapes(&self) -> Vec<Option<Shape>> {
        (0..self.l1.values.len())
            .map(|index| {
                let v = Value(u32::try_from(index).unwrap_or(u32::MAX));
                if self.canonical(v) != v || self.role(v) == Role::None {
                    return None;
                }
                Some(match self.kind(v) {
                    Kind::None => return None,
                    Kind::Const(bits) => Shape::Const(bits),
                    Kind::Address(offset) => Shape::Address(offset),
                    Kind::Phi => Shape::Phi(self.phi_arguments(v)),
                    Kind::Pure(inst) => Shape::Pure(inst),
                    Kind::Load(inst) => Shape::Load(inst),
                    Kind::Undefined(..)
                    | Kind::Entry(_)
                    | Kind::Result(_)
                    | Kind::CallView { .. } => Shape::Other,
                })
            })
            .collect()
    }

    /// The arguments block parameter `v` gets from its lowered
    /// predecessors.
    fn phi_arguments(&self, v: Value) -> Vec<Value> {
        let Some(&ValueInfo {
            definition: Definition::Parameter { block, index },
            ..
        }) = self.l1.value(v)
        else {
            return Vec::new();
        };
        self.incoming(block, index as usize)
            .into_iter()
            .map(|(_, argument)| argument)
            .collect()
    }

    /// The block parameters and arguments (parameter, argument) where the
    /// argument is zero on every edge it arrives by
    /// ([`Self::zero_on`]): the parameter holds no object of its there.
    fn null_arguments(&self, shapes: &[Option<Shape>]) -> BTreeSet<(Value, Value)> {
        let mut nulls = BTreeSet::new();
        for (index, shape) in shapes.iter().enumerate() {
            let Some(Shape::Phi(_)) = shape else {
                continue;
            };
            let v = Value(u32::try_from(index).unwrap_or(u32::MAX));
            let Some(&ValueInfo {
                definition: Definition::Parameter { block, index },
                ..
            }) = self.l1.value(v)
            else {
                continue;
            };
            let edges = self.incoming_edges(block, index as usize);
            for &(_, _, argument) in &edges {
                let zero = edges
                    .iter()
                    .filter(|&&(_, _, other)| other == argument)
                    .all(|&(pred, edge, _)| self.zero_on(pred, edge, argument));
                if zero {
                    nulls.insert((v, argument));
                }
            }
        }
        nulls
    }

    /// Whether `value` is zero on the edge leaving block `pred` by its
    /// target `edge`: that edge, or the one into a chain of jumps (each
    /// block of it with one lowered predecessor) leading to `pred`, is
    /// the side of a branch on `value == 0` (or `!= 0`) where it is zero.
    /// Values are SSA: what the test saw is what the edge carries.
    fn zero_on(&self, mut pred: BlockId, mut edge: usize, value: Value) -> bool {
        /// Jumps followed back at most.
        const CHAIN: usize = 16;
        let zero = |v: Value| matches!(self.kind(v), Kind::Const(bits) if bits.low_u64() == 0 && bits.width() <= 64);
        for _ in 0..CHAIN {
            let Some(block) = self.l1.block(pred) else {
                return false;
            };
            match &block.terminator {
                &Terminator::Branch { condition, .. } => {
                    let Some(test) = comparison(self.l1, self.constants, condition) else {
                        return false;
                    };
                    let tested = (test.left == value && zero(test.right))
                        || (test.right == value && zero(test.left));
                    return tested
                        && matches!((test.relation, edge), (Relation::Eq, 0) | (Relation::Ne, 1));
                }
                Terminator::Jump(_) => {
                    let preds: Vec<(BlockId, usize)> = self
                        .preds
                        .get(pred.0 as usize)
                        .map_or(&[][..], Vec::as_slice)
                        .iter()
                        .copied()
                        .filter(|&(from, _)| self.reached(from))
                        .collect();
                    let &[(from, at)] = preds.as_slice() else {
                        return false;
                    };
                    (pred, edge) = (from, at);
                }
                Terminator::IndirectJump { .. }
                | Terminator::Return { .. }
                | Terminator::Leave { .. }
                | Terminator::Trap(_)
                | Terminator::Stop
                | Terminator::Invoke { .. }
                | Terminator::Open => return false,
            }
        }
        false
    }

    /// The stores lowered (not atomic; [`Self::store_lowered`]), in blocks
    /// the entry reaches.
    fn lowered_stores(&self) -> Vec<InstId> {
        let mut stores = Vec::new();
        for (_, block) in self.blocks() {
            for &inst in &block.insts {
                let store = matches!(
                    self.l1.inst(inst).map(|i| &i.op),
                    Some(Op::Store { atomic: None, .. })
                );
                if store && self.store_lowered(inst) {
                    stores.push(inst);
                }
            }
        }
        stores
    }

    /// The low parts of kept values: each `extract(v, 0, w)` kept, by
    /// `(v, w)` (`v` canonical).
    fn low_parts(&self) -> BTreeMap<(Value, u16), Vec<Value>> {
        let mut parts: BTreeMap<(Value, u16), Vec<Value>> = BTreeMap::new();
        for index in 0..self.l1.values.len() {
            let v = Value(u32::try_from(index).unwrap_or(u32::MAX));
            if self.canonical(v) != v || self.role(v) == Role::None {
                continue;
            }
            if let Kind::Pure(inst) = self.kind(v)
                && let Some(&Op::Extract {
                    value,
                    offset: 0,
                    width,
                }) = self.l1.inst(inst).map(|i| &i.op)
            {
                parts
                    .entry((self.canonical(value), width))
                    .or_default()
                    .push(v);
            }
        }
        parts
    }

    /// The conditions of branches and selects, in blocks the entry
    /// reaches (lowering reads them back as comparisons, so they are often
    /// not kept themselves).
    fn conditions(&self) -> Vec<Value> {
        let mut conditions = Vec::new();
        for (_, block) in self.blocks() {
            for &inst in &block.insts {
                if let Some(
                    &(Op::Select { condition, .. }
                    | Op::Lanes {
                        lanes: 1,
                        op: LaneOp::Select,
                        operands: [condition, ..],
                    }),
                ) = self.l1.inst(inst).map(|i| &i.op)
                {
                    conditions.push(self.canonical(condition));
                }
            }
            if let Terminator::Branch { condition, .. } = block.terminator {
                conditions.push(self.canonical(condition));
            }
        }
        conditions.sort_unstable();
        conditions.dedup();
        conditions
    }

    /// The values that are `value`'s low `width` bits: itself if that wide,
    /// else what it extends or concatenates above, and the extractions of
    /// them kept (`parts`, [`Self::low_parts`]).
    fn parts(
        &self,
        value: Value,
        width: u16,
        parts: &BTreeMap<(Value, u16), Vec<Value>>,
    ) -> Vec<Value> {
        let value = self.canonical(value);
        if self.width(value) == width {
            return vec![value];
        }
        let mut found = parts.get(&(value, width)).cloned().unwrap_or_default();
        let inner = match self.defining(value).map(|(_, op)| op) {
            Some(&(Op::Extend { value: low, .. } | Op::Concat { low, .. })) => Some(low),
            _ => None,
        };
        if let Some(low) = inner.filter(|&low| self.width(low) == width) {
            found.push(self.canonical(low));
        }
        found
    }

    /// [`Self::parts`], or with none kept, `value` whole (whose low part
    /// the narrower piece is).
    fn parts_or_whole(
        &self,
        value: Value,
        width: u16,
        parts: &BTreeMap<(Value, u16), Vec<Value>>,
    ) -> Vec<Value> {
        let found = self.parts(value, width, parts);
        if found.is_empty() {
            vec![self.canonical(value)]
        } else {
            found
        }
    }

    /// The calls and tail calls, with the values of their arguments and
    /// result (their low parts where the register is wider, else the
    /// register's value whole; and the register's value where its variable
    /// holds the result, [`Kind::CallView`]).
    fn typing_calls(&self, parts: &BTreeMap<(Value, u16), Vec<Value>>) -> Vec<Call> {
        let mut calls = Vec::new();
        for (&site, callee) in &self.callees {
            if callee.foreign {
                continue;
            }
            let target = match site {
                Site::Call(inst) => match self.l1.inst(inst).map(|i| &i.op) {
                    Some(&Op::Call { target, .. }) => target,
                    _ => continue,
                },
                Site::Tail(block) => match self.l1.block(block).map(|b| &b.terminator) {
                    Some(&Terminator::Leave { address, .. }) => address,
                    _ => continue,
                },
            };
            let registers = self.site_registers(site);
            let arguments = callee
                .arguments
                .iter()
                .map(|source| match *source {
                    Source::Register(piece) if piece.offset == 0 => registers
                        .get(usize::from(piece.register.0))
                        .map_or_else(Vec::new, |&v| self.parts_or_whole(v, piece.width, parts)),
                    Source::Register(_) | Source::Stack { .. } => Vec::new(),
                })
                .collect();
            let result = match (site, callee.results.as_slice()) {
                (Site::Call(inst), [piece]) if piece.offset == 0 => self
                    .l1
                    .inst(inst)
                    .and_then(|i| {
                        i.results
                            .iter()
                            .skip(1)
                            .copied()
                            .find(|&r| self.call_register(inst, r) == Some(piece.register))
                    })
                    .map_or_else(Vec::new, |r| {
                        let mut values = self.parts_or_whole(r, piece.width, parts);
                        let r = self.canonical(r);
                        if matches!(self.kind(r), Kind::CallView { offset: 0, width, .. } if width == piece.width)
                            && !values.contains(&r)
                        {
                            values.push(r);
                        }
                        values
                    }),
                _ => Vec::new(),
            };
            calls.push(Call {
                target: self.canonical(target),
                indirect: callee.target.is_none() && callee.import.is_none(),
                tail: matches!(site, Site::Tail(_)),
                signature: callee.signature,
                guessed: !callee.declared && !callee.interfaced,
                variadic: callee.variadic.clone(),
                arguments,
                result,
                callee: callee.target.filter(|_| callee.interfaced),
                sources: callee.arguments.clone(),
                alloc_size: callee.alloc_size,
            });
        }
        calls
    }

    /// The parameters: their entry values or stack slots, declared types.
    fn typing_parameters(&self, parts: &BTreeMap<(Value, u16), Vec<Value>>) -> Vec<Parameter> {
        let slots: BTreeMap<usize, usize> = self
            .needed
            .stack
            .iter()
            .map(|(&slot, &index)| (index, slot))
            .collect();
        let entry = self.l1.blocks.first().map_or(&[][..], |b| &b.parameters);
        self.needed
            .parameters
            .iter()
            .enumerate()
            .map(|(index, parameter)| {
                let values = match parameter.source {
                    Source::Register(piece) if piece.offset == 0 => entry
                        .get(usize::from(piece.register.0))
                        .map_or_else(Vec::new, |&v| self.parts(v, piece.width, parts)),
                    Source::Register(_) | Source::Stack { .. } => Vec::new(),
                };
                Parameter {
                    source: parameter.source,
                    values,
                    slot: slots.get(&index).copied(),
                    ty: parameter.ty,
                    evidence: parameter.evidence,
                }
            })
            .collect()
    }

    /// The values `value` is: itself, or through block parameters and
    /// selects, what they take; not an argument proved null where it
    /// arrives (`nulls`: returned only when zero, it is no object the
    /// function returns).
    fn sources(&self, value: Value, nulls: &BTreeSet<(Value, Value)>) -> Vec<Value> {
        let mut seen = BTreeSet::new();
        let mut stack = vec![self.canonical(value)];
        let mut found = Vec::new();
        while let Some(v) = stack.pop() {
            if !seen.insert(v) {
                continue;
            }
            if matches!(self.kind(v), Kind::Phi) {
                stack.extend(
                    self.phi_arguments(v)
                        .into_iter()
                        .filter(|&argument| !nulls.contains(&(v, argument)))
                        .map(|argument| self.canonical(argument)),
                );
            } else if let Some(&Op::Select {
                then, otherwise, ..
            }) = self.defining(v).map(|(_, op)| op)
            {
                stack.extend([self.canonical(then), self.canonical(otherwise)]);
            } else {
                found.push(v);
            }
        }
        found
    }

    /// The return value: the values returned (where the register is
    /// wider, the low parts of what it takes through block parameters and
    /// selects, and those with none whole); its declared type.
    fn typing_returns(
        &self,
        parts: &BTreeMap<(Value, u16), Vec<Value>>,
        nulls: &BTreeSet<(Value, Value)>,
    ) -> Returns {
        let returns = &self.returns;
        let [piece] = returns.pieces.as_slice() else {
            return Returns::default();
        };
        let mut values = Vec::new();
        let mut registers = Vec::new();
        for (_, block) in self.blocks() {
            let Terminator::Return { state, .. } = &block.terminator else {
                continue;
            };
            if let Some(&value) = state.registers.get(usize::from(piece.register.0))
                && piece.offset == 0
            {
                let value = self.canonical(value);
                let found = self.parts(value, piece.width, parts);
                // The values returned: the register, its parts, and the
                // wider values those are the low part of.
                let wide =
                    found
                        .iter()
                        .filter_map(|&part| match self.defining(part).map(|(_, op)| op) {
                            Some(&Op::Extract {
                                value: whole,
                                offset: 0,
                                ..
                            }) => Some(self.canonical(whole)),
                            _ => None,
                        });
                let roots: Vec<Value> = core::iter::once(value)
                    .chain(found.iter().copied())
                    .chain(wide)
                    .collect();
                if self.width(value) > piece.width {
                    registers.push(value);
                }
                for source in roots.into_iter().flat_map(|root| self.sources(root, nulls)) {
                    let found = self.parts(source, piece.width, parts);
                    if found.is_empty() && self.width(source) > piece.width {
                        registers.push(source);
                    }
                    values.extend(found);
                }
                values.extend(found);
            }
        }
        values.sort_unstable();
        values.dedup();
        registers.sort_unstable();
        registers.dedup();
        let evidence = returns.stated.then_some(if returns.open {
            Evidence::DeclaredPointer
        } else {
            Evidence::Declared
        });
        Returns {
            width: piece.width,
            values,
            registers,
            ty: returns.ty.filter(|_| returns.stated),
            evidence,
        }
    }
}
