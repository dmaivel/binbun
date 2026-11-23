//! Building a [`Semantics`]: expressions are hash-consed, statements go into
//! the innermost open `if` or `loop`, and width mistakes are collected and
//! returned by [`Builder::finish`] instead of panicking (they are bugs in
//! whatever drives the builder, found by tests that lift every form).

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use crate::bits::{Bits, MAX_WIDTH};
use crate::ir::{
    Binary, Expr, ExprId, Flag, FloatOp, FloatOutput, Format, IntrinsicId, LaneOp, Local,
    Semantics, SiteId, SiteUse, Stmt, Trap, Unary, View,
};
use crate::verify::{float_width, lanes_width};

/// A mistake found while building.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildError(pub String);

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An open `if` or `loop`.
#[derive(Debug)]
enum Frame {
    If {
        condition: ExprId,
        then: Vec<Stmt>,
        /// `Some` once `otherwise` has begun.
        otherwise: Option<Vec<Stmt>>,
    },
    Loop(Vec<Stmt>),
    Atomic(Vec<Stmt>),
}

/// Builds one instruction's [`Semantics`].
#[derive(Debug, Default)]
pub struct Builder {
    semantics: Semantics,
    interned: BTreeMap<(Expr, u16), ExprId>,
    frames: Vec<Frame>,
    /// The open blocks (an `if`'s part, a loop, an atomic block), each
    /// numbered differently: see [`scope`](Self::scope).
    scope: Vec<u32>,
    blocks: u32,
    undefined: u32,
    errors: Vec<BuildError>,
}

impl Builder {
    /// An empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    fn error(&mut self, message: String) {
        self.errors.push(BuildError(message));
    }

    /// The open blocks, outermost first, each with a number of its own (an
    /// `if`'s `then` and `else` parts have different numbers): a local
    /// defined while the scope was `a` may be used while it is `b` if `a`
    /// is a prefix of `b`.
    pub fn scope(&self) -> &[u32] {
        &self.scope
    }

    fn open(&mut self) {
        self.blocks += 1;
        self.scope.push(self.blocks);
    }

    fn intern(&mut self, expr: Expr, width: u16) -> ExprId {
        if let Some(&id) = self.interned.get(&(expr, width)) {
            return id;
        }
        let id = ExprId(u32::try_from(self.semantics.exprs.len()).unwrap_or(u32::MAX));
        self.semantics.exprs.push((expr, width));
        self.interned.insert((expr, width), id);
        id
    }

    /// The width of expression `id`.
    pub fn width(&self, id: ExprId) -> u16 {
        self.semantics.width(id)
    }

    fn check_width(&mut self, width: u16, what: &str) -> u16 {
        if width == 0 || width > MAX_WIDTH {
            self.error(format!("{what}: width {width} out of range"));
            return width.clamp(1, MAX_WIDTH);
        }
        width
    }

    fn same(&mut self, what: &str, a: ExprId, b: ExprId) -> u16 {
        let (wa, wb) = (self.width(a), self.width(b));
        if wa != wb {
            self.error(format!("{what}: operand widths {wa} and {wb} differ"));
        }
        wa
    }

    fn statement(&mut self, stmt: Stmt) {
        match self.frames.last_mut() {
            Some(
                Frame::If {
                    otherwise: Some(list),
                    ..
                }
                | Frame::Loop(list)
                | Frame::Atomic(list)
                | Frame::If { then: list, .. },
            ) => list.push(stmt),
            None => self.semantics.body.push(stmt),
        }
    }

    fn local(&mut self, width: u16) -> ExprId {
        let local = Local(u32::try_from(self.semantics.locals.len()).unwrap_or(u32::MAX));
        self.semantics.locals.push(width);
        self.intern(Expr::Local(local), width)
    }

    fn local_of(&self, id: ExprId) -> Local {
        match self.semantics.expr(id) {
            Some((Expr::Local(local), _)) => local,
            _ => Local(u32::MAX),
        }
    }

    /// The constant `value` truncated to `width` bits.
    pub fn constant(&mut self, width: u16, value: u64) -> ExprId {
        let width = self.check_width(width, "constant");
        self.intern(Expr::Const(Bits::from_u64(width, value)), width)
    }

    /// A constant of any width.
    pub fn bits(&mut self, value: Bits) -> ExprId {
        self.intern(Expr::Const(value), value.width())
    }

    /// A new unknown value: what the architecture leaves undefined.
    pub fn undefined(&mut self, width: u16) -> ExprId {
        let width = self.check_width(width, "undefined");
        let serial = self.undefined;
        self.undefined += 1;
        self.intern(Expr::Undefined { width, serial }, width)
    }

    /// Says that `undefined` (made by [`undefined`](Self::undefined)) is
    /// `site`, with the values of its `inputs`.
    pub fn site(&mut self, undefined: ExprId, site: SiteId, inputs: Vec<ExprId>) {
        let Some((Expr::Undefined { serial, .. }, _)) = self.semantics.expr(undefined) else {
            self.error(format!("site of e{}, which is not undefined", undefined.0));
            return;
        };
        let sites = &mut self.semantics.sites;
        match sites.binary_search_by_key(&serial, |use_| use_.serial) {
            Ok(_) => self.error(format!("two sites for undefined value {serial}")),
            Err(at) => sites.insert(
                at,
                SiteUse {
                    serial,
                    site,
                    inputs,
                },
            ),
        }
    }

    /// Reads a register view now; the result is a new local.
    pub fn read(&mut self, view: View) -> ExprId {
        let id = self.local(view.width);
        let local = self.local_of(id);
        self.statement(Stmt::Read { local, view });
        id
    }

    /// Writes `value` to a register view.
    pub fn write(&mut self, view: View, value: ExprId) {
        if self.width(value) != view.width {
            let width = self.width(value);
            self.error(format!(
                "write of a {width}-bit value to a {}-bit view",
                view.width
            ));
        }
        self.statement(Stmt::Write { view, value });
    }

    /// Loads `bytes` bytes from `address` now; the result is a new local.
    pub fn load(&mut self, address: ExprId, bytes: u16) -> ExprId {
        let width = bytes.saturating_mul(8);
        let width = self.check_width(width, "load");
        let id = self.local(width);
        let local = self.local_of(id);
        self.statement(Stmt::Load {
            local,
            address,
            bytes,
        });
        id
    }

    /// The outputs of `intrinsic` on `inputs`, `outputs` bits wide (as the
    /// architecture declares it).
    pub fn intrinsic(
        &mut self,
        intrinsic: IntrinsicId,
        inputs: &[ExprId],
        outputs: &[u16],
    ) -> Vec<ExprId> {
        let ids: Vec<ExprId> = outputs
            .iter()
            .map(|&width| {
                let width = self.check_width(width, "intrinsic");
                self.local(width)
            })
            .collect();
        let locals = ids.iter().map(|&id| self.local_of(id)).collect();
        self.statement(Stmt::Intrinsic {
            intrinsic,
            inputs: inputs.to_vec(),
            outputs: locals,
        });
        ids
    }

    /// Stores `value` (a whole number of bytes) at `address`.
    pub fn store(&mut self, address: ExprId, value: ExprId) {
        let width = self.width(value);
        if !width.is_multiple_of(8) {
            self.error(format!("store of a {width}-bit value"));
        }
        self.statement(Stmt::Store { address, value });
    }

    /// An operation of one operand.
    pub fn unary(&mut self, op: Unary, a: ExprId) -> ExprId {
        let width = self.width(a);
        let result = match op {
            Unary::EvenParity8 => 1,
            Unary::ByteSwap => {
                if !width.is_multiple_of(8) {
                    self.error(format!("byte swap of a {width}-bit value"));
                }
                width
            }
            Unary::Not
            | Unary::Neg
            | Unary::Popcount
            | Unary::LeadingZeros
            | Unary::TrailingZeros => width,
        };
        self.intern(Expr::Unary(op, a), result)
    }

    /// An operation of two operands of the same width.
    pub fn binary(&mut self, op: Binary, a: ExprId, b: ExprId) -> ExprId {
        let width = self.same("binary operation", a, b);
        let result = match op {
            Binary::Eq | Binary::Ne | Binary::ULt | Binary::ULe | Binary::SLt | Binary::SLe => 1,
            Binary::Mul | Binary::UDiv | Binary::URem | Binary::SDiv | Binary::SRem => {
                if width > 128 {
                    self.error(format!("{op:?} of {width}-bit values (at most 128)"));
                }
                width
            }
            Binary::Add
            | Binary::Sub
            | Binary::And
            | Binary::Or
            | Binary::Xor
            | Binary::Shl
            | Binary::LShr
            | Binary::AShr
            | Binary::Rol
            | Binary::Ror => width,
        };
        self.intern(Expr::Binary(op, a, b), result)
    }

    /// A flag computation over three operands of the same width.
    pub fn flag(&mut self, op: Flag, a: ExprId, b: ExprId, c: ExprId) -> ExprId {
        self.same("flag computation", a, b);
        self.same("flag computation", a, c);
        self.intern(Expr::Flag(op, a, b, c), 1)
    }

    /// `width` bits of `value` from bit `offset`.
    pub fn extract(&mut self, value: ExprId, offset: u16, width: u16) -> ExprId {
        let source = self.width(value);
        if width == 0 || u32::from(offset) + u32::from(width) > u32::from(source) {
            self.error(format!(
                "extract of bits {offset}..{} from a {source}-bit value",
                u32::from(offset) + u32::from(width)
            ));
        }
        if offset == 0 && width == source {
            return value;
        }
        self.intern(
            Expr::Extract {
                value,
                offset,
                width,
            },
            width,
        )
    }

    /// `high` above `low`.
    pub fn concat(&mut self, high: ExprId, low: ExprId) -> ExprId {
        let width = u32::from(self.width(high)) + u32::from(self.width(low));
        let width = u16::try_from(width).unwrap_or(u16::MAX);
        let width = self.check_width(width, "concatenation");
        self.intern(Expr::Concat { high, low }, width)
    }

    fn extend(&mut self, signed: bool, value: ExprId, width: u16) -> ExprId {
        let source = self.width(value);
        if width < source {
            self.error(format!("extension of a {source}-bit value to {width} bits"));
        }
        if width == source {
            return value;
        }
        let width = self.check_width(width, "extension");
        self.intern(
            Expr::Extend {
                signed,
                value,
                width,
            },
            width,
        )
    }

    /// `value` zero-extended to `width` bits.
    pub fn zext(&mut self, value: ExprId, width: u16) -> ExprId {
        self.extend(false, value, width)
    }

    /// `value` sign-extended to `width` bits.
    pub fn sext(&mut self, value: ExprId, width: u16) -> ExprId {
        self.extend(true, value, width)
    }

    /// `then` if the 1-bit `condition` is 1, else `otherwise`.
    pub fn select(&mut self, condition: ExprId, then: ExprId, otherwise: ExprId) -> ExprId {
        if self.width(condition) != 1 {
            let width = self.width(condition);
            self.error(format!("{width}-bit select condition"));
        }
        let width = self.same("select", then, otherwise);
        self.intern(
            Expr::Select {
                condition,
                then,
                otherwise,
            },
            width,
        )
    }

    /// The operands of an operation taking `arity`: the unused ones repeat
    /// the first (so equal operations stay equal).
    fn operands(&mut self, what: &str, arity: usize, given: &[ExprId]) -> [ExprId; 3] {
        if given.len() != arity {
            self.error(format!(
                "{what} takes {arity} operands, not {}",
                given.len()
            ));
        }
        let first = given.first().copied().unwrap_or(ExprId(0));
        let mut operands = [first; 3];
        for (slot, &operand) in operands.iter_mut().zip(given.iter().take(arity)) {
            *slot = operand;
        }
        operands
    }

    /// `op` lane by lane on `lanes` lanes of `operands` (as many as `op`
    /// takes).
    pub fn lanes(&mut self, op: LaneOp, lanes: u16, operands: &[ExprId]) -> ExprId {
        let operands = self.operands("lane operation", op.arity(), operands);
        let widths: Vec<u16> = operands
            .iter()
            .take(op.arity())
            .map(|&a| self.width(a))
            .collect();
        let width = lanes_width(op, lanes, &widths).unwrap_or_else(|e| {
            self.error(e);
            1
        });
        self.intern(
            Expr::Lanes {
                lanes,
                op,
                operands,
            },
            width,
        )
    }

    /// The result of the IEEE operation `op` on `lanes` lanes of `format`
    /// (`operands` as many as `op` takes), rounded as the 2-bit `rounding`
    /// says.
    pub fn float(
        &mut self,
        op: FloatOp,
        format: Format,
        lanes: u16,
        rounding: ExprId,
        operands: &[ExprId],
    ) -> ExprId {
        self.float_expr(FloatOutput::Value, op, format, lanes, rounding, operands)
    }

    /// The exceptions the same operation raises, five bits per lane
    /// ([`Exception`](crate::ir::Exception)).
    pub fn float_status(
        &mut self,
        op: FloatOp,
        format: Format,
        lanes: u16,
        rounding: ExprId,
        operands: &[ExprId],
    ) -> ExprId {
        self.float_expr(FloatOutput::Status, op, format, lanes, rounding, operands)
    }

    fn float_expr(
        &mut self,
        output: FloatOutput,
        op: FloatOp,
        format: Format,
        lanes: u16,
        rounding: ExprId,
        operands: &[ExprId],
    ) -> ExprId {
        let operands = self.operands("floating-point operation", op.arity(), operands);
        let widths: Vec<u16> = operands
            .iter()
            .take(op.arity())
            .map(|&a| self.width(a))
            .collect();
        let rounding_width = self.width(rounding);
        let width =
            float_width(op, format, lanes, output, rounding_width, &widths).unwrap_or_else(|e| {
                self.error(e);
                1
            });
        self.intern(
            Expr::Float {
                op,
                format,
                lanes,
                output,
                rounding,
                operands,
            },
            width,
        )
    }

    /// Opens an `if` on the 1-bit `condition`; statements go to its `then`
    /// part until [`otherwise`](Self::otherwise) or [`end_if`](Self::end_if).
    pub fn begin_if(&mut self, condition: ExprId) {
        if self.width(condition) != 1 {
            let width = self.width(condition);
            self.error(format!("{width}-bit if condition"));
        }
        self.frames.push(Frame::If {
            condition,
            then: Vec::new(),
            otherwise: None,
        });
        self.open();
    }

    /// Switches the innermost `if` to its `else` part.
    pub fn otherwise(&mut self) {
        match self.frames.last_mut() {
            Some(Frame::If { otherwise, .. }) if otherwise.is_none() => {
                *otherwise = Some(Vec::new());
                self.scope.pop();
                self.open();
            }
            Some(Frame::If { .. } | Frame::Loop(_) | Frame::Atomic(_)) | None => {
                self.error("else outside an if, or twice".into());
            }
        }
    }

    /// Closes the innermost `if`.
    pub fn end_if(&mut self) {
        match self.frames.pop() {
            Some(Frame::If {
                condition,
                then,
                otherwise,
            }) => self.statement(Stmt::If {
                condition,
                then,
                otherwise: otherwise.unwrap_or_default(),
            }),
            Some(frame @ (Frame::Loop(_) | Frame::Atomic(_))) => {
                self.frames.push(frame);
                self.error("end of if inside a loop or atomic block that is still open".into());
                return;
            }
            None => {
                self.error("end of if without an if".into());
                return;
            }
        }
        self.scope.pop();
    }

    /// Opens a loop; it repeats until a [`brk`](Self::brk) runs.
    pub fn begin_loop(&mut self) {
        self.frames.push(Frame::Loop(Vec::new()));
        self.open();
    }

    /// Closes the innermost loop.
    pub fn end_loop(&mut self) {
        match self.frames.pop() {
            Some(Frame::Loop(body)) => self.statement(Stmt::Loop(body)),
            Some(frame @ (Frame::If { .. } | Frame::Atomic(_))) => {
                self.frames.push(frame);
                self.error("end of loop inside an if or atomic block that is still open".into());
                return;
            }
            None => {
                self.error("end of loop without a loop".into());
                return;
            }
        }
        self.scope.pop();
    }

    /// Opens an atomic block: its statements access memory indivisibly.
    pub fn begin_atomic(&mut self) {
        self.frames.push(Frame::Atomic(Vec::new()));
        self.open();
    }

    /// Closes the innermost atomic block.
    pub fn end_atomic(&mut self) {
        match self.frames.pop() {
            Some(Frame::Atomic(body)) => self.statement(Stmt::Atomic(body)),
            Some(frame @ (Frame::If { .. } | Frame::Loop(_))) => {
                self.frames.push(frame);
                self.error("end of atomic block inside an if or loop that is still open".into());
                return;
            }
            None => {
                self.error("end of atomic block without one".into());
                return;
            }
        }
        self.scope.pop();
    }

    /// Enters the operating system.
    pub fn system_call(&mut self) {
        self.statement(Stmt::SystemCall);
    }

    /// Leaves the innermost loop.
    pub fn brk(&mut self) {
        if !self
            .frames
            .iter()
            .any(|frame| matches!(frame, Frame::Loop(_)))
        {
            self.error("break outside a loop".into());
        }
        self.statement(Stmt::Break);
    }

    /// Stops the instruction with a trap.
    pub fn trap(&mut self, trap: Trap) {
        self.statement(Stmt::Trap(trap));
    }

    /// Continues at `target`.
    pub fn jump(&mut self, target: ExprId) {
        self.statement(Stmt::Jump { target });
    }

    /// A call to `target` returning to `return_address`.
    pub fn call(&mut self, target: ExprId, return_address: ExprId) {
        self.statement(Stmt::Call {
            target,
            return_address,
        });
    }

    /// A return to `target`.
    pub fn ret(&mut self, target: ExprId) {
        self.statement(Stmt::Return { target });
    }

    /// The finished semantics, or every mistake found.
    ///
    /// # Errors
    ///
    /// If a width did not fit, or an `if` or `loop` is still open.
    pub fn finish(mut self) -> Result<Semantics, Vec<BuildError>> {
        if !self.frames.is_empty() {
            self.error(format!("{} if or loop left open", self.frames.len()));
        }
        self.order();
        if self.errors.is_empty() {
            Ok(self.semantics)
        } else {
            Err(self.errors)
        }
    }

    /// Renumbers the expressions, if needed, so that each undefined value
    /// comes after its site inputs (which a lifter may learn after it made
    /// the value: what the instruction defines), keeping their order
    /// otherwise.
    fn order(&mut self) {
        let s = &self.semantics;
        let position = |serial: u32| {
            s.exprs.iter().position(
                |&(expr, _)| matches!(expr, Expr::Undefined { serial: own, .. } if own == serial),
            )
        };
        let ordered = s.sites.iter().all(|site| {
            position(site.serial)
                .is_some_and(|index| site.inputs.iter().all(|input| (input.0 as usize) < index))
        });
        if ordered {
            return;
        }
        let dependencies = |id: ExprId| -> Vec<ExprId> {
            match s.expr(id) {
                Some((Expr::Undefined { serial, .. }, _)) => s
                    .site(serial)
                    .map(|site| site.inputs.clone())
                    .unwrap_or_default(),
                Some((expr, _)) => expr.operands(),
                None => Vec::new(),
            }
        };
        // Depth first, operands before users; 1 while visiting, 2 when done.
        let count = s.exprs.len();
        let mut state = vec![0u8; count];
        let mut order: Vec<usize> = Vec::with_capacity(count);
        let mut cycle = false;
        for root in 0..count {
            let mut stack = vec![(root, false)];
            while let Some((index, expanded)) = stack.pop() {
                let Some(slot) = state.get_mut(index) else {
                    continue;
                };
                if expanded {
                    *slot = 2;
                    order.push(index);
                    continue;
                }
                if *slot != 0 {
                    continue;
                }
                *slot = 1;
                stack.push((index, true));
                let id = ExprId(u32::try_from(index).unwrap_or(u32::MAX));
                for dependency in dependencies(id).into_iter().rev() {
                    match state.get(dependency.0 as usize) {
                        Some(0) => stack.push((dependency.0 as usize, false)),
                        Some(1) => cycle = true,
                        _ => {}
                    }
                }
            }
        }
        if cycle {
            self.error("a site input depends on its undefined value".into());
            return;
        }
        let mut renumbered = vec![ExprId(0); count];
        for (new, &old) in (0u32..).zip(&order) {
            if let Some(slot) = renumbered.get_mut(old) {
                *slot = ExprId(new);
            }
        }
        let mut map = |id: ExprId| renumbered.get(id.0 as usize).copied().unwrap_or(id);
        let exprs = order
            .iter()
            .filter_map(|&old| self.semantics.exprs.get(old).copied())
            .map(|(expr, width)| (expr.map_operands(&mut map), width))
            .collect();
        self.semantics.exprs = exprs;
        for stmt in &mut self.semantics.body {
            stmt.map_exprs(&mut map);
        }
        for site in &mut self.semantics.sites {
            for input in &mut site.inputs {
                *input = map(*input);
            }
        }
        self.interned.clear();
    }
}
