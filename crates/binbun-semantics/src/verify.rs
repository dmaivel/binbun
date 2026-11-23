//! Checking a [`Semantics`] against L0's rules: every expression's width
//! follows from its operands, operands come before their users, locals are
//! defined once and before use (in scope), views lie within their register,
//! conditions are 1 bit, and `break` is inside a loop. An undefined value's
//! site inputs count as its operands: they come before it, and their locals
//! are defined wherever it is used.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use crate::bits::MAX_WIDTH;
use crate::ir::{
    Binary, Declarations, EXCEPTIONS, Expr, ExprId, FloatOp, FloatOutput, Format, IntrinsicId,
    LaneOp, Local, Semantics, Stmt, Unary, View,
};

/// A broken rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyError(pub String);

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Checks `semantics` against the registers and intrinsics of
/// `declarations`.
///
/// # Errors
///
/// The first broken rule found.
pub fn verify(semantics: &Semantics, declarations: &Declarations) -> Result<(), VerifyError> {
    for (index, &(expr, width)) in semantics.exprs.iter().enumerate() {
        let id = ExprId(u32::try_from(index).unwrap_or(u32::MAX));
        expression(semantics, id, expr, width)
            .map_err(|e| VerifyError(format!("e{index}: {e}")))?;
    }
    sites(semantics, declarations)?;
    let mut checker = Checker {
        semantics,
        declarations,
        defined: vec![false; semantics.locals.len()],
        scope: Vec::new(),
        loops: 0,
    };
    checker.block(&semantics.body)
}

/// Checks the site uses: in serial order, each of an undefined value, of a
/// declared site, with as many inputs as it declares, each before the
/// undefined value.
fn sites(semantics: &Semantics, declarations: &Declarations) -> Result<(), VerifyError> {
    let mut undefined = BTreeMap::new();
    for (index, &(expr, _)) in semantics.exprs.iter().enumerate() {
        if let Expr::Undefined { serial, .. } = expr {
            undefined.insert(serial, index);
        }
    }
    let mut previous = None;
    for site in &semantics.sites {
        let serial = site.serial;
        if previous.is_some_and(|previous| previous >= serial) {
            return Err(VerifyError(format!(
                "site of undefined {serial} out of order"
            )));
        }
        previous = Some(serial);
        let Some(&index) = undefined.get(&serial) else {
            return Err(VerifyError(format!(
                "site of undefined {serial}, which is not used"
            )));
        };
        let Some(info) = declarations.site(site.site) else {
            return Err(VerifyError(format!("e{index}: no site {}", site.site.0)));
        };
        if info.inputs.len() != site.inputs.len() {
            return Err(VerifyError(format!(
                "e{index}: site {} has {} inputs, not {}",
                info.name,
                info.inputs.len(),
                site.inputs.len()
            )));
        }
        for (input, name) in site.inputs.iter().zip(info.inputs) {
            if input.0 as usize >= index {
                return Err(VerifyError(format!(
                    "e{index}: input {name} (e{}) of site {} is not defined before it",
                    input.0, info.name
                )));
            }
        }
    }
    Ok(())
}

fn expression(semantics: &Semantics, id: ExprId, expr: Expr, width: u16) -> Result<(), String> {
    let operand = |operand: ExprId| -> Result<u16, String> {
        if operand.0 >= id.0 {
            return Err(format!(
                "operand e{} is not defined before its user",
                operand.0
            ));
        }
        Ok(semantics.width(operand))
    };
    if width == 0 || width > MAX_WIDTH {
        return Err(format!("width {width} out of range"));
    }
    let expected = match expr {
        Expr::Const(bits) => bits.width(),
        Expr::Local(local) => *semantics
            .locals
            .get(local.0 as usize)
            .ok_or_else(|| format!("no local l{}", local.0))?,
        Expr::Undefined { width: own, .. } => own,
        Expr::Unary(op, a) => unary_width(op, operand(a)?)?,
        Expr::Binary(op, a, b) => binary_width(op, operand(a)?, operand(b)?)?,
        Expr::Flag(op, a, b, c) => {
            let (a, b, c) = (operand(a)?, operand(b)?, operand(c)?);
            if a != b || a != c {
                return Err(format!("{op:?} of {a}-, {b}- and {c}-bit operands"));
            }
            1
        }
        Expr::Extract {
            value,
            offset,
            width: own,
        } => {
            let source = operand(value)?;
            if u32::from(offset) + u32::from(own) > u32::from(source) {
                return Err(format!("extract past the end of a {source}-bit value"));
            }
            own
        }
        Expr::Concat { high, low } => {
            let sum = u32::from(operand(high)?) + u32::from(operand(low)?);
            u16::try_from(sum).map_err(|_| String::from("concatenation too wide"))?
        }
        Expr::Extend {
            value, width: own, ..
        } => {
            let source = operand(value)?;
            if own <= source {
                return Err(format!("extension of {source} bits to {own}"));
            }
            own
        }
        Expr::Select {
            condition,
            then,
            otherwise,
        } => {
            if operand(condition)? != 1 {
                return Err("select condition is not 1 bit".into());
            }
            let (then, otherwise) = (operand(then)?, operand(otherwise)?);
            if then != otherwise {
                return Err(format!("select of {then}- and {otherwise}-bit values"));
            }
            then
        }
        Expr::Lanes {
            lanes,
            op,
            operands,
        } => {
            let widths = operands
                .iter()
                .take(op.arity())
                .map(|&a| operand(a))
                .collect::<Result<Vec<u16>, String>>()?;
            lanes_width(op, lanes, &widths)?
        }
        Expr::Float {
            op,
            format,
            lanes,
            output,
            rounding,
            operands,
        } => {
            let rounding = operand(rounding)?;
            let widths = operands
                .iter()
                .take(op.arity())
                .map(|&a| operand(a))
                .collect::<Result<Vec<u16>, String>>()?;
            float_width(op, format, lanes, output, rounding, &widths)?
        }
    };
    if expected == width {
        Ok(())
    } else {
        Err(format!("width {width}, but its operation gives {expected}"))
    }
}

/// The width of `op` applied to an `a`-bit operand.
///
/// # Errors
///
/// The rule the width breaks.
pub fn unary_width(op: Unary, a: u16) -> Result<u16, String> {
    match op {
        Unary::EvenParity8 => Ok(1),
        Unary::ByteSwap if !a.is_multiple_of(8) => Err(format!("byte swap of {a} bits")),
        Unary::ByteSwap
        | Unary::Not
        | Unary::Neg
        | Unary::Popcount
        | Unary::LeadingZeros
        | Unary::TrailingZeros => Ok(a),
    }
}

/// The width of each of `widths`' `lanes` lanes.
fn lane_widths(lanes: u16, widths: &[u16]) -> Result<Vec<u16>, String> {
    if lanes == 0 {
        return Err("no lanes".into());
    }
    widths
        .iter()
        .map(|&width| {
            if width.is_multiple_of(lanes) {
                Ok(width / lanes)
            } else {
                Err(format!("{width} bits do not split into {lanes} lanes"))
            }
        })
        .collect()
}

/// `lanes` lanes of `lane` bits, if they fit in a value.
fn total(lanes: u16, lane: u16) -> Result<u16, String> {
    lanes
        .checked_mul(lane)
        .filter(|&width| width <= MAX_WIDTH)
        .ok_or_else(|| format!("{lanes} lanes of {lane} bits are too wide"))
}

/// The width of [`Expr::Lanes`] with `op` on `lanes` lanes of operands
/// `widths` bits wide (one per operand the operation takes).
///
/// # Errors
///
/// The rule the widths break.
pub fn lanes_width(op: LaneOp, lanes: u16, widths: &[u16]) -> Result<u16, String> {
    let lane = lane_widths(lanes, widths)?;
    let first = lane.first().copied().unwrap_or(0);
    let result = match (op, lane.as_slice()) {
        (LaneOp::Unary(op), &[a]) => unary_width(op, a)?,
        (LaneOp::Binary(op), &[a, b]) => binary_width(op, a, b)?,
        (LaneOp::Extract { offset, width }, &[a]) => {
            if width == 0 || u32::from(offset) + u32::from(width) > u32::from(a) {
                return Err(format!("lanes: extract past the end of {a}-bit lanes"));
            }
            width
        }
        (LaneOp::Extend { width, .. }, &[a]) => {
            if width <= a {
                return Err(format!("lanes: extension of {a} bits to {width}"));
            }
            width
        }
        (LaneOp::Select, &[condition, then, otherwise]) => {
            if condition != 1 || then != otherwise {
                return Err(format!(
                    "lanes: select of {then}- and {otherwise}-bit lanes on {condition} bits"
                ));
            }
            then
        }
        (op, _) => {
            return Err(format!(
                "{op:?} takes {} operands, not {}",
                op.arity(),
                lane.len()
            ));
        }
    };
    if result == 0 || first == 0 {
        return Err("empty lanes".into());
    }
    total(lanes, result)
}

/// The width of [`Expr::Float`] with `op` on `lanes` lanes of `format`,
/// a `rounding`-bit rounding and operands `widths` bits wide.
///
/// # Errors
///
/// The rule the widths break.
pub fn float_width(
    op: FloatOp,
    format: Format,
    lanes: u16,
    output: FloatOutput,
    rounding: u16,
    widths: &[u16],
) -> Result<u16, String> {
    if rounding != 2 {
        return Err(format!("{rounding}-bit rounding"));
    }
    if widths.len() != op.arity() {
        return Err(format!(
            "{op:?} takes {} operands, not {}",
            op.arity(),
            widths.len()
        ));
    }
    let lane = lane_widths(lanes, widths)?;
    let own = format.width();
    let integer = |width: u16| (1..=128).contains(&width);
    let result = match op {
        FloatOp::FromInt { .. } => {
            if !lane.iter().all(|&w| integer(w)) {
                return Err(format!("{op:?} of {lane:?}-bit integers"));
            }
            own
        }
        FloatOp::Add
        | FloatOp::Sub
        | FloatOp::Mul
        | FloatOp::Div
        | FloatOp::Sqrt
        | FloatOp::MulAdd
        | FloatOp::RoundToIntegral
        | FloatOp::Compare { .. }
        | FloatOp::Convert(_)
        | FloatOp::ToInt { .. } => {
            if lane.iter().any(|&w| w != own) {
                return Err(format!("{op:?} of {lane:?}-bit lanes as {format:?}"));
            }
            match op {
                FloatOp::Compare { .. } => 4,
                FloatOp::Convert(target) if target == format => {
                    return Err(format!("conversion of {format:?} to itself"));
                }
                FloatOp::Convert(target) => target.width(),
                FloatOp::ToInt { width, .. } if !integer(width) => {
                    return Err(format!("conversion to a {width}-bit integer"));
                }
                FloatOp::ToInt { width, .. } => width,
                FloatOp::Add
                | FloatOp::Sub
                | FloatOp::Mul
                | FloatOp::Div
                | FloatOp::Sqrt
                | FloatOp::MulAdd
                | FloatOp::RoundToIntegral
                | FloatOp::FromInt { .. } => own,
            }
        }
    };
    match output {
        FloatOutput::Value => total(lanes, result),
        FloatOutput::Status => total(lanes, EXCEPTIONS),
    }
}

/// The width of `op` applied to `a`- and `b`-bit operands.
///
/// # Errors
///
/// The rule the widths break.
pub fn binary_width(op: Binary, a: u16, b: u16) -> Result<u16, String> {
    if a != b {
        return Err(format!("{op:?} of {a}- and {b}-bit operands"));
    }
    match op {
        Binary::Eq | Binary::Ne | Binary::ULt | Binary::ULe | Binary::SLt | Binary::SLe => Ok(1),
        Binary::Mul | Binary::UDiv | Binary::URem | Binary::SDiv | Binary::SRem if a > 128 => {
            Err(format!("{op:?} of {a}-bit operands (at most 128)"))
        }
        Binary::Mul
        | Binary::UDiv
        | Binary::URem
        | Binary::SDiv
        | Binary::SRem
        | Binary::Add
        | Binary::Sub
        | Binary::And
        | Binary::Or
        | Binary::Xor
        | Binary::Shl
        | Binary::LShr
        | Binary::AShr
        | Binary::Rol
        | Binary::Ror => Ok(a),
    }
}

struct Checker<'a> {
    semantics: &'a Semantics,
    declarations: &'a Declarations,
    /// Whether each local is defined in the current scope.
    defined: Vec<bool>,
    /// Locals defined in each open block, to forget when it closes.
    scope: Vec<Vec<Local>>,
    loops: u32,
}

impl Checker<'_> {
    fn block(&mut self, statements: &[Stmt]) -> Result<(), VerifyError> {
        self.scope.push(Vec::new());
        let result = statements.iter().try_for_each(|stmt| self.statement(stmt));
        for local in self.scope.pop().unwrap_or_default() {
            if let Some(slot) = self.defined.get_mut(local.0 as usize) {
                *slot = false;
            }
        }
        result
    }

    fn define(&mut self, local: Local, width: u16) -> Result<(), VerifyError> {
        let Some(&own) = self.semantics.locals.get(local.0 as usize) else {
            return Err(VerifyError(format!("no local l{}", local.0)));
        };
        if own != width {
            return Err(VerifyError(format!(
                "l{} is {own} bits but defined by a {width}-bit access",
                local.0
            )));
        }
        let slot = self.defined.get_mut(local.0 as usize);
        match slot {
            Some(slot) if !*slot => *slot = true,
            Some(_) | None => {
                return Err(VerifyError(format!("l{} defined twice", local.0)));
            }
        }
        if let Some(scope) = self.scope.last_mut() {
            scope.push(local);
        }
        Ok(())
    }

    /// Checks that `id` uses only locals defined in scope; returns its width.
    fn uses(&self, id: ExprId) -> Result<u16, VerifyError> {
        let mut stack = vec![id];
        let mut seen = vec![false; self.semantics.exprs.len()];
        while let Some(id) = stack.pop() {
            let Some((expr, _)) = self.semantics.expr(id) else {
                return Err(VerifyError(format!("no expression e{}", id.0)));
            };
            match seen.get_mut(id.0 as usize) {
                Some(true) => continue,
                Some(slot) => *slot = true,
                None => {}
            }
            match expr {
                Expr::Local(local) => {
                    if !self.defined.get(local.0 as usize).copied().unwrap_or(false) {
                        return Err(VerifyError(format!(
                            "l{} used where it is not defined",
                            local.0
                        )));
                    }
                }
                Expr::Undefined { serial, .. } => {
                    if let Some(site) = self.semantics.site(serial) {
                        stack.extend(site.inputs.iter().copied());
                    }
                }
                Expr::Const(_) => {}
                Expr::Unary(_, a)
                | Expr::Extract { value: a, .. }
                | Expr::Extend { value: a, .. } => stack.push(a),
                Expr::Binary(_, a, b) | Expr::Concat { high: a, low: b } => {
                    stack.extend([a, b]);
                }
                Expr::Flag(_, a, b, c)
                | Expr::Select {
                    condition: a,
                    then: b,
                    otherwise: c,
                }
                | Expr::Lanes {
                    operands: [a, b, c],
                    ..
                } => stack.extend([a, b, c]),
                Expr::Float {
                    rounding,
                    operands: [a, b, c],
                    ..
                } => stack.extend([rounding, a, b, c]),
            }
        }
        Ok(self.semantics.width(id))
    }

    fn view(&self, view: View) -> Result<(), VerifyError> {
        let info = self
            .declarations
            .info(view.register)
            .ok_or_else(|| VerifyError(format!("no register {}", view.register.0)))?;
        if view.width == 0 || u32::from(view.offset) + u32::from(view.width) > u32::from(info.width)
        {
            return Err(VerifyError(format!(
                "view {}..{} of {}-bit {}",
                view.offset,
                u32::from(view.offset) + u32::from(view.width),
                info.width,
                info.name
            )));
        }
        Ok(())
    }

    fn condition(&self, id: ExprId) -> Result<(), VerifyError> {
        if self.uses(id)? == 1 {
            Ok(())
        } else {
            Err(VerifyError(format!("condition e{} is not 1 bit", id.0)))
        }
    }

    fn statement(&mut self, stmt: &Stmt) -> Result<(), VerifyError> {
        match stmt {
            Stmt::Read { local, view } => {
                self.view(*view)?;
                self.define(*local, view.width)?;
            }
            Stmt::Write { view, value } => {
                self.view(*view)?;
                let width = self.uses(*value)?;
                if width != view.width {
                    return Err(VerifyError(format!(
                        "write of {width} bits to a {}-bit view",
                        view.width
                    )));
                }
            }
            Stmt::Load {
                local,
                address,
                bytes,
            } => {
                self.uses(*address)?;
                if *bytes == 0 {
                    return Err(VerifyError("load of 0 bytes".into()));
                }
                self.define(*local, bytes.saturating_mul(8))?;
            }
            Stmt::Store { address, value } => {
                self.uses(*address)?;
                let width = self.uses(*value)?;
                if width % 8 != 0 {
                    return Err(VerifyError(format!("store of {width} bits")));
                }
            }
            Stmt::If {
                condition,
                then,
                otherwise,
            } => {
                self.condition(*condition)?;
                self.block(then)?;
                self.block(otherwise)?;
            }
            Stmt::Loop(body) => {
                self.loops += 1;
                let result = self.block(body);
                self.loops -= 1;
                result?;
            }
            Stmt::Atomic(body) => self.block(body)?,
            Stmt::Intrinsic {
                intrinsic,
                inputs,
                outputs,
            } => self.intrinsic(*intrinsic, inputs, outputs)?,
            Stmt::Break => {
                if self.loops == 0 {
                    return Err(VerifyError("break outside a loop".into()));
                }
            }
            Stmt::Trap(_) | Stmt::SystemCall => {}
            Stmt::Jump { target } | Stmt::Return { target } => {
                self.uses(*target)?;
            }
            Stmt::Call {
                target,
                return_address,
            } => {
                self.uses(*target)?;
                self.uses(*return_address)?;
            }
        }
        Ok(())
    }

    /// An intrinsic statement: its inputs and outputs as many and as wide
    /// as its declaration says, or, for an opaque one, its own.
    fn intrinsic(
        &mut self,
        intrinsic: IntrinsicId,
        inputs: &[ExprId],
        outputs: &[Local],
    ) -> Result<(), VerifyError> {
        let info = self
            .declarations
            .intrinsic(intrinsic)
            .ok_or_else(|| VerifyError(format!("no intrinsic {}", intrinsic.0)))?;
        if info.opaque {
            // Its own inputs and outputs: each a value's width.
            for &input in inputs {
                self.uses(input)?;
            }
            for &output in outputs {
                let width = self
                    .semantics
                    .locals
                    .get(output.0 as usize)
                    .copied()
                    .unwrap_or(0);
                self.define(output, width)?;
            }
            return Ok(());
        }
        if inputs.len() != info.inputs.len() || outputs.len() != info.outputs.len() {
            return Err(VerifyError(format!(
                "`{}` takes {} inputs and gives {} outputs",
                info.name,
                info.inputs.len(),
                info.outputs.len()
            )));
        }
        for (&input, &width) in inputs.iter().zip(info.inputs) {
            if self.uses(input)? != width {
                return Err(VerifyError(format!(
                    "`{}` takes a {width}-bit input, not e{}",
                    info.name, input.0
                )));
            }
        }
        for (&output, &width) in outputs.iter().zip(info.outputs) {
            self.define(output, width)?;
        }
        Ok(())
    }
}
