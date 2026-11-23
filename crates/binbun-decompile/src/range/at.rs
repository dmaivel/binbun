//! What the code before a statement says of a value where the statement
//! runs ([`Values`]): the comparisons the range facts find walking back
//! from it ([`before`]: an `if` whose one branch leaves, the branch or the
//! loop body it is in), and a variable's last write before it if that is
//! a constant. A front end reads it for the values a call passes.

use alloc::vec;
use alloc::vec::Vec;

use binbun_ast::ir::{Expr, ExprId, Function, StmtId};

use super::facts::{Fact, Known, Rel, Term, WIDEST, term, value};
use super::{Index, Interval, before};

/// The values an expression may have at a point, read signed and
/// unsigned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Bounds {
    /// Its width in bits.
    pub width: u16,
    /// Its values read signed.
    pub signed: Interval,
    /// Its values read unsigned.
    pub unsigned: Interval,
}

impl Bounds {
    /// Every value of `width` bits.
    pub fn full(width: u16) -> Self {
        Self {
            width,
            signed: Interval::full(true, width),
            unsigned: Interval::full(false, width),
        }
    }

    /// The one value, if there is one (read unsigned).
    pub fn constant(&self) -> Option<i128> {
        (self.unsigned.lo == self.unsigned.hi).then_some(self.unsigned.lo)
    }

    /// Whether anything is known: a reading narrower than every value.
    pub fn known(&self) -> bool {
        *self != Self::full(self.width)
    }
}

/// The range facts of one function, asked at its statements.
#[derive(Debug)]
pub struct Values<'f> {
    function: &'f Function,
    index: Index,
    /// The first statement evaluating each expression (in the body's
    /// order), if one does.
    owners: Vec<Option<StmtId>>,
}

impl<'f> Values<'f> {
    /// The facts of `function`.
    pub fn new(function: &'f Function) -> Self {
        let mut owners = vec![None; function.exprs.len()];
        let mut blocks = vec![&function.body];
        while let Some(block) = blocks.pop() {
            for &id in block {
                let Some(stmt) = function.stmt(id) else {
                    continue;
                };
                let mut work = stmt.roots();
                while let Some(at) = work.pop() {
                    let Some(owner) = owners.get_mut(at.0 as usize) else {
                        continue;
                    };
                    if owner.is_none() {
                        *owner = Some(id);
                        if let Some(expr) = function.expr(at) {
                            work.extend(expr.operands(function));
                        }
                    }
                }
                blocks.extend(stmt.blocks());
            }
        }
        Self {
            function,
            index: Index::new(function),
            owners,
        }
    }

    /// The statement evaluating expression `id` (the first, if several
    /// do).
    pub fn statement(&self, id: ExprId) -> Option<StmtId> {
        self.owners.get(id.0 as usize).copied().flatten()
    }

    /// The values `expr` may have where statement `stmt` runs: a
    /// constant's own; a variable's (not in memory) from the facts
    /// holding there and its last write before it if that writes a
    /// constant; through a zero or sign extension, its operand's; through
    /// a cast (the same bits read as another type), its operand's. `None`
    /// for anything else or wider than 64 bits.
    pub fn at(&self, stmt: StmtId, expr: ExprId) -> Option<Bounds> {
        let width = self.function.width(expr)?;
        if width == 0 || width > WIDEST {
            return None;
        }
        if let Some(&Expr::Extend { value, signed, .. }) = self.function.expr(expr) {
            let inner = self.at(stmt, value)?;
            return Some(extended(inner, signed, width));
        }
        if let Some(&Expr::Cast { value, .. }) = self.function.expr(expr) {
            return self.at(stmt, value);
        }
        let wanted = term(self.function, expr)?;
        let found = match wanted {
            Term::Const(_) => Vec::new(),
            Term::Var(var) => {
                let found = before(self.function, &self.index, stmt, var);
                let mut facts = found.facts;
                if let Some((_, written)) = found.init
                    && let Some(Term::Const(bits)) = term(self.function, written)
                    && bits.width() == width
                {
                    // The last write: the variable equals that constant.
                    facts.push(Fact {
                        a: wanted,
                        rel: Rel::Eq,
                        b: Term::Const(bits),
                        width,
                    });
                }
                facts
            }
        };
        let known = Known::new(&found);
        let signed = known.interval(wanted, true, width);
        let unsigned = known.interval(wanted, false, width);
        Some(Bounds {
            width,
            signed: if let Term::Const(bits) = wanted {
                Interval::point(value(bits, true))
            } else {
                signed
            },
            unsigned,
        })
    }
}

/// `inner` extended to `width` bits, zero (`signed` false) or sign
/// extended.
fn extended(inner: Bounds, signed: bool, width: u16) -> Bounds {
    let full = Bounds::full(width);
    if signed {
        Bounds {
            width,
            signed: inner.signed,
            unsigned: if inner.signed.lo >= 0 {
                inner.signed
            } else {
                full.unsigned
            },
        }
    } else {
        Bounds {
            width,
            signed: inner.unsigned,
            unsigned: inner.unsigned,
        }
    }
}

#[cfg(test)]
mod tests {
    use binbun_ast::ir::{Place, Stmt, VarId, VarKind, Variable};
    use binbun_ast::types::{Evidence, Type, Types};
    use binbun_semantics::bits::Bits;
    use binbun_semantics::ir::Binary;

    use super::*;

    fn local(function: &mut Function) -> VarId {
        let ty = function.types.intern(Type::Int(32));
        function.add_var(Variable {
            kind: VarKind::Local,
            name: None,
            ty,
            evidence: Evidence::Declared,
            origins: Vec::new(),
        })
    }

    /// `if (x < 0) return; f(x);` with `y = 5;` before: at the call, `x`
    /// is in `0..=i32::MAX` and `y` is 5.
    #[test]
    fn guard_and_constant_write() {
        let mut function = Function::new(0x1000, Types::new(64));
        let x = local(&mut function);
        let y = local(&mut function);
        let five = function.add_expr(Expr::Const(Bits::from_u64(32, 5)));
        let set = function.add_stmt(Stmt::Assign {
            place: Place::Var(y),
            value: five,
        });
        let read_x = function.add_expr(Expr::Var(x));
        let zero = function.add_expr(Expr::Const(Bits::from_u64(32, 0)));
        let negative = function.add_expr(Expr::Binary(Binary::SLt, read_x, zero));
        let leave = function.add_stmt(Stmt::Return(None));
        let guard = function.add_stmt(Stmt::If {
            condition: negative,
            then: vec![leave],
            otherwise: Vec::new(),
        });
        let use_x = function.add_expr(Expr::Var(x));
        let use_y = function.add_expr(Expr::Var(y));
        let call = function.add_stmt(Stmt::Expr(use_x));
        let other = function.add_stmt(Stmt::Expr(use_y));
        function.body = vec![set, guard, call, other];

        let values = Values::new(&function);
        assert_eq!(values.statement(use_x), Some(call));
        let bounds = values.at(call, use_x).expect("a variable of 32 bits");
        assert_eq!(
            bounds.signed,
            Interval {
                lo: 0,
                hi: i128::from(i32::MAX)
            }
        );
        assert!(bounds.known());
        assert_eq!(values.at(other, use_y).and_then(|b| b.constant()), Some(5));
        // Before the guard nothing is known of `x`.
        assert_eq!(values.at(guard, read_x).map(|b| b.known()), Some(false));
    }
}
