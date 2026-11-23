//! What the proof tests share: L2 expressions over a function's variables
//! as L0 semantics (each variable a register), encoded with
//! `binbun_semantics::smt`, and z3 asked for a counterexample.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use binbun_ast::ir::{Expr, ExprId, Function};
use binbun_semantics::bits::MAX_WIDTH;
use binbun_semantics::ir::{Declarations, ExprId as L0Expr, RegisterId, RegisterInfo};
use binbun_semantics::smt::{self, Options, Script, Term};
use binbun_semantics::{Builder, Semantics, View};

/// Runs z3 on `script`: one answer per line. `None` (with a notice) if z3
/// cannot be run.
pub fn z3(script: &str) -> Option<Vec<String>> {
    let mut child = match Command::new("z3")
        .args(["-in", "-smt2"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            eprintln!("skipped: cannot run z3 ({error})");
            return None;
        }
    };
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    Some(text.lines().map(str::to_owned).collect())
}

/// Registers as wide as any L0 value ([`MAX_WIDTH`] bits): a function's
/// variables are the low bits of the first ones (variable `i` of register
/// `i`), the outputs of those after.
const REGISTERS: [RegisterInfo; 24] = {
    const NAMES: [&str; 24] = [
        "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "r13",
        "r14", "r15", "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
    ];
    let mut registers = [RegisterInfo {
        name: "",
        width: MAX_WIDTH,
    }; 24];
    let mut index = 0;
    while index < 24 {
        registers[index].name = NAMES[index];
        index += 1;
    }
    registers
};

const DECLARATIONS: Declarations = Declarations {
    registers: &REGISTERS,
    intrinsics: &[],
    sites: &[],
};

/// The low `width` bits of register `index`.
fn view(index: usize, width: u16) -> View {
    View {
        register: RegisterId(u16::try_from(index).unwrap()),
        offset: 0,
        width,
    }
}

/// `roots` (pure L2 expressions over `function`'s variables) as L0
/// semantics writing each to the low bits of its output register; with
/// the roots' widths.
fn semantics(function: &Function, roots: &[ExprId]) -> (Semantics, Vec<u16>) {
    let widths: Vec<u16> = roots
        .iter()
        .map(|&root| function.width(root).unwrap())
        .collect();
    assert!(function.variables.len() + roots.len() <= REGISTERS.len());
    let mut b = Builder::new();
    let mut done: BTreeMap<ExprId, L0Expr> = BTreeMap::new();
    for &root in roots {
        let mut work = vec![(root, false)];
        while let Some((id, ready)) = work.pop() {
            if done.contains_key(&id) {
                continue;
            }
            let expr = *function.expr(id).unwrap();
            if !ready {
                work.push((id, true));
                work.extend(expr.operands(function).map(|operand| (operand, false)));
                continue;
            }
            let get = |operand: ExprId| done[&operand];
            let value = match expr {
                Expr::Const(bits) => b.bits(bits),
                Expr::Var(var) => {
                    let ty = function.var(var).unwrap().ty;
                    let width = function.types.value_width(ty).unwrap();
                    b.read(view(var.0 as usize, width))
                }
                Expr::Unary(op, a) => b.unary(op, get(a)),
                Expr::Binary(op, x, y) => b.binary(op, get(x), get(y)),
                Expr::Flag(op, x, y, z) => b.flag(op, get(x), get(y), get(z)),
                Expr::Extract {
                    value,
                    offset,
                    width,
                } => b.extract(get(value), offset, width),
                Expr::Concat { high, low } => b.concat(get(high), get(low)),
                Expr::Extend {
                    signed,
                    value,
                    width,
                } => {
                    if signed {
                        b.sext(get(value), width)
                    } else {
                        b.zext(get(value), width)
                    }
                }
                Expr::Select {
                    condition,
                    then,
                    otherwise,
                } => b.select(get(condition), get(then), get(otherwise)),
                other @ (Expr::Undefined(..)
                | Expr::AddressOf(_)
                | Expr::Logical(..)
                | Expr::Lanes { .. }
                | Expr::Float { .. }
                | Expr::Cast { .. }
                | Expr::Load { .. }
                | Expr::Call(_)
                | Expr::Exception { .. }
                | Expr::Assign { .. }) => panic!("not a pure scalar expression: {other:?}"),
            };
            done.insert(id, value);
        }
    }
    let base = function.variables.len();
    for (index, &root) in roots.iter().enumerate() {
        b.write(view(base + index, widths[index]), done[&root]);
    }
    (b.finish().unwrap(), widths)
}

/// Queries collected into one z3 run, each given at most 10 minutes (an
/// answer other than `unsat`, `unknown` included, fails).
pub struct Proofs {
    script: Script,
    /// What each query proves, in order.
    pub names: Vec<String>,
}

impl Default for Proofs {
    fn default() -> Self {
        let mut script = Script::new();
        script.command("(set-option :timeout 600000)");
        Self {
            script,
            names: Vec::new(),
        }
    }
}

impl Proofs {
    /// How many queries it holds.
    pub fn count(&self) -> usize {
        self.names.len()
    }

    /// Adds the query: `lhs` and `rhs` (expressions of `function`) differ
    /// for some values of its variables while every expression of
    /// `conditions` (1 bit) is 1. z3 must answer `unsat`.
    pub fn differ(
        &mut self,
        name: String,
        function: &Function,
        lhs: ExprId,
        rhs: ExprId,
        conditions: &[ExprId],
    ) {
        let mut roots = vec![lhs, rhs];
        roots.extend(conditions);
        let (semantics, widths) = semantics(function, &roots);
        let options = Options::default();
        let index = self.names.len();
        self.script.push();
        let initial = self
            .script
            .initial_state(&DECLARATIONS, &format!("q{index}."), &options);
        let after = self
            .script
            .encode(
                &semantics,
                &DECLARATIONS,
                &initial,
                &format!("q{index}.e"),
                &options,
            )
            .unwrap();
        let base = function.variables.len();
        let output = |offset: usize| {
            let register = &after.state.registers[base + offset];
            let high = widths[offset] - 1;
            Term::new(format!("((_ extract {high} 0) {register})"))
        };
        let mut assumptions: Vec<Term> = (0..conditions.len())
            .map(|offset| smt::holds(&output(2 + offset)))
            .collect();
        assumptions.push(smt::not(&smt::eq(&output(0), &output(1))));
        self.script.assert(&smt::and(&assumptions));
        self.script.command("(check-sat)");
        self.script.pop();
        self.names.push(name);
    }

    /// Runs z3: the names of the queries it did not refute (`None`: z3
    /// is not installed).
    pub fn run(&self) -> Option<Vec<String>> {
        let answers = z3(self.script.as_str())?;
        assert_eq!(answers.len(), self.names.len(), "z3 answered {answers:?}");
        Some(
            self.names
                .iter()
                .zip(answers)
                .filter(|(_, answer)| answer != "unsat")
                .map(|(name, answer)| format!("{name}: {answer}"))
                .collect(),
        )
    }
}

/// What a z3 run did not refute, and how long it took.
pub type Outcome = (Vec<String>, Duration);

/// Runs each of `proofs` (a z3 each, eight at a time): per entry, its
/// [`Outcome`]; `None` if z3 is not installed.
pub fn run_all(proofs: &[Proofs]) -> Option<Vec<Outcome>> {
    let next = AtomicUsize::new(0);
    let results: Mutex<Vec<Option<Outcome>>> =
        Mutex::new(vec![Some((Vec::new(), Duration::ZERO)); proofs.len()]);
    thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(proof) = proofs.get(index) else {
                        break;
                    };
                    let started = Instant::now();
                    let failed = proof.run();
                    results.lock().unwrap()[index] =
                        failed.map(|failed| (failed, started.elapsed()));
                }
            });
        }
    });
    results.into_inner().unwrap().into_iter().collect()
}
