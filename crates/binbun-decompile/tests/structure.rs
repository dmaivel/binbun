#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::similar_names,
    reason = "test helpers fail loudly"
)]

//! Structuring: hand-built goto-only functions and thousands of random
//! ones (reducible and irreducible), each structured and checked — the
//! control graph through its blocks unchanged, binbun-ast's verifier
//! passing, and its interpreter giving the same outcome on random inputs
//! — then the same after short circuits merged.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use binbun_ast::interpret::{Outcome, run};
use binbun_ast::ir::{
    Arm, Escape, Expr, ExprId, Function as Ast, LabelId, Logical, Origin, Place, Stmt, StmtId,
    VarId, VarKind, Variable,
};
use binbun_ast::text::print;
use binbun_ast::types::{Evidence, Type, Types};
use binbun_ast::verify::verify;
use binbun_decompile::itanium::NONE;
use binbun_decompile::pass::{self as l2, L2Env};
use binbun_decompile::structure::{
    Conditions, Exits, Options, PostDominator, ShortCircuit, Stats, Structure, regions,
};
use binbun_decompile::validate::graph::{Graph, Successor};
use binbun_semantics::Declarations;
use binbun_semantics::bits::Bits;
use binbun_semantics::core::pass::{Changed, Fuel, Manager, Refusal};
use binbun_semantics::interpret::{Fault, Machine, Value};
use binbun_semantics::ir::{Binary, RegisterId};
use binbun_ssa::ir::BlockId;

const DECLARATIONS: Declarations = Declarations {
    registers: &[],
    intrinsics: &[],
    sites: &[],
};

/// Every variable is a 32-bit integer: two parameters, three locals and
/// a step counter `k`.
const P0: usize = 0;
const P1: usize = 1;
const X: [usize; 3] = [2, 3, 4];
const K: usize = 5;

/// A goto-only function under construction: the entry (unlabelled)
/// initialises the locals and jumps to block 0; block `i` has label `i`.
/// As lowering makes them, a block's statements (not those in its
/// terminator's arms) stand for it: L1 block 0 for the entry, `i + 1`
/// for block `i`.
struct Goto {
    f: Ast,
    vars: Vec<VarId>,
    labels: Vec<LabelId>,
    body: Vec<StmtId>,
}

impl Goto {
    fn new(blocks: usize) -> Self {
        let mut types = Types::new(64);
        let int32 = types.intern(Type::Int(32));
        let mut f = Ast::new(0x1000, types);
        f.returns = Some(int32);
        let mut vars = Vec::new();
        for index in 0..6 {
            let kind = if index < 2 {
                VarKind::Parameter
            } else {
                VarKind::Local
            };
            let id = f.add_var(Variable {
                kind,
                name: None,
                ty: int32,
                evidence: Evidence::Default,
                origins: Vec::new(),
            });
            if index < 2 {
                f.parameters.push(id);
            }
            vars.push(id);
        }
        let labels = (0..blocks).map(|_| f.add_label()).collect();
        let mut goto = Self {
            f,
            vars,
            labels,
            body: Vec::new(),
        };
        for (x, value) in [(X[0], None), (X[1], Some(P1)), (X[2], Some(P0)), (K, None)] {
            let value = match value {
                Some(var) => goto.read(var),
                None => goto.c(0),
            };
            let stmt = goto.assign(x, value);
            goto.body.push(stmt);
        }
        let stmt = goto.goto(0);
        goto.body.push(stmt);
        goto
    }

    fn c(&mut self, value: u64) -> ExprId {
        self.f.add_expr(Expr::Const(Bits::from_u64(32, value)))
    }

    fn read(&mut self, var: usize) -> ExprId {
        self.f.add_expr(Expr::Var(self.vars[var]))
    }

    fn bin(&mut self, op: Binary, a: ExprId, b: ExprId) -> ExprId {
        self.f.add_expr(Expr::Binary(op, a, b))
    }

    fn assign(&mut self, var: usize, value: ExprId) -> StmtId {
        self.f.add_stmt(Stmt::Assign {
            place: Place::Var(self.vars[var]),
            value,
        })
    }

    fn push(&mut self, stmt: Stmt) -> StmtId {
        let id = self.f.add_stmt(stmt);
        self.body.push(id);
        id
    }

    fn label(&mut self, block: usize) {
        self.push(Stmt::Label(self.labels[block]));
    }

    fn goto(&mut self, block: usize) -> StmtId {
        self.f.add_stmt(Stmt::Goto(self.labels[block]))
    }

    /// `var = var + value`, in the body.
    fn step(&mut self, var: usize, value: u64) {
        let read = self.read(var);
        let constant = self.c(value);
        let sum = self.bin(Binary::Add, read, constant);
        let stmt = self.assign(var, sum);
        self.body.push(stmt);
    }

    /// `var op value`, 1 bit.
    fn test(&mut self, op: Binary, var: usize, value: u64) -> ExprId {
        let read = self.read(var);
        let constant = self.c(value);
        self.bin(op, read, constant)
    }

    /// `if (condition) { copies; goto then } else { copies; goto otherwise }`.
    fn branch(
        &mut self,
        condition: ExprId,
        then: (Vec<StmtId>, usize),
        otherwise: (Vec<StmtId>, usize),
    ) {
        let [then, otherwise] = [then, otherwise].map(|(mut copies, block)| {
            copies.push(self.goto(block));
            copies
        });
        self.push(Stmt::If {
            condition,
            then,
            otherwise,
        });
    }

    fn jump(&mut self, block: usize) {
        let stmt = self.goto(block);
        self.body.push(stmt);
    }

    fn ret(&mut self, var: usize) {
        let read = self.read(var);
        self.push(Stmt::Return(Some(read)));
    }

    /// `switch (var & 3)`: each case to its block; the default to a block
    /// or an unresolved jump.
    fn switch(&mut self, var: usize, cases: &[(u64, usize)], default: Option<usize>) {
        let read = self.read(var);
        let three = self.c(3);
        let scrutinee = self.bin(Binary::And, read, three);
        let mut arms: Vec<Arm> = cases
            .iter()
            .map(|&(value, block)| Arm {
                values: vec![Bits::from_u64(32, value)],
                default: false,
                body: vec![self.goto(block)],
                fallthrough: false,
            })
            .collect();
        let body = match default {
            Some(block) => vec![self.goto(block)],
            None => vec![self.f.add_stmt(Stmt::Escape {
                kind: Escape::UnresolvedJump,
                operands: vec![read],
                results: Vec::new(),
            })],
        };
        arms.push(Arm {
            values: Vec::new(),
            default: true,
            body,
            fallthrough: false,
        });
        self.push(Stmt::Switch { scrutinee, arms });
    }

    fn finish(mut self) -> Ast {
        self.f.body = self.body;
        let mut block = 0;
        for &id in &self.f.body {
            let stmt = &self.f.stmts[id.0 as usize];
            if let Stmt::Label(label) = stmt {
                block = label.0 + 1;
            } else if !matches!(stmt, Stmt::Goto(_)) {
                self.f
                    .provenance
                    .set_stmt(id, &[Origin::Block(BlockId(block))]);
            }
        }
        verify(&self.f, &DECLARATIONS).unwrap();
        self.f
    }
}

/// The blocks' graph through [`Graph::flow`] (as the check that structure
/// equals L1's CFG sees it): where the body starts, and each block's
/// successors.
fn shape(f: &Ast) -> (Successor, BTreeMap<BlockId, BTreeSet<Successor>>) {
    let flow = Graph::of(f, &NONE).unwrap().flow().unwrap();
    (flow.start, flow.blocks())
}

/// [`shape`] of `before` as structuring keeps it in `after`: without the
/// blocks `after` has no node of that go to one place only (a decision
/// with nothing in either arm, which refinement drops, as the check
/// against L1 allows); what went to one goes where it went (round and
/// round, where it went back to itself).
fn kept_shape(before: &Ast, after: &Ast) -> (Successor, BTreeMap<BlockId, BTreeSet<Successor>>) {
    let (mut start, mut blocks) = shape(before);
    let kept = shape(after).1;
    loop {
        let dropped = blocks.iter().find_map(|(&block, successors)| {
            let mut ways = successors.iter();
            match (ways.next(), ways.next()) {
                (Some(&way), None) if !kept.contains_key(&block) => Some((
                    block,
                    if way == Successor::Block(block) {
                        Successor::Spin
                    } else {
                        way
                    },
                )),
                _ => None,
            }
        });
        let Some((block, way)) = dropped else {
            return (start, blocks);
        };
        blocks.remove(&block);
        for successors in blocks.values_mut() {
            if successors.remove(&Successor::Block(block)) {
                successors.insert(way);
            }
        }
        if start == Successor::Block(block) {
            start = way;
        }
    }
}

/// A machine without memory: the functions here only use variables.
struct NoMemory;

impl Machine for NoMemory {
    fn read(&mut self, _: RegisterId) -> Value {
        unreachable!("no registers")
    }

    fn write(&mut self, _: RegisterId, _: Value) {
        unreachable!("no registers")
    }

    fn load(&mut self, address: u64, _: u16) -> Result<Value, Fault> {
        Err(Fault {
            address,
            write: false,
        })
    }

    fn store(&mut self, address: u64, _: Value) -> Result<(), Fault> {
        Err(Fault {
            address,
            write: true,
        })
    }
}

const FUEL: u64 = 4000;

fn outcome(f: &Ast, arguments: [u64; 2], fuel: u64) -> Outcome {
    let arguments = arguments.map(|value| Value::defined(Bits::from_u64(32, value)));
    run(f, &mut NoMemory, &arguments, 0x8000, fuel)
}

/// Runs [`Structure`] under `options` on `f` through a pass manager: what
/// it did, or why it refused.
fn structure(f: &mut Ast, options: &Options) -> Result<Stats, Refusal> {
    let mut pass = Structure::new(*options);
    let mut manager = Manager::new(Fuel::new(u64::MAX));
    let env = L2Env {
        declarations: &DECLARATIONS,
        exceptions: &NONE,
        feeds: None,
    };
    manager.run(&mut pass, f, &env).unwrap();
    match manager.refusals() {
        [] => Ok(pass.stats().unwrap()),
        [(_, refusal), ..] => Err(refusal.clone()),
    }
}

/// Runs [`ShortCircuit`] on `f` through a pass manager (with the
/// verifier): how many `if`s it merged.
fn short_circuit(f: &mut Ast) -> usize {
    let mut pass = ShortCircuit::default();
    let mut manager = Manager::new(Fuel::new(u64::MAX)).with_verifier(l2::verify);
    let env = L2Env {
        declarations: &DECLARATIONS,
        exceptions: &NONE,
        feeds: None,
    };
    manager.run(&mut pass, f, &env).unwrap();
    assert_eq!(manager.refusals(), []);
    pass.merged()
}

/// Runs [`Exits`] on `f` through a pass manager (with the verifier): how
/// many `goto`s it replaced by a copy.
fn copy_exits(f: &mut Ast) -> usize {
    let mut pass = Exits::default();
    let mut manager = Manager::new(Fuel::new(u64::MAX)).with_verifier(l2::verify);
    let env = L2Env {
        declarations: &DECLARATIONS,
        exceptions: &NONE,
        feeds: None,
    };
    manager.run(&mut pass, f, &env).unwrap();
    assert_eq!(manager.refusals(), []);
    pass.copied()
}

/// Checks `after`, where blocks may be entered at several places, against
/// `before`: the verifier, the same blocks with the same successors, every
/// entry into a block going to all of them (L1's CFG unfolded), the same
/// outcomes on `inputs`.
fn unfolded(before: &Ast, after: &Ast, inputs: &[[u64; 2]]) {
    let context = || {
        format!(
            "before:\n{}\nafter:\n{}",
            print(before, &DECLARATIONS),
            print(after, &DECLARATIONS)
        )
    };
    if let Err(error) = verify(after, &DECLARATIONS) {
        panic!("{error:?}\n{}", context());
    }
    let (start, blocks) = kept_shape(before, after);
    assert_eq!(
        (start, &blocks),
        (shape(after).0, &shape(after).1),
        "{}",
        context()
    );
    for region in Graph::of(after, &NONE).unwrap().flow().unwrap().regions {
        assert_eq!(
            Some(&region.successors),
            blocks.get(&region.block),
            "block {} entered at node {}\n{}",
            region.block.0,
            region.entry.0,
            context()
        );
    }
    for &input in inputs {
        let expected = outcome(before, input, FUEL);
        if expected != Outcome::OutOfFuel {
            assert_eq!(
                expected,
                outcome(after, input, 10 * FUEL),
                "input {input:?}\n{}",
                context()
            );
        }
    }
}

/// Checks `after` against `before`: the same graph, the verifier, the
/// same outcomes on `inputs`; how many runs ended within the fuel.
fn same(before: &Ast, after: &Ast, inputs: &[[u64; 2]]) -> usize {
    let context = || {
        format!(
            "before:\n{}\nafter:\n{}",
            print(before, &DECLARATIONS),
            print(after, &DECLARATIONS)
        )
    };
    if let Err(error) = verify(after, &DECLARATIONS) {
        panic!("{error:?}\n{}", context());
    }
    assert_eq!(kept_shape(before, after), shape(after), "{}", context());
    let mut ended = 0;
    for &input in inputs {
        let expected = outcome(before, input, FUEL);
        if expected == Outcome::OutOfFuel {
            continue;
        }
        ended += 1;
        let found = outcome(after, input, 10 * FUEL);
        assert_eq!(expected, found, "input {input:?}\n{}", context());
    }
    ended
}

/// Structures `before` and checks it against its goto form ([`same`]),
/// then merges short circuits and checks that too. Returns the
/// structured function, the stats, how many runs ended within the fuel
/// and how many `if`s merged.
fn check(before: &Ast, options: &Options, inputs: &[[u64; 2]]) -> (Ast, Stats, usize, usize) {
    let mut after = before.clone();
    let stats = structure(&mut after, options)
        .unwrap_or_else(|refusal| panic!("{refusal}\n{}", print(before, &DECLARATIONS)));
    let ended = same(before, &after, inputs);
    let mut merged = after.clone();
    let count = short_circuit(&mut merged);
    same(before, &merged, inputs);
    (after, stats, ended, count)
}

/// A small deterministic random number generator (xorshift).
struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(bound).unwrap()).unwrap()
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }
}

/// How a random block ends.
enum End {
    Jump(usize),
    /// A test of `k` (else of a local), each arm with a copy or not.
    Branch(bool, [(bool, usize); 2]),
    Switch(Vec<(u64, usize)>, Option<usize>),
    Return,
}

/// A random goto-only function of up to `blocks` blocks (those reached
/// from the entry); `back` is the percent of edges going to an earlier
/// block (anywhere: often irreducible), `returns` the percent of blocks
/// that return, `bare` the percent of blocks with no code before their
/// terminator (a decision alone, as short circuits are made of).
fn random_cfg(random: &mut Random, blocks: usize, back: u64, returns: usize, bare: u64) -> Ast {
    let ends: Vec<End> = (0..blocks)
        .map(|block| {
            let target = |random: &mut Random| {
                if block + 1 >= blocks || random.chance(back) {
                    random.below(block + 1)
                } else {
                    let skip = if random.chance(50) {
                        0
                    } else {
                        random.below((blocks - block - 1).min(4))
                    };
                    block + 1 + skip
                }
            };
            if block + 1 == blocks {
                return End::Return;
            }
            let kind = random.below(100);
            match kind {
                _ if kind < returns => End::Return,
                0..25 => End::Jump(target(random)),
                25..85 => {
                    let counted = random.chance(50);
                    let then = (random.chance(30), target(random));
                    let otherwise = (random.chance(30), target(random));
                    End::Branch(counted, [then, otherwise])
                }
                _ => {
                    let mut cases = Vec::new();
                    for value in 0..3 {
                        if random.chance(70) {
                            cases.push((value, target(random)));
                        }
                    }
                    let default = if cases.is_empty() || random.chance(70) {
                        Some(target(random))
                    } else {
                        None
                    };
                    End::Switch(cases, default)
                }
            }
        })
        .collect();
    let mut reached = vec![false; blocks];
    let mut work = vec![0];
    while let Some(block) = work.pop() {
        if std::mem::replace(&mut reached[block], true) {
            continue;
        }
        match &ends[block] {
            End::Jump(to) => work.push(*to),
            End::Branch(_, arms) => work.extend(arms.iter().map(|arm| arm.1)),
            End::Switch(cases, default) => {
                work.extend(cases.iter().map(|case| case.1).chain(*default));
            }
            End::Return => {}
        }
    }
    let mut g = Goto::new(blocks);
    for (block, end) in ends.iter().enumerate().filter(|&(block, _)| reached[block]) {
        g.label(block);
        if bare == 0 || !random.chance(bare) {
            g.step(K, 1);
            for _ in 0..random.below(3) {
                let var = X[random.below(3)];
                g.step(var, random.next() % 7);
            }
        }
        match end {
            &End::Jump(to) => g.jump(to),
            &End::Branch(counted, arms) => {
                let condition = if counted {
                    g.test(Binary::ULt, K, 8 + random.next() % 24)
                } else {
                    g.test(Binary::Eq, X[random.below(3)], random.next() % 4)
                };
                let [then, otherwise] = arms.map(|(copy, to)| {
                    let copies = if copy {
                        let value = g.c(random.next() % 5);
                        vec![g.assign(X[random.below(3)], value)]
                    } else {
                        Vec::new()
                    };
                    (copies, to)
                });
                g.branch(condition, then, otherwise);
            }
            End::Switch(cases, default) => g.switch(X[random.below(3)], cases, *default),
            End::Return => g.ret(X[random.below(3)]),
        }
    }
    g.finish()
}

/// A statement of a random structured program.
#[derive(Clone, Debug)]
enum Source {
    Step(usize),
    If(usize, Vec<Source>, Vec<Source>),
    While(u64, Vec<Source>),
    DoWhile(Vec<Source>, u64),
    Switch(usize, Vec<(Vec<u64>, Vec<Source>, bool)>),
    Break,
    Continue,
    Return(usize),
}

fn program(random: &mut Random, depth: usize, in_loop: bool, budget: &mut usize) -> Vec<Source> {
    let mut out = Vec::new();
    // The top level goes on until the budget is spent.
    let length = if depth == 0 {
        usize::MAX
    } else {
        1 + random.below(4)
    };
    for _ in 0..length {
        if *budget == 0 {
            break;
        }
        *budget -= 1;
        let pick = random.below(100);
        let nested = depth < 4;
        let stmt = match pick {
            0..30 => Source::Step(X[random.below(3)]),
            30..50 if nested => Source::If(
                X[random.below(3)],
                program(random, depth + 1, in_loop, budget),
                if random.chance(50) {
                    program(random, depth + 1, in_loop, budget)
                } else {
                    Vec::new()
                },
            ),
            50..62 if nested => Source::While(
                8 + random.next() % 24,
                program(random, depth + 1, true, budget),
            ),
            62..70 if nested => Source::DoWhile(
                program(random, depth + 1, true, budget),
                8 + random.next() % 24,
            ),
            70..77 if nested => {
                let arms = (0..=random.below(3))
                    .map(|value| {
                        (
                            vec![value as u64],
                            program(random, depth + 1, in_loop, budget),
                            random.chance(25),
                        )
                    })
                    .collect();
                Source::Switch(X[random.below(3)], arms)
            }
            77..84 if in_loop => Source::Break,
            84..90 if in_loop => Source::Continue,
            90..95 if depth > 0 => Source::Return(X[random.below(3)]),
            _ => Source::Step(K),
        };
        let ends = matches!(stmt, Source::Break | Source::Continue | Source::Return(_));
        out.push(stmt);
        if ends {
            break;
        }
    }
    out
}

/// Lowers a structured program to goto form, as a compiler would: a block
/// per join, loop header and arm.
struct Lowering {
    g: Goto,
    blocks: usize,
    /// The blocks: their statements, and whether they end.
    code: Vec<Vec<StmtId>>,
    current: usize,
    /// Enclosing loops' (continue, break) blocks, and switches' break.
    breaks: Vec<(Option<usize>, usize)>,
    /// Whether each block is jumped to.
    reached: Vec<bool>,
}

impl Lowering {
    fn block(&mut self) -> usize {
        self.code.push(Vec::new());
        self.reached.push(false);
        self.blocks += 1;
        self.blocks - 1
    }

    fn emit(&mut self, stmt: StmtId) {
        self.code[self.current].push(stmt);
    }

    fn to(&mut self, block: usize) -> StmtId {
        self.reached[block] = true;
        self.g.goto(block)
    }

    fn goto(&mut self, block: usize) {
        let stmt = self.to(block);
        self.emit(stmt);
    }

    fn branch(&mut self, condition: ExprId, then: usize, otherwise: usize) {
        let then = vec![self.to(then)];
        let otherwise = vec![self.to(otherwise)];
        let stmt = self.g.f.add_stmt(Stmt::If {
            condition,
            then,
            otherwise,
        });
        self.emit(stmt);
    }

    /// Lowers `source`; false if control does not go on after it.
    fn lower(&mut self, source: &[Source]) -> bool {
        for stmt in source {
            if !self.statement(stmt) {
                return false;
            }
        }
        true
    }

    fn statement(&mut self, stmt: &Source) -> bool {
        match stmt {
            &Source::Step(var) => {
                let read = self.g.read(var);
                let one = self.g.c(3);
                let sum = self.g.bin(Binary::Add, read, one);
                let stmt = self.g.assign(var, sum);
                self.emit(stmt);
            }
            Source::If(var, then, otherwise) => {
                let condition = self.g.test(Binary::Eq, *var, 0);
                let [a, b, join] = [self.block(), self.block(), self.block()];
                self.branch(condition, a, b);
                for (block, arm) in [(a, then), (b, otherwise)] {
                    self.current = block;
                    if self.lower(arm) {
                        self.goto(join);
                    }
                }
                self.current = join;
            }
            Source::While(bound, body) => {
                let [head, inside, exit] = [self.block(), self.block(), self.block()];
                self.goto(head);
                self.current = head;
                let condition = self.g.test(Binary::ULt, K, *bound);
                self.branch(condition, inside, exit);
                self.current = inside;
                self.breaks.push((Some(head), exit));
                if self.lower(body) {
                    self.goto(head);
                }
                self.breaks.pop();
                self.current = exit;
            }
            Source::DoWhile(body, bound) => {
                let [inside, latch, exit] = [self.block(), self.block(), self.block()];
                self.goto(inside);
                self.current = inside;
                self.breaks.push((Some(latch), exit));
                if self.lower(body) {
                    self.goto(latch);
                }
                self.breaks.pop();
                self.current = latch;
                if self.reached[latch] {
                    let condition = self.g.test(Binary::ULt, K, *bound);
                    self.branch(condition, inside, exit);
                }
                self.current = exit;
            }
            Source::Switch(var, arms) => self.switch(*var, arms),
            Source::Break => {
                let &(_, exit) = self.breaks.last().unwrap();
                self.goto(exit);
                return false;
            }
            Source::Continue => {
                let head = self
                    .breaks
                    .iter()
                    .rev()
                    .find_map(|&(head, _)| head)
                    .unwrap();
                self.goto(head);
                return false;
            }
            &Source::Return(var) => {
                let read = self.g.read(var);
                let stmt = self.g.f.add_stmt(Stmt::Return(Some(read)));
                self.emit(stmt);
                return false;
            }
        }
        self.reached[self.current]
    }
}

impl Lowering {
    /// `switch (var & 3)` with these arms (values, body, falls through),
    /// the default going on after it.
    fn switch(&mut self, var: usize, arms: &[(Vec<u64>, Vec<Source>, bool)]) {
        let starts: Vec<usize> = arms.iter().map(|_| self.block()).collect();
        let exit = self.block();
        let read = self.g.read(var);
        let three = self.g.c(3);
        let scrutinee = self.g.bin(Binary::And, read, three);
        let mut cases: Vec<Arm> = arms
            .iter()
            .zip(&starts)
            .map(|((values, _, _), &start)| Arm {
                values: values.iter().map(|&v| Bits::from_u64(32, v)).collect(),
                default: false,
                body: vec![self.to(start)],
                fallthrough: false,
            })
            .collect();
        cases.push(Arm {
            values: Vec::new(),
            default: true,
            body: vec![self.to(exit)],
            fallthrough: false,
        });
        let stmt = self.g.f.add_stmt(Stmt::Switch {
            scrutinee,
            arms: cases,
        });
        self.emit(stmt);
        self.breaks.push((None, exit));
        for (index, (_, body, fallthrough)) in arms.iter().enumerate() {
            self.current = starts[index];
            if self.lower(body) {
                let next = if *fallthrough {
                    starts.get(index + 1).copied().unwrap_or(exit)
                } else {
                    exit
                };
                self.goto(next);
            }
        }
        self.breaks.pop();
        self.current = exit;
    }
}

/// A random structured program of about `size` statements, lowered.
fn random_structured(random: &mut Random, size: usize) -> Ast {
    let mut budget = size;
    let source = program(random, 0, false, &mut budget);
    lower_program(&source, size)
}

/// `chunks` random loops of about 40 statements each, one after the
/// other, lowered.
fn random_loops(random: &mut Random, chunks: usize) -> Ast {
    let source: Vec<Source> = (0..chunks)
        .map(|_| {
            let mut budget = 40;
            let body = program(random, 1, true, &mut budget);
            Source::While(8 + random.next() % 24, body)
        })
        .collect();
    lower_program(&source, 40 * chunks)
}

/// `source` (about `size` statements) lowered to goto form.
fn lower_program(source: &[Source], size: usize) -> Ast {
    let mut lowering = Lowering {
        g: Goto::new(4 * size + 16),
        blocks: 0,
        code: Vec::new(),
        current: 0,
        breaks: Vec::new(),
        reached: Vec::new(),
    };
    lowering.block();
    lowering.reached[0] = true;
    if lowering.lower(source) {
        let read = lowering.g.read(X[0]);
        let stmt = lowering.g.f.add_stmt(Stmt::Return(Some(read)));
        lowering.emit(stmt);
    }
    let Lowering {
        mut g,
        code,
        reached,
        ..
    } = lowering;
    for (block, stmts) in code.into_iter().enumerate() {
        if !reached[block] {
            continue;
        }
        g.label(block);
        g.step(K, 1);
        g.body.extend(stmts);
    }
    g.finish()
}

fn inputs(random: &mut Random) -> Vec<[u64; 2]> {
    (0..6)
        .map(|_| [random.next() % 8, random.next() % 8])
        .collect()
}

#[test]
fn diamond_becomes_if_else() {
    // 0: if (x0 == 0) goto 1 else goto 2; 1: goto 3; 2: goto 3; 3: return.
    let mut g = Goto::new(4);
    g.label(0);
    let condition = g.test(Binary::Eq, P0, 0);
    g.branch(condition, (Vec::new(), 1), (Vec::new(), 2));
    for block in [1, 2] {
        g.label(block);
        g.step(X[block - 1], 1);
        g.jump(3);
    }
    g.label(3);
    g.ret(X[0]);
    let before = g.finish();
    let (after, stats, _, _) = check(&before, &Options::default(), &[[0, 0], [1, 0]]);
    assert_eq!(
        (stats.gotos_before, stats.gotos_after, stats.ifs),
        (5, 0, 1),
        "{}",
        print(&after, &DECLARATIONS)
    );
    // No label is left: nothing jumps to one.
    let text = print(&after, &DECLARATIONS);
    assert!(!text.contains("label l"), "{text}");
}

#[test]
fn loops_become_while_and_do_while() {
    // 0: if (k < 5) goto 1 else goto 2; 1: x0 += 1; goto 0;
    // 2: x1 += 1; if (k < 9) goto 2 else goto 3; 3: return.
    let mut g = Goto::new(4);
    g.label(0);
    let condition = g.test(Binary::ULt, K, 5);
    g.branch(condition, (Vec::new(), 1), (Vec::new(), 2));
    g.label(1);
    g.step(K, 1);
    g.jump(0);
    g.label(2);
    g.step(K, 1);
    let condition = g.test(Binary::ULt, K, 9);
    g.branch(condition, (Vec::new(), 2), (Vec::new(), 3));
    g.label(3);
    g.ret(K);
    let before = g.finish();
    let (after, stats, ended, _) = check(&before, &Options::default(), &[[0, 0]]);
    assert_eq!(ended, 1);
    assert_eq!((stats.gotos_after, stats.loops, stats.exits), (0, 2, 0));
    let text = print(&after, &DECLARATIONS);
    assert!(text.contains("while ult(v5, 0x5:32) {"), "{text}");
    assert!(text.contains("} while ult(v5, 0x9:32)"), "{text}");
    // Without refinement: `while (1)` with `break`s, the same graph.
    let raw = Options {
        refine: false,
        ..Options::default()
    };
    let (after, stats, _, _) = check(&before, &raw, &[[0, 0]]);
    assert_eq!((stats.gotos_after, stats.loops), (0, 2));
    assert!(print(&after, &DECLARATIONS).contains("while 0x1:1 {"));
}

#[test]
fn a_jump_to_an_empty_latch_is_a_continue() {
    // 0: k += 1; if (x0 == 0) goto 1 else goto 3; 1: if (x1 == 0) goto 2
    // else goto 4; 4: x2 += 1; goto 3; 3: x1 += 1; goto 2;
    // 2: if (k < 5) goto 0 else goto 5; 5: return.
    let mut g = Goto::new(6);
    g.label(0);
    g.step(K, 1);
    let condition = g.test(Binary::Eq, X[0], 0);
    g.branch(condition, (Vec::new(), 1), (Vec::new(), 3));
    g.label(1);
    let condition = g.test(Binary::Eq, X[1], 0);
    g.branch(condition, (Vec::new(), 2), (Vec::new(), 4));
    g.label(4);
    g.step(X[2], 1);
    g.jump(3);
    g.label(3);
    g.step(X[1], 1);
    g.jump(2);
    g.label(2);
    let condition = g.test(Binary::ULt, K, 5);
    g.branch(condition, (Vec::new(), 0), (Vec::new(), 5));
    g.label(5);
    g.ret(X[1]);
    let before = g.finish();
    let (after, stats, _, _) = check(&before, &Options::default(), &[[0, 0], [0, 1], [1, 0]]);
    let text = print(&after, &DECLARATIONS);
    assert_eq!(
        (stats.gotos_after, stats.exits, stats.loops),
        (0, 0, 1),
        "{text}"
    );
    assert!(
        text.contains("continue") && text.contains("} while ult(v5, 0x5:32)"),
        "{text}"
    );
}

#[test]
fn two_exits_of_a_loop_to_two_joins_leave_one_goto() {
    // 0: if (k < 5) goto 1 else goto 3; 1: if (x0 == 0) goto 4 else goto 2;
    // 2: if (x1 == 0) goto 3 else goto 0; 3: x1 += 1; goto 4; 4: return.
    // Exits to 3 and 4, both joins: 3 follows the loop, 4 after it is a
    // goto's target.
    let mut g = Goto::new(5);
    g.label(0);
    g.step(K, 1);
    let condition = g.test(Binary::ULt, K, 5);
    g.branch(condition, (Vec::new(), 1), (Vec::new(), 3));
    g.label(1);
    let condition = g.test(Binary::Eq, X[0], 0);
    g.branch(condition, (Vec::new(), 4), (Vec::new(), 2));
    g.label(2);
    let condition = g.test(Binary::Eq, X[1], 0);
    g.branch(condition, (Vec::new(), 3), (Vec::new(), 0));
    g.label(3);
    g.step(X[1], 1);
    g.jump(4);
    g.label(4);
    g.ret(X[1]);
    let before = g.finish();
    let (after, stats, _, _) = check(&before, &Options::default(), &[[0, 0], [1, 1], [1, 0]]);
    assert_eq!(
        (stats.loops, stats.gotos_after, stats.exits),
        (1, 1, 0),
        "{}",
        print(&after, &DECLARATIONS)
    );
}

#[test]
fn switch_arms_fall_through() {
    // 0: switch (x0 & 3) { case 0: goto 1; case 1: goto 2; default: goto 3 }
    // 1: x1 += 1; goto 2;  2: x2 += 1; goto 3;  3: return.
    let mut g = Goto::new(4);
    g.label(0);
    g.switch(P0, &[(0, 1), (1, 2)], Some(3));
    g.label(1);
    g.step(X[1], 1);
    g.jump(2);
    g.label(2);
    g.step(X[2], 1);
    g.jump(3);
    g.label(3);
    g.ret(X[2]);
    let before = g.finish();
    let (after, stats, _, _) = check(&before, &Options::default(), &[[0, 0], [1, 0], [2, 0]]);
    assert_eq!((stats.gotos_after, stats.switches), (0, 1));
    let text = print(&after, &DECLARATIONS);
    assert!(text.contains("fallthrough"), "{text}");
}

#[test]
fn an_irreducible_loop_keeps_a_goto() {
    // 0: if (x0 == 0) goto 1 else goto 2; 1: if (k < 9) goto 2 else goto 3;
    // 2: k += 1; goto 1;  3: return. The cycle 1–2 has two entries.
    let mut g = Goto::new(4);
    g.label(0);
    let condition = g.test(Binary::Eq, P0, 0);
    g.branch(condition, (Vec::new(), 1), (Vec::new(), 2));
    g.label(1);
    let condition = g.test(Binary::ULt, K, 9);
    g.branch(condition, (Vec::new(), 2), (Vec::new(), 3));
    g.label(2);
    g.step(K, 1);
    g.jump(1);
    g.label(3);
    g.ret(K);
    let before = g.finish();
    let analysis = regions(&before).unwrap();
    assert_eq!(analysis.irreducible.len(), 1);
    assert_eq!(analysis.loops, []);
    let (_, stats, ended, _) = check(&before, &Options::default(), &[[0, 0], [1, 0]]);
    assert_eq!(ended, 2);
    assert_eq!((stats.irreducible, stats.gotos_after), (1, 1));
}

#[test]
fn regions_reports_dominators_post_dominators_and_loops() {
    // Entry → 0; 0: if goto 1 else 3; 1: if goto 2 else 3; 2: goto 0
    // (a loop 0–2 exiting from 0 and 1); 3: return.
    let mut g = Goto::new(4);
    g.label(0);
    let condition = g.test(Binary::ULt, K, 5);
    g.branch(condition, (Vec::new(), 1), (Vec::new(), 3));
    g.label(1);
    let condition = g.test(Binary::Eq, X[0], 0);
    g.branch(condition, (Vec::new(), 2), (Vec::new(), 3));
    g.label(2);
    g.step(K, 1);
    g.jump(0);
    g.label(3);
    g.ret(K);
    let f = g.finish();
    let r = regions(&f).unwrap();
    // The node of label i's block (L1 block i + 1).
    let node = |label: u32| {
        let at = r.regions.iter().position(|&b| b == BlockId(label + 1));
        u32::try_from(at.unwrap()).unwrap()
    };
    assert_eq!(r.regions[0], BlockId(0));
    assert_eq!(r.idom(node(3)), Some(node(0)));
    assert_eq!(r.idom(node(2)), Some(node(1)));
    assert!(r.dominates(node(0), node(2)) && !r.dominates(node(1), node(3)));
    assert_eq!(r.ipdom(node(0)), Some(PostDominator::Node(node(3))));
    assert_eq!(r.ipdom(node(3)), Some(PostDominator::Sink));
    assert_eq!(r.loops.len(), 1);
    let found = &r.loops[0];
    assert_eq!(
        (found.header, found.latches.as_slice()),
        (node(0), &[node(2)][..])
    );
    let mut exits = vec![(node(0), node(3)), (node(1), node(3))];
    exits.sort_unstable();
    let mut found_exits = found.exits.clone();
    found_exits.sort_unstable();
    assert_eq!(found_exits, exits);
    assert!(r.in_loop(node(1), 0) && !r.in_loop(node(3), 0));
    assert_eq!(r.irreducible, []);
}

#[test]
fn refuses_what_is_not_goto_only_and_leaves_it_unchanged() {
    let mut g = Goto::new(1);
    g.label(0);
    let condition = g.test(Binary::Eq, P0, 0);
    let ret = {
        let read = g.read(X[0]);
        g.f.add_stmt(Stmt::Return(Some(read)))
    };
    let looping = g.push(Stmt::Unreachable);
    g.f.stmts[looping.0 as usize] = Stmt::While {
        condition,
        body: vec![ret],
    };
    g.ret(X[0]);
    let before = g.finish();
    let mut after = before.clone();
    let refusal = structure(&mut after, &Options::default()).unwrap_err();
    assert_eq!(
        refusal,
        Refusal::Malformed(format!("s{}: the body is not goto-only", looping.0))
    );
    assert_eq!(after, before);
}

#[test]
fn refuses_beyond_its_budget_and_leaves_the_function_unchanged() {
    let before = random_cfg(&mut Random(7), 40, 20, 10, 0);
    let mut after = before.clone();
    let tight = Options {
        work: 1,
        ..Options::default()
    };
    assert_eq!(structure(&mut after, &tight), Err(Refusal::OutOfFuel));
    assert_eq!(after, before);
    assert!(structure(&mut after, &Options::default()).is_ok());
}

#[test]
fn deep_nesting_is_deferred_not_refused() {
    // A chain of single-entry ifs: block i: if (x == i) goto i+1 else goto end.
    let blocks = 200;
    let mut g = Goto::new(blocks + 1);
    for block in 0..blocks {
        g.label(block);
        let condition = g.test(Binary::Eq, X[0], 0);
        g.branch(condition, (Vec::new(), block + 1), (Vec::new(), blocks));
    }
    g.label(blocks);
    g.ret(X[0]);
    let before = g.finish();
    let shallow = Options {
        depth: 8,
        ..Options::default()
    };
    let (after, stats, _, _) = check(&before, &shallow, &[[0, 0]]);
    assert!(stats.deferred > 0, "{stats:?}");
    assert!(depth(&after, &after.body) <= 9);
}

/// How deeply `block`'s statements nest.
fn depth(f: &Ast, block: &[StmtId]) -> usize {
    block
        .iter()
        .map(|&id| {
            f.stmts[id.0 as usize]
                .blocks()
                .map(|inner| 1 + depth(f, inner))
                .max()
                .unwrap_or(0)
        })
        .max()
        .unwrap_or(0)
}

/// Sums of stats over a corpus.
#[derive(Debug, Default)]
struct Totals {
    functions: usize,
    blocks: usize,
    gotos_before: usize,
    gotos_after: usize,
    exits: usize,
    with_gotos: usize,
    loops: usize,
    ended: usize,
    /// `if`s merged into short circuits.
    merged: usize,
}

impl Totals {
    fn add(&mut self, f: &Ast, stats: &Stats, ended: usize, merged: usize) {
        self.functions += 1;
        self.blocks += f
            .body
            .iter()
            .filter(|&&id| matches!(f.stmts[id.0 as usize], Stmt::Label(_)))
            .count();
        self.gotos_before += stats.gotos_before;
        self.gotos_after += stats.gotos_after;
        self.exits += stats.exits;
        self.with_gotos += usize::from(stats.gotos_after + stats.exits > 0);
        self.loops += stats.loops;
        self.ended += ended;
        self.merged += merged;
    }
}

#[test]
fn random_structured_programs_lose_almost_every_goto() {
    let mut random = Random(0x5eed);
    let mut totals = Totals::default();
    for _ in 0..1500 {
        let size = 4 + random.below(40);
        let before = random_structured(&mut random, size);
        let inputs = inputs(&mut random);
        let (_, stats, ended, merged) = check(&before, &Options::default(), &inputs);
        assert_eq!(regions(&before).unwrap().irreducible, []);
        totals.add(&before, &stats, ended, merged);
    }
    println!("structured: {totals:?}");
    assert!(totals.ended > totals.functions * 3, "{totals:?}");
    // What is left: mostly a `continue` of a `do`-`while` whose latch has
    // code (a `for` loop's step).
    assert!(totals.with_gotos * 10 < totals.functions, "{totals:?}");
}

#[test]
fn random_graphs_keep_their_flow() {
    let mut random = Random(0xdecaf);
    let mut reducible = Totals::default();
    let mut irreducible = Totals::default();
    for round in 0..3000 {
        let blocks = 2 + random.below(30);
        let back = [0, 10, 25, 40][round % 4];
        let before = random_cfg(&mut random, blocks, back, 12, 0);
        let inputs = inputs(&mut random);
        let (_, stats, ended, merged) = check(&before, &Options::default(), &inputs);
        if stats.irreducible == 0 {
            reducible.add(&before, &stats, ended, merged);
        } else {
            irreducible.add(&before, &stats, ended, merged);
        }
    }
    println!("reducible: {reducible:?}\nirreducible: {irreducible:?}");
    assert!(reducible.functions > 2000 && irreducible.functions > 300);
    assert!(reducible.ended > reducible.functions * 2, "{reducible:?}");
}

#[test]
fn random_graphs_of_bare_decisions_keep_their_flow_through_short_circuits() {
    let mut random = Random(0xb1a5);
    let mut totals = Totals::default();
    for round in 0..3000 {
        let blocks = 2 + random.below(30);
        let back = [0, 10, 25][round % 3];
        let before = random_cfg(&mut random, blocks, back, 12, 60);
        let inputs = inputs(&mut random);
        let (_, stats, ended, merged) = check(&before, &Options::default(), &inputs);
        totals.add(&before, &stats, ended, merged);
    }
    println!("bare decisions: {totals:?}");
    // Merges need two bare decisions sharing an arm: one function in
    // eleven or so has one.
    assert!(totals.merged * 20 > totals.functions, "{totals:?}");
    assert!(totals.ended > totals.functions, "{totals:?}");
}

/// The `goto`s in `f`'s body.
fn gotos(f: &Ast) -> usize {
    let mut count = 0;
    let mut work = f.body.clone();
    while let Some(at) = work.pop() {
        let stmt = &f.stmts[at.0 as usize];
        count += usize::from(matches!(stmt, Stmt::Goto(_)));
        work.extend(stmt.blocks().flatten().copied());
    }
    count
}

#[test]
fn a_small_exit_is_copied_at_each_goto_and_its_dead_original_goes() {
    // 0: if (p0 == 0) goto 1; else goto 2;  1: x0 += 1; goto 3;
    // 2: if (p1 == 0) goto 3; else goto 4;  3: k += 1; return x0;
    // 4: return x1.
    let mut g = Goto::new(5);
    g.label(0);
    let test = g.test(Binary::Eq, P0, 0);
    g.branch(test, (Vec::new(), 1), (Vec::new(), 2));
    g.label(1);
    g.step(X[0], 1);
    g.jump(3);
    g.label(2);
    let test = g.test(Binary::Eq, P1, 0);
    g.branch(test, (Vec::new(), 3), (Vec::new(), 4));
    g.label(3);
    g.step(K, 1);
    g.ret(X[0]);
    g.label(4);
    g.ret(X[1]);
    let before = g.finish();
    let inputs = [[0, 0], [0, 1], [1, 0], [1, 1]];
    let mut after = before.clone();
    // The gotos to blocks 3 and 4 (not to 1 and 2, whose code goes on).
    assert_eq!(
        copy_exits(&mut after),
        3,
        "{}",
        print(&after, &DECLARATIONS)
    );
    unfolded(&before, &after, &inputs);
    let text = print(&after, &DECLARATIONS);
    // Block 3 (`k += 1; return x0`) twice, block 4 once: nothing falls
    // into their originals (block 2's `if` never goes on), which went.
    assert_eq!(text.matches("return").count(), 3, "{text}");
    // Then block 0's `goto`s fold: to block 1, the next statement, and to
    // block 2 over block 1, which never goes on now (`if (p0 == 0) {
    // x0 += 1; k += 1; return x0; }`). Left: the entry's, to block 0 right
    // after it.
    assert_eq!(gotos(&after), 1, "{text}");
    for label in ["label l1", "label l2", "label l3", "label l4"] {
        assert!(!text.contains(label), "{text}");
    }
    assert_eq!(copy_exits(&mut after), 0);
}

#[test]
fn an_exit_longer_than_the_limit_or_falling_out_is_not_copied() {
    // 0: if (p0 == 0) goto 1; else goto 2;  1: x0 += 1; goto 2;
    // 2: k += 1; x1 += 2; x2 += 3; return x0 (four statements).
    let mut g = Goto::new(3);
    g.label(0);
    let test = g.test(Binary::Eq, P0, 0);
    g.branch(test, (Vec::new(), 1), (Vec::new(), 2));
    g.label(1);
    g.step(X[0], 1);
    g.jump(2);
    g.label(2);
    g.step(K, 1);
    g.step(X[1], 2);
    g.step(X[2], 3);
    g.ret(X[0]);
    let before = g.finish();
    let mut after = before.clone();
    assert_eq!(copy_exits(&mut after), 0);
    unfolded(&before, &after, &[[0, 0], [1, 0]]);
    // Block 2 kept once, block 0's `goto`s folded: `if (p0 == 0) { x0 +=
    // 1; }` falling into it.
    let text = print(&after, &DECLARATIONS);
    assert_eq!(text.matches("return").count(), 1, "{text}");
    assert_eq!(gotos(&after), 1, "{text}");
    let mut wider = before.clone();
    let mut pass = Exits::new(4);
    let mut manager = Manager::new(Fuel::new(u64::MAX)).with_verifier(l2::verify);
    let env = L2Env {
        declarations: &DECLARATIONS,
        exceptions: &NONE,
        feeds: None,
    };
    manager.run(&mut pass, &mut wider, &env).unwrap();
    // Under a limit of four, both gotos to block 2 are copies.
    assert_eq!(pass.copied(), 2, "{}", print(&wider, &DECLARATIONS));
    unfolded(&before, &wider, &[[0, 0], [1, 0]]);
    let text = print(&wider, &DECLARATIONS);
    assert_eq!(text.matches("return").count(), 2, "{text}");
    assert_eq!(gotos(&wider), 1, "{text}");
}

#[test]
fn random_graphs_keep_their_flow_through_copied_exits() {
    let mut random = Random(0xc0b1);
    let (mut copied, mut functions, mut saved) = (0, 0, 0);
    for round in 0..3000 {
        let blocks = 2 + random.below(30);
        let back = [0, 10, 25][round % 3];
        let before = random_cfg(&mut random, blocks, back, 25, 60);
        let inputs = inputs(&mut random);
        let (mut after, _, _, _) = check(&before, &Options::default(), &inputs);
        let left = gotos(&after);
        let count = copy_exits(&mut after);
        unfolded(&before, &after, &inputs);
        saved += left - gotos(&after);
        copied += count;
        functions += usize::from(count > 0);
    }
    println!("copied exits: {copied} in {functions} functions, gotos saved {saved}");
    assert!(functions > 300, "{functions}");
    // Each copy replaces a `goto`; folds drop more.
    assert!(saved >= copied, "{saved} {copied}");
}

/// `l0: if (p0 == 0) { x0 += 1; goto l2; }  l1: x1 += 2; x2 += 1;
/// x0 += 3; [return x1]  l2: k += 1; x0 += 1; x1 += 1; return x0` (no
/// `goto` to `l1`; both exits too long to copy).
fn jump_over(returns: bool) -> Ast {
    let mut g = Goto::new(3);
    g.label(0);
    let test = g.test(Binary::Eq, P0, 0);
    let one = g.c(1);
    let read = g.read(X[0]);
    let sum = g.bin(Binary::Add, read, one);
    let step = g.assign(X[0], sum);
    let jump = g.goto(2);
    g.push(Stmt::If {
        condition: test,
        then: vec![step, jump],
        otherwise: Vec::new(),
    });
    g.label(1);
    g.step(X[1], 2);
    g.step(X[2], 1);
    g.step(X[0], 3);
    if returns {
        g.ret(X[1]);
    }
    g.label(2);
    g.step(K, 1);
    g.step(X[0], 1);
    g.step(X[1], 1);
    g.ret(X[0]);
    g.finish()
}

#[test]
fn a_goto_over_code_that_never_reaches_its_label_is_folded() {
    let inputs = [[0, 0], [1, 0], [2, 5]];
    let before = jump_over(true);
    let mut after = before.clone();
    assert_eq!(copy_exits(&mut after), 0);
    unfolded(&before, &after, &inputs);
    let text = print(&after, &DECLARATIONS);
    // `if (p0 != 0) { x1 += 2; …; return x1; } x0 += 1; k += 1; …`: only
    // the entry's `goto` to block 0 (the next statement) is left.
    assert_eq!(gotos(&after), 1, "{text}");
    assert!(!text.contains("label l2"), "{text}");
    // Code falling into `l2` belongs to the opposite arm, not after both
    // arms: moving it there would also run it on the skipped path.
    let before = jump_over(false);
    let mut after = before.clone();
    assert_eq!(copy_exits(&mut after), 0);
    assert_eq!(gotos(&after), 1, "{}", print(&after, &DECLARATIONS));
    unfolded(&before, &after, &inputs);
}

#[test]
fn forward_join_folding_keeps_external_entries_and_both_arm_effects() {
    for in_then in [true, false] {
        let mut g = Goto::new(4);
        g.label(0);
        let test = g.test(Binary::Eq, P1, 0);
        g.branch(test, (Vec::new(), 2), (Vec::new(), 1));
        g.label(1);
        let test = g.test(Binary::Eq, P0, 0);
        let value = g.c(7);
        let step = g.assign(X[0], value);
        let jump = g.goto(3);
        let value = g.c(11);
        let other = g.assign(X[1], value);
        let (then, otherwise) = if in_then {
            (vec![step, jump], vec![other])
        } else {
            (vec![other], vec![step, jump])
        };
        g.push(Stmt::If {
            condition: test,
            then,
            otherwise,
        });
        g.label(2);
        g.step(X[0], 3);
        g.step(X[1], 5);
        g.label(3);
        // Too long for exit copying: only the forward fold applies.
        g.step(X[0], 1);
        g.step(X[0], 2);
        g.step(X[0], 3);
        g.ret(X[0]);
        let before = g.finish();
        let mut after = before.clone();
        assert_eq!(copy_exits(&mut after), 0);
        assert!(gotos(&after) < gotos(&before));
        unfolded(&before, &after, &[[0, 0], [0, 1], [1, 0], [1, 1]]);
        // The code after label 2 (L1's block 3) is entered by block 0's
        // `goto` too: it stays after the `if`, not in its other arm, where
        // it would read as run only where the `if`'s test went that way.
        let mut nested = 0;
        let mut work: Vec<(StmtId, bool)> = after.body.iter().map(|&id| (id, false)).collect();
        while let Some((id, inside)) = work.pop() {
            let entered = after
                .provenance
                .stmt(id)
                .contains(&Origin::Block(BlockId(3)));
            nested += usize::from(inside && entered);
            let stmt = &after.stmts[id.0 as usize];
            work.extend(stmt.blocks().flatten().map(|&inner| (inner, true)));
        }
        assert_eq!(nested, 0, "{}", print(&after, &DECLARATIONS));
    }
}

/// Runs [`Conditions`] on `f` through a pass manager (with the
/// verifier): whether it changed it.
fn conditions(f: &mut Ast) -> bool {
    let mut manager = Manager::new(Fuel::new(u64::MAX)).with_verifier(l2::verify);
    let env = L2Env {
        declarations: &DECLARATIONS,
        exceptions: &NONE,
        feeds: None,
    };
    let changed = manager.run(&mut Conditions, f, &env).unwrap();
    assert_eq!(manager.refusals(), []);
    changed == Changed::Yes
}

#[test]
fn an_assignment_moves_into_the_condition_that_reads_it_first() {
    // l0: x0 = p0 + 1; if (x0 != 3) return x0; return x1.
    let mut g = Goto::new(1);
    g.label(0);
    let read = g.read(P0);
    let one = g.c(1);
    let sum = g.bin(Binary::Add, read, one);
    let assign = g.assign(X[0], sum);
    g.body.push(assign);
    let test = g.test(Binary::Ne, X[0], 3);
    let value = g.read(X[0]);
    let early = g.f.add_stmt(Stmt::Return(Some(value)));
    g.push(Stmt::If {
        condition: test,
        then: vec![early],
        otherwise: Vec::new(),
    });
    g.ret(X[1]);
    let before = g.finish();
    let mut after = before.clone();
    assert!(conditions(&mut after));
    let text = print(&after, &DECLARATIONS);
    assert!(
        text.contains("if ne((v2 = add(v0, 0x1:32)), 0x3:32)"),
        "{text}"
    );
    assert_eq!(text.matches(" = add(v0").count(), 1, "{text}");
    same(&before, &after, &[[0, 0], [2, 5], [7, 1]]);

    // Read first on the right of `&&` (`if (p1 == 2 && x0 == 3)`): the
    // assignment would be made only when `p1 == 2`; it stays.
    let mut g = Goto::new(1);
    g.label(0);
    let read = g.read(P0);
    let one = g.c(1);
    let sum = g.bin(Binary::Add, read, one);
    let assign = g.assign(X[0], sum);
    g.body.push(assign);
    let left = g.test(Binary::Eq, P1, 2);
    let right = g.test(Binary::Eq, X[0], 3);
    let both = g.f.add_expr(Expr::Logical(Logical::And, left, right));
    let value = g.read(X[0]);
    let early = g.f.add_stmt(Stmt::Return(Some(value)));
    g.push(Stmt::If {
        condition: both,
        then: vec![early],
        otherwise: Vec::new(),
    });
    g.ret(X[0]);
    let before = g.finish();
    let mut after = before.clone();
    assert!(!conditions(&mut after));
    assert_eq!(after, before);
}

#[test]
fn an_assignment_stays_before_a_one_bit_or_reading_it_on_the_right() {
    // l0: x0 = p0 + 1; if (p1 < 0 | x0 == 0) return x0; return x1 (a
    // signed `<=` as flags compute it). L2 evaluates both operands of the
    // `|`, but C prints it `p1 < 0 || x0 == 0`: an assignment on the right
    // would be made only when `p1 >= 0` (and `return x0` read it
    // unassigned), so it stays a statement.
    let mut g = Goto::new(1);
    g.label(0);
    let read = g.read(P0);
    let one = g.c(1);
    let sum = g.bin(Binary::Add, read, one);
    let assign = g.assign(X[0], sum);
    g.body.push(assign);
    let left = g.test(Binary::SLt, P1, 0);
    let right = g.test(Binary::Eq, X[0], 0);
    let either = g.bin(Binary::Or, left, right);
    let value = g.read(X[0]);
    let early = g.f.add_stmt(Stmt::Return(Some(value)));
    g.push(Stmt::If {
        condition: either,
        then: vec![early],
        otherwise: Vec::new(),
    });
    g.ret(X[1]);
    let before = g.finish();
    let mut after = before.clone();
    assert!(!conditions(&mut after), "{}", print(&after, &DECLARATIONS));
    assert_eq!(after, before);

    // On the left of the `|`, it moves: `if ((x0 = p0 + 1) == 0 | p1 < 0)`.
    let mut g = Goto::new(1);
    g.label(0);
    let read = g.read(P0);
    let one = g.c(1);
    let sum = g.bin(Binary::Add, read, one);
    let assign = g.assign(X[0], sum);
    g.body.push(assign);
    let left = g.test(Binary::Eq, X[0], 0);
    let right = g.test(Binary::SLt, P1, 0);
    let either = g.bin(Binary::Or, left, right);
    let value = g.read(X[0]);
    let early = g.f.add_stmt(Stmt::Return(Some(value)));
    g.push(Stmt::If {
        condition: either,
        then: vec![early],
        otherwise: Vec::new(),
    });
    g.ret(X[1]);
    let before = g.finish();
    let mut after = before.clone();
    assert!(conditions(&mut after), "{}", print(&after, &DECLARATIONS));
    let text = print(&after, &DECLARATIONS);
    assert!(
        text.contains("eq((v2 = add(v0, 0x1:32)), 0x0:32)"),
        "{text}"
    );
    // p1 negative; p0 + 1 wrapping to 0; neither.
    same(
        &before,
        &after,
        &[[7, 0xffff_ffff], [0xffff_ffff, 5], [7, 1]],
    );
}

#[test]
fn a_loop_whose_body_starts_with_an_assigned_test_becomes_a_while() {
    // l0: while (1) { x1 = x1 - 1; if (x1 == 0) break; k += 1; }
    // return k (x1 starts as p1).
    let mut g = Goto::new(1);
    g.label(0);
    let looping = g.push(Stmt::Unreachable);
    let read = g.read(X[1]);
    let one = g.c(1);
    let less = g.bin(Binary::Sub, read, one);
    let assign = g.assign(X[1], less);
    let test = g.test(Binary::Eq, X[1], 0);
    let leave = g.f.add_stmt(Stmt::Break(looping));
    let exit = g.f.add_stmt(Stmt::If {
        condition: test,
        then: vec![leave],
        otherwise: Vec::new(),
    });
    let read = g.read(K);
    let one = g.c(1);
    let more = g.bin(Binary::Add, read, one);
    let count = g.assign(K, more);
    let always = g.f.add_expr(Expr::Const(Bits::from_u64(1, 1)));
    g.f.stmts[looping.0 as usize] = Stmt::While {
        condition: always,
        body: vec![assign, exit, count],
    };
    g.ret(K);
    let mut before = g.finish();
    // The loop's statements stand for block 1 as the code around them.
    for id in [assign, exit, count] {
        before.provenance.set_stmt(id, &[Origin::Block(BlockId(1))]);
    }
    let mut after = before.clone();
    assert!(conditions(&mut after));
    let text = print(&after, &DECLARATIONS);
    // `while ((x1 = x1 - 1) != 0) k += 1;`
    assert!(
        text.contains("while ne((v3 = sub(v3, 0x1:32)), 0x0:32)"),
        "{text}"
    );
    let Stmt::While { body, .. } = &after.stmts[looping.0 as usize] else {
        panic!("{text}");
    };
    assert_eq!(body, &vec![count], "{text}");
    same(&before, &after, &[[0, 1], [0, 4], [3, 9]]);
}

#[test]
fn an_assignment_before_a_do_while_stays_before_it() {
    // l0: x0 = p1; do { k = k + x0; x1 = x1 + 1; } while (k < x0);
    // return k. The loop's condition is evaluated after its body, which
    // reads `x0` (and its last assignment is not read by the condition).
    let mut g = Goto::new(1);
    g.label(0);
    let read = g.read(P1);
    let assign = g.assign(X[0], read);
    g.body.push(assign);
    let k = g.read(K);
    let x = g.read(X[0]);
    let sum = g.bin(Binary::Add, k, x);
    let step = g.assign(K, sum);
    let read = g.read(X[1]);
    let one = g.c(1);
    let more = g.bin(Binary::Add, read, one);
    let other = g.assign(X[1], more);
    let k = g.read(K);
    let x = g.read(X[0]);
    let test = g.bin(Binary::ULt, k, x);
    g.push(Stmt::DoWhile {
        body: vec![step, other],
        condition: test,
    });
    g.ret(K);
    let mut after = g.finish();
    assert!(!conditions(&mut after), "{}", print(&after, &DECLARATIONS));
}

#[test]
fn ten_thousand_blocks() {
    let mut random = Random(42);
    let corpus = [
        ("structured", random_loops(&mut random, 750)),
        ("random acyclic", random_cfg(&mut random, 10_000, 0, 0, 0)),
        (
            "random, 1% back edges",
            random_cfg(&mut random, 10_000, 1, 0, 0),
        ),
        (
            "random acyclic, half the blocks bare",
            random_cfg(&mut random, 10_000, 0, 0, 50),
        ),
    ];
    for (name, before) in corpus {
        let mut after = before.clone();
        let start = Instant::now();
        let stats = structure(&mut after, &Options::default()).unwrap();
        let elapsed = start.elapsed();
        let blocks = before
            .body
            .iter()
            .filter(|&&id| matches!(before.stmts[id.0 as usize], Stmt::Label(_)))
            .count();
        println!("{name}, {blocks} blocks: {elapsed:?} {stats:?}");
        verify(&after, &DECLARATIONS).unwrap();
        assert_eq!(kept_shape(&before, &after), shape(&after));
        let start = Instant::now();
        let merged = short_circuit(&mut after);
        println!("  short circuits: {merged} merged in {:?}", start.elapsed());
        assert_eq!(kept_shape(&before, &after), shape(&after));
    }
}

/// `0: if (p0 == 0) goto 1 else goto 3; 1: [x0 += 1;] if (p1 == 0) goto 2
/// else goto 3; 2: x2 += 1; goto 3; 3: return x2`.
fn nested_ifs(code: bool) -> Ast {
    let mut g = Goto::new(4);
    g.label(0);
    let condition = g.test(Binary::Eq, P0, 0);
    g.branch(condition, (Vec::new(), 1), (Vec::new(), 3));
    g.label(1);
    if code {
        g.step(X[0], 1);
    }
    let condition = g.test(Binary::Eq, P1, 0);
    g.branch(condition, (Vec::new(), 2), (Vec::new(), 3));
    g.label(2);
    g.step(X[2], 1);
    g.jump(3);
    g.label(3);
    g.ret(X[2]);
    g.finish()
}

const BOTH: [[u64; 2]; 4] = [[0, 0], [0, 1], [1, 0], [1, 1]];

#[test]
fn short_circuit_merges_nested_ifs_into_and() {
    let before = nested_ifs(false);
    let (mut after, _, _, merged) = check(&before, &Options::default(), &BOTH);
    assert_eq!(merged, 1);
    short_circuit(&mut after);
    let text = print(&after, &DECLARATIONS);
    assert!(
        text.contains("if and-then(eq(v0, 0x0:32), eq(v1, 0x0:32)) {"),
        "{text}"
    );
    assert_eq!(text.matches("if ").count(), 1, "{text}");
}

#[test]
fn short_circuit_keeps_an_if_with_code_before_it_or_over_budget() {
    // Block 1's code would have to run between the two conditions.
    let (_, _, _, merged) = check(&nested_ifs(true), &Options::default(), &BOTH);
    assert_eq!(merged, 0);
    // One operand per condition allowed: nothing merges.
    let mut after = nested_ifs(false);
    structure(&mut after, &Options::default()).unwrap();
    let mut pass = ShortCircuit::new(1);
    let mut manager = Manager::new(Fuel::new(u64::MAX));
    let env = L2Env {
        declarations: &DECLARATIONS,
        exceptions: &NONE,
        feeds: None,
    };
    let unchanged = after.clone();
    manager.run(&mut pass, &mut after, &env).unwrap();
    assert_eq!((pass.merged(), &after), (0, &unchanged));
}

#[test]
fn short_circuit_merges_breaks_into_or_and_the_loop_condition() {
    // 0: goto 1; 1: if (k < 9) goto 2 else goto 5; 2: if (p0 == 0) goto 5
    // else goto 3; 3: if (p1 == 0) goto 5 else goto 4; 4: x2 += 1;
    // k += 1; goto 1; 5: return x2.
    let mut g = Goto::new(6);
    g.label(0);
    g.jump(1);
    g.label(1);
    let condition = g.test(Binary::ULt, K, 9);
    g.branch(condition, (Vec::new(), 2), (Vec::new(), 5));
    for (block, var) in [(2, P0), (3, P1)] {
        g.label(block);
        let condition = g.test(Binary::Eq, var, 0);
        g.branch(condition, (Vec::new(), 5), (Vec::new(), block + 1));
    }
    g.label(4);
    g.step(X[2], 1);
    g.step(K, 1);
    g.jump(1);
    g.label(5);
    g.ret(X[2]);
    let before = g.finish();
    let (mut after, _, _, merged) = check(&before, &Options::default(), &BOTH);
    // `if (p0 == 0 || p1 == 0) break;`, then that into the loop's condition.
    assert_eq!(merged, 2);
    short_circuit(&mut after);
    let text = print(&after, &DECLARATIONS);
    assert!(
        text.contains(
            "while and-then(and-then(ult(v5, 0x9:32), ne(v0, 0x0:32)), ne(v1, 0x0:32)) {"
        ),
        "{text}"
    );
    assert!(!text.contains("break"), "{text}");
}
