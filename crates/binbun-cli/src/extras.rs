//! Why L2 has parameters and return values the source does not: each
//! extra parameter (an L2 parameter no source parameter maps to) and each
//! extra return value (L2 returns a value, the source `void`) classified
//! by what the function does with it ([`Extras`]).
//!
//! A parameter's reads in the final L2 decide:
//! - none: *unused* (lowering kept it, the L2 passes removed its reads);
//! - a thread pointer or floating-point control register: *environment*;
//! - a register that is no argument register of the convention: *not an
//!   argument register* (code entered mid-frame, a register kept across a
//!   call it never set);
//! - only stored to memory or the frame: *spilled* (a variadic
//!   definition's spills, a save);
//! - only passed, unchanged up to extensions, extractions and casts, as
//!   arguments of calls: *forwarded*, by the root of the chain: through a
//!   pointer, to code with no prototype or interface (rule 1), past a
//!   declared variadic prototype's parameters (rule 1), into a declared
//!   parameter, or into a defined function's parameter, followed into
//!   that function (its own parameter extra: its cause; mapped: a real
//!   parameter);
//! - else *read in the body*.
//!
//! An extra return value: what its `return`s give: a call's result
//! unchanged (*a callee's result left*, `void f(void) { g(); }`), a
//! constant, or a computed value.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use binbun_ast::ir::{
    Block, Call, Callee, Expr, ExprId, Function as Ast, Place, Stmt, VarId, VarKind,
};
use binbun_ast::types::Type;

/// Where a parameter is passed on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Sink {
    /// To a call through a pointer.
    Pointer,
    /// Past a declared variadic signature's parameters.
    Variadic,
    /// Into a declared (typed) parameter.
    Declared,
    /// To a defined function's parameter `index`, at `entry`.
    Defined { entry: u64, index: usize },
}

/// What a function does with a parameter.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Use {
    Unused,
    Environment,
    NotArgument(String),
    Spilled,
    Body,
    Forwarded(BTreeSet<Sink>),
}

/// One decompiled function, as the classification needs it.
#[derive(Clone, Debug, Default)]
pub struct Record {
    /// Each parameter's use, in order.
    uses: Vec<Use>,
    /// Whether each parameter maps to a source parameter (`None`: the
    /// function is not in the debug information).
    mapped: Option<Vec<bool>>,
    /// Why the return value is extra, if it is.
    void_extra: Option<&'static str>,
}

/// The causes of extra parameters and return values, counted.
#[derive(Clone, Debug, Default)]
pub struct Extras {
    records: BTreeMap<u64, Record>,
    /// Extra parameters by cause.
    pub parameters: BTreeMap<String, usize>,
    /// Extra return values by cause.
    pub returns: BTreeMap<String, usize>,
}

/// What the classification knows of the convention, by register name.
#[derive(Clone, Debug, Default)]
pub struct Registers {
    /// The argument registers, integer and vector.
    pub arguments: BTreeSet<String>,
    /// The thread pointer and floating-point control registers.
    pub environment: BTreeSet<String>,
}

impl Extras {
    /// Records `ast` (decompiled from the function at its address): its
    /// parameters' registers by `name`, which map to source parameters
    /// (`mapped`, if the function has debug information), and whether its
    /// return value is extra.
    pub fn record(
        &mut self,
        ast: &Ast,
        name: &dyn Fn(VarId) -> Option<String>,
        registers: &Registers,
        mapped: Option<Vec<bool>>,
        void_extra: bool,
    ) {
        let reads = Reads::of(ast);
        let uses = ast
            .parameters
            .iter()
            .map(|&parameter| {
                let register = name(parameter).unwrap_or_default();
                if registers.environment.contains(&register) {
                    Use::Environment
                } else if !registers.arguments.contains(&register) {
                    Use::NotArgument(register)
                } else {
                    reads.usage(parameter)
                }
            })
            .collect();
        let void_extra = void_extra.then(|| returned(ast));
        self.records.insert(
            ast.address,
            Record {
                uses,
                mapped,
                void_extra,
            },
        );
    }

    /// Counts the causes over the functions recorded.
    pub fn finish(&mut self) {
        let mut parameters = BTreeMap::new();
        let mut returns = BTreeMap::new();
        for (&entry, record) in &self.records {
            if let Some(cause) = record.void_extra {
                *returns.entry(cause.to_owned()).or_insert(0) += 1;
            }
            let Some(mapped) = &record.mapped else {
                continue;
            };
            for (index, (&mapped, _)) in mapped.iter().zip(&record.uses).enumerate() {
                if !mapped {
                    let cause = self.cause(entry, index, &mut BTreeSet::new());
                    *parameters.entry(cause).or_insert(0) += 1;
                }
            }
        }
        self.parameters = parameters;
        self.returns = returns;
    }

    /// The cause of parameter `index` of the function at `entry` being
    /// extra, following forwards (`seen`: the parameters on the chain).
    fn cause(&self, entry: u64, index: usize, seen: &mut BTreeSet<(u64, usize)>) -> String {
        let Some(record) = self.records.get(&entry) else {
            return "forwarded: into a function not decompiled".to_owned();
        };
        if !seen.insert((entry, index)) {
            return "forwarded: around a cycle".to_owned();
        }
        let Some(usage) = record.uses.get(index) else {
            return "forwarded: past the callee's parameters (rule 1, its interface unknown: a cycle break)"
                .to_owned();
        };
        match usage {
            Use::Unused
                if record
                    .uses
                    .iter()
                    .skip(index + 1)
                    .any(|later| *later != Use::Unused) =>
            {
                "unused in L2, before a later parameter".to_owned()
            }
            Use::Unused => "unused in L2".to_owned(),
            Use::Environment => "environment register".to_owned(),
            Use::NotArgument(register) => format!("not an argument register: {register}"),
            Use::Spilled => "only spilled to memory (variadic spills, saves)".to_owned(),
            Use::Body => "read in the body".to_owned(),
            Use::Forwarded(sinks) => {
                let roots: BTreeSet<String> = sinks
                    .iter()
                    .map(|&sink| match sink {
                        Sink::Pointer => {
                            "forwarded: to a call through a pointer (rule 1)".to_owned()
                        }
                        Sink::Variadic => {
                            "forwarded: past a declared variadic signature (rule 1)".to_owned()
                        }
                        Sink::Declared => "forwarded: into a declared parameter".to_owned(),
                        Sink::Defined { entry, index } => self.callee_cause(entry, index, seen),
                    })
                    .collect();
                // The strongest root: a parameter per debug information,
                // else the first.
                roots
                    .iter()
                    .find(|root| root.contains("per debug information"))
                    .or_else(|| roots.iter().next())
                    .cloned()
                    .unwrap_or_default()
            }
        }
    }

    /// The cause of an argument passed to parameter `index` of the
    /// function at `entry`.
    fn callee_cause(&self, entry: u64, index: usize, seen: &mut BTreeSet<(u64, usize)>) -> String {
        let Some(record) = self.records.get(&entry) else {
            return "forwarded: to code with no prototype or interface (rule 1)".to_owned();
        };
        match &record.mapped {
            Some(mapped) if mapped.get(index) == Some(&true) => {
                "forwarded: into a callee's parameter per debug information".to_owned()
            }
            Some(_) => self.cause(entry, index, seen),
            None => "forwarded: into a function without debug information".to_owned(),
        }
    }
}

/// The reads of variables in a function's reachable statements.
struct Reads<'a> {
    ast: &'a Ast,
    /// For each variable, how it is read.
    uses: BTreeMap<VarId, Use>,
}

impl<'a> Reads<'a> {
    fn of(ast: &'a Ast) -> Self {
        let mut reads = Self {
            ast,
            uses: BTreeMap::new(),
        };
        let mut work: Vec<&Block> = vec![&ast.body];
        while let Some(block) = work.pop() {
            for &id in block {
                let Some(stmt) = ast.stmts.get(id.0 as usize) else {
                    continue;
                };
                reads.statement(stmt);
                work.extend(stmt.blocks());
            }
        }
        reads
    }

    /// How `var` is read.
    fn usage(&self, var: VarId) -> Use {
        self.uses.get(&var).cloned().unwrap_or(Use::Unused)
    }

    fn statement(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Call { call, results } => {
                self.call(call);
                for place in results {
                    if let &Place::Memory { address, .. } = place {
                        self.value(address);
                    }
                }
            }
            Stmt::Assign { place, value } => {
                let spill = match *place {
                    Place::Var(var) => self
                        .ast
                        .var(var)
                        .is_some_and(|v| matches!(v.kind, VarKind::Frame(_) | VarKind::Global(_))),
                    Place::Memory { address, .. } => {
                        self.value(address);
                        true
                    }
                };
                match self.plain(*value) {
                    Some(var) if spill => self.add(var, Use::Spilled),
                    Some(_) | None => self.value(*value),
                }
            }
            Stmt::Intrinsic { .. }
            | Stmt::Expr(_)
            | Stmt::If { .. }
            | Stmt::While { .. }
            | Stmt::DoWhile { .. }
            | Stmt::For { .. }
            | Stmt::Switch { .. }
            | Stmt::Break(_)
            | Stmt::Continue(_)
            | Stmt::Label(_)
            | Stmt::Goto(_)
            | Stmt::Return(_)
            | Stmt::Trap(_)
            | Stmt::Unreachable
            | Stmt::Escape { .. }
            | Stmt::Try { .. }
            | Stmt::VaStart { .. } => {
                for root in stmt.roots() {
                    self.value(root);
                }
            }
        }
    }

    fn call(&mut self, call: &Call) {
        let types = &self.ast.types;
        let signature = types.signature(call.signature);
        let fixed = signature.map_or(usize::MAX, |signature| {
            if signature.variadic {
                signature.parameters.len()
            } else {
                usize::MAX
            }
        });
        // A typed parameter is declared; interfaces and unknown callees
        // give widths only.
        let declared: Vec<bool> = signature.map_or_else(Vec::new, |signature| {
            signature
                .parameters
                .iter()
                .map(|&ty| !matches!(types.get(ty), Some(Type::Bits(_)) | None))
                .collect()
        });
        if let Callee::Expr(target) = call.callee {
            self.value(target);
        }
        for (index, &argument) in call.arguments.iter().enumerate() {
            let Some(var) = self.plain(argument) else {
                self.value(argument);
                continue;
            };
            let sink = match call.callee {
                Callee::Address(_) | Callee::Import(_) if index >= fixed => Sink::Variadic,
                Callee::Address(_) | Callee::Import(_) if declared.get(index) == Some(&true) => {
                    Sink::Declared
                }
                // An import without a declared parameter here is passed
                // what it would be through its slot's pointer.
                Callee::Expr(_) | Callee::Import(_) => Sink::Pointer,
                Callee::Address(entry) => Sink::Defined { entry, index },
            };
            self.add(var, Use::Forwarded(BTreeSet::from([sink])));
        }
    }

    /// The variable `id` is, through extensions, extractions and casts.
    fn plain(&self, mut id: ExprId) -> Option<VarId> {
        loop {
            match *self.ast.expr(id)? {
                Expr::Var(var) => return Some(var),
                Expr::Extract { value, .. }
                | Expr::Extend { value, .. }
                | Expr::Cast { value, .. } => {
                    id = value;
                }
                Expr::Const(_)
                | Expr::Undefined(..)
                | Expr::AddressOf(_)
                | Expr::Unary(..)
                | Expr::Binary(..)
                | Expr::Logical(..)
                | Expr::Flag(..)
                | Expr::Concat { .. }
                | Expr::Select { .. }
                | Expr::Lanes { .. }
                | Expr::Float { .. }
                | Expr::Load { .. }
                | Expr::Call(_)
                | Expr::Exception { .. }
                | Expr::Assign { .. } => return None,
            }
        }
    }

    /// Reads in `id`: a call's arguments as for [`Self::call`], the
    /// variables elsewhere read in the body.
    fn value(&mut self, id: ExprId) {
        let mut work = vec![id];
        while let Some(id) = work.pop() {
            let Some(expr) = self.ast.expr(id) else {
                continue;
            };
            match *expr {
                Expr::Var(var) => self.add(var, Use::Body),
                Expr::Call(call) => {
                    if let Some(call) = self.ast.call(call) {
                        let call = call.clone();
                        self.call(&call);
                    }
                }
                Expr::Const(_)
                | Expr::Undefined(..)
                | Expr::AddressOf(_)
                | Expr::Unary(..)
                | Expr::Binary(..)
                | Expr::Logical(..)
                | Expr::Flag(..)
                | Expr::Extract { .. }
                | Expr::Concat { .. }
                | Expr::Extend { .. }
                | Expr::Select { .. }
                | Expr::Lanes { .. }
                | Expr::Float { .. }
                | Expr::Cast { .. }
                | Expr::Load { .. }
                | Expr::Exception { .. }
                | Expr::Assign { .. } => work.extend(expr.operands(self.ast)),
            }
        }
    }

    /// `var` is read as `usage`: a forward joins forwards, a spill joins
    /// spills; anything else is read in the body.
    fn add(&mut self, var: VarId, usage: Use) {
        let joined = match (self.uses.remove(&var), usage) {
            (None | Some(Use::Unused), usage) => usage,
            (Some(Use::Forwarded(mut a)), Use::Forwarded(b)) => {
                a.extend(b);
                Use::Forwarded(a)
            }
            (Some(Use::Spilled), Use::Spilled) => Use::Spilled,
            (Some(_), _) => Use::Body,
        };
        self.uses.insert(var, joined);
    }
}

/// Why a function's return value is extra: what its `return`s give.
fn returned(ast: &Ast) -> &'static str {
    let reads = Reads::of(ast);
    let mut called = BTreeSet::new();
    for stmt in &ast.stmts {
        if let Stmt::Call { results, .. } = stmt {
            for place in results {
                if let &Place::Var(var) = place {
                    called.insert(var);
                }
            }
        }
        if let &Stmt::Assign {
            place: Place::Var(var),
            value,
        } = stmt
            && matches!(ast.expr(value), Some(Expr::Call(_)))
        {
            called.insert(var);
        }
    }
    let mut kinds = BTreeSet::new();
    let mut work: Vec<&Block> = vec![&ast.body];
    while let Some(block) = work.pop() {
        for &id in block {
            let Some(stmt) = ast.stmts.get(id.0 as usize) else {
                continue;
            };
            if let &Stmt::Return(Some(value)) = stmt {
                let plain = reads.plain(value);
                let kind = match (plain, reads.ast.expr(value)) {
                    (_, Some(Expr::Call(_))) => 0,
                    (Some(var), _) if called.contains(&var) => 0,
                    (_, Some(Expr::Const(_) | Expr::Undefined(..))) => 1,
                    _ => 2,
                };
                kinds.insert(kind);
            }
            work.extend(stmt.blocks());
        }
    }
    match (kinds.contains(&2), kinds.contains(&0)) {
        (true, _) => "a computed value",
        (false, true) => "a callee's result left",
        (false, false) => "a constant",
    }
}

impl fmt::Display for Extras {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "extra parameters by cause:")?;
        let mut parameters: Vec<_> = self.parameters.iter().collect();
        parameters.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        for (cause, count) in parameters {
            writeln!(f, "  {count:>6} {cause}")?;
        }
        writeln!(f, "extra return values by cause:")?;
        for (cause, count) in &self.returns {
            writeln!(f, "  {count:>6} {cause}")?;
        }
        Ok(())
    }
}
