//! The semantics language's front end, shared by every architecture: the
//! hand-written semantics files (`crates/binbun-<arch>-lift/semantics/*.rs`)
//! read, and each entry compiled into a Rust function that drives the
//! architecture's lift runtime (its `Lifter`).
//!
//! The semantics language is a strict subset of Rust syntax (parsed here,
//! never compiled as Rust): a fixed list of constructs is allowed and
//! anything else is refused with what to write instead. Entries are `fn`s
//! with an architecture's key attribute (x86: `#[iclass(...)]`,
//! `#[iform(...)]`; AArch64: `#[operation(...)]`); other `fn`s are
//! helpers, inlined where called.
//! What is architecture-specific (names of registers and flags, built-ins
//! of the architecture's runtime, trap kinds, what ends an entry) is a
//! [`Target`]; checking entries against an architecture's operand
//! metadata stays with the architecture's generator.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use proc_macro2::{Delimiter, Ident, Span, TokenStream, TokenTree};
use quote::{ToTokens, format_ident, quote};
use syn::spanned::Spanned;
use syn::{BinOp, Expr, ExprCall, ExprIf, ExprLit, Item, ItemFn, Lit, Pat, Stmt, UnOp};

use crate::Result;

/// A mistake in a semantics file, with its place.
pub fn at(file: &Path, span: Span, message: impl std::fmt::Display) -> Box<dyn std::error::Error> {
    let start = span.start();
    format!(
        "{}:{}:{}: {message}",
        file.display(),
        start.line,
        start.column + 1
    )
    .into()
}

/// One entry: the semantics of some forms.
pub struct Entry {
    pub file: PathBuf,
    pub function: ItemFn,
    /// The names of each key attribute, in the order of the attributes
    /// [`read_semantics`] was given.
    pub keys: Vec<Vec<String>>,
    pub params: Vec<String>,
}

/// Names listed in `#[name(A, B, ...)]` attributes.
fn attribute_names(function: &ItemFn, name: &str, file: &Path) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for attribute in &function.attrs {
        if !attribute.path().is_ident(name) {
            continue;
        }
        attribute
            .parse_nested_meta(|meta| {
                let name = meta
                    .path
                    .get_ident()
                    .ok_or_else(|| meta.error("expected a name"))?;
                names.push(name.to_string());
                Ok(())
            })
            .map_err(|e| at(file, e.span(), e))?;
    }
    Ok(names)
}

/// Helper functions by name, with their files.
pub type Helpers = HashMap<String, (PathBuf, ItemFn)>;

/// Reads every semantics file of `directory` (relative to `root`): entries
/// (functions with one of the key `attributes`) and helpers.
pub fn read_semantics(
    root: &Path,
    directory: &str,
    attributes: &[&str],
) -> Result<(Vec<Entry>, Helpers)> {
    let directory = root.join(directory);
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&directory)
        .map_err(|e| format!("{}: {e}", directory.display()))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.extension().is_some_and(|e| e == "rs"))
        .collect();
    paths.sort();
    let mut entries = Vec::new();
    let mut helpers = HashMap::new();
    for path in paths {
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let relative = path.strip_prefix(root).unwrap_or(&path).to_owned();
        let file = syn::parse_file(&text).map_err(|e| at(&relative, e.span(), e))?;
        for item in file.items {
            let Item::Fn(function) = item else {
                return Err(at(&relative, item.span(), "only `fn` items are allowed"));
            };
            for attribute in &function.attrs {
                if !attributes
                    .iter()
                    .any(|name| attribute.path().is_ident(name))
                {
                    return Err(at(&relative, attribute.span(), "unknown attribute"));
                }
            }
            let keys = attributes
                .iter()
                .map(|name| attribute_names(&function, name, &relative))
                .collect::<Result<Vec<_>>>()?;
            let mut params = Vec::new();
            for input in &function.sig.inputs {
                let syn::FnArg::Typed(typed) = input else {
                    return Err(at(&relative, input.span(), "no `self` in semantics"));
                };
                let Pat::Ident(name) = &*typed.pat else {
                    return Err(at(
                        &relative,
                        typed.pat.span(),
                        "parameters are plain names",
                    ));
                };
                params.push(name.ident.to_string());
            }
            if keys.iter().all(Vec::is_empty) {
                let name = function.sig.ident.to_string();
                if helpers
                    .insert(name.clone(), (relative.clone(), function))
                    .is_some()
                {
                    return Err(format!("helper `{name}` defined twice").into());
                }
            } else {
                entries.push(Entry {
                    file: relative.clone(),
                    function,
                    keys,
                    params,
                });
            }
        }
    }
    Ok((entries, helpers))
}

/// What an entry does, for checking it against forms.
#[derive(Debug, Default)]
pub struct Summary {
    /// Parameters assigned anywhere.
    pub assigned: BTreeSet<usize>,
    /// Parameters read from their operand.
    pub read: BTreeSet<usize>,
    /// Parameters whose operand's value the entry reads (not only an
    /// address or a part of it): when it starts, or later if it never
    /// assigns them (so the value as read can still be read).
    pub values: BTreeSet<usize>,
    /// Parameters assigned a value (`p = ...`), not only stored into.
    pub whole: BTreeSet<usize>,
    /// Flags the entry reads before it assigns them.
    pub read_flags: BTreeSet<&'static str>,
    /// The sites of the entry's undefined values, named, with the output
    /// each goes to, in the order the entry makes them.
    pub sites: Vec<(String, String)>,
    /// Flags assigned anywhere.
    pub flags: BTreeSet<&'static str>,
    pub transfers: bool,
    /// Whether the entry enters the operating system.
    pub system_call: bool,
    /// Whether the entry always traps (its last top-level statement is a
    /// trap): it never completes, so the effects an architecture's metadata
    /// gives the instruction (x86: XED's flags and instruction pointer,
    /// those of delivering the exception) do not apply.
    pub always_traps: bool,
}

/// What an architecture adds to the semantics language. Its own state
/// (what it records about an entry beyond [`Summary`], the tables it
/// names registers from) is the compiler's [`Compiler::arch`].
pub trait Target: Sized {
    /// Built-ins whose first argument is an operand they access themselves
    /// (not its value): an entry does not read that operand by using them.
    const OPERAND_BUILT_INS: &'static [&'static str];
    /// Built-ins (besides `width`) whose arguments are not read at all.
    const NOT_READING: &'static [&'static str];
    /// The trap kinds, as the error for an unknown one lists them.
    const TRAPS: &'static str;
    /// Whether undefined values are sites ([`site_constant`]): the
    /// generated code then names each (`l.site(sites::SHRD_OF, ...)`).
    const SITES: bool = false;

    /// Whether `name` is reserved: flags and registers the semantics name
    /// are always read and written as such, so a parameter or `let` of that
    /// name would silently mean them.
    fn reserved(name: &str) -> bool;

    /// The value of parameter `index` if it is known when lifting (an
    /// AArch64 immediate): computed when the entry starts, never read from
    /// its operand.
    fn parameter(c: &mut Compiler<'_, Self>, index: usize) -> Option<Val> {
        let _ = (c, index);
        None
    }

    /// The value of `name` if the architecture gives it one (a register, a
    /// flag, a lift-time property such as x86's `osz`); bindings shadow
    /// registers (the target checks [`Compiler::lookup`]).
    ///
    /// # Errors
    ///
    /// A misused name.
    fn read(c: &mut Compiler<'_, Self>, name: &str, span: Span) -> Result<Option<Val>>;

    /// Compiles `name = right` if `name` is the architecture's (a flag, a
    /// register): whether it was.
    ///
    /// # Errors
    ///
    /// As for the value.
    fn assign(c: &mut Compiler<'_, Self>, name: &str, right: &Expr) -> Result<bool>;

    /// Compiles a call of the architecture's built-in `name`, or `None` if
    /// there is none of that name (then helpers are tried).
    ///
    /// # Errors
    ///
    /// A misused built-in.
    fn call(
        c: &mut Compiler<'_, Self>,
        name: &str,
        args: &[&Expr],
        span: Span,
    ) -> Result<Option<Val>>;

    /// The L0 trap (`Trap::...` code) of `trap(kind)`.
    fn trap(kind: &str) -> Option<TokenStream>;

    /// Code run when the entry completes (x86: the flags XED fixes).
    fn finish(c: &Compiler<'_, Self>) -> Option<TokenStream>;
}

/// A value during compilation.
#[derive(Clone)]
pub enum Val {
    /// Known at lift time: a Rust `u64` expression.
    Static(TokenStream),
    /// An L0 expression: the Rust variable holding its `ExprId`.
    Dyn(Ident),
    /// `undefined()`, its width still to come from its use, and its site
    /// (the constant naming it), if the architecture has sites.
    Undefined(Option<Ident>),
}

/// What a name stands for in a scope.
#[derive(Clone)]
pub enum Binding {
    /// Parameter `index`: its current value, or `None` if it must be read
    /// from the operand (not read yet, or after a conditional assignment).
    /// Operands used at the entry's top level are read when it starts (the
    /// processor reads operands before its effects: `call rsp` jumps to
    /// the old rsp); the others where first used, so a read the instruction
    /// makes only sometimes (a `rep` with a count of 0) stays conditional.
    Param(usize, Option<Val>),
    /// A `let`, and the scope depth it was made at.
    Local(Val, usize),
    /// A `let` a `for` loop assigns: a mutable Rust variable holding an L0
    /// value.
    Mutable(Ident),
}

/// Compiles one entry for an architecture `T`.
pub struct Compiler<'a, T> {
    pub file: &'a Path,
    helpers: &'a HashMap<String, (PathBuf, ItemFn)>,
    /// The architecture's state.
    pub arch: T,
    pub out: Vec<TokenStream>,
    scopes: Vec<HashMap<String, Binding>>,
    counter: usize,
    pub summary: Summary,
    /// Effectful operations emitted (to keep them out of `if` expressions).
    pub effects: usize,
    /// Helpers being inlined (no recursion).
    inlining: Vec<String>,
    /// Inside `status(...)`: floating-point built-ins give exceptions.
    status: bool,
    /// Parameters the entry has assigned unconditionally: reading them
    /// again reads the entry's own value, not the operand's input.
    pub written: BTreeSet<usize>,
    /// How many `if`s decided at lift time (on a value known only when
    /// lifting, such as an immediate, not a literal) enclose the code being
    /// compiled: effects in them happen for some words of the entry only.
    pub lift_time_ifs: usize,
    /// The variables holding targets `target(x)` checked: a transfer to
    /// one checks nothing more.
    targets: BTreeSet<Ident>,
    /// The entry's name, which its sites are named after.
    entry: String,
    /// How many parameters the entry has.
    params: usize,
    /// The output (a flag, register or parameter) the value being compiled
    /// is assigned to; `None` in a `let`.
    assigning: Option<String>,
    /// Parameters read where first used ([`Binding::Param`]).
    lazy: BTreeSet<usize>,
}

/// Compiles `entry` (with `helpers`) for the architecture whose state
/// starts as `arch`: a function `fn name(l: &mut Lifter<'_>, p: [usize; N])`
/// (`p`: the operand of each parameter), what the entry does, and the
/// architecture's state after it.
///
/// # Errors
///
/// The entry is not valid semantics.
pub fn compile<T: Target>(
    entry: &Entry,
    helpers: &Helpers,
    arch: T,
) -> Result<(TokenStream, Summary, T)> {
    let mut c = Compiler {
        file: &entry.file,
        helpers,
        arch,
        out: Vec::new(),
        scopes: vec![HashMap::new()],
        counter: 0,
        summary: Summary::default(),
        effects: 0,
        inlining: Vec::new(),
        status: false,
        written: BTreeSet::new(),
        lift_time_ifs: 0,
        targets: BTreeSet::new(),
        entry: entry.function.sig.ident.to_string(),
        params: entry.params.len(),
        assigning: None,
        lazy: BTreeSet::new(),
    };
    let eager = top_level_names::<T>(&entry.function.block.stmts);
    for (index, name) in entry.params.iter().enumerate() {
        c.declare(name, entry.function.sig.ident.span())?;
        if let Some(value) = T::parameter(&mut c, index) {
            c.bind(name, Binding::Param(index, Some(value)));
        } else if eager.contains(name) {
            c.summary.read.insert(index);
            c.summary.values.insert(index);
            let value = c.emit(quote!(l.read(p[#index])));
            c.bind(name, Binding::Param(index, Some(Val::Dyn(value))));
        } else {
            c.bind(name, Binding::Param(index, None));
        }
    }
    c.block(&entry.function.block.stmts)?;
    let lazy: Vec<usize> = c.lazy.difference(&c.summary.whole).copied().collect();
    c.summary.values.extend(lazy);
    let name = &entry.function.sig.ident;
    let count = entry.params.len();
    let body = &c.out;
    let doc = format!(" `{}` in {}.", name, entry.file.display());
    let signature = if count == 0 {
        quote!(fn #name(l: &mut Lifter<'_>))
    } else {
        quote!(fn #name(l: &mut Lifter<'_>, p: [usize; #count]))
    };
    let finish = T::finish(&c);
    let tokens = quote! {
        #[doc = #doc]
        #[allow(unused_variables, unused_mut, unused_assignments, unused_parens, unused_braces, clippy::collapsible_else_if, clippy::double_parens, clippy::identity_op, clippy::let_and_return, clippy::similar_names, clippy::too_many_lines, clippy::unreadable_literal, reason = "generated straight from the semantics")]
        #signature {
            #(#body)*
            #finish
        }
    };
    Ok((tokens, c.summary, c.arch))
}

/// The names used by `statements` outside any `{ }` block, other than as
/// the target of an assignment, the arguments of `width(...)` and the
/// target's [`Target::NOT_READING`] built-ins (which read nothing), or the
/// operand (first) argument of [`Target::OPERAND_BUILT_INS`] (which read it
/// where they are): what an entry reads unconditionally.
fn top_level_names<T: Target>(statements: &[Stmt]) -> BTreeSet<String> {
    fn walk<T: Target>(tokens: TokenStream, names: &mut BTreeSet<String>) {
        let mut after_width = false;
        let mut after_operand = false;
        for token in tokens {
            let skip = std::mem::take(&mut after_width);
            let first = std::mem::take(&mut after_operand);
            match token {
                TokenTree::Ident(ident) => {
                    after_width =
                        ident == "width" || T::NOT_READING.iter().any(|name| ident == name);
                    after_operand = T::OPERAND_BUILT_INS.iter().any(|name| ident == *name);
                    names.insert(ident.to_string());
                }
                TokenTree::Group(group) if group.delimiter() == Delimiter::Parenthesis && first => {
                    walk::<T>(group.stream().into_iter().skip(1).collect(), names);
                }
                TokenTree::Group(group) if group.delimiter() != Delimiter::Brace && !skip => {
                    walk::<T>(group.stream(), names);
                }
                TokenTree::Group(_) | TokenTree::Punct(_) | TokenTree::Literal(_) => {}
            }
        }
    }
    let mut names = BTreeSet::new();
    for statement in statements {
        let tokens = match statement {
            Stmt::Expr(Expr::Assign(assign), _) => assign.right.to_token_stream(),
            Stmt::Local(local) => local
                .init
                .as_ref()
                .map(|init| init.expr.to_token_stream())
                .unwrap_or_default(),
            other @ (Stmt::Item(_) | Stmt::Expr(..) | Stmt::Macro(_)) => other.to_token_stream(),
        };
        walk::<T>(tokens, &mut names);
    }
    names
}

/// The Rust constant naming site `name` in the generated site table:
/// `shrd.of` is `SHRD_OF`.
pub fn site_constant(name: &str) -> Ident {
    format_ident!("{}", name.to_ascii_uppercase().replace('.', "_"))
}

/// The number a lift-time value is, if it is a literal.
pub fn literal(value: &TokenStream) -> Option<u64> {
    let mut tokens = value.clone().into_iter();
    match (tokens.next(), tokens.next()) {
        (Some(TokenTree::Literal(number)), None) => number
            .to_string()
            .trim_end_matches("u64")
            .replace('_', "")
            .parse()
            .ok(),
        (Some(TokenTree::Group(group)), None) if group.delimiter() == Delimiter::Parenthesis => {
            literal(&group.stream())
        }
        _ => None,
    }
}

/// `x op y` on lift-time numbers, as the generated code would compute it.
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "syn's `BinOp` is non_exhaustive"
)]
fn fold(op: &BinOp, x: u64, y: u64) -> Option<u64> {
    let shift = |f: fn(u64, u32) -> Option<u64>| {
        Some(
            u32::try_from(y)
                .ok()
                .and_then(|count| f(x, count))
                .unwrap_or(0),
        )
    };
    Some(match op {
        BinOp::Add(_) => x.wrapping_add(y),
        BinOp::Sub(_) => x.wrapping_sub(y),
        BinOp::Mul(_) => x.wrapping_mul(y),
        BinOp::Div(_) => x.checked_div(y).unwrap_or_default(),
        BinOp::BitAnd(_) => x & y,
        BinOp::BitOr(_) => x | y,
        BinOp::BitXor(_) => x ^ y,
        BinOp::Shl(_) => return shift(u64::checked_shl),
        BinOp::Shr(_) => return shift(u64::checked_shr),
        BinOp::Eq(_) => u64::from(x == y),
        BinOp::Ne(_) => u64::from(x != y),
        BinOp::Lt(_) => u64::from(x < y),
        BinOp::Le(_) => u64::from(x <= y),
        BinOp::Gt(_) => u64::from(x > y),
        BinOp::Ge(_) => u64::from(x >= y),
        BinOp::And(_) => u64::from(x != 0 && y != 0),
        BinOp::Or(_) => u64::from(x != 0 || y != 0),
        _ => return None,
    })
}

/// The names `statements` assign to, anywhere inside.
fn assigned_names(statements: &[Stmt]) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for statement in statements {
        if let Stmt::Expr(expr, _) = statement {
            assigned_in(expr, &mut names);
        }
    }
    names
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "syn's `Expr` is non_exhaustive"
)]
fn assigned_in(expr: &Expr, names: &mut BTreeSet<String>) {
    match expr {
        Expr::Assign(assign) => {
            if let Expr::Path(path) = &*assign.left
                && let Some(ident) = path.path.get_ident()
            {
                names.insert(ident.to_string());
            }
        }
        Expr::If(e) => {
            names.extend(assigned_names(&e.then_branch.stmts));
            if let Some((_, otherwise)) = &e.else_branch {
                assigned_in(otherwise, names);
            }
        }
        Expr::Block(block) => names.extend(assigned_names(&block.block.stmts)),
        Expr::ForLoop(f) => names.extend(assigned_names(&f.body.stmts)),
        Expr::While(w) => names.extend(assigned_names(&w.body.stmts)),
        _ => {}
    }
}

impl<T: Target> Compiler<'_, T> {
    /// A mistake at `span` of the entry's file.
    pub fn error(&self, span: Span, message: impl std::fmt::Display) -> Box<dyn std::error::Error> {
        at(self.file, span, message)
    }

    /// A new Rust variable name.
    pub fn fresh(&mut self) -> Ident {
        self.counter += 1;
        format_ident!("v{}", self.counter)
    }

    /// Emits `let vN = <code>;` and returns `vN`.
    pub fn emit(&mut self, code: TokenStream) -> Ident {
        let name = self.fresh();
        let mut statement = quote!(let #name =);
        statement.extend(code);
        statement.extend(quote!(;));
        self.out.push(statement);
        name
    }

    /// `intrinsic("name", inputs...)` with `count` outputs: the variables
    /// holding them.
    fn intrinsic(&mut self, call: &ExprCall, count: usize) -> Result<Vec<Ident>> {
        let is_intrinsic =
            matches!(&*call.func, Expr::Path(path) if path.path.is_ident("intrinsic"));
        let mut args = call.args.iter();
        let Some(Expr::Lit(ExprLit {
            lit: Lit::Str(name),
            ..
        })) = args.next().filter(|_| is_intrinsic)
        else {
            return Err(self.error(call.span(), "expected `intrinsic(\"name\", inputs...)`"));
        };
        let mut inputs = Vec::new();
        for arg in args {
            let Val::Dyn(input) = self.expr(arg, None)? else {
                return Err(self.error(arg.span(), "an intrinsic's input is an L0 value"));
            };
            inputs.push(input);
        }
        let outputs: Vec<Ident> = (0..count).map(|_| self.fresh()).collect();
        self.effects += 1;
        self.out.push(quote!(
            let [#(#outputs),*] = l.intrinsic::<#count>(#name, &[#(#inputs),*]);
        ));
        Ok(outputs)
    }

    /// Fails if `name` cannot be bound: flags and the registers named in
    /// semantics are always read and written as such ([`Target::reserved`]).
    fn declare(&self, name: &str, span: Span) -> Result<()> {
        if T::reserved(name) {
            return Err(self.error(
                span,
                format!("`{name}` names a flag or register: choose another name"),
            ));
        }
        Ok(())
    }

    fn bind(&mut self, name: &str, binding: Binding) {
        if let Some(scope) = self.scopes.last_mut() {
            scope.insert(name.to_owned(), binding);
        }
    }

    /// What `name` is bound to in the current scope.
    pub fn lookup(&self, name: &str) -> Option<Binding> {
        self.scopes
            .iter()
            .rev()
            .find_map(|scope| scope.get(name).cloned())
    }

    /// Runs `f` in a new scope; parameters assigned in it must be read
    /// again afterwards (the assignment may not have happened).
    fn scoped<R>(&mut self, f: impl FnOnce(&mut Self) -> Result<R>) -> Result<R> {
        self.scopes.push(HashMap::new());
        let result = f(self);
        let scope = self.scopes.pop().unwrap_or_default();
        for (name, binding) in scope {
            if let Binding::Param(index, _) = binding {
                self.bind(&name, Binding::Param(index, None));
            }
        }
        result
    }

    /// Runs `f`, collecting what it emits instead of emitting it.
    fn capture(&mut self, f: impl FnOnce(&mut Self) -> Result<()>) -> Result<Vec<TokenStream>> {
        let saved = std::mem::take(&mut self.out);
        let result = f(self);
        let captured = std::mem::replace(&mut self.out, saved);
        result.map(|()| captured)
    }

    fn block(&mut self, statements: &[Stmt]) -> Result<()> {
        for statement in statements {
            self.statement(statement)?;
        }
        Ok(())
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn's `Expr` is non_exhaustive"
    )]
    fn statement(&mut self, statement: &Stmt) -> Result<()> {
        match statement {
            // `let (a, b, ...) = intrinsic(...)`: one name per output.
            Stmt::Local(local) if matches!(local.pat, Pat::Tuple(_)) => {
                let Pat::Tuple(tuple) = &local.pat else {
                    return Err(self.error(local.pat.span(), "`let` binds names"));
                };
                let names = tuple
                    .elems
                    .iter()
                    .map(|pat| match pat {
                        Pat::Ident(name) => Ok(name.ident.to_string()),
                        other => Err(self.error(other.span(), "bind a name")),
                    })
                    .collect::<Result<Vec<_>>>()?;
                let Some(Expr::Call(call)) = local.init.as_ref().map(|init| &*init.expr) else {
                    return Err(
                        self.error(local.span(), "several names come from `intrinsic(...)`")
                    );
                };
                for name in &names {
                    self.declare(name, local.pat.span())?;
                }
                let outputs = self.intrinsic(call, names.len())?;
                let depth = self.scopes.len();
                for (name, output) in names.iter().zip(outputs) {
                    self.bind(name, Binding::Local(Val::Dyn(output), depth));
                }
                Ok(())
            }
            Stmt::Local(local) => {
                let Pat::Ident(name) = &local.pat else {
                    return Err(self.error(local.pat.span(), "`let` binds one name"));
                };
                let Some(init) = &local.init else {
                    return Err(self.error(local.span(), "`let` needs a value"));
                };
                self.declare(&name.ident.to_string(), name.span())?;
                let saved = self.assigning.take();
                let value = self.expr(&init.expr, None);
                self.assigning = saved;
                let value = value?;
                let depth = self.scopes.len();
                self.bind(&name.ident.to_string(), Binding::Local(value, depth));
                Ok(())
            }
            Stmt::Expr(expr, semicolon) => match expr {
                Expr::If(e) => self.if_statement(e),
                Expr::ForLoop(f) => self.for_loop(f),
                Expr::While(w) => {
                    self.out.push(quote!(l.b.begin_loop();));
                    let condition = self.expr(&w.cond, None)?;
                    let Val::Dyn(condition) = condition else {
                        return Err(self.error(
                            w.cond.span(),
                            "a `while` condition depends on the instruction's state",
                        ));
                    };
                    self.out.push(quote!({
                        let done = l.b.unary(Unary::Not, #condition);
                        l.b.begin_if(done);
                        l.b.brk();
                        l.b.end_if();
                    }));
                    self.scoped(|c| c.block(&w.body.stmts))?;
                    self.out.push(quote!(l.b.end_loop();));
                    Ok(())
                }
                Expr::Assign(assign) => self.assign(&assign.left, &assign.right),
                Expr::Call(call) => {
                    if semicolon.is_none() {
                        return Err(self
                            .error(call.span(), "entries return nothing: end the call with `;`"));
                    }
                    // An intrinsic without outputs (a fence).
                    if matches!(&*call.func, Expr::Path(path) if path.path.is_ident("intrinsic")) {
                        return self.intrinsic(call, 0).map(|_| ());
                    }
                    self.call(call, None).map(|_| ())
                }
                other => Err(self.error(other.span(), "not a statement of the semantics language")),
            },
            Stmt::Item(item) => Err(self.error(item.span(), "no items inside entries")),
            Stmt::Macro(m) => Err(self.error(m.span(), "no macros in semantics")),
        }
    }

    fn if_statement(&mut self, e: &ExprIf) -> Result<()> {
        let condition = self.expr(&e.cond, None)?;
        let otherwise = e.else_branch.as_ref().map(|(_, branch)| &**branch);
        match condition {
            Val::Dyn(condition) => {
                self.out.push(quote!(l.b.begin_if(#condition);));
                self.scoped(|c| c.block(&e.then_branch.stmts))?;
                if let Some(branch) = otherwise {
                    self.out.push(quote!(l.b.otherwise();));
                    self.scoped(|c| c.else_branch(branch))?;
                }
                self.out.push(quote!(l.b.end_if();));
            }
            Val::Static(condition) if literal(&condition).is_some() => {
                if literal(&condition) != Some(0) {
                    self.scoped(|c| c.block(&e.then_branch.stmts))?;
                } else if let Some(branch) = otherwise {
                    self.scoped(|c| c.else_branch(branch))?;
                }
            }
            Val::Static(condition) => {
                self.lift_time_ifs += 1;
                let then = self.capture(|c| c.scoped(|c| c.block(&e.then_branch.stmts)))?;
                let otherwise = match otherwise {
                    Some(branch) => self.capture(|c| c.scoped(|c| c.else_branch(branch)))?,
                    None => Vec::new(),
                };
                self.lift_time_ifs -= 1;
                // An `else if` decided at lift time stays one.
                let chained = match otherwise.as_slice() {
                    [only] => only
                        .clone()
                        .into_iter()
                        .next()
                        .is_some_and(|token| token.to_string() == "if"),
                    _ => false,
                };
                self.out.push(if otherwise.is_empty() {
                    quote!(if #condition != 0 { #(#then)* })
                } else if chained {
                    quote!(if #condition != 0 { #(#then)* } else #(#otherwise)*)
                } else {
                    quote!(if #condition != 0 { #(#then)* } else { #(#otherwise)* })
                });
            }
            Val::Undefined(_) => {
                return Err(self.error(e.cond.span(), "an `if` on an undefined value"));
            }
        }
        Ok(())
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn's `Expr` is non_exhaustive"
    )]
    fn else_branch(&mut self, branch: &Expr) -> Result<()> {
        match branch {
            Expr::Block(block) => self.block(&block.block.stmts),
            Expr::If(e) => self.if_statement(e),
            other => Err(self.error(other.span(), "expected a block or `else if`")),
        }
    }

    fn assign(&mut self, left: &Expr, right: &Expr) -> Result<()> {
        let Expr::Path(path) = left else {
            return Err(self.error(left.span(), "assign to an operand, flag, register or `let`"));
        };
        let name = path
            .path
            .get_ident()
            .map(ToString::to_string)
            .unwrap_or_default();
        // An `undefined()` on the right goes to `name`, unless it is a `let`.
        let output = match self.lookup(&name) {
            Some(Binding::Local(..) | Binding::Mutable(_)) => None,
            Some(Binding::Param(..)) | None => Some(name.clone()),
        };
        let saved = std::mem::replace(&mut self.assigning, output);
        let result = self.assign_to(&name, left, right);
        self.assigning = saved;
        result
    }

    fn assign_to(&mut self, name: &str, left: &Expr, right: &Expr) -> Result<()> {
        if T::assign(self, name, right)? {
            return Ok(());
        }
        match self.lookup(name) {
            Some(Binding::Param(index, _)) => {
                let width = quote!(l.width(p[#index]));
                let value = self.expr(right, Some(&width))?;
                let value = self.materialize(value, &width);
                self.out.push(quote!(l.write(p[#index], #value);));
                self.summary.assigned.insert(index);
                self.summary.whole.insert(index);
                if self.scopes.len() == 1 {
                    self.written.insert(index);
                }
                self.bind(name, Binding::Param(index, Some(Val::Dyn(value))));
                Ok(())
            }
            Some(Binding::Mutable(variable)) => {
                let value = self.expr(right, None)?;
                let Val::Dyn(value) = value else {
                    return Err(
                        self.error(right.span(), "a value a `for` loop carries is an L0 value")
                    );
                };
                self.out.push(quote!(#variable = #value;));
                Ok(())
            }
            Some(Binding::Local(_, depth)) => {
                if depth != self.scopes.len() {
                    return Err(self.error(
                        left.span(),
                        "a `let` made outside an `if` or `while` cannot be assigned inside it",
                    ));
                }
                let value = self.expr(right, None)?;
                self.bind(name, Binding::Local(value, depth));
                Ok(())
            }
            None => Err(self.error(left.span(), format!("unknown name `{name}`"))),
        }
    }

    /// `value` as an L0 expression `width` bits wide if it is not one yet.
    pub fn materialize(&mut self, value: Val, width: &TokenStream) -> Ident {
        match value {
            Val::Dyn(id) => id,
            Val::Static(v) => self.emit(quote!(l.constant(#width, #v))),
            Val::Undefined(site) => self.undefined_value(site.as_ref(), width),
        }
    }

    /// `value` as an L0 expression as wide as `like`.
    fn like(&mut self, value: Val, like: &Ident) -> Ident {
        match value {
            Val::Dyn(id) => id,
            Val::Static(v) => self.emit(quote!(l.literal(#like, #v))),
            Val::Undefined(site) => self.undefined_like(site.as_ref(), like),
        }
    }

    /// The site of an `undefined()` the entry has here: named after the
    /// entry and `label` or else the output being assigned (`shrd.of`),
    /// whose value it is part of (else the label's). `None` for an
    /// architecture without sites.
    fn site(&mut self, label: Option<String>, span: Span) -> Result<Option<Ident>> {
        if !T::SITES {
            return Ok(None);
        }
        let Some(label) = label.or_else(|| self.assigning.clone()) else {
            return Err(self.error(
                span,
                "name the output this undefined value goes to: `undefined(\"dst\")`",
            ));
        };
        let output = self.assigning.clone().unwrap_or_else(|| label.clone());
        let name = format!("{}.{label}", self.entry);
        let constant = site_constant(&name);
        if !self.summary.sites.iter().any(|(own, _)| *own == name) {
            self.summary.sites.push((name, output));
        }
        Ok(Some(constant))
    }

    /// The operands of the entry, for the lifter to find a site's inputs.
    pub fn positions(&self) -> TokenStream {
        if self.params == 0 {
            quote!(&[])
        } else {
            quote!(&p)
        }
    }

    /// The entry's name.
    pub fn entry(&self) -> &str {
        &self.entry
    }

    /// A new undefined value of `site`, `width` bits wide.
    fn undefined_value(&mut self, site: Option<&Ident>, width: &TokenStream) -> Ident {
        let positions = self.positions();
        match site {
            Some(site) => self.emit(quote!(l.site(sites::#site, #width, #positions))),
            None => self.emit(quote!(l.undefined(#width))),
        }
    }

    /// A new undefined value of `site`, as wide as `like`.
    fn undefined_like(&mut self, site: Option<&Ident>, like: &Ident) -> Ident {
        let positions = self.positions();
        match site {
            Some(site) => self.emit(quote!(l.site_like(sites::#site, #like, #positions))),
            None => self.emit(quote!(l.undefined_like(#like))),
        }
    }

    /// Two operands of an operation as L0 expressions of one width.
    fn pair(
        &mut self,
        a: Val,
        b: Val,
        hint: Option<&TokenStream>,
        span: Span,
    ) -> Result<(Ident, Ident)> {
        Ok(match (a, b) {
            (Val::Dyn(a), b) => {
                let b = self.like(b, &a);
                (a, b)
            }
            (a, Val::Dyn(b)) => {
                let a = self.like(a, &b);
                (a, b)
            }
            (a, b) => {
                let Some(width) = hint else {
                    return Err(self.error(span, "the width of this value is not known: write it as an operand's or with zext"));
                };
                let width = width.clone();
                (self.materialize(a, &width), self.materialize(b, &width))
            }
        })
    }

    /// Compiles expression `e` (`hint`: the width of its use, if known).
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn's `Expr` is non_exhaustive"
    )]
    pub fn expr(&mut self, e: &Expr, hint: Option<&TokenStream>) -> Result<Val> {
        match e {
            Expr::Lit(ExprLit {
                lit: Lit::Int(n), ..
            }) => {
                let value: u64 = n.base10_parse().map_err(|err| self.error(n.span(), err))?;
                Ok(Val::Static(quote!(#value)))
            }
            Expr::Lit(lit) => Err(self.error(lit.span(), "only integer literals")),
            Expr::Paren(p) => self.expr(&p.expr, hint),
            Expr::Group(g) => self.expr(&g.expr, hint),
            Expr::Path(path) => {
                let name = path
                    .path
                    .get_ident()
                    .map(ToString::to_string)
                    .unwrap_or_default();
                self.name(&name, path.span())
            }
            Expr::Binary(binary) => self.binary(binary, hint),
            Expr::Unary(unary) => {
                let value = self.expr(&unary.expr, hint)?;
                match (&unary.op, value) {
                    (UnOp::Not(_), Val::Static(v)) => {
                        Ok(Val::Static(if let Some(x) = literal(&v) {
                            let value = u64::from(x == 0);
                            quote!(#value)
                        } else {
                            quote!(u64::from(#v == 0))
                        }))
                    }
                    (UnOp::Neg(_), Val::Static(v)) => Ok(Val::Static(quote!(#v.wrapping_neg()))),
                    (UnOp::Not(_), Val::Dyn(v)) => {
                        Ok(Val::Dyn(self.emit(quote!(l.unary(Unary::Not, #v)))))
                    }
                    (UnOp::Neg(_), Val::Dyn(v)) => {
                        Ok(Val::Dyn(self.emit(quote!(l.unary(Unary::Neg, #v)))))
                    }
                    (_, _) => {
                        Err(self.error(unary.span(), "not an operation of the semantics language"))
                    }
                }
            }
            Expr::If(e) => self.if_expression(e, hint),
            Expr::Call(call) => self.call(call, hint),
            Expr::MethodCall(m) => Err(self.error(m.span(), "no method calls: write `f(x, ...)`")),
            Expr::Cast(c) => Err(self.error(c.span(), "no `as`: use zext, sext, trunc or fit")),
            Expr::Closure(c) => Err(self.error(c.span(), "no closures")),
            Expr::Match(m) => Err(self.error(m.span(), "no `match`: use `if`")),
            other => Err(self.error(other.span(), "not an expression of the semantics language")),
        }
    }

    fn name(&mut self, name: &str, span: Span) -> Result<Val> {
        if let Some(value) = T::read(self, name, span)? {
            return Ok(value);
        }
        match self.lookup(name) {
            Some(Binding::Param(_, Some(value)) | Binding::Local(value, _)) => Ok(value),
            Some(Binding::Mutable(variable)) => Ok(Val::Dyn(variable)),
            Some(Binding::Param(index, None)) => {
                if !self.written.contains(&index) {
                    self.summary.read.insert(index);
                    self.lazy.insert(index);
                }
                let value = self.emit(quote!(l.read(p[#index])));
                self.bind(name, Binding::Param(index, Some(Val::Dyn(value.clone()))));
                Ok(Val::Dyn(value))
            }
            None => Err(self.error(span, format!("unknown name `{name}`"))),
        }
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn's `BinOp` is non_exhaustive"
    )]
    fn binary(&mut self, binary: &syn::ExprBinary, hint: Option<&TokenStream>) -> Result<Val> {
        let span = binary.span();
        let a = self.expr(&binary.left, hint)?;
        let b = self.expr(&binary.right, hint)?;
        if let (Val::Static(x), Val::Static(y)) = (&a, &b) {
            if let (Some(x), Some(y)) = (literal(x), literal(y))
                && let Some(value) = fold(&binary.op, x, y)
            {
                return Ok(Val::Static(quote!(#value)));
            }
            let code = match binary.op {
                BinOp::Add(_) => quote!(#x.wrapping_add(#y)),
                BinOp::Sub(_) => quote!(#x.wrapping_sub(#y)),
                BinOp::Mul(_) => quote!(#x.wrapping_mul(#y)),
                // Lift-time only: L0 division is `udiv` and `sdiv`.
                BinOp::Div(_) => quote!(#x.checked_div(#y).unwrap_or_default()),
                BinOp::BitAnd(_) => quote!((#x & #y)),
                BinOp::BitOr(_) => quote!((#x | #y)),
                BinOp::BitXor(_) => quote!((#x ^ #y)),
                BinOp::Shl(_) => quote!(u32::try_from(#y)
                    .ok()
                    .and_then(|count| #x.checked_shl(count))
                    .unwrap_or(0)),
                BinOp::Shr(_) => quote!(u32::try_from(#y)
                    .ok()
                    .and_then(|count| #x.checked_shr(count))
                    .unwrap_or(0)),
                BinOp::Eq(_) => quote!(u64::from(#x == #y)),
                BinOp::Ne(_) => quote!(u64::from(#x != #y)),
                BinOp::Lt(_) => quote!(u64::from(#x < #y)),
                BinOp::Le(_) => quote!(u64::from(#x <= #y)),
                BinOp::Gt(_) => quote!(u64::from(#x > #y)),
                BinOp::Ge(_) => quote!(u64::from(#x >= #y)),
                BinOp::And(_) => quote!(u64::from(#x != 0 && #y != 0)),
                BinOp::Or(_) => quote!(u64::from(#x != 0 || #y != 0)),
                _ => return Err(self.error(span, "not an operator of the semantics language")),
            };
            return Ok(Val::Static(code));
        }
        let (op, swap) = match binary.op {
            BinOp::Add(_) => (quote!(Binary::Add), false),
            BinOp::Sub(_) => (quote!(Binary::Sub), false),
            BinOp::Mul(_) => (quote!(Binary::Mul), false),
            BinOp::BitAnd(_) | BinOp::And(_) => (quote!(Binary::And), false),
            BinOp::BitOr(_) | BinOp::Or(_) => (quote!(Binary::Or), false),
            BinOp::BitXor(_) => (quote!(Binary::Xor), false),
            BinOp::Shl(_) => (quote!(Binary::Shl), false),
            BinOp::Shr(_) => (quote!(Binary::LShr), false),
            BinOp::Eq(_) => (quote!(Binary::Eq), false),
            BinOp::Ne(_) => (quote!(Binary::Ne), false),
            BinOp::Lt(_) => (quote!(Binary::ULt), false),
            BinOp::Le(_) => (quote!(Binary::ULe), false),
            BinOp::Gt(_) => (quote!(Binary::ULt), true),
            BinOp::Ge(_) => (quote!(Binary::ULe), true),
            _ => return Err(self.error(span, "not an operator of the semantics language")),
        };
        if matches!(binary.op, BinOp::Shl(_) | BinOp::Shr(_)) {
            return self.shift(&op, a, b, span);
        }
        let (x, y) = self.pair(a, b, hint, span)?;
        let (x, y) = if swap { (y, x) } else { (x, y) };
        Ok(Val::Dyn(self.emit(quote!(l.binary(#op, #x, #y)))))
    }

    /// A shift or rotate: the count is fitted to the value's width.
    fn shift(&mut self, op: &TokenStream, value: Val, count: Val, span: Span) -> Result<Val> {
        let Val::Dyn(value) = value else {
            return Err(self.error(span, "shift an L0 value (an operand or a computed value)"));
        };
        let count = match count {
            Val::Dyn(count) => self.emit(quote!(l.fit_like(#count, #value))),
            other @ (Val::Static(_) | Val::Undefined(_)) => self.like(other, &value),
        };
        Ok(Val::Dyn(self.emit(quote!(l.binary(#op, #value, #count)))))
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn's `Expr` is non_exhaustive"
    )]
    fn if_expression(&mut self, e: &ExprIf, hint: Option<&TokenStream>) -> Result<Val> {
        let Some((_, otherwise)) = &e.else_branch else {
            return Err(self.error(e.span(), "an `if` value needs an `else`"));
        };
        let condition = self.expr(&e.cond, None)?;
        let then_expr = tail(&e.then_branch.stmts)
            .ok_or_else(|| self.error(e.then_branch.span(), "expected one value"))?;
        let else_expr = match &**otherwise {
            Expr::Block(block) => tail(&block.block.stmts),
            other => Some(other),
        }
        .ok_or_else(|| self.error(otherwise.span(), "expected one value"))?;
        match condition {
            Val::Static(condition) if literal(&condition).is_some() => {
                if literal(&condition) == Some(0) {
                    self.expr(else_expr, hint)
                } else {
                    self.expr(then_expr, hint)
                }
            }
            Val::Static(condition) => {
                let effects = self.effects;
                let (then_code, then) = self.captured_value(then_expr, hint)?;
                let (else_code, otherwise) = self.captured_value(else_expr, hint)?;
                if self.effects != effects {
                    return Err(
                        self.error(e.span(), "no stack or memory access inside an `if` value")
                    );
                }
                match (then, otherwise) {
                    (Val::Static(a), Val::Static(b))
                        if then_code.is_empty() && else_code.is_empty() =>
                    {
                        Ok(Val::Static(quote!(if #condition != 0 { #a } else { #b })))
                    }
                    (a, b) => {
                        let width = match (hint, &a, &b) {
                            (Some(width), _, _) => width.clone(),
                            // Two L0 values: nothing to widen.
                            (None, Val::Dyn(_), Val::Dyn(_)) => quote!(0u64),
                            _ => {
                                return Err(
                                    self.error(e.span(), "the width of this value is not known")
                                );
                            }
                        };
                        let a = self.captured_dyn(then_code, a, &width)?;
                        let b = self.captured_dyn(else_code, b, &width)?;
                        Ok(Val::Dyn(
                            self.emit(quote!(if #condition != 0 { #a } else { #b })),
                        ))
                    }
                }
            }
            Val::Dyn(condition) => {
                let effects = self.effects;
                let then = self.expr(then_expr, hint)?;
                let otherwise = self.expr(else_expr, hint)?;
                if self.effects != effects {
                    return Err(self.error(
                        e.span(),
                        "no stack or memory access inside an `if` value: both sides are computed",
                    ));
                }
                let (a, b) = self.pair(then, otherwise, hint, e.span())?;
                Ok(Val::Dyn(self.emit(quote!(l.select(#condition, #a, #b)))))
            }
            Val::Undefined(_) => Err(self.error(e.cond.span(), "an `if` on an undefined value")),
        }
    }

    fn captured_value(
        &mut self,
        e: &Expr,
        hint: Option<&TokenStream>,
    ) -> Result<(Vec<TokenStream>, Val)> {
        let mut value = None;
        let code = self.capture(|c| {
            value = Some(c.expr(e, hint)?);
            Ok(())
        })?;
        Ok((code, value.ok_or("value")?))
    }

    /// A Rust block computing `value` after `code`, as an L0 expression.
    fn captured_dyn(
        &mut self,
        code: Vec<TokenStream>,
        value: Val,
        width: &TokenStream,
    ) -> Result<TokenStream> {
        let mut result = None;
        let mut code = code;
        let more = self.capture(|c| {
            result = Some(c.materialize(value, width));
            Ok(())
        })?;
        code.extend(more);
        let result = result.ok_or("value")?;
        Ok(if code.is_empty() {
            quote!(#result)
        } else {
            quote!({ #(#code)* #result })
        })
    }

    fn call(&mut self, call: &ExprCall, hint: Option<&TokenStream>) -> Result<Val> {
        let Expr::Path(path) = &*call.func else {
            return Err(self.error(call.func.span(), "call a built-in or helper by name"));
        };
        let name = path
            .path
            .get_ident()
            .map(ToString::to_string)
            .unwrap_or_default();
        let args: Vec<&Expr> = call.args.iter().collect();
        let span = call.span();
        let file = self.file;
        let arity = |n: usize| -> Result<()> {
            if args.len() == n {
                Ok(())
            } else {
                Err(at(file, span, format!("`{name}` takes {n} arguments")))
            }
        };
        let arg = |i: usize| -> Result<&Expr> {
            args.get(i)
                .copied()
                .ok_or_else(|| at(file, span, format!("`{name}` needs argument {}", i + 1)))
        };
        match name.as_str() {
            "intrinsic" => {
                let [output] = <[Ident; 1]>::try_from(self.intrinsic(call, 1)?)
                    .map_err(|_| self.error(span, "one output"))?;
                Ok(Val::Dyn(output))
            }
            "zext" | "sext" | "trunc" | "fit" => {
                arity(2)?;
                let value = self.expr(arg(0)?, None)?;
                let Val::Static(width) = self.expr(arg(1)?, None)? else {
                    return Err(self.error(
                        arg(1)?.span(),
                        "the width is known at lift time (a number or osz)",
                    ));
                };
                let value = match value {
                    Val::Dyn(v) => v,
                    other @ (Val::Static(_) | Val::Undefined(_)) => self.materialize(other, &width),
                };
                let code = match name.as_str() {
                    "zext" => quote!(l.zext(#value, #width)),
                    "sext" => quote!(l.sext(#value, #width)),
                    "trunc" => quote!(l.trunc(#value, #width)),
                    _ => quote!(l.fit(#value, #width)),
                };
                Ok(Val::Dyn(self.emit(code)))
            }
            "msb" | "parity8" | "popcount" | "clz" | "ctz" | "bswap" => {
                arity(1)?;
                let value = self.expr(arg(0)?, hint)?;
                let Val::Dyn(value) = value else {
                    return Err(self.error(arg(0)?.span(), "an L0 value"));
                };
                let code = match name.as_str() {
                    "msb" => quote!(l.msb(#value)),
                    "parity8" => quote!(l.b.unary(Unary::EvenParity8, #value)),
                    "popcount" => quote!(l.b.unary(Unary::Popcount, #value)),
                    "clz" => quote!(l.b.unary(Unary::LeadingZeros, #value)),
                    "ctz" => quote!(l.b.unary(Unary::TrailingZeros, #value)),
                    _ => quote!(l.unary(Unary::ByteSwap, #value)),
                };
                Ok(Val::Dyn(self.emit(code)))
            }
            "bit" => {
                arity(2)?;
                let Val::Dyn(value) = self.expr(arg(0)?, None)? else {
                    return Err(self.error(arg(0)?.span(), "an L0 value"));
                };
                Ok(Val::Dyn(match self.expr(arg(1)?, None)? {
                    Val::Static(index) => self.emit(quote!(l.bit(#value, #index))),
                    Val::Dyn(index) => self.emit(quote!(l.bit_at(#value, #index))),
                    Val::Undefined(_) => {
                        return Err(self.error(arg(1)?.span(), "an undefined index"));
                    }
                }))
            }
            "bits" => {
                arity(3)?;
                let Val::Dyn(value) = self.expr(arg(0)?, None)? else {
                    return Err(self.error(arg(0)?.span(), "an L0 value"));
                };
                let (Val::Static(offset), Val::Static(width)) =
                    (self.expr(arg(1)?, None)?, self.expr(arg(2)?, None)?)
                else {
                    return Err(self.error(span, "the offset and width are known at lift time"));
                };
                Ok(Val::Dyn(self.emit(quote!(l.bits(#value, #offset, #width)))))
            }
            "sar" | "rol" | "ror" => {
                arity(2)?;
                let value = self.expr(arg(0)?, hint)?;
                let count = self.expr(arg(1)?, None)?;
                let op = match name.as_str() {
                    "sar" => quote!(Binary::AShr),
                    "rol" => quote!(Binary::Rol),
                    _ => quote!(Binary::Ror),
                };
                self.shift(&op, value, count, span)
            }
            "slt" | "sle" | "sgt" | "sge" | "udiv" | "urem" | "sdiv" | "srem" | "concat" => {
                arity(2)?;
                let a = self.expr(arg(0)?, hint)?;
                let b = self.expr(arg(1)?, hint)?;
                if name == "concat" {
                    let (Val::Dyn(high), Val::Dyn(low)) = (a, b) else {
                        return Err(self.error(span, "concatenate L0 values"));
                    };
                    return Ok(Val::Dyn(self.emit(quote!(l.b.concat(#high, #low)))));
                }
                let (x, y) = self.pair(a, b, hint, span)?;
                let (op, x, y) = match name.as_str() {
                    "slt" => (quote!(Binary::SLt), x, y),
                    "sle" => (quote!(Binary::SLe), x, y),
                    "sgt" => (quote!(Binary::SLt), y, x),
                    "sge" => (quote!(Binary::SLe), y, x),
                    "udiv" => (quote!(Binary::UDiv), x, y),
                    "urem" => (quote!(Binary::URem), x, y),
                    "sdiv" => (quote!(Binary::SDiv), x, y),
                    _ => (quote!(Binary::SRem), x, y),
                };
                Ok(Val::Dyn(self.emit(quote!(l.binary(#op, #x, #y)))))
            }
            "add_cf" | "add_of" | "sub_cf" | "sub_of" | "aux_carry" => {
                arity(3)?;
                let values = args
                    .iter()
                    .map(|a| self.expr(a, None))
                    .collect::<Result<Vec<_>>>()?;
                let Some(reference) = values.iter().find_map(|v| match v {
                    Val::Dyn(id) => Some(id.clone()),
                    Val::Static(_) | Val::Undefined(_) => None,
                }) else {
                    return Err(self.error(span, "at least one operand must be an L0 value"));
                };
                let mut ids = Vec::new();
                for value in values {
                    let id = match value {
                        // Carries are fitted to the operands' width.
                        Val::Dyn(id) => self.emit(quote!(l.fit_like(#id, #reference))),
                        other @ (Val::Static(_) | Val::Undefined(_)) => {
                            self.like(other, &reference)
                        }
                    };
                    ids.push(id);
                }
                let op = match name.as_str() {
                    "add_cf" => quote!(FlagOp::AddCarry),
                    "add_of" => quote!(FlagOp::AddOverflow),
                    "sub_cf" => quote!(FlagOp::SubBorrow),
                    "sub_of" => quote!(FlagOp::SubOverflow),
                    _ => quote!(FlagOp::NibbleCarry),
                };
                let [a, b, c] = ids.as_slice() else {
                    return Err(self.error(span, "three operands"));
                };
                Ok(Val::Dyn(self.emit(quote!(l.b.flag(#op, #a, #b, #c)))))
            }
            "undefined" => {
                // `undefined()` takes its width from its use;
                // `undefined(n)` is n bits wide. A last string argument names
                // the output it goes to, where the assignment does not.
                let (label, args) = match args.split_last() {
                    Some((
                        Expr::Lit(ExprLit {
                            lit: Lit::Str(label),
                            ..
                        }),
                        rest,
                    )) => (Some(label.value()), rest),
                    _ => (None, args.as_slice()),
                };
                let site = self.site(label, span)?;
                match args {
                    [] => Ok(Val::Undefined(site)),
                    [width] => {
                        let Val::Static(width) = self.expr(width, None)? else {
                            return Err(self.error(width.span(), "a width known at lift time"));
                        };
                        Ok(Val::Dyn(self.undefined_value(site.as_ref(), &width)))
                    }
                    _ => Err(self.error(
                        span,
                        "`undefined` takes at most a width and the output's name",
                    )),
                }
            }
            "system_call" => {
                arity(0)?;
                self.summary.system_call = true;
                self.effects += 1;
                self.out.push(quote!(l.system_call();));
                Ok(Val::Static(quote!(0u64)))
            }
            "cond" => {
                arity(0)?;
                Ok(Val::Dyn(self.emit(quote!(l.condition()))))
            }
            "next" => {
                arity(0)?;
                Ok(Val::Dyn(self.emit(quote!(l.next_address()))))
            }
            // `target(x)`: `x` checked as a control transfer's target (as
            // `jump`, `call` and `ret` check theirs), for an entry whose
            // check comes before other effects (x86's `call`: #GP before
            // the push); a transfer to it checks nothing more.
            "target" => {
                arity(1)?;
                let target = self.expr(arg(0)?, Some(&quote!(64u64)))?;
                let target = self.materialize(target, &quote!(64u64));
                let target = self.emit(quote!(l.target(#target)));
                self.targets.insert(target.clone());
                self.effects += 1;
                Ok(Val::Dyn(target))
            }
            "jump" | "call" | "ret" => {
                arity(1)?;
                let target = self.expr(arg(0)?, Some(&quote!(64u64)))?;
                let target = self.materialize(target, &quote!(64u64));
                let target = if self.targets.contains(&target) {
                    target
                } else {
                    self.emit(quote!(l.target(#target)))
                };
                self.summary.transfers = true;
                self.effects += 1;
                let code = match name.as_str() {
                    "jump" => quote!(l.b.jump(#target);),
                    "call" => quote!({ let next = l.next_address(); l.b.call(#target, next); }),
                    _ => quote!(l.b.ret(#target);),
                };
                self.out.push(code);
                Ok(Val::Static(quote!(0u64)))
            }
            "trap" => {
                arity(1)?;
                let kind = if let Expr::Path(p) = arg(0)? {
                    p.path
                        .get_ident()
                        .map(ToString::to_string)
                        .unwrap_or_default()
                } else {
                    String::new()
                };
                let Some(trap) = T::trap(&kind) else {
                    return Err(self.error(arg(0)?.span(), T::TRAPS));
                };
                self.effects += 1;
                self.out.push(quote!(l.b.trap(#trap);));
                // At the top level, the entry always traps.
                self.summary.always_traps |= self.at_top_level();
                Ok(Val::Static(quote!(0u64)))
            }
            // `lanes(n, expr)`: the operations of `expr` apply lane by lane,
            // on `n` lanes of each operand (literals in each lane).
            "lanes" => {
                arity(2)?;
                let Val::Static(count) = self.expr(arg(0)?, None)? else {
                    return Err(self.error(arg(0)?.span(), "a lane count known at lift time"));
                };
                self.out.push(quote!(l.begin_lanes(#count);));
                let value = self.expr(arg(1)?, hint);
                self.out.push(quote!(l.end_lanes();));
                value
            }
            "status" => {
                arity(1)?;
                let saved = std::mem::replace(&mut self.status, true);
                let value = self.expr(arg(0)?, hint);
                self.status = saved;
                value
            }
            "fadd" | "fsub" | "fmul" | "fdiv" | "fsqrt" | "fma" | "fround" | "fcmp" | "fcmps"
            | "fcvt" | "ftoi" | "ftou" | "itof" | "utof" => self.float(&name, &args, span),
            // `farith(op, a, b, rc)`: op 0, 1, 2, 3 (known at lift time) is
            // add, subtract, multiply, divide.
            "farith" => {
                arity(4)?;
                let Val::Static(code) = self.expr(arg(0)?, None)? else {
                    return Err(self.error(arg(0)?.span(), "an operation known at lift time"));
                };
                let rest: Vec<&Expr> = args.iter().skip(1).copied().collect();
                self.float_with(&quote!(l.arith(#code)), 2, &rest, span)
            }
            // An operand's width (without reading it), or a value's.
            "width" => {
                arity(1)?;
                if let Expr::Path(path) = arg(0)?
                    && let Some(Binding::Param(index, _)) = path
                        .path
                        .get_ident()
                        .and_then(|name| self.lookup(&name.to_string()))
                {
                    return Ok(Val::Static(quote!(l.width(p[#index]))));
                }
                let Val::Dyn(value) = self.expr(arg(0)?, None)? else {
                    return Err(self.error(arg(0)?.span(), "the width of an L0 value"));
                };
                Ok(Val::Static(quote!(u64::from(l.b.width(#value)))))
            }
            _ => match T::call(self, &name, &args, span)? {
                Some(value) => Ok(value),
                None => self.inline(&name, &args, hint, span),
            },
        }
    }

    /// The position of the operand `e` names (a parameter), for built-ins
    /// that access the operand themselves.
    pub fn operand(&self, e: &Expr) -> Result<usize> {
        if let Expr::Path(path) = e
            && let Some(Binding::Param(index, _)) = path
                .path
                .get_ident()
                .and_then(|name| self.lookup(&name.to_string()))
        {
            return Ok(index);
        }
        Err(self.error(e.span(), "an operand (a parameter)"))
    }

    /// Whether the statement compiled is at the entry's top level (not
    /// under a condition): a trap there always traps.
    pub fn at_top_level(&self) -> bool {
        self.scopes.len() == 1
    }

    /// A floating-point built-in: `fadd(a, b, rc)`, `fsqrt(a, rc)`,
    /// `fma(a, b, c, rc)`, `fround(a, rc)`, `fcmp(a, b)` (quiet),
    /// `fcmps(a, b)` (signalling), `fcvt(a, width, rc)`, `ftoi`/`ftou(a,
    /// width, rc)`, `itof`/`utof(a, width, rc)`. The format is the operands'
    /// (lanes') width; `status(...)` around one gives its exceptions.
    fn float(&mut self, name: &str, args: &[&Expr], span: Span) -> Result<Val> {
        let (op, values, widened) = match name {
            "fadd" => (quote!(FloatOp::Add), 2, false),
            "fsub" => (quote!(FloatOp::Sub), 2, false),
            "fmul" => (quote!(FloatOp::Mul), 2, false),
            "fdiv" => (quote!(FloatOp::Div), 2, false),
            "fsqrt" => (quote!(FloatOp::Sqrt), 1, false),
            "fma" => (quote!(FloatOp::MulAdd), 3, false),
            "fround" => (quote!(FloatOp::RoundToIntegral), 1, false),
            "fcmp" => (quote!(FloatOp::Compare { signaling: false }), 2, false),
            "fcmps" => (quote!(FloatOp::Compare { signaling: true }), 2, false),
            _ => (quote!(), 1, true),
        };
        if !widened && !name.starts_with("fcmp") {
            return self.float_with(&op, values, args, span);
        }
        let compare = name.starts_with("fcmp");
        let expected = values + usize::from(widened) + usize::from(!compare);
        if args.len() != expected {
            return Err(self.error(span, format!("`{name}` takes {expected} arguments")));
        }
        let mut operands = Vec::new();
        for arg in args.iter().take(values) {
            let Val::Dyn(value) = self.expr(arg, None)? else {
                return Err(self.error(arg.span(), "a floating-point operand is an L0 value"));
            };
            operands.push(value);
        }
        let rounding = if compare {
            self.emit(quote!(l.b.constant(2, 0)))
        } else {
            let last = args.last().copied().ok_or("argument")?;
            match self.expr(last, None)? {
                Val::Dyn(value) => value,
                Val::Static(value) => self.emit(quote!(l.b.constant(2, #value))),
                Val::Undefined(_) => {
                    return Err(self.error(last.span(), "an undefined rounding"));
                }
            }
        };
        let (op, target) = if widened {
            let width_arg = args.get(1).copied().ok_or("argument")?;
            let Val::Static(width) = self.expr(width_arg, None)? else {
                return Err(self.error(width_arg.span(), "a width known at lift time"));
            };
            let narrow = quote!(u16::try_from(#width).unwrap_or(u16::MAX));
            match name {
                "fcvt" => (quote!(FloatOp::Convert(l.format_of(#width))), quote!(None)),
                "ftoi" | "ftou" => {
                    let signed = name == "ftoi";
                    (
                        quote!(FloatOp::ToInt { signed: #signed, width: #narrow }),
                        quote!(None),
                    )
                }
                _ => {
                    let signed = name == "itof";
                    (
                        quote!(FloatOp::FromInt { signed: #signed }),
                        quote!(Some(#narrow)),
                    )
                }
            }
        } else {
            (op, quote!(None))
        };
        let status = self.status;
        let op = self.emit(op);
        Ok(Val::Dyn(self.emit(quote!(
            l.float(#op, &[#(#operands),*], #rounding, #target, #status)
        ))))
    }

    /// The floating-point operation `op` on the first `values` of `args`,
    /// rounded as the last says.
    fn float_with(
        &mut self,
        op: &TokenStream,
        values: usize,
        args: &[&Expr],
        span: Span,
    ) -> Result<Val> {
        if args.len() != values + 1 {
            return Err(self.error(span, format!("{} arguments expected", values + 1)));
        }
        let mut operands = Vec::new();
        for arg in args.iter().take(values) {
            let Val::Dyn(value) = self.expr(arg, None)? else {
                return Err(self.error(arg.span(), "a floating-point operand is an L0 value"));
            };
            operands.push(value);
        }
        let last = args.last().copied().ok_or("argument")?;
        let rounding = match self.expr(last, None)? {
            Val::Dyn(value) => value,
            Val::Static(value) => self.emit(quote!(l.b.constant(2, #value))),
            Val::Undefined(_) => return Err(self.error(last.span(), "an undefined rounding")),
        };
        let status = self.status;
        let op = self.emit(op.clone());
        Ok(Val::Dyn(self.emit(quote!(
            l.float(#op, &[#(#operands),*], #rounding, None, #status)
        ))))
    }

    /// `for i in start..end { ... }` with bounds known at lift time: a loop
    /// in the generated code, `i` a lift-time value. A `let` from outside
    /// that the body assigns becomes a mutable variable.
    fn for_loop(&mut self, f: &syn::ExprForLoop) -> Result<()> {
        let Pat::Ident(variable) = &*f.pat else {
            return Err(self.error(f.pat.span(), "`for` binds one name"));
        };
        let Expr::Range(range) = &*f.expr else {
            return Err(self.error(f.expr.span(), "`for i in start..end`"));
        };
        let (Some(start), Some(end), syn::RangeLimits::HalfOpen(_)) =
            (&range.start, &range.end, &range.limits)
        else {
            return Err(self.error(range.span(), "`for i in start..end`"));
        };
        let (Val::Static(start), Val::Static(end)) =
            (self.expr(start, None)?, self.expr(end, None)?)
        else {
            return Err(self.error(range.span(), "the bounds are known at lift time"));
        };
        for name in assigned_names(&f.body.stmts) {
            // Each iteration reads the operand as the previous one left it.
            if let Some(Binding::Param(index, _)) = self.lookup(&name) {
                self.bind(&name, Binding::Param(index, None));
            }
            if let Some(Binding::Local(value, _)) = self.lookup(&name) {
                let Val::Dyn(value) = value else {
                    return Err(self.error(
                        f.span(),
                        format!("`{name}`, which the loop assigns, is not an L0 value"),
                    ));
                };
                let carried = self.fresh();
                self.out.push(quote!(let mut #carried = #value;));
                self.bind(&name, Binding::Mutable(carried));
            }
        }
        let index = self.fresh();
        let name = variable.ident.to_string();
        self.declare(&name, variable.span())?;
        let depth = self.scopes.len() + 1;
        let body = self.capture(|c| {
            c.scoped(|c| {
                c.bind(&name, Binding::Local(Val::Static(quote!(#index)), depth));
                c.block(&f.body.stmts)
            })
        })?;
        self.out
            .push(quote!(for #index in #start..#end { #(#body)* }));
        Ok(())
    }

    fn inline(
        &mut self,
        name: &str,
        args: &[&Expr],
        hint: Option<&TokenStream>,
        span: Span,
    ) -> Result<Val> {
        let Some((file, helper)) = self.helpers.get(name) else {
            return Err(self.error(span, format!("unknown function `{name}`")));
        };
        if self.inlining.iter().any(|n| n == name) {
            return Err(self.error(span, format!("`{name}` calls itself")));
        }
        if helper.sig.inputs.len() != args.len() {
            return Err(self.error(
                span,
                format!("`{name}` takes {} arguments", helper.sig.inputs.len()),
            ));
        }
        let mut values = Vec::new();
        for arg in args {
            values.push(self.expr(arg, hint)?);
        }
        self.inlining.push(name.to_owned());
        let depth = self.scopes.len() + 1;
        let result = self.scoped(|c| {
            for (input, value) in helper.sig.inputs.iter().zip(values) {
                if let syn::FnArg::Typed(typed) = input
                    && let Pat::Ident(param) = &*typed.pat
                {
                    c.declare(&param.ident.to_string(), param.span())?;
                    c.bind(&param.ident.to_string(), Binding::Local(value, depth));
                }
            }
            let statements = &helper.block.stmts;
            let (body, last) = match statements.split_last() {
                // A last `if` without `else`, or loop, is a statement, not
                // the value.
                Some((Stmt::Expr(e, None), body))
                    if !matches!(e, Expr::If(i) if i.else_branch.is_none())
                        && !matches!(e, Expr::ForLoop(_) | Expr::While(_)) =>
                {
                    (body, Some(e))
                }
                _ => (statements.as_slice(), None),
            };
            c.block(body)?;
            match last {
                Some(e) => c.expr(e, hint),
                None => Ok(Val::Static(quote!(0u64))),
            }
        });
        self.inlining.pop();
        result.map_err(|e| at(file, helper.sig.ident.span(), format!("in `{name}`: {e}")))
    }
}

/// The single value of a block: `{ value }`.
fn tail(statements: &[Stmt]) -> Option<&Expr> {
    match statements {
        [Stmt::Expr(e, None)] => Some(e),
        _ => None,
    }
}
