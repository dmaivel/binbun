//! L2's text form, for reading (deterministic; not C, and not parsed
//! back): [`print`].
//!
//! ```text
//! function 0x401000 "count" (v0) -> int32 deduced
//!   type t5 = struct "node" size 16 { 0: ptr(t5) "next", 8: int32 "value" }
//!   var v0 param int32 "n" deduced [rdi]
//!   var v1 local int32 default [%v12]
//!   var v2 global 0x404010 int32 "total" declared
//!   var v3 frame -0x48 array(uint8, 72) default
//! {
//!   s0: v1 = 0x0:32  ; @0x401000
//!   s1: while slt(v1, v0) {
//!     s4: if eq(v1, 0x5:32) {
//!       s2: break s1
//!     } else {
//!       s3: mem<int32>(&v2) = v1
//!     }
//!     s5: v1 = add(v1, 0x1:32)
//!   }
//!   s6: return v1
//! }
//! ```
//!
//! (`binbun-ast`'s test `text_form` prints exactly this.)
//!
//! - The header gives the address, name, parameters, return type (`void`
//!   for none; `...` last among the parameters if variadic) and the
//!   return type's evidence, then the structs and
//!   unions, then every variable: its number, kind (`param`, `local`,
//!   `global address`, `frame offset`, `env register`), type, name,
//!   evidence and origins.
//!   A variadic function's `va_start` facts follow the header: `va tag(gp
//!   0x8, fp 0x30, overflow [sp+0x8], save [sp-0xc8])` (`fp unset` where
//!   the function leaves `fp_offset` as it was) or `va pointer
//!   [sp+0x18]`, then each save as `save rsi:8 [sp-0xa0]`, `if al` where
//!   guarded.
//! - Each statement starts with its number (`s5:`); blocks are indented in
//!   braces, two spaces per level up to [`MAX_INDENT`] levels (deeper
//!   blocks are indented as that level, so the text stays linear in the
//!   function's size). A statement's provenance follows `;`.
//!   The locals declared at a statement ([`Function::declared`]) follow
//!   its number: `s5: decl v1, v2; v1 = 0x0:32`.
//! - Types: `bits32`, `int32`, `uint8`, `bool1`, `half`/`single`/`double`/
//!   `extended`, `ptr` (to nothing known) or `ptr(T)`, `code(T, ...) -> T`,
//!   `array(T, n)` or `array(T)`, `vector(lanes, T)`; a struct or union by
//!   its number (`t4`).
//! - Expressions: constants `0x5:32` (hexadecimal, then the width),
//!   unknown values `undefined:32` with where they come from after it
//!   (`(arch 0x401000 of)`, `(parameter)`, `(call 0x401000 rdx)`,
//!   `(landing)`, `(entry rcx)`, `(unwritten)`, `(lowering)`),
//!   variables `v1`, `&v2`, L0's operation names as calls
//!   (`add(a, b)`, `add-carry(a, b, c)`, `extract(a, offset, width)`,
//!   `zext.64(a)`, `sext.64(a)`, `select(c, a, b)`, `lanes.4.add(a, b)`,
//!   `float.2.add.double(rounding, a, b)`, `float-status...`),
//!   `and-then(a, b)` and `or-else(a, b)` (`&&`, `||`), `cast<T>(a)`,
//!   loads `mem<T>(address)`.
//! - Statements: `place = e` (a place is a variable or `mem<T>(address)`),
//!   `r1, r2 = call 0x401200(args) : code(...) -> T` (or `call e(args)`),
//!   `r = intrinsic name(inputs)`, `eval e`, `if e {`/`} else {`,
//!   `while e {`, `do {`/`} while e`, `for (init; e; step) {`, `switch e {`
//!   with `case values:`/`default:` arms and `fallthrough`, `break s5`,
//!   `continue s5`, `label l0`, `goto l0`, `return`/`return e`,
//!   `trap kind`, `unreachable`, `r = escape kind(operands)`,
//!   `va_start v3`, `try {`
//!   then each handler as `} landing 0x401020 {`, `} catch T {`, `} catch ... {`,
//!   `} cleanup {` or `} unexpected(T, ...) {`; `exception` and
//!   `selector` (with their width) read what the runtime handed it.
//! - Origins: `%v12` (an L1 value), `@0x401004` (an instruction), a
//!   register's name, `[sp-0x48]` (a stack slot), `^b3` (an L1 block).

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::{self, Write};

use binbun_semantics::bits::Bits;
use binbun_semantics::ir::{Declarations, FloatOutput, LaneOp, RegisterId, SiteId};
use binbun_semantics::text::{
    binary_name, flag_name, float_name, format_name, trap_name, unary_name,
};
use binbun_ssa::ir::Unknown;

use crate::ir::{
    Arm, Block, Call, Callee, CatchType, Escape, ExceptionValue, Expr, ExprId, Function, Handler,
    HandlerKind, InputsId, Logical, Origin, Place, SehFilter, SiteInput, Stmt, StmtId, Update, Va,
    VaList, VarId, VarKind, Variable,
};
use crate::types::{Aggregate, Evidence, Type, TypeId};

/// The deepest indentation printed, in levels.
pub const MAX_INDENT: usize = 64;

/// `(vN = value)`: an assignment expression's pieces.
fn assignment<'a>(var: VarId, value: ExprId) -> Vec<Piece<'a>> {
    vec![
        Piece::Owned(format!("(v{} = ", var.0)),
        Piece::Expr(value),
        Piece::Text(")"),
    ]
}

/// The text of `function`, with register and intrinsic names from
/// `declarations`.
pub fn print(function: &Function, declarations: &Declarations) -> String {
    let mut out = String::new();
    // Writing to a `String` cannot fail.
    let _ = Printer {
        out: &mut out,
        function,
        declarations,
        work: Vec::new(),
    }
    .function();
    out
}

/// The name of an escape.
fn escape(kind: Escape) -> &'static str {
    match kind {
        Escape::UnresolvedJump => "unresolved-jump",
        Escape::ForeignJump => "foreign-jump",
        Escape::OverlappingCode => "overlapping-code",
        Escape::NonStandardCall => "non-standard-call",
        Escape::StackTrick => "stack-trick",
        Escape::SystemCall => "system-call",
        Escape::Atomic => "atomic",
        Escape::Update(Update::Exchange) => "atomic-exchange",
        Escape::Update(Update::Add) => "atomic-add",
        Escape::Update(Update::Sub) => "atomic-sub",
        Escape::Update(Update::And) => "atomic-and",
        Escape::Update(Update::Or) => "atomic-or",
        Escape::Update(Update::Xor) => "atomic-xor",
        Escape::Update(Update::CompareExchange) => "atomic-compare-exchange",
    }
}

/// A catch type: its name, else its type information's symbol or
/// address.
fn catch_type(ty: &CatchType) -> String {
    match (&ty.name, &ty.symbol, ty.address) {
        (Some(name), _, _) => name.clone(),
        (None, Some(symbol), _) => symbol.clone(),
        (None, None, Some(address)) => format!("typeinfo@{address:#x}"),
        (None, None, None) => String::from("?"),
    }
}

/// An exception value's name.
fn exception_name(value: ExceptionValue) -> &'static str {
    match value {
        ExceptionValue::Object => "exception",
        ExceptionValue::Selector => "selector",
        ExceptionValue::Code => "exception-code",
        ExceptionValue::Abnormal => "abnormal-termination",
    }
}

/// A `Try`'s parts at `depth`, up to its closing brace: `try {`, its
/// body, then each handler's head and body.
fn try_pieces<'a>(body: &'a Block, handlers: &'a [Handler], depth: usize) -> Vec<Piece<'a>> {
    let mut pieces = vec![Piece::Text("try {\n"), Piece::Block(body, depth + 1)];
    for handler in handlers {
        pieces.extend([
            Piece::Indent(depth),
            Piece::Owned(format!("}} {} {{\n", handler_head(&handler.kind))),
            Piece::Block(&handler.body, depth + 1),
        ]);
    }
    pieces
}

/// A handler's head, between its braces: `landing`, `catch T`, ...
fn handler_head(kind: &HandlerKind) -> String {
    match kind {
        HandlerKind::Landing(pad) => format!("landing {pad:#x}"),
        HandlerKind::Catch(ty) => format!("catch {}", catch_type(ty)),
        HandlerKind::CatchAll => String::from("catch ..."),
        HandlerKind::Cleanup => String::from("cleanup"),
        HandlerKind::Unexpected(types) => {
            let names: Vec<String> = types.iter().map(catch_type).collect();
            format!("unexpected({})", names.join(", "))
        }
        HandlerKind::Except(SehFilter::Constant(value)) => format!("except({value})"),
        HandlerKind::Except(SehFilter::Funclet(funclet)) => format!("except(filter {funclet:#x})"),
        HandlerKind::Finally => String::from("finally"),
    }
}

fn evidence(evidence: Evidence) -> &'static str {
    match evidence {
        Evidence::Default => "default",
        Evidence::Deduced => "deduced",
        Evidence::DeclaredPointer => "declared-pointer",
        Evidence::Declared => "declared",
    }
}

/// A signed offset: `-0x48`, `0x8`.
struct Offset(i64);

impl fmt::Display for Offset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 < 0 {
            write!(f, "-{:#x}", self.0.unsigned_abs())
        } else {
            write!(f, "{:#x}", self.0)
        }
    }
}

/// A constant: `0x5:32`.
struct Constant<'a>(&'a Bits);

impl fmt::Display for Constant<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.0, self.0.width())
    }
}

/// A piece of text still to print. Nested statements, expressions and
/// types are pieces on a work stack, not recursive calls: nesting may be
/// arbitrarily deep.
#[derive(Clone)]
enum Piece<'a> {
    /// Text as it is.
    Text(&'a str),
    /// Text made for it.
    Owned(String),
    /// Indentation for this depth.
    Indent(usize),
    /// An expression.
    Expr(ExprId),
    /// A type, following at most this many more types inside it (a
    /// malformed table may have cycles).
    Type(TypeId, usize),
    /// A statement on its own lines, at this depth.
    Stmt(StmtId, usize),
    /// A block's statements, at this depth.
    Block(&'a Block, usize),
    /// A switch arm, at the switch's depth.
    Arm(&'a Arm, usize),
    /// A statement that holds no blocks, without its number or a newline.
    Simple(&'a Stmt),
    /// A place.
    Place(Place),
    /// A statement's provenance (`  ; ...`, nothing for none).
    Origins(&'a [Origin]),
}

struct Printer<'a> {
    out: &'a mut String,
    function: &'a Function,
    declarations: &'a Declarations,
    /// The pieces still to print, the next last.
    work: Vec<Piece<'a>>,
}

/// `(a, b, c)`.
fn arguments<'a>(ids: &[ExprId]) -> Vec<Piece<'a>> {
    let mut pieces = vec![Piece::Text("(")];
    for (position, &id) in ids.iter().enumerate() {
        if position > 0 {
            pieces.push(Piece::Text(", "));
        }
        pieces.push(Piece::Expr(id));
    }
    pieces.push(Piece::Text(")"));
    pieces
}

/// `r1, r2 = ` for results (nothing for none).
fn results(places: &[Place]) -> Vec<Piece<'_>> {
    let mut pieces = Vec::new();
    for (position, &place) in places.iter().enumerate() {
        if position > 0 {
            pieces.push(Piece::Text(", "));
        }
        pieces.push(Piece::Place(place));
    }
    if !places.is_empty() {
        pieces.push(Piece::Text(" = "));
    }
    pieces
}

impl<'a> Printer<'a> {
    fn function(&mut self) -> fmt::Result {
        let function = self.function;
        write!(self.out, "function {:#x}", function.address)?;
        if let Some(name) = &function.name {
            write!(self.out, " {name:?}")?;
        }
        self.out.push_str(" (");
        for (position, parameter) in function.parameters.iter().enumerate() {
            if position > 0 {
                self.out.push_str(", ");
            }
            write!(self.out, "v{}", parameter.0)?;
        }
        if function.variadic {
            self.out.push_str(if function.parameters.is_empty() {
                "..."
            } else {
                ", ..."
            });
        }
        self.out.push_str(") -> ");
        match function.returns {
            Some(ty) => self.print(vec![self.type_piece(ty)])?,
            None => self.out.push_str("void"),
        }
        write!(self.out, " {}", evidence(function.returns_evidence))?;
        self.out.push('\n');
        if let Some(va) = &function.va {
            self.va(va)?;
        }
        for (id, ty) in function.types.iter() {
            if let Type::Struct(aggregate) | Type::Union(aggregate) = ty {
                let kind = if matches!(ty, Type::Struct(_)) {
                    "struct"
                } else {
                    "union"
                };
                write!(self.out, "  type t{} = {kind}", id.0)?;
                self.aggregate(aggregate)?;
                self.out.push('\n');
            }
        }
        for (index, variable) in function.variables.iter().enumerate() {
            write!(self.out, "  var v{index} ")?;
            self.variable(variable)?;
            self.out.push('\n');
        }
        self.out.push_str("{\n");
        self.print(vec![Piece::Block(&function.body, 1)])?;
        self.out.push_str("}\n");
        Ok(())
    }

    /// Prints `pieces`, in order, and everything they hold.
    fn print(&mut self, pieces: Vec<Piece<'a>>) -> fmt::Result {
        self.queue(pieces);
        while let Some(piece) = self.work.pop() {
            self.piece(piece)?;
        }
        Ok(())
    }

    /// Queues `pieces` to print next, in order.
    fn queue(&mut self, pieces: Vec<Piece<'a>>) {
        self.work.extend(pieces.into_iter().rev());
    }

    /// Prints the leaf `piece`, or queues what it holds.
    fn piece(&mut self, piece: Piece<'a>) -> fmt::Result {
        match piece {
            Piece::Text(text) => self.out.push_str(text),
            Piece::Owned(text) => self.out.push_str(&text),
            Piece::Indent(depth) => {
                for _ in 0..depth.min(MAX_INDENT) {
                    self.out.push_str("  ");
                }
            }
            Piece::Expr(id) => self.expr(id)?,
            Piece::Type(id, depth) => self.ty(id, depth)?,
            Piece::Stmt(id, depth) => self.stmt(id, depth)?,
            Piece::Block(block, depth) => self
                .work
                .extend(block.iter().rev().map(|&id| Piece::Stmt(id, depth))),
            Piece::Arm(arm, depth) => self.arm(arm, depth)?,
            Piece::Simple(stmt) => self.simple(stmt)?,
            Piece::Place(Place::Var(id)) => write!(self.out, "v{}", id.0)?,
            Piece::Place(Place::Memory { address, ty }) => {
                let pieces = self.memory(address, ty);
                self.queue(pieces);
            }
            Piece::Origins(origins) => {
                if !origins.is_empty() {
                    self.out.push_str("  ; ");
                    self.origins(origins)?;
                }
            }
        }
        Ok(())
    }

    /// Type `id`, with all the depth a type may have.
    fn type_piece(&self, id: TypeId) -> Piece<'a> {
        Piece::Type(id, self.function.types.len())
    }

    /// `mem<T>(address)`.
    fn memory(&self, address: ExprId, ty: TypeId) -> Vec<Piece<'a>> {
        vec![
            Piece::Text("mem<"),
            self.type_piece(ty),
            Piece::Text(">("),
            Piece::Expr(address),
            Piece::Text(")"),
        ]
    }

    fn aggregate(&mut self, aggregate: &'a Aggregate) -> fmt::Result {
        if let Some(name) = &aggregate.name {
            write!(self.out, " {name:?}")?;
        }
        write!(self.out, " size {} {{", aggregate.size)?;
        for (position, field) in aggregate.fields.iter().enumerate() {
            self.out.push_str(if position > 0 { ", " } else { " " });
            write!(self.out, "{}: ", field.offset)?;
            self.print(vec![self.type_piece(field.ty)])?;
            if let Some(name) = &field.name {
                write!(self.out, " {name:?}")?;
            }
        }
        self.out.push_str(" }");
        Ok(())
    }

    fn variable(&mut self, variable: &Variable) -> fmt::Result {
        match variable.kind {
            VarKind::Parameter => self.out.push_str("param "),
            VarKind::Local => self.out.push_str("local "),
            VarKind::Global(address) => write!(self.out, "global {address:#x} ")?,
            VarKind::Frame(offset) => write!(self.out, "frame {} ", Offset(offset))?,
            VarKind::Environment(register) => {
                let name = self
                    .declarations
                    .info(register)
                    .map_or("?", |info| info.name);
                write!(self.out, "env {name} ")?;
            }
        }
        self.print(vec![self.type_piece(variable.ty)])?;
        if let Some(name) = &variable.name {
            write!(self.out, " {:?}", name.text)?;
        }
        write!(self.out, " {}", evidence(variable.evidence))?;
        if !variable.origins.is_empty() {
            self.out.push_str(" [");
            self.origins(&variable.origins)?;
            self.out.push(']');
        }
        Ok(())
    }

    fn origins(&mut self, origins: &[Origin]) -> fmt::Result {
        for (position, origin) in origins.iter().enumerate() {
            if position > 0 {
                self.out.push_str(", ");
            }
            match *origin {
                Origin::Value(value) => write!(self.out, "%v{}", value.0)?,
                Origin::Instruction(address) => write!(self.out, "@{address:#x}")?,
                Origin::Register(register) => self.out.push_str(self.register(register)),
                Origin::Held(register) => {
                    self.out.push_str("held ");
                    self.out.push_str(self.register(register));
                }
                Origin::Slot(offset) => self.slot(offset)?,
                Origin::Block(block) => write!(self.out, "^b{}", block.0)?,
                Origin::Absorbed(block) => write!(self.out, "~b{}", block.0)?,
                Origin::Proved => self.out.push_str("proved"),
            }
        }
        Ok(())
    }

    /// A register's name.
    fn register(&self, register: RegisterId) -> &'static str {
        self.declarations
            .info(register)
            .map_or("?", |info| info.name)
    }

    /// An unknown value of `width` bits, with where it comes from:
    /// `undefined:64(call 0x401000 rdx)`.
    fn undefined(&mut self, width: u16, unknown: Unknown, inputs: Option<InputsId>) -> fmt::Result {
        if let Unknown::Architecture {
            site: Some(site), ..
        } = unknown
        {
            return self.out.write_str(&self.site_text(width, site, inputs));
        }
        write!(self.out, "undefined:{width}(")?;
        match unknown {
            Unknown::Architecture {
                address, register, ..
            } => {
                write!(self.out, "arch {address:#x}")?;
                if let Some(register) = register {
                    write!(self.out, " {}", self.register(register))?;
                }
            }
            Unknown::Parameter => self.out.write_str("parameter")?,
            Unknown::Call { address, register } => {
                write!(self.out, "call {address:#x} {}", self.register(register))?;
            }
            Unknown::Landing => self.out.write_str("landing")?,
            Unknown::Entry { register } => {
                self.out.write_str("entry")?;
                if let Some(register) = register {
                    write!(self.out, " {}", self.register(register))?;
                }
            }
            Unknown::Unwritten => self.out.write_str("unwritten")?,
            Unknown::Lowering => self.out.write_str("lowering")?,
        }
        self.out.write_str(")")
    }

    /// A stack offset: `[sp-0x48]`.
    fn slot(&mut self, offset: i64) -> fmt::Result {
        let sign = if offset < 0 { '-' } else { '+' };
        write!(self.out, "[sp{sign}{:#x}]", offset.unsigned_abs())
    }

    /// The `va_start` facts' lines.
    fn va(&mut self, va: &Va) -> fmt::Result {
        match va.list {
            VaList::Tag {
                gp_offset,
                fp_offset,
                overflow,
                save_area,
            } => {
                write!(self.out, "  va tag(gp {gp_offset:#x}, fp ")?;
                match fp_offset {
                    Some(fp_offset) => write!(self.out, "{fp_offset:#x}")?,
                    None => self.out.push_str("unset"),
                }
                self.out.push_str(", overflow ");
                self.slot(overflow)?;
                self.out.push_str(", save ");
                self.slot(save_area)?;
                self.out.push_str(")\n");
            }
            VaList::Pointer(offset) => {
                self.out.push_str("  va pointer ");
                self.slot(offset)?;
                self.out.push('\n');
            }
            VaList::Aapcs64 {
                stack,
                gr_top,
                vr_top,
                gr_offs,
                vr_offs,
            } => {
                self.out.push_str("  va aapcs64(stack ");
                self.slot(stack)?;
                for (name, top) in [("gr_top", gr_top), ("vr_top", vr_top)] {
                    write!(self.out, ", {name} ")?;
                    match top {
                        Some(top) => self.slot(top)?,
                        None => self.out.push_str("unset"),
                    }
                }
                writeln!(self.out, ", gr_offs {gr_offs}, vr_offs {vr_offs})")?;
            }
        }
        for save in &va.saves {
            write!(
                self.out,
                "  save {}:{} ",
                self.register(save.register),
                save.bytes
            )?;
            self.slot(save.offset)?;
            if let Some(guard) = save.guard {
                write!(self.out, " if {}", self.register(guard))?;
            }
            self.out.push('\n');
        }
        Ok(())
    }

    /// Type `id`: written, or its parts queued.
    fn ty(&mut self, id: TypeId, depth: usize) -> fmt::Result {
        let types = &self.function.types;
        let (Some(ty), Some(depth)) = (types.get(id), depth.checked_sub(1)) else {
            return write!(self.out, "t{}?", id.0);
        };
        let pieces = match ty {
            Type::Bits(width) => return write!(self.out, "bits{width}"),
            Type::Int(width) => return write!(self.out, "int{width}"),
            Type::UInt(width) => return write!(self.out, "uint{width}"),
            &Type::Char { signed } => {
                return self.out.write_str(if signed { "char" } else { "uchar" });
            }
            Type::Bool(width) => return write!(self.out, "bool{width}"),
            &Type::Float(format) => return self.out.write_str(format_name(format)),
            Type::Pointer(None) => return self.out.write_str("ptr"),
            Type::Struct(_) | Type::Union(_) => return write!(self.out, "t{}", id.0),
            Type::Enum(enumeration) => {
                let sign = if enumeration.signed { "int" } else { "uint" };
                let width = enumeration.width;
                return match &enumeration.name {
                    Some(name) => write!(self.out, "enum({name}, {sign}{width})"),
                    None => write!(self.out, "enum({sign}{width})"),
                };
            }
            &Type::Pointer(Some(target)) => vec![
                Piece::Text("ptr("),
                Piece::Type(target, depth),
                Piece::Text(")"),
            ],
            Type::Code(signature) => {
                let mut pieces = vec![Piece::Text("code(")];
                for (position, &parameter) in signature.parameters.iter().enumerate() {
                    if position > 0 {
                        pieces.push(Piece::Text(", "));
                    }
                    pieces.push(Piece::Type(parameter, depth));
                }
                if signature.variadic {
                    let first = signature.parameters.is_empty();
                    pieces.push(Piece::Text(if first { "..." } else { ", ..." }));
                }
                pieces.push(Piece::Text(") -> "));
                pieces.push(match signature.returns {
                    Some(returns) => Piece::Type(returns, depth),
                    None => Piece::Text("void"),
                });
                pieces
            }
            &Type::Array { element, length } => vec![
                Piece::Text("array("),
                Piece::Type(element, depth),
                Piece::Owned(match length {
                    Some(length) => format!(", {length})"),
                    None => String::from(")"),
                }),
            ],
            &Type::Vector { lanes, element } => vec![
                Piece::Owned(format!("vector({lanes}, ")),
                Piece::Type(element, depth),
                Piece::Text(")"),
            ],
        };
        self.queue(pieces);
        Ok(())
    }

    /// Statement `id`'s number, then its parts queued.
    fn stmt(&mut self, id: StmtId, depth: usize) -> fmt::Result {
        self.piece(Piece::Indent(depth))?;
        write!(self.out, "s{}: {}", id.0, self.declared(id))?;
        let function = self.function;
        let Some(stmt) = function.stmt(id) else {
            return self.out.write_str("?\n");
        };
        let close = [Piece::Indent(depth), Piece::Text("}\n")];
        let mut pieces = match stmt {
            Stmt::If {
                condition,
                then,
                otherwise,
            } => {
                let mut pieces = vec![
                    Piece::Text("if "),
                    Piece::Expr(*condition),
                    Piece::Text(" {\n"),
                    Piece::Block(then, depth + 1),
                ];
                if !otherwise.is_empty() {
                    pieces.extend([
                        Piece::Indent(depth),
                        Piece::Text("} else {\n"),
                        Piece::Block(otherwise, depth + 1),
                    ]);
                }
                pieces
            }
            Stmt::While { condition, body } => vec![
                Piece::Text("while "),
                Piece::Expr(*condition),
                Piece::Text(" {\n"),
                Piece::Block(body, depth + 1),
            ],
            Stmt::DoWhile { body, condition } => {
                self.queue(vec![
                    Piece::Text("do {\n"),
                    Piece::Block(body, depth + 1),
                    Piece::Indent(depth),
                    Piece::Text("} while "),
                    Piece::Expr(*condition),
                    Piece::Text("\n"),
                ]);
                return Ok(());
            }
            Stmt::For {
                init,
                condition,
                step,
                body,
            } => {
                let mut pieces = vec![Piece::Text("for (")];
                pieces.extend(self.inline(init));
                pieces.extend([
                    Piece::Text("; "),
                    Piece::Expr(*condition),
                    Piece::Text("; "),
                ]);
                pieces.extend(self.inline(step));
                pieces.extend([Piece::Text(") {\n"), Piece::Block(body, depth + 1)]);
                pieces
            }
            Stmt::Switch { scrutinee, arms } => {
                let mut pieces = vec![
                    Piece::Text("switch "),
                    Piece::Expr(*scrutinee),
                    Piece::Text(" {\n"),
                ];
                pieces.extend(arms.iter().map(|arm| Piece::Arm(arm, depth)));
                pieces
            }
            Stmt::Try { body, handlers } => try_pieces(body, handlers, depth),
            Stmt::Assign { .. }
            | Stmt::Call { .. }
            | Stmt::Intrinsic { .. }
            | Stmt::Expr(_)
            | Stmt::Break(_)
            | Stmt::Continue(_)
            | Stmt::Label(_)
            | Stmt::Goto(_)
            | Stmt::Return(_)
            | Stmt::Trap(_)
            | Stmt::Unreachable
            | Stmt::Escape { .. }
            | Stmt::VaStart { .. } => {
                self.queue(vec![
                    Piece::Simple(stmt),
                    Piece::Origins(function.provenance.stmt(id)),
                    Piece::Text("\n"),
                ]);
                return Ok(());
            }
        };
        pieces.extend(close);
        self.queue(pieces);
        Ok(())
    }

    /// A switch arm's first line, then its body queued.
    fn arm(&mut self, arm: &'a Arm, depth: usize) -> fmt::Result {
        self.piece(Piece::Indent(depth))?;
        let mut first = true;
        for value in &arm.values {
            self.out.push_str(if first { "case " } else { ", " });
            write!(self.out, "{}", Constant(value))?;
            first = false;
        }
        if arm.default {
            self.out
                .push_str(if first { "default" } else { ", default" });
        }
        self.out.push_str(":\n");
        let mut pieces = vec![Piece::Block(&arm.body, depth + 1)];
        if arm.fallthrough {
            pieces.extend([Piece::Indent(depth + 1), Piece::Text("fallthrough\n")]);
        }
        self.queue(pieces);
        Ok(())
    }

    /// A `for`'s init or step: its statements on one line.
    fn inline(&self, block: &'a Block) -> Vec<Piece<'a>> {
        let mut pieces = Vec::new();
        for (position, &id) in block.iter().enumerate() {
            let separator = if position > 0 { ", " } else { "" };
            pieces.push(Piece::Owned(format!(
                "{separator}s{}: {}",
                id.0,
                self.declared(id)
            )));
            pieces.push(match self.function.stmt(id) {
                Some(stmt) => Piece::Simple(stmt),
                None => Piece::Text("?"),
            });
        }
        pieces
    }

    /// `decl v1, v2; ` for the locals declared at `id`, else nothing.
    fn declared(&self, id: StmtId) -> String {
        let Some(vars) = self.function.declared.get(&id) else {
            return String::new();
        };
        let names: Vec<String> = vars.iter().map(|var| format!("v{}", var.0)).collect();
        format!("decl {}; ", names.join(", "))
    }

    /// A statement that holds no blocks, without its number: written, or
    /// its parts queued.
    fn simple(&mut self, stmt: &'a Stmt) -> fmt::Result {
        let pieces = match stmt {
            Stmt::Assign { place, value } => vec![
                Piece::Place(*place),
                Piece::Text(" = "),
                Piece::Expr(*value),
            ],
            Stmt::Call {
                results: places,
                call,
            } => {
                let mut pieces = results(places);
                pieces.extend(self.call(call));
                pieces
            }
            Stmt::Intrinsic {
                results: places,
                intrinsic,
                inputs,
            } => {
                let name = self
                    .declarations
                    .intrinsic(*intrinsic)
                    .map_or("?", |info| info.name);
                let mut pieces = results(places);
                pieces.push(Piece::Owned(format!("intrinsic {name}")));
                pieces.extend(arguments(inputs));
                pieces
            }
            Stmt::Escape {
                kind,
                operands,
                results: places,
            } => {
                let mut pieces = results(places);
                pieces.push(Piece::Owned(format!("escape {}", escape(*kind))));
                pieces.extend(arguments(operands));
                pieces
            }
            Stmt::Expr(value) => vec![Piece::Text("eval "), Piece::Expr(*value)],
            Stmt::Return(Some(value)) => vec![Piece::Text("return "), Piece::Expr(*value)],
            Stmt::Break(target) => return write!(self.out, "break s{}", target.0),
            Stmt::Continue(target) => return write!(self.out, "continue s{}", target.0),
            Stmt::Label(label) => return write!(self.out, "label l{}", label.0),
            Stmt::Goto(label) => return write!(self.out, "goto l{}", label.0),
            Stmt::Return(None) => return self.out.write_str("return"),
            Stmt::Trap(kind) => return write!(self.out, "trap {}", trap_name(*kind)),
            Stmt::Unreachable => return self.out.write_str("unreachable"),
            Stmt::VaStart { list } => vec![Piece::Text("va_start "), Piece::Place(*list)],
            Stmt::If { .. }
            | Stmt::While { .. }
            | Stmt::DoWhile { .. }
            | Stmt::For { .. }
            | Stmt::Switch { .. }
            | Stmt::Try { .. } => return self.out.write_str("?"),
        };
        self.queue(pieces);
        Ok(())
    }

    /// `call target(arguments) : signature`.
    fn call(&self, call: &'a Call) -> Vec<Piece<'a>> {
        let mut pieces = match call.callee {
            Callee::Address(address) => vec![Piece::Owned(format!("call {address:#x}"))],
            Callee::Import(slot) => vec![Piece::Owned(format!("call import {slot:#x}"))],
            Callee::Expr(target) => vec![Piece::Text("call "), Piece::Expr(target)],
        };
        pieces.extend(arguments(&call.arguments));
        pieces.extend([Piece::Text(" : "), self.type_piece(call.signature)]);
        pieces
    }

    /// The undefined value of site `site`, with its inputs:
    /// `undefined:1 @shrd.of(not_kept:64, 0x1d:8, ...)` (a constant input,
    /// or one lowering did not keep, with its width).
    fn site_text(&self, width: u16, site: SiteId, inputs: Option<InputsId>) -> String {
        let mut text = match self.declarations.site(site) {
            Some(info) => format!("undefined:{width} @{}", info.name),
            None => format!("undefined:{width} @{}", site.0),
        };
        let inputs = inputs.map_or(&[][..], |id| self.function.site_inputs(id));
        if !inputs.is_empty() {
            let inputs: Vec<String> = inputs
                .iter()
                .map(|input| match input {
                    SiteInput::Kept(bits) => format!("{}", Constant(bits)),
                    SiteInput::NotKept(width) => format!("not_kept:{width}"),
                })
                .collect();
            text = format!("{text}({})", inputs.join(", "));
        }
        text
    }

    /// Expression `id`: written, or its parts queued.
    fn expr(&mut self, id: ExprId) -> fmt::Result {
        let Some(&expr) = self.function.expr(id) else {
            return write!(self.out, "e{}?", id.0);
        };
        let pieces = match expr {
            Expr::Const(bits) => return write!(self.out, "{}", Constant(&bits)),
            Expr::Undefined(width, unknown, inputs) => {
                return self.undefined(width, unknown, inputs);
            }
            Expr::Var(var) => return write!(self.out, "v{}", var.0),
            Expr::AddressOf(var) => return write!(self.out, "&v{}", var.0),
            Expr::Unary(op, a) => operation(Piece::Text(unary_name(op)), &[a]),
            Expr::Binary(op, a, b) => operation(Piece::Text(binary_name(op)), &[a, b]),
            Expr::Logical(op, a, b) => {
                let name = match op {
                    Logical::And => "and-then",
                    Logical::Or => "or-else",
                };
                operation(Piece::Text(name), &[a, b])
            }
            Expr::Flag(op, a, b, c) => operation(Piece::Text(flag_name(op)), &[a, b, c]),
            Expr::Extract {
                value,
                offset,
                width,
            } => vec![
                Piece::Text("extract("),
                Piece::Expr(value),
                Piece::Owned(format!(", {offset}, {width})")),
            ],
            Expr::Concat { high, low } => operation(Piece::Text("concat"), &[high, low]),
            Expr::Extend {
                signed,
                value,
                width,
            } => {
                let name = if signed { "sext" } else { "zext" };
                operation(Piece::Owned(format!("{name}.{width}")), &[value])
            }
            Expr::Select {
                condition,
                then,
                otherwise,
            } => operation(Piece::Text("select"), &[condition, then, otherwise]),
            Expr::Lanes {
                lanes,
                op,
                operands,
            } => {
                let name = match op {
                    LaneOp::Unary(op) => String::from(unary_name(op)),
                    LaneOp::Binary(op) => String::from(binary_name(op)),
                    LaneOp::Extract { offset, width } => format!("extract.{offset}.{width}"),
                    LaneOp::Extend { signed, width } => {
                        format!("{}.{width}", if signed { "sext" } else { "zext" })
                    }
                    LaneOp::Select => String::from("select"),
                };
                operation(
                    Piece::Owned(format!("lanes.{lanes}.{name}")),
                    operands.get(..op.arity()).unwrap_or(&[]),
                )
            }
            Expr::Float {
                op,
                format,
                lanes,
                output,
                rounding,
                operands,
            } => {
                let what = match output {
                    FloatOutput::Value => "float",
                    FloatOutput::Status => "float-status",
                };
                let mut ids = vec![rounding];
                ids.extend(operands.iter().take(op.arity()));
                let name = format!("{what}.{lanes}.{}.{}", float_name(op), format_name(format));
                operation(Piece::Owned(name), &ids)
            }
            Expr::Cast { value, ty } => vec![
                Piece::Text("cast<"),
                self.type_piece(ty),
                Piece::Text(">("),
                Piece::Expr(value),
                Piece::Text(")"),
            ],
            Expr::Load { address, ty } => self.memory(address, ty),
            Expr::Call(call) => match self.function.call(call) {
                Some(call) => self.call_expr(call),
                None => return write!(self.out, "c{}?", call.0),
            },
            Expr::Exception { value, width } => {
                return write!(self.out, "{}:{width}", exception_name(value));
            }
            Expr::Assign { var, value } => assignment(var, value),
        };
        self.queue(pieces);
        Ok(())
    }

    /// A call expression: its call in parentheses.
    fn call_expr(&self, call: &'a Call) -> Vec<Piece<'a>> {
        let mut pieces = vec![Piece::Text("(")];
        pieces.extend(self.call(call));
        pieces.push(Piece::Text(")"));
        pieces
    }
}

/// `name(operands)`.
fn operation<'a>(name: Piece<'a>, operands: &[ExprId]) -> Vec<Piece<'a>> {
    let mut pieces = vec![name];
    pieces.extend(arguments(operands));
    pieces
}
