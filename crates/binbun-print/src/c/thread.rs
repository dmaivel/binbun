//! The thread pointer in C: an environment variable
//! ([`VarKind::Environment`]) and the memory at addresses computed from
//! it, by the platform's own spelling ([`ThreadPointer`]).
//!
//! - [`ThreadPointer::Builtin`] (ELF: x86-64 System V's `fs_base`,
//!   AArch64's `tpidr_el0`): the value is `__builtin_thread_pointer()`,
//!   and memory relative to it is reached through that value like through
//!   any pointer: `*(uint64_t *)((char *)__builtin_thread_pointer() + 40)`.
//!   On AArch64 the builtin reads `tpidr_el0` itself. On x86-64 it reads
//!   `%fs:0`, which the TLS ABI requires to hold the thread pointer (the
//!   thread control block's first word is its own address: TLS variant
//!   II, Drepper, "ELF Handling For Thread-Local Storage"): the same value,
//!   though not the same instruction as the binary's single `%fs:40`
//!   access. A `__seg_fs` pointer (`*(uint64_t __seg_fs *)40`) would be
//!   that instruction, but GCC accepts it only in GNU C, not in the ISO C
//!   the output is compiled as.
//! - [`ThreadPointer::Teb`] (Windows x64: the TEB, in `gs`): an integer,
//!   pointer or float of 1, 2, 4 or 8 bytes at the thread pointer plus an
//!   offset is read with Microsoft's `__readgsbyte`, `__readgsword`,
//!   `__readgsdword`, `__readgsqword` of the offset and written with
//!   `__writegs…(offset, value)`: the same single segment-relative access.
//!   The value itself is `NtCurrentTeb()` (it reads `NT_TIB.Self`, which
//!   holds the TEB's own address: the same value), and any other access
//!   relative to it is reached through that value. `binbun_defs.h` defines them
//!   for GCC and Clang where the compiler does not.
//! - [`ThreadPointer::Kpcr`] (Windows x64 kernel-mode code: the
//!   processor's control region, KPCR, in `gs`): accesses as the TEB's,
//!   the value `KeGetPcr()` (it reads the KPCR's `Self`, at 0x18, as the
//!   WDK's `wdm.h` does; `binbun_defs.h` defines it). No metadata describes
//!   the KPCR, so its accesses stay offsets: `__readgsqword(0x188)`, the
//!   current thread.
//! - [`ThreadPointer::TebX18`] (Windows ARM64: the TEB, in the platform
//!   register `x18`): the value is `NtCurrentTeb()` (winnt.h's reads
//!   `x18` itself, `__getReg(18)`; `binbun_defs.h` defines it for GCC and
//!   Clang), and memory relative to it is reached through that value like
//!   through any pointer, as the binary's `ldr x8, [x18, #0x60]` is a
//!   plain load at the register plus an offset.
//! - [`ThreadPointer::KpcrX18`] (Windows ARM64 kernel-mode code: the
//!   KPCR, in `x18`): as the TEB's, the value `KeGetPcr()` (wdm.h's reads
//!   `x18`).
//!
//! Where the thread pointer's variable has the type its platform
//! declares (a pointer to Windows' `struct _TEB`, phnt's, or to
//! x86-64 glibc's `tcbhead_t`), its value has that type: `NtCurrentTeb()`
//! (which `binbun_defs.h` declares to return a `struct _TEB *`, as Microsoft's
//! `winnt.h` does) or `binbun_tcb()` (`binbun_defs.h`'s
//! `__builtin_thread_pointer()` as a `struct tcbhead_t *`), so memory
//! through it reads as its fields: `binbun_tcb()->stack_guard`, the same
//! value as the binary's `%fs:0x28` (through `%fs:0`, as above). A
//! segment intrinsic's offset that starts a field of the TEB (in nested
//! structures and arrays too) is spelled
//! `offsetof(struct _TEB, ProcessEnvironmentBlock)`, the same constant:
//! the access stays the binary's single `gs`-relative one
//! (`__readgsqword`); the field path (`NtCurrentTeb()->…`) is printed
//! only for what no intrinsic reads (an aggregate, an odd width), as
//! through `NtCurrentTeb()` before. A tag the function names otherwise
//! (another `_TEB`) gets the plain builtin cast to the type.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use binbun_ast::ir::{Expr, ExprId, Node, VarId, VarKind};
use binbun_ast::types::{Type, TypeId};
use binbun_semantics::bits::Bits;
use binbun_semantics::ir::{Binary, Format};

use super::types::{CTy, field_names};
use super::value::{Class, Op, Value};
use super::{PrintError, Printer, error};
use crate::document::Doc;

/// How C reaches the thread pointer on an image's platform ([the
/// module](self) says why each is exact).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum ThreadPointer {
    /// `__builtin_thread_pointer()`, and memory through it (the ELF TLS
    /// ABIs).
    #[default]
    Builtin,
    /// Windows x64's TEB, in `gs`: `__readgs…`/`__writegs…` for accesses,
    /// `NtCurrentTeb()` for the value.
    Teb,
    /// Windows x64 kernel mode's KPCR, in `gs`: `__readgs…`/`__writegs…`
    /// for accesses, `KeGetPcr()` for the value.
    Kpcr,
    /// Windows ARM64's TEB, in `x18`: `NtCurrentTeb()` for the value, and
    /// memory through it.
    TebX18,
    /// Windows ARM64 kernel mode's KPCR, in `x18`: `KeGetPcr()` for the
    /// value, and memory through it.
    KpcrX18,
}

/// The suffix of Microsoft's segment intrinsics for an access of `bits`
/// bits.
fn suffix(bits: u16) -> Option<&'static str> {
    match bits {
        8 => Some("byte"),
        16 => Some("word"),
        32 => Some("dword"),
        64 => Some("qword"),
        _ => None,
    }
}

impl Printer<'_> {
    /// Whether variable `id` is an environment variable holding the
    /// thread pointer ([`Image::is_thread_pointer`](super::Image)).
    pub(super) fn thread_variable(&self, id: VarId) -> bool {
        self.f.var(id).is_some_and(|variable| match variable.kind {
            VarKind::Environment(register) => self.image.is_thread_pointer(register),
            VarKind::Parameter | VarKind::Local | VarKind::Global(_) | VarKind::Frame(_) => false,
        })
    }

    /// The value of environment variable `id`, which holds the thread
    /// pointer: `__builtin_thread_pointer()`, `(void *)NtCurrentTeb()` or
    /// `(void *)KeGetPcr()`, a `void *`; where the variable has its platform's
    /// declared type, `binbun_tcb()` or `NtCurrentTeb()` of that type (the
    /// builtin cast to it where the function names the tag otherwise, or
    /// the platform declares none).
    pub(super) fn environment_value(&mut self, id: VarId) -> Result<Value, PrintError> {
        let variable = self
            .f
            .var(id)
            .ok_or_else(|| error(Some(Node::Var(id)), "no such variable"))?;
        let width = self.type_width(variable.ty)?;
        if width != self.pointer_width() {
            return Err(error(
                Some(Node::Var(id)),
                "a thread pointer not as wide as a pointer",
            ));
        }
        let name = match self.image.thread_pointer() {
            ThreadPointer::Builtin => "__builtin_thread_pointer",
            ThreadPointer::Teb | ThreadPointer::TebX18 => "NtCurrentTeb",
            ThreadPointer::Kpcr | ThreadPointer::KpcrX18 => "KeGetPcr",
        };
        let void = self.types.intern(Type::Pointer(None));
        let raw = self.helper(name, Vec::new(), CTy::Pointer(void), Class::Low, width);
        let Some(target) = self.thread_structure(variable.ty) else {
            // `NtCurrentTeb()` and `KeGetPcr()` give a `struct _TEB *` and
            // a `struct _KPCR *`, on which arithmetic would count
            // structures: as a `void *`, it counts bytes.
            if name == "__builtin_thread_pointer" {
                return Ok(raw);
            }
            return Ok(self.cast(raw, CTy::Pointer(void)));
        };
        let declared = match self.image.thread_pointer() {
            ThreadPointer::Builtin => Some(("binbun_tcb", "tcbhead_t")),
            ThreadPointer::Teb | ThreadPointer::TebX18 => Some(("NtCurrentTeb", "_TEB")),
            ThreadPointer::Kpcr | ThreadPointer::KpcrX18 => None,
        };
        let ty = variable.ty;
        self.aggregate_specifier(target)?;
        if let Some((typed, tag)) = declared
            && self.struct_names.get(&target).map(String::as_str) == Some(tag)
        {
            return Ok(self.helper(typed, Vec::new(), CTy::Pointer(ty), Class::Low, width));
        }
        Ok(self.cast(raw, CTy::Pointer(ty)))
    }

    /// The structure the thread pointer's type `ty` points to, if it is
    /// a pointer to one (its platform's declared type).
    fn thread_structure(&self, ty: TypeId) -> Option<TypeId> {
        let &Type::Pointer(Some(target)) = self.types.get(ty)? else {
            return None;
        };
        matches!(self.types.get(target)?, Type::Struct(_) | Type::Union(_)).then_some(target)
    }

    /// `offsetof(struct _TEB, NtTib.Self)`: the offset of the field (not an
    /// aggregate; an array's element by its index) of `bits` bits that
    /// starts `offset` bytes into the structure the thread pointer `base`
    /// points to, if its type says one does.
    fn designated(
        &mut self,
        base: ExprId,
        offset: i128,
        bits: u16,
    ) -> Result<Option<Value>, PrintError> {
        let Some(&Expr::Var(var)) = self.f.expr(base) else {
            return Ok(None);
        };
        let Some(target) = self
            .f
            .var(var)
            .and_then(|variable| self.thread_structure(variable.ty))
        else {
            return Ok(None);
        };
        let Some(path) = u64::try_from(offset)
            .ok()
            .and_then(|offset| self.designator(target, offset, bits, 0))
        else {
            return Ok(None);
        };
        let specifier = self.aggregate_specifier(target)?;
        let width = self.pointer_width();
        let (doc, depth) = self.call_doc(
            vec![Doc::macro_name("offsetof", self.node)],
            vec![specifier, path],
            0,
        );
        Ok(Some(Value {
            doc,
            op: Op::Postfix,
            ty: CTy::Int {
                signed: false,
                bits: width,
            },
            class: Class::Zero,
            width,
            constant: None,
            lvalue: false,
            loads: false,
            depth,
            address_of: None,
            unsigned_literal: None,
        }))
    }

    /// The member designator of the field of `bits` bits at `offset` in
    /// aggregate `aggregate` (`NtTib.Self`, `TlsSlots[3]`), if one starts
    /// there: through nested structures and unions (a union's first
    /// member that has one), to an element of an array.
    fn designator(&self, aggregate: TypeId, offset: u64, bits: u16, depth: u8) -> Option<Vec<Doc>> {
        let (Type::Struct(fields) | Type::Union(fields)) = self.types.get(aggregate)? else {
            return None;
        };
        let depth = depth.checked_add(1).filter(|&depth| depth < 16)?;
        let node = self.node;
        field_names(fields)
            .into_iter()
            .find_map(|(start, ty, name)| {
                let within = offset.checked_sub(start)?;
                if within >= self.types.width(ty)? / 8 {
                    return None;
                }
                match *self.types.get(ty)? {
                    Type::Struct(_) | Type::Union(_) => {
                        let rest = self.designator(ty, within, bits, depth)?;
                        let mut path = vec![name.doc(node), Doc::op(".", node)];
                        path.extend(rest);
                        Some(path)
                    }
                    Type::Array { element, .. } => {
                        let size = self.types.width(element)? / 8;
                        let scalar = !matches!(
                            self.types.get(element)?,
                            Type::Struct(_) | Type::Union(_) | Type::Array { .. }
                        );
                        (scalar
                            && size > 0
                            && within % size == 0
                            && self.types.value_width(element) == Some(bits))
                        .then(|| {
                            vec![
                                name.doc(node),
                                Doc::punct("[", node),
                                Doc::number(format!("{}", within / size), node),
                                Doc::punct("]", node),
                            ]
                        })
                    }
                    Type::Bits(_)
                    | Type::Int(_)
                    | Type::UInt(_)
                    | Type::Char { .. }
                    | Type::Bool(_)
                    | Type::Float(_)
                    | Type::Pointer(_)
                    | Type::Code(_)
                    | Type::Vector { .. }
                    | Type::Enum(_) => (within == 0 && self.types.value_width(ty) == Some(bits))
                        .then(|| vec![name.doc(node)]),
                }
            })
    }

    /// Whether memory at `base` plus an offset is accessed by segment
    /// intrinsics: `base` reads an environment variable and the platform
    /// reaches its thread pointer by segment.
    pub(super) fn segment(&self, base: ExprId) -> bool {
        let Some(&Expr::Var(var)) = self.f.expr(base) else {
            return false;
        };
        matches!(
            self.image.thread_pointer(),
            ThreadPointer::Teb | ThreadPointer::Kpcr
        ) && self.thread_variable(var)
    }

    /// The offset of an access at the thread pointer plus
    /// `index * scale + offset`, pointer-wide: the field's
    /// [`offsetof`](Self::designated) where the thread pointer `base`
    /// points to a structure with one of `bits` bits there.
    fn segment_offset(
        &mut self,
        base: ExprId,
        index: Option<(Value, u64)>,
        offset: i128,
        bits: u16,
    ) -> Result<Value, PrintError> {
        let width = self.pointer_width();
        if index.is_none()
            && let Some(designated) = self.designated(base, offset, bits)?
        {
            return Ok(designated);
        }
        let constant = self.constant(
            Bits::from_u128(width, offset.cast_unsigned()),
            Class::Zero,
            false,
        )?;
        let Some((index, scale)) = index else {
            return Ok(constant);
        };
        let index = self.int_view(index)?;
        let term = self.scale(index, scale)?;
        if offset == 0 {
            return Ok(term);
        }
        self.binary(Binary::Add, term, constant, width)
    }

    /// The access width of a load or store of L2 type `ty` through a
    /// segment intrinsic, and its C type; `None` if it has none (not 1, 2,
    /// 4 or 8 bytes, a `bool`, an aggregate, a float other than `float` and
    /// `double`).
    pub(super) fn segment_access(&self, ty: TypeId) -> Result<Option<(u16, CTy)>, PrintError> {
        let cty = self.cty(ty)?;
        let width = self.type_width(ty)?;
        let fits = match cty {
            CTy::Int { .. } | CTy::Pointer(_) | CTy::Code(_) | CTy::Bytes => true,
            CTy::Float(format) => matches!(format, Format::Single | Format::Double),
            CTy::Bool | CTy::Other(_) | CTy::Vector(_) => false,
        };
        Ok((fits && suffix(width).is_some()).then_some((width, cty)))
    }

    /// `__readgs<size>(offset)` as L2 type `ty`, for a load at the
    /// thread pointer `base` plus `index * scale + offset`; `None` where
    /// no intrinsic reads `ty`.
    pub(super) fn segment_read(
        &mut self,
        base: ExprId,
        index: Option<(Value, u64)>,
        offset: i128,
        ty: TypeId,
    ) -> Result<Option<Value>, PrintError> {
        let Some((width, cty)) = self.segment_access(ty)? else {
            return Ok(None);
        };
        let Some(size) = suffix(width) else {
            return Ok(None);
        };
        let at = self.segment_offset(base, index, offset, width)?;
        let name = format!("__readgs{size}");
        let integer = CTy::Int {
            signed: false,
            bits: width,
        };
        let mut value = self.helper(&name, vec![at], integer, Class::Zero, width);
        value.loads = true;
        let value = match cty {
            CTy::Int { .. } => value,
            CTy::Pointer(_) | CTy::Code(_) | CTy::Bytes => self.int_to_pointer(value, cty)?,
            CTy::Float(format) => self.as_float(value, format)?,
            CTy::Bool | CTy::Other(_) | CTy::Vector(_) => return Ok(None),
        };
        Ok(Some(value))
    }

    /// `__writegs<size>(offset, value)` statement tokens, for a store of
    /// `value` (L2 type `ty`) at the thread pointer `base` plus
    /// `index * scale + offset`; `None` where no intrinsic writes `ty`.
    pub(super) fn segment_write(
        &mut self,
        base: ExprId,
        index: Option<(Value, u64)>,
        offset: i128,
        ty: TypeId,
        value: Value,
    ) -> Result<Option<Vec<Doc>>, PrintError> {
        let Some((width, _)) = self.segment_access(ty)? else {
            return Ok(None);
        };
        let Some(size) = suffix(width) else {
            return Ok(None);
        };
        let at = self.segment_offset(base, index, offset, width)?;
        let value = self.int_view(value)?;
        let (value, _) = self.helper_operand(value, false)?;
        let name: String = format!("__writegs{size}");
        let (doc, _) = self.call_doc(
            vec![Doc::macro_name(name, self.node)],
            vec![at.doc, value.doc],
            0,
        );
        Ok(Some(doc))
    }
}
