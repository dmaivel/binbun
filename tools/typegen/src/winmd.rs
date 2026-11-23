//! Windows metadata (`.winmd`, as in Microsoft's Win32 metadata package):
//! functions with the DLL they are imported from and semantic parameter
//! types (`VirtualAlloc`'s `flAllocationType` is
//! `VIRTUAL_ALLOCATION_TYPE`, not `DWORD`).
//!
//! Types are keyed by their namespace-qualified names (`struct
//! Windows.Win32.Foundation.RECT`; a nested type under its outer one).
//! Handles (`[NativeTypedef]` structures such as `HANDLE`) and delegates
//! (function pointer types) become typedefs; COM interfaces are opaque, a
//! reference to one a pointer. Where the metadata declares a type or
//! function per architecture, the target's is taken. Layouts are only what
//! the metadata states (an explicit size), unless asked for
//! ([`Layouts::Computed`]): then each structure's and union's fields are
//! laid out as MSVC lays out C's (natural alignment, under the packing the
//! metadata states), which is how the headers the metadata comes from are
//! compiled.
//!
//! Several files are read as one: Microsoft's WDK metadata
//! (`Windows.Wdk.winmd`) refers to the Win32 metadata's types
//! (`UNICODE_STRING`, `HANDLE`), which resolve in `Windows.Win32.winmd`
//! read with it.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use binbun_typedb::database::{Definition, Function, Target, TypeRef};
use binbun_typedb::types::{
    Convention, Enum, Field, FloatFormat, Opaque, Param, Record, Signature, Typedef, Variant,
};
use windows_metadata::reader::{File, HasAttributes, MethodDef, TypeCategory, TypeDef, TypeIndex};
use windows_metadata::{
    FieldAttributes, MethodAttributes, MethodCallAttributes, Type, TypeAttributes, TypeName, Value,
};

use crate::Declarations;

/// Whether the records' layouts are computed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layouts {
    /// Only what the metadata states: a size where it gives one, no field
    /// offsets.
    Stated,
    /// Every record's size, alignment and field offsets as MSVC lays it
    /// out, where all its fields' types have a layout (a field of a type
    /// the metadata does not define has none); a record whose stated size
    /// is not the one computed keeps only its stated size.
    Computed,
}

/// Parses the metadata files at `paths`, as one, for `target`, with the
/// records' `layouts`.
///
/// # Errors
///
/// If a file cannot be read, the target's architecture is not one the
/// metadata distinguishes, or a signature has a form this generator does
/// not convert.
pub fn parse(paths: &[&Path], target: &Target, layouts: Layouts) -> Result<Declarations, String> {
    let files = paths
        .iter()
        .map(|path| {
            File::read(path).ok_or_else(|| format!("{}: not a .winmd file", path.display()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let index = TypeIndex::new(files);
    // `SupportedArchitecture`'s bits.
    let arch = match target.arch.as_str() {
        "x86" | "i386" | "i686" => 1,
        "x86_64" => 2,
        "aarch64" => 4,
        other => return Err(format!("Windows metadata has no architecture `{other}`")),
    };
    let mut converter = Converter {
        index: &index,
        target,
        arch,
        declarations: Declarations::default(),
        done: HashSet::new(),
        packing: HashMap::new(),
    };
    let mut types: Vec<_> = index.iter().collect();
    types.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
    for (namespace, _, def) in types {
        if !converter.for_target(def.arches()) {
            continue;
        }
        match def.category() {
            TypeCategory::Class => converter.functions(def)?,
            TypeCategory::Enum
            | TypeCategory::Struct
            | TypeCategory::Delegate
            | TypeCategory::Interface => {
                converter.define(def, &format!("{namespace}.{}", def.name()), &[])?;
            }
            TypeCategory::Attribute => {}
        }
    }
    if layouts == Layouts::Computed {
        lay_out(
            &mut converter.declarations.types,
            u64::from(target.pointer_size),
            &converter.packing,
        );
    }
    Ok(converter.declarations)
}

/// A type being defined, for resolving references to its nested types.
#[derive(Clone, Copy)]
struct Scope<'a, 'i> {
    def: TypeDef<'i>,
    qualified: &'a str,
}

struct Converter<'i> {
    index: &'i TypeIndex,
    target: &'i Target,
    /// The target's `SupportedArchitecture` bit.
    arch: i32,
    declarations: Declarations,
    /// The keys defined or being defined.
    done: HashSet<String>,
    /// The packing the metadata states for a record (`#pragma pack`), by
    /// key: the most its fields are aligned to.
    packing: HashMap<String, u64>,
}

impl<'i> Converter<'i> {
    fn for_target(&self, arches: i32) -> bool {
        arches == 0 || arches & self.arch != 0
    }

    /// The reference to `def`, whose qualified name is `qualified`.
    fn reference(def: TypeDef<'_>, qualified: &str) -> TypeRef {
        match def.category() {
            TypeCategory::Enum => TypeRef::Named(format!("enum {qualified}")),
            TypeCategory::Struct if def.has_attribute("NativeTypedefAttribute") => {
                TypeRef::Named(qualified.to_owned())
            }
            TypeCategory::Struct if def.flags().contains(TypeAttributes::ExplicitLayout) => {
                TypeRef::Named(format!("union {qualified}"))
            }
            TypeCategory::Struct => TypeRef::Named(format!("struct {qualified}")),
            TypeCategory::Delegate => TypeRef::Named(qualified.to_owned()),
            TypeCategory::Interface => {
                TypeRef::Pointer(Box::new(TypeRef::Named(format!("interface {qualified}"))))
            }
            TypeCategory::Class | TypeCategory::Attribute => {
                TypeRef::Named(format!("class {qualified}"))
            }
        }
    }

    /// Defines `def` (once), giving the reference to it.
    fn define(
        &mut self,
        def: TypeDef<'i>,
        qualified: &str,
        scope: &[Scope<'_, 'i>],
    ) -> Result<TypeRef, String> {
        let reference = Self::reference(def, qualified);
        let named = if let TypeRef::Pointer(target) = &reference {
            target.as_ref()
        } else {
            &reference
        };
        let TypeRef::Named(key) = named else {
            return Err(format!("{qualified}: reference {reference:?}"));
        };
        let key = key.clone();
        if !self.done.insert(key.clone()) {
            return Ok(reference);
        }
        let mut inner = scope.to_vec();
        inner.push(Scope { def, qualified });
        let name = def.name().to_owned();
        let definition = match def.category() {
            TypeCategory::Enum => Definition::Enum(enumeration(def, key)),
            TypeCategory::Struct if def.has_attribute("NativeTypedefAttribute") => {
                let field = def
                    .fields()
                    .next()
                    .ok_or_else(|| format!("{qualified}: a handle without a field"))?;
                Definition::Typedef(Typedef {
                    key,
                    name,
                    target: self.convert(&field.ty(), &inner)?,
                })
            }
            TypeCategory::Struct => {
                let mut fields = Vec::new();
                for field in def.fields() {
                    if field.flags().contains(FieldAttributes::Literal)
                        || field.flags().contains(FieldAttributes::Static)
                    {
                        continue;
                    }
                    fields.push(Field {
                        name: Some(field.name().to_owned()),
                        ty: self.convert(&field.ty(), &inner)?,
                        bit_offset: None,
                        bit_width: None,
                    });
                }
                if let Some(packing) = def
                    .class_layout()
                    .map(|layout| u64::from(layout.packing_size()))
                    .filter(|&packing| packing != 0)
                {
                    self.packing.insert(key.clone(), packing);
                }
                Definition::Record(Record {
                    key,
                    name: Some(name),
                    union: def.flags().contains(TypeAttributes::ExplicitLayout),
                    size: def
                        .class_layout()
                        .map(|layout| u64::from(layout.class_size()))
                        .filter(|&size| size != 0),
                    align: None,
                    fields: Some(fields),
                })
            }
            TypeCategory::Delegate => {
                let invoke = def
                    .methods()
                    .find(|method| method.name() == "Invoke")
                    .ok_or_else(|| format!("{qualified}: a delegate without Invoke"))?;
                let signature = self.signature(invoke, &inner)?;
                Definition::Typedef(Typedef {
                    key,
                    name,
                    target: TypeRef::Pointer(Box::new(TypeRef::Function(Box::new(signature)))),
                })
            }
            TypeCategory::Interface | TypeCategory::Class | TypeCategory::Attribute => {
                Definition::Opaque(Opaque { key, name })
            }
        };
        self.declarations.define(definition)?;
        Ok(reference)
    }

    /// The static methods of an `Apis` class: the functions.
    fn functions(&mut self, def: TypeDef<'i>) -> Result<(), String> {
        for method in def.methods() {
            if !method.flags().contains(MethodAttributes::Static)
                || !self.for_target(method.arches())
            {
                continue;
            }
            let import = method.impl_map();
            let name = import
                .as_ref()
                .map(|import| import.import_name().to_owned())
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| method.name().to_owned());
            let signature = self.signature(method, &[])?;
            self.declarations.functions.push(Function {
                name,
                library: import.map(|import| import.import_scope().name().to_owned()),
                signature,
                no_return: method.has_attribute("DoesNotReturnAttribute"),
                // Windows metadata records no exception specifications.
                no_throw: false,
                // Windows metadata records no format strings.
                format: None,
                format_arg: Vec::new(),
                // Nor allocation sizes.
                alloc_size: None,
                number: None,
            });
        }
        Ok(())
    }

    fn signature(
        &mut self,
        method: MethodDef<'i>,
        scope: &[Scope<'_, 'i>],
    ) -> Result<Signature<TypeRef>, String> {
        let signature = method.signature(&[]);
        let names: Vec<_> = method.params().collect();
        let mut params = Vec::new();
        for (sequence, ty) in (1u16..).zip(&signature.types) {
            params.push(Param {
                name: names
                    .iter()
                    .find(|param| param.sequence() == sequence)
                    .map(|param| param.name().to_owned()),
                ty: self.convert(ty, scope)?,
            });
        }
        let system_is_stdcall = matches!(self.target.arch.as_str(), "x86" | "i386" | "i686");
        Ok(Signature {
            ret: self.convert(&signature.return_type, scope)?,
            params,
            variadic: signature.flags.contains(MethodCallAttributes::VARARG),
            convention: (method.calling_convention() == "system" && system_is_stdcall)
                .then_some(Convention::Stdcall),
        })
    }

    fn int(&self, signed: bool) -> TypeRef {
        TypeRef::Int {
            signed,
            size: self.target.pointer_size,
        }
    }

    fn convert(&mut self, ty: &Type, scope: &[Scope<'_, 'i>]) -> Result<TypeRef, String> {
        let int = |signed, size| TypeRef::Int { signed, size };
        Ok(match ty {
            Type::Void => TypeRef::Void,
            Type::Bool => TypeRef::Bool,
            Type::Char | Type::U16 => int(false, 2),
            Type::I8 => int(true, 1),
            Type::U8 => int(false, 1),
            Type::I16 => int(true, 2),
            Type::I32 => int(true, 4),
            Type::U32 => int(false, 4),
            Type::I64 => int(true, 8),
            Type::U64 => int(false, 8),
            Type::F32 => TypeRef::Float(FloatFormat::Single),
            Type::F64 => TypeRef::Float(FloatFormat::Double),
            Type::ISize => self.int(true),
            Type::USize => self.int(false),
            Type::String => TypeRef::Pointer(Box::new(int(false, 2))),
            Type::Object => TypeRef::Pointer(Box::new(TypeRef::Void)),
            Type::Name(name) => self.named(name, scope)?,
            Type::PtrMut(inner, count) | Type::PtrConst(inner, count) => {
                let mut ty = self.convert(inner, scope)?;
                for _ in 0..*count {
                    ty = TypeRef::Pointer(Box::new(ty));
                }
                ty
            }
            Type::RefMut(inner)
            | Type::RefConst(inner)
            | Type::Array(inner)
            | Type::ArrayRef(inner) => TypeRef::Pointer(Box::new(self.convert(inner, scope)?)),
            Type::ArrayFixed(inner, count) => TypeRef::Array {
                element: Box::new(self.convert(inner, scope)?),
                count: u64::try_from(*count).ok(),
            },
            Type::Generic(_) | Type::AttributeEnum => {
                return Err(format!("a type {ty:?} in a signature"));
            }
        })
    }

    /// A named type: nested in an enclosing one (an empty namespace), else
    /// by namespace; opaque if the metadata does not define it.
    fn named(&mut self, name: &TypeName, scope: &[Scope<'_, 'i>]) -> Result<TypeRef, String> {
        let index = self.index;
        if name.namespace.is_empty() {
            for enclosing in scope.iter().rev() {
                if let Some(nested) = index
                    .nested(enclosing.def)
                    .find(|nested| nested.name() == name.name && self.for_target(nested.arches()))
                {
                    let qualified = format!("{}.{}", enclosing.qualified, name.name);
                    return self.define(nested, &qualified, scope);
                }
            }
        } else if let Some(def) = index
            .get(&name.namespace, &name.name)
            .find(|def| self.for_target(def.arches()))
        {
            let qualified = format!("{}.{}", name.namespace, name.name);
            return self.define(def, &qualified, &[]);
        }
        let key = if name.namespace.is_empty() {
            name.name.clone()
        } else {
            format!("{}.{}", name.namespace, name.name)
        };
        if self.done.insert(key.clone()) {
            self.declarations.define(Definition::Opaque(Opaque {
                key: key.clone(),
                name: name.name.clone(),
            }))?;
        }
        Ok(TypeRef::Named(key))
    }
}

fn enumeration(def: TypeDef<'_>, key: String) -> Enum {
    let mut size = None;
    let mut variants = Vec::new();
    for field in def.fields() {
        if !field.flags().contains(FieldAttributes::Literal) {
            // `value__`, of the underlying type.
            size = match field.ty() {
                Type::I8 | Type::U8 => Some(1),
                Type::I16 | Type::U16 => Some(2),
                Type::I32 | Type::U32 => Some(4),
                Type::I64 | Type::U64 => Some(8),
                Type::Void
                | Type::Bool
                | Type::Char
                | Type::F32
                | Type::F64
                | Type::ISize
                | Type::USize
                | Type::String
                | Type::Object
                | Type::AttributeEnum
                | Type::Name(_)
                | Type::Array(_)
                | Type::ArrayRef(_)
                | Type::Generic(_)
                | Type::RefMut(_)
                | Type::RefConst(_)
                | Type::PtrMut(..)
                | Type::PtrConst(..)
                | Type::ArrayFixed(..) => None,
            };
            continue;
        }
        let value = field
            .constant()
            .and_then(|constant| match constant.value() {
                Value::I8(value) => Some(i128::from(value)),
                Value::U8(value) => Some(i128::from(value)),
                Value::I16(value) => Some(i128::from(value)),
                Value::U16(value) => Some(i128::from(value)),
                Value::I32(value) => Some(i128::from(value)),
                Value::U32(value) => Some(i128::from(value)),
                Value::I64(value) => Some(i128::from(value)),
                Value::U64(value) => Some(i128::from(value)),
                Value::Bool(_)
                | Value::F32(_)
                | Value::F64(_)
                | Value::Utf8(_)
                | Value::Utf16(_)
                | Value::AttributeEnum(..) => None,
            });
        variants.push(Variant {
            name: field.name().to_owned(),
            value,
        });
    }
    Enum {
        key,
        name: Some(def.name().to_owned()),
        size,
        flags: def.has_attribute("FlagsAttribute"),
        variants,
    }
}

/// A record's layout: its size, its alignment and its fields' offsets, in
/// bytes.
struct RecordLayout {
    size: u64,
    align: u64,
    offsets: Vec<u64>,
}

/// MSVC's layouts of the records in `types` ([`Layouts::Computed`]), with
/// pointers of `pointer` bytes and the records' stated `packing`.
fn lay_out(
    types: &mut BTreeMap<String, Definition<TypeRef>>,
    pointer: u64,
    packing: &HashMap<String, u64>,
) {
    let mut layouts = Layouter {
        types: &*types,
        pointer,
        packing,
        records: HashMap::new(),
    };
    let keys: Vec<&str> = types
        .iter()
        .filter(|(_, definition)| matches!(definition, Definition::Record(_)))
        .map(|(key, _)| key.as_str())
        .collect();
    for key in keys {
        layouts.record(key);
    }
    let computed: Vec<(String, RecordLayout)> = layouts
        .records
        .into_iter()
        .filter_map(|(key, layout)| Some((key.to_owned(), layout?)))
        .collect();
    for (key, layout) in computed {
        let Some(Definition::Record(record)) = types.get_mut(&key) else {
            continue;
        };
        if record.size.is_some_and(|stated| stated != layout.size) {
            continue;
        }
        record.size = Some(layout.size);
        record.align = Some(layout.align);
        for (field, offset) in record.fields.iter_mut().flatten().zip(layout.offsets) {
            field.bit_offset = Some(offset * 8);
        }
    }
}

/// Computes the layouts of [`lay_out`]'s records.
struct Layouter<'d> {
    types: &'d BTreeMap<String, Definition<TypeRef>>,
    pointer: u64,
    packing: &'d HashMap<String, u64>,
    /// The layouts computed (`None`: none can be, or being computed).
    records: HashMap<&'d str, Option<RecordLayout>>,
}

impl<'d> Layouter<'d> {
    /// The size and alignment of `ty`, if it has a layout.
    fn of(&mut self, ty: &'d TypeRef) -> Option<(u64, u64)> {
        match ty {
            TypeRef::Void
            | TypeRef::Function(_)
            | TypeRef::Float(FloatFormat::Half | FloatFormat::X87 | FloatFormat::Quad) => None,
            TypeRef::Bool | TypeRef::Char { .. } => Some((1, 1)),
            &TypeRef::Int { size, .. } => Some((u64::from(size), u64::from(size))),
            TypeRef::Float(FloatFormat::Single) => Some((4, 4)),
            TypeRef::Float(FloatFormat::Double) => Some((8, 8)),
            TypeRef::Pointer(_) => Some((self.pointer, self.pointer)),
            TypeRef::Array { element, count } => {
                let (size, align) = self.of(element)?;
                Some((size.checked_mul((*count)?)?, align))
            }
            TypeRef::Named(key) => match self.types.get(key)? {
                Definition::Typedef(typedef) => self.of(&typedef.target),
                Definition::Enum(definition) => {
                    let size = u64::from(definition.size.unwrap_or(4));
                    Some((size, size))
                }
                Definition::Record(_) => self.record(key),
                Definition::Opaque(_) => None,
            },
        }
    }

    /// The size and alignment of record `key`, laid out once: each field
    /// at the next multiple of its alignment (at most the record's
    /// packing), a union's all at 0; the size a multiple of the largest.
    fn record(&mut self, key: &'d str) -> Option<(u64, u64)> {
        if let Some(layout) = self.records.get(key) {
            return layout.as_ref().map(|layout| (layout.size, layout.align));
        }
        // A record that holds itself (no C one can) has no layout.
        self.records.insert(key, None);
        let Some(Definition::Record(record)) = self.types.get(key) else {
            return None;
        };
        let fields = record.fields.as_ref().filter(|fields| !fields.is_empty())?;
        let packing = self.packing.get(key).copied();
        let (mut end, mut align, mut offsets) = (0u64, 1u64, Vec::with_capacity(fields.len()));
        for field in fields {
            let (size, natural) = self.of(&field.ty)?;
            let field_align = packing.map_or(natural, |packing| natural.min(packing));
            align = align.max(field_align);
            let offset = if record.union {
                0
            } else {
                end.checked_next_multiple_of(field_align)?
            };
            offsets.push(offset);
            end = end.max(offset.checked_add(size)?);
        }
        let size = end.checked_next_multiple_of(align)?;
        self.records.insert(
            key,
            Some(RecordLayout {
                size,
                align,
                offsets,
            }),
        );
        Some((size, align))
    }
}
