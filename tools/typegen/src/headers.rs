//! C headers, parsed by libclang.
//!
//! Types keep their typedefs: a parameter declared `size_t` refers to the
//! typedef `size_t`, which refers to `unsigned long`. Anonymous structures,
//! unions and enumerations get keys from where they appear (see
//! [`TypeRef::Named`]). A function is keyed by the name it links as: a
//! declaration redirected with `__asm__("…")` (glibc's `__REDIRECT`)
//! declares the label, and also the C name unless that is reserved (`__`):
//! `strtol`, redirected to `__isoc23_strtol` by C23 headers, is the same
//! function where it is not redirected.
//!
//! C++ headers (read with `-x c++`: the C++ runtime's `cxxabi.h`) declare
//! what has C linkage, in namespaces and `extern "C"` blocks: a function
//! whose linkage name is a C++ mangling is left out. A class or structure
//! is keyed as a C structure by its unqualified name (`std::type_info` is
//! `struct type_info`).

use std::collections::HashMap;
use std::fmt::{Display, Write as _};
use std::path::{Path, PathBuf};

use binbun_typedb::database::{Definition, Format, Function, Target, TypeRef};
use binbun_typedb::types::{
    Convention, Enum, Field, FloatFormat, Opaque, Param, Record, Signature, Typedef, Variant,
};
use clang::diagnostic::Severity;
use clang::token::Token;
use clang::{
    CallingConvention, Clang, Entity, EntityKind, ExceptionSpecification, Index,
    PrintingPolicyFlag, StorageClass, Type, TypeKind, Unsaved,
};

use crate::Declarations;

/// The parser's options.
#[derive(Clone, Debug)]
pub struct Options<'a> {
    /// The target, for clang's `--target` and `long double`'s format.
    pub target: &'a Target,
    /// Arguments passed on to clang (`-D_GNU_SOURCE`, `-I…`).
    pub args: &'a [String],
    /// Whether declarations in system headers are kept (a libc's own
    /// headers are system headers); otherwise only those in the headers
    /// given are.
    pub include_system: bool,
    /// Where declarations are kept from (files, or directories and what
    /// they hold): a declaration in any other header is left out, though
    /// a type it declares is still converted where a kept one uses it.
    /// Empty: anywhere.
    pub from: &'a [PathBuf],
    /// C declarations read after the headers, as a last header's
    /// (GCC's fortified builtins, [`gcc::fortified`](crate::gcc::fortified)):
    /// kept only where `from` is empty (they are in no header file); a
    /// function the headers declare keeps their prototype.
    pub extra: &'a str,
}

/// Parses `headers`, included in this order.
///
/// # Errors
///
/// If libclang cannot be loaded, it reports an error (such as a missing
/// header: a database must not silently shrink), or a declaration has a
/// form this generator does not convert.
pub fn parse(headers: &[&Path], options: &Options<'_>) -> Result<Declarations, String> {
    let clang = Clang::new()?;
    let index = Index::new(&clang, false, false);
    let mut umbrella = String::new();
    for header in headers {
        let path = header
            .canonicalize()
            .map_err(|error| format!("{}: {error}", header.display()))?;
        let _ = writeln!(umbrella, "#include \"{}\"", path.display());
    }
    umbrella.push_str(options.extra);
    let mut args = options.args.to_vec();
    // A target among the arguments is the one the headers are read for
    // (mingw-w64's, GNU's, for an MSVC target's database).
    if !args.iter().any(|arg| arg.starts_with("--target=")) {
        args.push(format!("--target={}", triple(options.target)));
    }
    let unit = index
        .parser("__binbun_typegen.h")
        .arguments(&args)
        .unsaved(&[Unsaved::new("__binbun_typegen.h", &umbrella)])
        .parse()
        .map_err(|error| format!("libclang: {error}"))?;
    let errors: Vec<String> = unit
        .get_diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.get_severity() >= Severity::Error)
        .map(ToString::to_string)
        .collect();
    if !errors.is_empty() {
        return Err(errors.join("\n"));
    }
    let mut converter = Converter {
        target: options.target,
        cplusplus: args.windows(2).any(|pair| pair == ["-x", "c++"])
            || args.iter().any(|arg| arg == "-xc++"),
        declarations: Declarations::default(),
        keys: HashMap::new(),
        functions: HashMap::new(),
    };
    // Anonymous enumerations nothing refers to (glibc's `_SC_*` constants),
    // converted last: one a typedef names gets the typedef's key.
    let mut constants = Vec::new();
    for entity in declarations(unit.get_entity()) {
        if !options.include_system && entity.is_in_system_header() {
            continue;
        }
        if !options.from.is_empty() && !declared_in(entity, options.from) {
            continue;
        }
        let kind = entity.get_kind();
        if kind == EntityKind::FunctionDecl {
            converter.function(entity)?;
        } else if kind == EntityKind::TypedefDecl {
            converter.typedef(entity)?;
        } else if tag_kind(kind).is_some() {
            if converter.tag_name(entity).is_some() {
                converter.tag(entity, "")?;
            } else if kind == EntityKind::EnumDecl {
                constants.push(entity);
            }
            // Other anonymous ones are converted where they are used.
        }
    }
    for entity in constants {
        let first = entity
            .get_children()
            .into_iter()
            .find(|child| child.get_kind() == EntityKind::EnumConstantDecl)
            .and_then(|constant| constant.get_name());
        if let Some(first) = first {
            converter.tag(entity, &format!("({first})"))?;
        }
    }
    Ok(converter.declarations)
}

/// clang's target triple for `target`.
fn triple(target: &Target) -> String {
    let vendor = match target.os.as_str() {
        "windows" => "pc",
        "macos" | "ios" => "apple",
        _ => "unknown",
    };
    format!("{}-{vendor}-{}-{}", target.arch, target.os, target.env)
}

/// The declarations of the translation unit at `unit`, with those in its
/// namespaces and linkage specifications (C++'s `extern "C"` blocks).
fn declarations(unit: Entity<'_>) -> Vec<Entity<'_>> {
    let mut found = Vec::new();
    let mut work = unit.get_children();
    work.reverse();
    while let Some(entity) = work.pop() {
        if matches!(
            entity.get_kind(),
            EntityKind::Namespace | EntityKind::LinkageSpec
        ) {
            work.extend(entity.get_children().into_iter().rev());
        } else {
            found.push(entity);
        }
    }
    found
}

/// The keyword of a tag declaration's kind.
fn tag_kind(kind: EntityKind) -> Option<&'static str> {
    [
        (EntityKind::StructDecl, "struct"),
        (EntityKind::ClassDecl, "struct"),
        (EntityKind::UnionDecl, "union"),
        (EntityKind::EnumDecl, "enum"),
    ]
    .into_iter()
    .find_map(|(tag, keyword)| (tag == kind).then_some(keyword))
}

struct Converter<'a> {
    target: &'a Target,
    /// Whether the headers are read as C++.
    cplusplus: bool,
    declarations: Declarations,
    /// The key of each type converted or being converted, by identity: a
    /// typedef's or tag's name (one namespace each in C), an anonymous
    /// tag's USR.
    keys: HashMap<String, String>,
    /// The index in `declarations.functions` of each function, by name.
    functions: HashMap<String, usize>,
}

/// What a function's declaration states besides its prototype.
struct Attributes<'a> {
    no_return: bool,
    no_throw: bool,
    format: Option<&'a Format>,
    format_arg: &'a [u32],
    alloc_size: Option<&'a [u32]>,
}

impl Converter<'_> {
    /// A structure's, union's or enumeration's tag; `None` for an
    /// anonymous one. libclang names an anonymous one after the typedef
    /// that names it (`typedef struct { … } anon_t`); only a tagged type's
    /// spelling is `struct tag` in C. In C++ a tagged type's spelling is
    /// its name, qualified by its namespaces.
    fn tag_name(&self, entity: Entity<'_>) -> Option<String> {
        let name = entity.get_name()?;
        let kind = tag_kind(entity.get_kind())?;
        let spelling = entity.get_type()?.get_display_name();
        let tagged = if self.cplusplus {
            !entity.is_anonymous() && (spelling == name || spelling.ends_with(&format!("::{name}")))
        } else {
            spelling == format!("{kind} {name}")
        };
        tagged.then_some(name)
    }

    fn function(&mut self, entity: Entity<'_>) -> Result<(), String> {
        // A static function is never imported.
        if entity.get_storage_class() == Some(StorageClass::Static) {
            return Ok(());
        }
        let Some(c_name) = entity.get_name() else {
            return Ok(());
        };
        // A C++ function is imported by its mangled name; only those of C
        // linkage are declared.
        if self.cplusplus
            && entity
                .get_mangled_name()
                .is_none_or(|linked| linked.starts_with("_Z") || linked.starts_with('?'))
        {
            return Ok(());
        }
        let ty = entity.get_type().ok_or_else(|| missing(&c_name, "type"))?;
        let place = format!("({c_name})");
        let ret = ty
            .get_result_type()
            .ok_or_else(|| missing(&c_name, "result"))?;
        let ret = self.convert(ret, &place)?;
        let mut params = Vec::new();
        for argument in entity.get_arguments().unwrap_or_default() {
            let name = argument.get_name().filter(|name| !name.is_empty());
            let ty = argument
                .get_type()
                .ok_or_else(|| missing(&c_name, "parameter type"))?;
            params.push(Param {
                ty: self.convert(ty, &place)?,
                name,
            });
        }
        let signature = Signature {
            ret,
            params,
            variadic: ty.is_variadic() || ty.get_kind() == TypeKind::FunctionNoPrototype,
            convention: convention(ty.get_calling_convention(), &c_name)?,
        };
        let no_return = declares_no_return(entity, ty);
        let no_throw = declares_no_throw(entity, ty);
        let format = declared_format(entity);
        let tokens = attribute_tokens(entity);
        let format_arg = tokens.as_deref().map(format_args).unwrap_or_default();
        let alloc_size = tokens.as_deref().and_then(alloc_size);
        let label = entity
            .get_children()
            .into_iter()
            .find(|child| child.get_kind() == EntityKind::AsmLabelAttr)
            .and_then(|label| label.get_name());
        let names = match label {
            Some(label) if label != c_name && !c_name.starts_with("__") => vec![label, c_name],
            Some(label) => vec![label],
            None => vec![c_name],
        };
        for name in names {
            let attributes = Attributes {
                no_return,
                no_throw,
                format: format.as_ref(),
                format_arg: &format_arg,
                alloc_size: alloc_size.as_deref(),
            };
            self.add_function(name, &signature, &attributes);
        }
        Ok(())
    }

    /// Adds a function; a redeclaration keeps the first prototype (which
    /// names the parameters) and adds a `noreturn`, `nothrow`, format,
    /// format argument or allocation size it states.
    fn add_function(
        &mut self,
        name: String,
        signature: &Signature<TypeRef>,
        attributes: &Attributes<'_>,
    ) {
        let &Attributes {
            no_return,
            no_throw,
            format,
            format_arg,
            alloc_size,
        } = attributes;
        if let Some(&index) = self.functions.get(&name) {
            if let Some(function) = self.declarations.functions.get_mut(index) {
                function.no_return |= no_return;
                function.no_throw |= no_throw;
                if function.format.is_none() {
                    function.format = format.cloned();
                }
                if function.format_arg.is_empty() {
                    function.format_arg = format_arg.to_vec();
                }
                if function.alloc_size.is_none() {
                    function.alloc_size = alloc_size.map(<[u32]>::to_vec);
                }
            }
            return;
        }
        self.functions
            .insert(name.clone(), self.declarations.functions.len());
        self.declarations.functions.push(Function {
            name,
            library: None,
            signature: signature.clone(),
            no_return,
            no_throw,
            format: format.cloned(),
            format_arg: format_arg.to_vec(),
            alloc_size: alloc_size.map(<[u32]>::to_vec),
            // A header declares functions, not system calls.
            number: None,
        });
    }

    /// The reference to `ty`, converting the types it names. `place` says
    /// where it appears, to key an anonymous type.
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "libclang's type kinds are open-ended; the rest is opaque"
    )]
    fn convert(&mut self, ty: Type<'_>, place: &str) -> Result<TypeRef, String> {
        let int = |signed| -> Result<TypeRef, String> {
            let size = ty
                .get_sizeof()
                .ok()
                .and_then(|size| u8::try_from(size).ok())
                .ok_or_else(|| format!("{}: no size", ty.get_display_name()))?;
            Ok(TypeRef::Int { signed, size })
        };
        Ok(match ty.get_kind() {
            TypeKind::Typedef => match ty.get_declaration() {
                Some(declaration) => self.typedef(declaration)?,
                None => self.canonical(ty, place)?,
            },
            TypeKind::Elaborated => match ty.get_elaborated_type() {
                Some(named) => self.convert(named, place)?,
                None => self.canonical(ty, place)?,
            },
            TypeKind::Attributed => match ty.get_modified_type() {
                Some(modified) => self.convert(modified, place)?,
                None => self.canonical(ty, place)?,
            },
            TypeKind::Record | TypeKind::Enum => match ty.get_declaration() {
                Some(declaration) => self.tag(declaration, place)?,
                None => self.opaque(ty)?,
            },
            TypeKind::Pointer
            | TypeKind::BlockPointer
            | TypeKind::LValueReference
            | TypeKind::RValueReference
            | TypeKind::MemberPointer => {
                let pointee = ty
                    .get_pointee_type()
                    .ok_or_else(|| format!("{}: no pointee", ty.get_display_name()))?;
                TypeRef::Pointer(Box::new(self.convert(pointee, place)?))
            }
            TypeKind::ConstantArray
            | TypeKind::IncompleteArray
            | TypeKind::VariableArray
            | TypeKind::DependentSizedArray => {
                let element = ty
                    .get_element_type()
                    .ok_or_else(|| format!("{}: no element", ty.get_display_name()))?;
                TypeRef::Array {
                    element: Box::new(self.convert(element, place)?),
                    count: if ty.get_kind() == TypeKind::ConstantArray {
                        ty.get_size().and_then(|count| u64::try_from(count).ok())
                    } else {
                        None
                    },
                }
            }
            TypeKind::FunctionPrototype | TypeKind::FunctionNoPrototype => {
                TypeRef::Function(Box::new(self.signature(ty, place)?))
            }
            TypeKind::Void => TypeRef::Void,
            TypeKind::Bool => TypeRef::Bool,
            TypeKind::CharS => TypeRef::Char { signed: true },
            TypeKind::CharU => TypeRef::Char { signed: false },
            TypeKind::SChar
            | TypeKind::Short
            | TypeKind::Int
            | TypeKind::Long
            | TypeKind::LongLong
            | TypeKind::Int128
            | TypeKind::WChar => int(true)?,
            TypeKind::UChar
            | TypeKind::UShort
            | TypeKind::UInt
            | TypeKind::ULong
            | TypeKind::ULongLong
            | TypeKind::UInt128
            | TypeKind::Char16
            | TypeKind::Char32 => int(false)?,
            TypeKind::Half | TypeKind::Float16 => TypeRef::Float(FloatFormat::Half),
            TypeKind::Float => TypeRef::Float(FloatFormat::Single),
            TypeKind::Double => TypeRef::Float(FloatFormat::Double),
            TypeKind::LongDouble => TypeRef::Float(self.long_double(ty)?),
            TypeKind::Float128 => TypeRef::Float(FloatFormat::Quad),
            TypeKind::Nullptr => TypeRef::Pointer(Box::new(TypeRef::Void)),
            TypeKind::Unexposed => self.canonical(ty, place)?,
            _ => self.opaque(ty)?,
        })
    }

    /// `ty` through its canonical type, or opaque if that is no clearer.
    fn canonical(&mut self, ty: Type<'_>, place: &str) -> Result<TypeRef, String> {
        let canonical = ty.get_canonical_type();
        if canonical.get_kind() == TypeKind::Unexposed || canonical == ty {
            self.opaque(ty)
        } else {
            self.convert(canonical, place)
        }
    }

    /// An opaque type keyed by its spelling (`_Complex double`, a vector
    /// type).
    fn opaque(&mut self, ty: Type<'_>) -> Result<TypeRef, String> {
        let key = ty.get_display_name();
        if !self.declarations.has_type(&key) {
            self.declarations.define(Definition::Opaque(Opaque {
                key: key.clone(),
                name: key.clone(),
            }))?;
        }
        Ok(TypeRef::Named(key))
    }

    fn long_double(&self, ty: Type<'_>) -> Result<FloatFormat, String> {
        let x86 = matches!(
            self.target.arch.as_str(),
            "x86_64" | "x86" | "i386" | "i686"
        );
        match ty.get_sizeof() {
            Ok(8) => Ok(FloatFormat::Double),
            Ok(12 | 16) if x86 => Ok(FloatFormat::X87),
            Ok(16) => Ok(FloatFormat::Quad),
            size => Err(format!("long double of size {size:?}")),
        }
    }

    /// The prototype of function type `ty` (parameters unnamed).
    fn signature(&mut self, ty: Type<'_>, place: &str) -> Result<Signature<TypeRef>, String> {
        let name = ty.get_display_name();
        let ret = ty
            .get_result_type()
            .ok_or_else(|| missing(&name, "result"))?;
        let mut params = Vec::new();
        for param in ty.get_argument_types().unwrap_or_default() {
            params.push(Param {
                name: None,
                ty: self.convert(param, place)?,
            });
        }
        Ok(Signature {
            ret: self.convert(ret, place)?,
            params,
            variadic: ty.is_variadic() || ty.get_kind() == TypeKind::FunctionNoPrototype,
            convention: convention(ty.get_calling_convention(), &name)?,
        })
    }

    fn typedef(&mut self, declaration: Entity<'_>) -> Result<TypeRef, String> {
        let name = declaration
            .get_name()
            .ok_or_else(|| "a typedef without a name".to_owned())?;
        let identity = format!("typedef {name}");
        if self.keys.contains_key(&identity) {
            return Ok(TypeRef::Named(name));
        }
        self.keys.insert(identity, name.clone());
        let underlying = declaration
            .get_typedef_underlying_type()
            .ok_or_else(|| missing(&name, "underlying type"))?;
        // A builtin typedef of the type it names (AArch64's SVE types,
        // `__SVFloat32_t`): that type, opaque under the name.
        if underlying.get_display_name() == name {
            return self.opaque(underlying);
        }
        let target = self.convert(underlying, &format!("({name})"))?;
        self.declarations.define(Definition::Typedef(Typedef {
            key: name.clone(),
            name: name.clone(),
            target,
        }))?;
        Ok(TypeRef::Named(name))
    }

    /// A structure, union or enumeration.
    fn tag(&mut self, declaration: Entity<'_>, place: &str) -> Result<TypeRef, String> {
        let kind = tag_kind(declaration.get_kind())
            .ok_or_else(|| format!("{:?} is not a tag", declaration.get_kind()))?;
        let name = self.tag_name(declaration);
        // An anonymous one by its USR and where it is declared: in C, the
        // USRs of a structure's anonymous members are all alike
        // (`c:@S@_TEB@Ua`).
        let identity = match &name {
            Some(name) => format!("{kind} {name}"),
            None => declaration
                .get_usr()
                .map(|usr| usr.0)
                .filter(|usr| !usr.is_empty())
                .map(|usr| {
                    let at = declaration
                        .get_location()
                        .map(|location| location.get_file_location());
                    let file = at
                        .as_ref()
                        .and_then(|at| at.file)
                        .map(|file| file.get_path().display().to_string());
                    let offset = at.as_ref().map(|at| at.offset);
                    format!("{usr}@{file:?}:{offset:?}")
                })
                .ok_or_else(|| format!("an anonymous {kind} without a USR, in {place}"))?,
        };
        if let Some(key) = self.keys.get(&identity) {
            return Ok(TypeRef::Named(key.clone()));
        }
        let key = match &name {
            Some(name) => format!("{kind} {name}"),
            None if place.is_empty() => {
                return Err(format!("an anonymous {kind} outside any declaration"));
            }
            None => format!("{kind} {place}"),
        };
        self.keys.insert(identity, key.clone());
        let definition = declaration.get_definition();
        let definition = if kind == "enum" {
            Definition::Enum(enumeration(key.clone(), name, definition))
        } else {
            Definition::Record(self.record(key.clone(), name, kind == "union", definition)?)
        };
        self.declarations.define(definition)?;
        Ok(TypeRef::Named(key))
    }

    fn record(
        &mut self,
        key: String,
        name: Option<String>,
        union: bool,
        definition: Option<Entity<'_>>,
    ) -> Result<Record<TypeRef>, String> {
        let Some(definition) = definition else {
            return Ok(Record {
                key,
                name,
                union,
                size: None,
                align: None,
                fields: None,
            });
        };
        let ty = definition.get_type().ok_or_else(|| missing(&key, "type"))?;
        let mut fields = Vec::new();
        // In declaration order: named fields, and anonymous member
        // structures and unions (whose implicit fields libclang does not
        // show).
        let members = definition.get_children().into_iter().filter(|child| {
            child.get_kind() == EntityKind::FieldDecl || child.is_anonymous_record_decl()
        });
        for (index, field) in members.enumerate() {
            if field.get_kind() != EntityKind::FieldDecl {
                let place = format!("({key}).#{index}");
                let member = self.tag(field, &place)?;
                fields.push(Field {
                    name: None,
                    ty: member,
                    bit_offset: anonymous_member_offset(ty, field),
                    bit_width: None,
                });
                continue;
            }
            let field_name = field.get_name().filter(|name| !name.is_empty());
            let place = match &field_name {
                Some(field_name) => format!("({key}).{field_name}"),
                None => format!("({key}).#{index}"),
            };
            let field_type = field.get_type().ok_or_else(|| missing(&place, "type"))?;
            fields.push(Field {
                ty: self.convert(field_type, &place)?,
                bit_offset: field
                    .get_offset_of_field()
                    .ok()
                    .and_then(|bits| u64::try_from(bits).ok()),
                bit_width: field
                    .get_bit_field_width()
                    .and_then(|width| u32::try_from(width).ok()),
                name: field_name,
            });
        }
        Ok(Record {
            key,
            name,
            union,
            size: ty
                .get_sizeof()
                .ok()
                .and_then(|size| u64::try_from(size).ok()),
            align: ty
                .get_alignof()
                .ok()
                .and_then(|align| u64::try_from(align).ok()),
            fields: Some(fields),
        })
    }
}

fn enumeration(key: String, name: Option<String>, definition: Option<Entity<'_>>) -> Enum {
    let underlying = definition.and_then(|definition| definition.get_enum_underlying_type());
    let signed = underlying.is_some_and(|ty| ty.get_canonical_type().is_signed_integer());
    let children = definition
        .map(|definition| definition.get_children())
        .unwrap_or_default();
    Enum {
        key,
        name,
        size: underlying
            .and_then(|ty| ty.get_sizeof().ok())
            .and_then(|size| u8::try_from(size).ok()),
        flags: children
            .iter()
            .any(|child| child.get_kind() == EntityKind::FlagEnum),
        variants: children
            .iter()
            .filter(|child| child.get_kind() == EntityKind::EnumConstantDecl)
            .map(|constant| Variant {
                name: constant.get_name().unwrap_or_default(),
                value: constant
                    .get_enum_constant_value()
                    .map(|(as_signed, as_unsigned)| {
                        if signed {
                            i128::from(as_signed)
                        } else {
                            i128::from(as_unsigned)
                        }
                    }),
            })
            .collect(),
    }
}

/// The offset in bits of anonymous member `member` of record type
/// `outer`: libclang gives offsets of named fields only, so through the
/// first named field inside it.
fn anonymous_member_offset(outer: Type<'_>, member: Entity<'_>) -> Option<u64> {
    let (name, inside) = first_named_field(member)?;
    let offset = outer.get_offsetof(&name).ok()?;
    u64::try_from(offset.checked_sub(inside)?).ok()
}

/// The first named field of `record` (looking into anonymous members) and
/// its offset in bits within it.
fn first_named_field(record: Entity<'_>) -> Option<(String, usize)> {
    record.get_children().into_iter().find_map(|child| {
        if child.get_kind() == EntityKind::FieldDecl {
            let name = child.get_name().filter(|name| !name.is_empty())?;
            Some((name, child.get_offset_of_field().ok()?))
        } else if child.is_anonymous_record_decl() {
            let (name, _) = first_named_field(child)?;
            let offset = record.get_type()?.get_offsetof(&name).ok()?;
            Some((name, offset))
        } else {
            None
        }
    })
}

/// Whether the declaration states that the function never returns. GNU
/// `__attribute__((noreturn))` is part of the function's type (so seen
/// through macros and inherited by redeclarations); C11 `_Noreturn` and
/// C23 `[[noreturn]]` are attributes of the declaration, which libclang
/// shows only as unexposed attributes, so by their tokens: those on the
/// attribute's first line, as a macro's attribute's range runs from its
/// spelling in the macro's definition to where the macro is used, over
/// all between (mingw-w64's `__prefetch` after the `noreturn`
/// `__fastfail`). Never inferred from the name or a `void` return.
fn declares_no_return(entity: Entity<'_>, ty: Type<'_>) -> bool {
    ty.get_display_name().ends_with("__attribute__((noreturn))")
        || entity.get_children().into_iter().any(|child| {
            child.get_kind() == EntityKind::UnexposedAttr
                && child.get_range().is_some_and(|range| {
                    let start = range.get_start().get_spelling_location();
                    range
                        .tokenize()
                        .iter()
                        .filter(|token| {
                            let at = token.get_location().get_spelling_location();
                            at.file == start.file && at.line == start.line
                        })
                        .map(Token::get_spelling)
                        .any(|token| {
                            matches!(token.as_str(), "_Noreturn" | "noreturn" | "__noreturn__")
                        })
                })
        })
}

/// Whether the declaration states that the function never throws: C++
/// `throw()`, `noexcept` (`noexcept(true)`) or `__declspec(nothrow)`,
/// part of the function's type; or GNU `__attribute__((nothrow))` (glibc's
/// `__THROW` in C), an attribute of the declaration that libclang shows
/// only as an unexposed attribute without tokens (a macro's), so by the
/// declaration as clang prints it. Never inferred from the name.
fn declares_no_throw(entity: Entity<'_>, ty: Type<'_>) -> bool {
    let specified = match ty.get_exception_specification() {
        Some(
            ExceptionSpecification::DynamicNone
            | ExceptionSpecification::BasicNoexcept
            | ExceptionSpecification::NoThrow,
        ) => true,
        Some(ExceptionSpecification::ComputedNoexcept) => {
            ty.get_display_name().ends_with("noexcept(true)")
        }
        Some(
            ExceptionSpecification::Dynamic
            | ExceptionSpecification::DynamicAny
            | ExceptionSpecification::Unevaluated
            | ExceptionSpecification::Uninstantiated
            | ExceptionSpecification::Unparsed,
        )
        | None => false,
    };
    specified || {
        let printer = entity.get_pretty_printer();
        printer.set_flag(PrintingPolicyFlag::UseTerseOutput, true);
        printer.print().contains("__attribute__((nothrow))")
    }
}

/// The format string the declaration states it takes: GNU
/// `__attribute__((format(archetype, string, first)))`, which libclang
/// shows only as an unexposed attribute, so by its tokens (`format` or
/// `__format__`, then the archetype, with or without underscores, and the
/// two indices). A format attribute clang adds to a library builtin it
/// knows (`printf`) is implicit, with no tokens: not seen.
fn declared_format(entity: Entity<'_>) -> Option<Format> {
    entity.get_children().into_iter().find_map(|child| {
        if child.get_kind() != EntityKind::UnexposedAttr {
            return None;
        }
        let tokens: Vec<String> = child
            .get_range()?
            .tokenize()
            .iter()
            .map(Token::get_spelling)
            .collect();
        let start = tokens
            .iter()
            .position(|token| matches!(token.as_str(), "format" | "__format__"))?;
        let [open, archetype, comma, string, comma2, first, close] =
            tokens.get(start + 1..start + 8)?
        else {
            return None;
        };
        if [open, comma, comma2, close].map(String::as_str) != ["(", ",", ",", ")"] {
            return None;
        }
        let archetype = archetype
            .strip_prefix("__")
            .and_then(|name| name.strip_suffix("__"))
            .unwrap_or(archetype);
        Some(Format {
            archetype: archetype.to_owned(),
            string: string.parse().ok()?,
            first: first.parse().ok()?,
        })
    })
}

/// The tokens a declaration's GNU attributes are read from where
/// libclang shows them only as unexposed attributes whose own tokens are
/// a macro's where glibc spells them so, outside the declaration's range
/// (and which its pretty printer leaves out): the declaration's tokens
/// and its file's text after them up to its `;`. `None` where it has no
/// unexposed attribute.
fn attribute_tokens(entity: Entity<'_>) -> Option<Vec<String>> {
    let attributed = entity
        .get_children()
        .iter()
        .any(|child| child.get_kind() == EntityKind::UnexposedAttr);
    if !attributed {
        return None;
    }
    let range = entity.get_range()?;
    let mut tokens: Vec<String> = range.tokenize().iter().map(Token::get_spelling).collect();
    let end = range.get_end().get_file_location();
    if let Some(contents) = end.file.and_then(|file| file.get_contents())
        && let Some(tail) = usize::try_from(end.offset)
            .ok()
            .and_then(|offset| contents.get(offset..))
        && let Some(tail) = tail.split([';', '{']).next()
    {
        tokens.extend(lex(tail));
    }
    Some(tokens)
}

/// The parameters a declaration's `tokens` ([`attribute_tokens`]) say give
/// the size of the object it returns: GNU `__attribute__((alloc_size(n)))`
/// or `alloc_size(n, m)` (counted from 1), spelled `alloc_size`,
/// `__alloc_size__`, or glibc's `__attribute_alloc_size__` macro, then one
/// or two indices in parentheses, nested as the macro's are.
fn alloc_size(tokens: &[String]) -> Option<Vec<u32>> {
    let start = tokens.iter().position(|token| {
        matches!(
            token.as_str(),
            "alloc_size" | "__alloc_size__" | "__attribute_alloc_size__"
        )
    })?;
    let indices = indices(tokens.get(start + 1..)?)?;
    matches!(indices.len(), 1 | 2).then_some(indices)
}

/// The parameters a declaration's `tokens` ([`attribute_tokens`]) say its
/// result is a format string of, translated: each GNU
/// `__attribute__((format_arg(n)))` (counted from 1), spelled
/// `format_arg`, `__format_arg__`, or glibc's `__attribute_format_arg__`
/// macro, then one index in parentheses, nested as the macro's are; in
/// order, without repeats. Empty where one does not parse.
fn format_args(tokens: &[String]) -> Vec<u32> {
    let mut found = Vec::new();
    for (at, token) in tokens.iter().enumerate() {
        if !matches!(
            token.as_str(),
            "format_arg" | "__format_arg__" | "__attribute_format_arg__"
        ) {
            continue;
        }
        match tokens.get(at + 1..).and_then(indices).as_deref() {
            Some(&[index]) => {
                if !found.contains(&index) {
                    found.push(index);
                }
            }
            _ => return Vec::new(),
        }
    }
    found
}

/// The indices in the parenthesised list `tokens` starts with (nested
/// parentheses, as a macro's, are taken through); `None` where it holds
/// anything but numbers and commas, or is not closed.
fn indices(tokens: &[String]) -> Option<Vec<u32>> {
    let mut depth = 0usize;
    let mut indices = Vec::new();
    for token in tokens {
        match token.as_str() {
            "(" => depth += 1,
            ")" => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(indices);
                }
            }
            "," => {}
            index if depth > 0 => indices.push(index.parse().ok()?),
            _ => return None,
        }
    }
    None
}

/// C text's identifiers, numbers and punctuation, as tokens (enough for
/// an attribute's arguments; comments are not skipped, as attributes are
/// read only after a declaration's own tokens).
fn lex(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut word = String::new();
    for c in text.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            word.push(c);
            continue;
        }
        if !word.is_empty() {
            tokens.push(core::mem::take(&mut word));
        }
        if !c.is_whitespace() {
            tokens.push(c.to_string());
        }
    }
    if !word.is_empty() {
        tokens.push(word);
    }
    tokens
}

/// The convention a declaration states, `None` for the target's default.
fn convention(
    convention: Option<CallingConvention>,
    function: &str,
) -> Result<Option<Convention>, String> {
    Ok(match convention {
        None | Some(CallingConvention::Cdecl) => None,
        Some(CallingConvention::Stdcall) => Some(Convention::Stdcall),
        Some(CallingConvention::Fastcall) => Some(Convention::Fastcall),
        Some(CallingConvention::Thiscall) => Some(Convention::Thiscall),
        Some(CallingConvention::Vectorcall) => Some(Convention::Vectorcall),
        Some(CallingConvention::RegCall) => Some(Convention::Regcall),
        Some(CallingConvention::Win64) => Some(Convention::Win64),
        Some(CallingConvention::SysV64) => Some(Convention::SysV64),
        Some(CallingConvention::Aapcs) => Some(Convention::Aapcs),
        Some(CallingConvention::AapcsVfp) => Some(Convention::AapcsVfp),
        Some(CallingConvention::PreserveMost) => Some(Convention::PreserveMost),
        Some(CallingConvention::PreserveAll) => Some(Convention::PreserveAll),
        Some(CallingConvention::Swift) => Some(Convention::Swift),
        Some(
            other @ (CallingConvention::Pascal
            | CallingConvention::IntelOcl
            | CallingConvention::Unexposed),
        ) => return Err(format!("{function}: calling convention {other:?}")),
    })
}

fn missing(what: &str, part: impl Display) -> String {
    format!("{what}: libclang gives no {part}")
}

/// Whether `entity` is declared in one of `places` (files, or directories
/// and what they hold).
fn declared_in(entity: Entity<'_>, places: &[PathBuf]) -> bool {
    let Some(file) = entity
        .get_location()
        .and_then(|location| location.get_file_location().file)
    else {
        return false;
    };
    let path = file.get_path();
    let path = path.canonicalize().unwrap_or(path);
    places.iter().any(|place| path.starts_with(place))
}
