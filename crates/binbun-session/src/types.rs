//! The user's types of the edits ([`Edits::types`],
//! [`Edits::definitions`]) read as C against the database's type library
//! ([`user_types`]): what decompilation takes
//! ([`Database::set_user`](binbun::Database::set_user)), and the edits
//! that do not read, with why.

use std::collections::{BTreeMap, BTreeSet};

use binbun::decompile::Callers;
use binbun::prototypes::enumeration as lib_enumeration;
use binbun::user::{UserTypes, data_model};
use binbun::{Database, GlobalField};
use binbun_ast::types::{Enumeration, Type, TypeId, Types};
use binbun_decompile::typing::{GlobalType, StructId};
use binbun_print::c::definitions;
use binbun_print::layout::render;
use binbun_print::style::Style;
use binbun_typedb::c::{CError, Scope};
use binbun_typedb::{Type as LibType, TypeId as LibId};

use crate::edits::{Edit, Edits, NumberForm, Typed, Unresolved, Variable};

/// A struct or union laid out as the target's compiler lays it out
/// ([`Session::struct_layout`](crate::Session::struct_layout)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StructLayout {
    /// Its key (`struct pair`).
    pub key: String,
    /// Its size in bytes.
    pub size: u64,
    /// Its members in order.
    pub members: Vec<StructMember>,
}

/// A member of a [`StructLayout`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StructMember {
    /// Its name (empty: an anonymous struct or union).
    pub name: String,
    /// Its offset in bits.
    pub bit_offset: u64,
    /// Its size in bytes: a bit-field's declared type's, a flexible array
    /// member's 0.
    pub size: u64,
    /// A bit-field's width in bits.
    pub bit_width: Option<u32>,
}

/// An enumeration as its C defines it
/// ([`Session::type_layout`](crate::Session::type_layout)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnumLayout {
    /// Its key (`enum perm`, or the typedef naming an anonymous one).
    pub key: String,
    /// The size of its underlying integer in bytes.
    pub size: u64,
    /// Whether its values are flags (`__attribute__((flag_enum))`).
    pub flags: bool,
    /// Its constants in order, each with its value.
    pub constants: Vec<(String, i128)>,
}

/// What a definition as C defines, laid out
/// ([`Session::type_layout`](crate::Session::type_layout)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TypeLayout {
    /// A struct or union.
    Record(StructLayout),
    /// An enumeration.
    Enum(EnumLayout),
}

impl TypeLayout {
    /// The key of what it lays out.
    pub fn key(&self) -> &str {
        match self {
            Self::Record(layout) => &layout.key,
            Self::Enum(layout) => &layout.key,
        }
    }
}

/// A struct of the program's table of synthesised structs
/// ([`Session::synthesised`](crate::Session::synthesised)), as it stands:
/// the user's version where there is one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Synthesised {
    /// The entry of the function it is born in.
    pub function: u64,
    /// Its number among the structs born there (from 1).
    pub k: u32,
    /// Its key as the C names it (`struct struct_main_1`, or the user's
    /// `struct pair`).
    pub key: String,
    /// Its size in bytes.
    pub size: u64,
    /// Its definition as C: the user's, else as the C prints it.
    pub c: String,
    /// Whether the user's version replaces the table's.
    pub stated: bool,
}

impl Synthesised {
    /// What the user's version of it types.
    pub const fn typed(&self) -> Typed {
        Typed::Struct {
            function: self.function,
            k: self.k,
        }
    }
}

/// A global's one type over the program
/// ([`Session::global_type`](crate::Session::global_type)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobalTyped {
    /// The type, with where it comes from and every function's evidence
    /// ([`GlobalType::clues`]); a struct's fields are the table's
    /// ([`Session::synthesised`](crate::Session::synthesised)).
    pub ty: GlobalType,
    /// Its name as the C prints it.
    pub name: String,
    /// Its declaration as the C prints it, without `extern` and the `;`
    /// (`struct struct_disable_priv_mode_1 current_user`); `None` where the
    /// image's code is not lifted.
    pub c: Option<String>,
    /// Its fields as a hex view overlays them, each with how many
    /// references there are into it ([`Database::global_fields`]).
    pub fields: Vec<GlobalField>,
}

impl GlobalTyped {
    /// What the user's type for it types (Set type, `Y`).
    pub const fn typed(&self) -> Typed {
        Typed::Global(self.ty.start)
    }
}

/// A global's type as a table of its own, each type named as the C names
/// it ([`Session::global_table`](crate::Session::global_table)): what a hex
/// view lays over the global's bytes.
#[derive(Clone, Debug)]
pub struct GlobalTable {
    /// The table: the type, the structs it holds or points to.
    pub types: Types,
    /// The global's type.
    pub ty: TypeId,
    /// Each of the table's types by id, as a cast names it
    /// (`uint32_t[4]`, `struct pair *`); `None` for one C cannot name.
    pub names: Vec<Option<String>>,
}

/// The synthesised structs of the whole-program table `callers`, each
/// with its definition as `style` prints it, the user's text where
/// `edits` has a version of it.
pub(crate) fn synthesised(
    database: &Database<'_>,
    callers: &Callers,
    edits: &Edits,
    style: &Style,
) -> Vec<Synthesised> {
    let Some(declarations) = database.declarations() else {
        return Vec::new();
    };
    let structs = callers.schemes.structs();
    let model = data_model(database.image());
    let pointer = u16::from(model.pointer) * 8;
    let long = u16::from(model.long) * 8;
    structs
        .iter()
        .filter_map(|(id, _)| {
            let (types, ty) = structs.table(id, pointer)?;
            let (Type::Struct(aggregate) | Type::Union(aggregate)) = types.get(ty)? else {
                return None;
            };
            let keyword = if matches!(types.get(ty), Some(Type::Union(_))) {
                "union"
            } else {
                "struct"
            };
            let key = format!("{keyword} {}", aggregate.name.as_deref()?);
            let user = Typed::Struct {
                function: id.function,
                k: id.k,
            };
            let stated = edits.type_of(&user).map(str::to_owned);
            let c = if let Some(c) = &stated {
                c.clone()
            } else {
                let document = definitions(&types, &[ty], declarations, style, long).ok()?;
                definition_in(&render(&document, style), &key)?
            };
            Some(Synthesised {
                function: id.function,
                k: id.k,
                key,
                size: aggregate.size,
                c,
                stated: stated.is_some(),
            })
        })
        .collect()
}

/// The definition of `key` (`struct pair`) in C `text`: from its line
/// `key {` to the `};` closing it.
pub fn definition_in(text: &str, key: &str) -> Option<String> {
    let head = format!("{key} {{");
    let start = text
        .match_indices(&head)
        .map(|(at, _)| at)
        .find(|&at| at == 0 || text.get(..at).is_some_and(|before| before.ends_with('\n')))?;
    let rest = text.get(start..)?;
    let end = rest.find("\n};")? + "\n};".len();
    rest.get(..end).map(str::to_owned)
}

/// The layout of the struct or union `c` defines (the last), in `scope`.
///
/// # Errors
///
/// The C is refused, or defines no struct or union.
pub(crate) fn struct_layout(scope: &mut Scope<'_>, c: &str) -> Result<StructLayout, CError> {
    let (key, id) = defined_record(scope, c)?;
    record_layout(scope, key, id).ok_or_else(|| no_record(c))
}

/// The layout of record `id` of `scope`, keyed `key`; `None` if it is no
/// record.
fn record_layout(scope: &Scope<'_>, key: String, id: LibId) -> Option<StructLayout> {
    let Some(LibType::Record(record)) = scope.types().ty(id) else {
        return None;
    };
    let members = record
        .fields
        .iter()
        .flatten()
        .map(|field| StructMember {
            name: field.name.clone().unwrap_or_default(),
            bit_offset: field.bit_offset.unwrap_or(0),
            size: scope.size_of(field.ty).unwrap_or(0),
            bit_width: field.bit_width,
        })
        .collect();
    Some(StructLayout {
        key,
        size: scope.size_of(id).unwrap_or(0),
        members,
    })
}

/// The layout of the struct, union or enumeration `c` defines (the last;
/// an enumeration by its tag, or by the typedef naming it), in `scope`.
///
/// # Errors
///
/// The C is refused, or defines none of them.
pub(crate) fn type_layout(scope: &mut Scope<'_>, c: &str) -> Result<TypeLayout, CError> {
    let nothing = || CError {
        message: "no struct, union or enumeration is defined".to_owned(),
        span: 0..c.len(),
    };
    let defined = scope.define(c)?;
    for key in defined.into_iter().rev() {
        let Some(id) = scope.lookup(&key) else {
            continue;
        };
        if key.starts_with("struct ") || key.starts_with("union ") {
            return record_layout(scope, key, id)
                .map(TypeLayout::Record)
                .ok_or_else(nothing);
        }
        if let Some(LibType::Enum(definition)) = scope.types().ty(scope.resolve(id)) {
            return Ok(TypeLayout::Enum(EnumLayout {
                key,
                size: u64::from(definition.size.unwrap_or(4)),
                flags: definition.flags,
                constants: definition
                    .variants
                    .iter()
                    .filter_map(|v| Some((v.name.clone(), v.value?)))
                    .collect(),
            }));
        }
    }
    Err(nothing())
}

/// Defines what `c` defines in `scope`; the key and type of the last
/// struct or union it defined.
///
/// # Errors
///
/// The C is refused, or defines no struct or union.
fn defined_record(scope: &mut Scope<'_>, c: &str) -> Result<(String, LibId), CError> {
    let defined = scope.define(c)?;
    let key = defined
        .iter()
        .rev()
        .find(|key| key.starts_with("struct ") || key.starts_with("union "))
        .ok_or_else(|| no_record(c))?
        .clone();
    let id = scope.lookup(&key).ok_or_else(|| no_record(c))?;
    Ok((key, id))
}

/// That C `c` defines no struct or union.
fn no_record(c: &str) -> CError {
    CError {
        message: "no struct or union is defined".to_owned(),
        span: 0..c.len(),
    }
}

/// A C scope over `database`'s type library with the user's definitions
/// (`edits`), and the definitions that do not read, with why.
pub(crate) fn scope<'d>(database: &'d Database<'_>, edits: &Edits) -> (Scope<'d>, Vec<Unresolved>) {
    let mut scope = Scope::new(data_model(database.image()), Some(database.library()));
    let definitions = edits.definitions().iter().map(|(key, c)| {
        let edit = Edit::Definition {
            key: key.clone(),
            c: c.clone(),
        };
        (edit, c.as_str())
    });
    // The user's versions of synthesised structs define their types too.
    let structs = edits
        .types()
        .iter()
        .filter(|(typed, _)| matches!(typed, Typed::Struct { .. }))
        .map(|(typed, c)| {
            let edit = Edit::Type {
                typed: typed.clone(),
                c: c.clone(),
            };
            (edit, c.as_str())
        });
    let mut left: Vec<(Edit, &str)> = definitions.chain(structs).collect();
    // In any order: each pass defines what it can, so a definition may
    // name one after it.
    loop {
        let before = left.len();
        left.retain(|(_, c)| scope.define(c).is_err());
        if left.is_empty() || left.len() == before {
            break;
        }
    }
    let unresolved = left
        .into_iter()
        .map(|(edit, c)| Unresolved {
            why: scope
                .clone()
                .define(c)
                .err()
                .map_or_else(String::new, |error| error.message),
            edit,
        })
        .collect();
    (scope, unresolved)
}

/// The enumerations the numbers' forms in `edits` name
/// ([`NumberForm::Enum`]), by that name: a typedef's (`ACCESS_MASK`) or
/// `enum tag`, through typedefs, in `database`'s types and the user's
/// definitions; a name that names no enumeration is left out.
pub(crate) fn enumerations(
    database: &Database<'_>,
    edits: &Edits,
) -> BTreeMap<String, Enumeration> {
    let names: BTreeSet<&str> = edits
        .numbers()
        .values()
        .filter_map(|form| match form {
            NumberForm::Enum(name) => Some(name.as_str()),
            NumberForm::Hex | NumberForm::Decimal | NumberForm::Char => None,
        })
        .collect();
    if names.is_empty() {
        return BTreeMap::new();
    }
    let (mut scope, _) = scope(database, edits);
    names
        .into_iter()
        .filter_map(|name| Some((name.to_owned(), enumeration(&mut scope, name)?)))
        .collect()
}

/// The enumeration type name `name` names in `scope`, through typedefs.
pub(crate) fn enumeration(scope: &mut Scope<'_>, name: &str) -> Option<Enumeration> {
    let mut id = scope.lookup(name)?;
    let types = scope.types();
    for _ in 0..64 {
        let ty = types.ty(id)?;
        if let LibType::Typedef(typedef) = ty {
            id = typedef.target;
            continue;
        }
        let LibType::Enum(definition) = ty else {
            return None;
        };
        return lib_enumeration(definition);
    }
    None
}

/// Every enumeration of `database`'s types and the user's definitions
/// (`edits`) a number's form may name ([`NumberForm::Enum`]), sorted by
/// that name: a typedef naming it (`ACCESS_MASK`), else its `enum tag`.
pub(crate) fn all_enumerations(
    database: &Database<'_>,
    edits: &Edits,
) -> Vec<(String, Enumeration)> {
    let library = database.library();
    let names_one = |key: &str| {
        let Some(mut id) = library.named(key) else {
            return false;
        };
        for _ in 0..64 {
            let ty = library.ty(id);
            if let Some(LibType::Typedef(typedef)) = ty {
                id = typedef.target;
                continue;
            }
            return matches!(ty, Some(LibType::Enum(_)));
        }
        false
    };
    let mut names: BTreeSet<&str> = library.keys().filter(|key| names_one(key)).collect();
    names.extend(edits.definitions().keys().map(String::as_str));
    let (mut scope, _) = scope(database, edits);
    // One enumeration named both ways by the typedef.
    let mut by_enumeration: BTreeMap<Enumeration, &str> = BTreeMap::new();
    for name in names {
        let Some(found) = enumeration(&mut scope, name) else {
            continue;
        };
        let kept = by_enumeration.entry(found).or_insert(name);
        if kept.starts_with("enum ") && !name.starts_with("enum ") {
            *kept = name;
        }
    }
    let mut out: Vec<(String, Enumeration)> = by_enumeration
        .into_iter()
        .map(|(found, name)| (name.to_owned(), found))
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// The places of `variable`: the L1 values it is made of, else its frame
/// slot.
fn places(variable: &Variable) -> (Vec<u32>, Option<i64>) {
    let values = variable
        .origins
        .iter()
        .filter_map(|origin| origin.strip_prefix("value ")?.parse().ok())
        .collect();
    let slot = variable
        .origins
        .iter()
        .find_map(|origin| origin.strip_prefix("slot ")?.parse().ok());
    (values, slot)
}

/// The type C `c` gives `typed` in `scope`, if decompilation can take it
/// there: for a variable `width` bits wide (as decompiled, when known),
/// a type of that width.
///
/// # Errors
///
/// The C does not read, or states a type that cannot be there.
pub(crate) fn read(
    scope: &mut Scope<'_>,
    typed: &Typed,
    c: &str,
    width: Option<u64>,
) -> Result<LibId, CError> {
    if let Typed::Struct { .. } = typed {
        return defined_record(scope, c).map(|(_, id)| id);
    }
    let declared = scope.declaration(c)?;
    let pointer = u16::from(scope.model().pointer) * 8;
    let refuse = |message: String| CError {
        message,
        span: 0..c.len(),
    };
    match typed {
        Typed::Prototype(_) => {
            UserTypes::check_prototype(scope.types(), declared.ty, pointer).map_err(refuse)?;
        }
        Typed::Global(_) => {
            UserTypes::check_variable(scope.types(), declared.ty, None, false, pointer)
                .map_err(refuse)?;
        }
        Typed::Variable(variable) => {
            let (values, slot) = places(variable);
            if values.is_empty() && slot.is_none() {
                return Err(refuse(
                    "this variable is made of no value or frame slot binbun can type".to_owned(),
                ));
            }
            UserTypes::check_variable(
                scope.types(),
                declared.ty,
                width,
                !values.is_empty(),
                pointer,
            )
            .map_err(refuse)?;
        }
        Typed::Struct { .. } => {}
    }
    Ok(declared.ty)
}

/// The user's types of `edits` read against `database`, and the edits
/// that do not read, with why. A struct or union the user defines is the
/// type of its key wherever the type library's declarations name it.
pub(crate) fn user_types(database: &Database<'_>, edits: &Edits) -> (UserTypes, Vec<Unresolved>) {
    let (mut scope, mut unresolved) = scope(database, edits);
    let records: Vec<(&str, LibId)> = edits
        .definitions()
        .keys()
        .filter(|key| {
            !unresolved
                .iter()
                .any(|u| matches!(&u.edit, Edit::Definition { key: k, .. } if k == *key))
        })
        .filter_map(|key| Some((key.as_str(), scope.lookup(key)?)))
        .collect();
    let mut stated = Vec::new();
    for (typed, c) in edits.types() {
        match read(&mut scope, typed, c, None) {
            Ok(ty) => stated.push((typed, ty)),
            Err(error) => unresolved.push(Unresolved {
                edit: Edit::Type {
                    typed: typed.clone(),
                    c: c.clone(),
                },
                why: error.message,
            }),
        }
    }
    let pointer = u16::from(scope.model().pointer) * 8;
    let mut user = UserTypes::new(scope.into_types(), pointer);
    for (key, ty) in records {
        user.set_record(key, ty);
    }
    for (typed, ty) in stated {
        match typed {
            &Typed::Prototype(entry) => user.set_prototype(entry, ty),
            &Typed::Global(address) => user.set_global(address, ty),
            &Typed::Struct { function, k } => user.set_struct(StructId { function, k }, ty),
            Typed::Variable(variable) => match places(variable) {
                (values, _) if !values.is_empty() => {
                    user.set_values(variable.function, &values, ty);
                }
                (_, Some(offset)) => user.set_frame(variable.function, offset, ty),
                (_, None) => {}
            },
        }
    }
    (user, unresolved)
}

#[cfg(test)]
mod tests {
    use binbun_typedb::c::DataModel;

    use super::*;

    #[test]
    fn a_layout_gives_each_members_offset_and_size() {
        let mut scope = Scope::new(DataModel::LP64, None);
        let c = "struct s {\n    char c;\n    int n;\n    long x;\n    unsigned a : 3;\n    char t[];\n};";
        let layout = struct_layout(&mut scope, c).unwrap();
        let members: Vec<(&str, u64, u64, Option<u32>)> = layout
            .members
            .iter()
            .map(|m| (m.name.as_str(), m.bit_offset, m.size, m.bit_width))
            .collect();
        assert_eq!(
            members,
            [
                ("c", 0, 1, None),
                ("n", 32, 4, None),
                ("x", 64, 8, None),
                ("a", 128, 4, Some(3)),
                ("t", 136, 0, None),
            ]
        );
        assert_eq!((layout.key.as_str(), layout.size), ("struct s", 24));
    }
}
