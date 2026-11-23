//! binbun-typegen: binbun's type databases
//! ([`binbun_typedb::database`]) generated from C headers ([`headers`],
//! libclang), Windows metadata ([`winmd`]) and syzkaller's syscall
//! descriptions ([`syzlang`]); GCC's table of its builtins ([`gcc`]) adds
//! to the headers the fortified functions they call only as builtins.
//!
//! Each front end gives [`Declarations`]: the functions, and the named
//! types under keys unique in the database, every key a type refers to
//! defined. [`Declarations::into_database`] checks that by loading the
//! result into a [`TypeLibrary`].

pub mod gcc;
#[cfg(feature = "headers")]
pub mod headers;
pub mod syzlang;
#[cfg(feature = "winmd")]
pub mod winmd;

use std::collections::{BTreeMap, BTreeSet};

use binbun_typedb::TypeLibrary;
use binbun_typedb::database::{Database, Definition, Function, Header, TypeRef};
use binbun_typedb::types::Signature;

/// What a front end declares.
#[derive(Debug, Default)]
pub struct Declarations {
    /// The functions.
    pub functions: Vec<Function>,
    /// The named types, by key.
    pub types: BTreeMap<String, Definition<TypeRef>>,
}

impl Declarations {
    /// Defines a type.
    ///
    /// # Errors
    ///
    /// If another type has its key.
    pub fn define(&mut self, definition: Definition<TypeRef>) -> Result<(), String> {
        let key = definition.key().to_owned();
        if self.types.insert(key.clone(), definition).is_some() {
            return Err(format!("two types have the key `{key}`"));
        }
        Ok(())
    }

    /// Whether a type has key `key`.
    pub fn has_type(&self, key: &str) -> bool {
        self.types.contains_key(key)
    }

    /// Keeps only the types the functions refer to and those `keys`
    /// name, with the types they refer to.
    ///
    /// # Errors
    ///
    /// If no type has one of `keys`.
    pub fn keep(&mut self, keys: &[String]) -> Result<(), String> {
        let mut pending: Vec<&str> = Vec::new();
        for key in keys {
            if !self.types.contains_key(key) {
                return Err(format!("--keep {key}: no such type"));
            }
            pending.push(key);
        }
        for function in &self.functions {
            signature_keys(&function.signature, &mut pending);
        }
        let mut kept = BTreeSet::new();
        while let Some(key) = pending.pop() {
            if !kept.insert(key.to_owned()) {
                continue;
            }
            match self.types.get(key) {
                Some(Definition::Record(record)) => {
                    for field in record.fields.iter().flatten() {
                        type_keys(&field.ty, &mut pending);
                    }
                }
                Some(Definition::Typedef(typedef)) => type_keys(&typedef.target, &mut pending),
                Some(Definition::Enum(_) | Definition::Opaque(_)) | None => {}
            }
        }
        self.types.retain(|key, _| kept.contains(key));
        Ok(())
    }

    /// The database of these declarations.
    ///
    /// # Errors
    ///
    /// If it does not load: a type it refers to is not defined.
    pub fn into_database(self, header: Header) -> Result<Database, String> {
        let database = Database {
            header,
            functions: self.functions,
            types: self.types.into_values().collect(),
        };
        TypeLibrary::new()
            .add(&database)
            .map_err(|error| format!("the generated database does not load: {error}"))?;
        Ok(database)
    }
}

/// The keys `ty` names, onto `out`.
fn type_keys<'a>(ty: &'a TypeRef, out: &mut Vec<&'a str>) {
    match ty {
        TypeRef::Named(key) => out.push(key),
        TypeRef::Pointer(target) => type_keys(target, out),
        TypeRef::Array { element, .. } => type_keys(element, out),
        TypeRef::Function(signature) => signature_keys(signature, out),
        TypeRef::Void
        | TypeRef::Bool
        | TypeRef::Char { .. }
        | TypeRef::Int { .. }
        | TypeRef::Float(_) => {}
    }
}

/// The keys `signature` names, onto `out`.
fn signature_keys<'a>(signature: &'a Signature<TypeRef>, out: &mut Vec<&'a str>) {
    type_keys(&signature.ret, out);
    for param in &signature.params {
        type_keys(&param.ty, out);
    }
}
