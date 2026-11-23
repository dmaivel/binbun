//! The user's types (retypes): a function's prototype (its parameters
//! and return value, for it and its callers), a global's type, a frame
//! variable's (by function and offset) and a register variable's (by the
//! L1 values it is made of), and the user's
//! version of a synthesised struct (by its identity: it replaces the
//! table's layout and name), each read from C
//! by [`binbun_typedb::c`] into one table ([`UserTypes`]) and given to
//! decompilation as the strongest evidence there is (the user ranks above
//! debug information): [`UserPrototypes`] answers before the type
//! library, the manglings and debug information, and the solver takes a
//! variable's type as a declared bound
//! ([`Reason::User`](binbun_decompile::typing::Reason::User)).
//!
//! A type L2 cannot hold where it is stated (a structure passed by value,
//! a frame variable's type of another size) is not taken: the
//! declarations the user's replace stay.

use std::collections::BTreeMap;
use std::sync::Arc;

use binbun_ast::types::{Type, TypeId, Types};
use binbun_decompile::prototype::{
    DebugStated, Open, Prototype, Prototypes, SystemCall, UserStated,
};
use binbun_decompile::typing::StructId;
use binbun_loader::{Format, Image, Machine};
use binbun_typedb::c::DataModel;
use binbun_typedb::{Type as LibType, TypeId as LibId, TypeLibrary};

use crate::prototypes::{Convert, LibraryPrototypes};

/// The user's types, by what they type, in one table.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UserTypes {
    /// The table every type below is in (a C scope's).
    types: TypeLibrary,
    /// The target's pointer width in bits.
    pointer: u16,
    /// Functions' prototypes (function types), by entry.
    prototypes: BTreeMap<u64, LibId>,
    /// Globals' types, by address.
    globals: BTreeMap<u64, LibId>,
    /// Frame variables' types, by function entry and offset from the entry
    /// stack pointer.
    frames: BTreeMap<u64, BTreeMap<i64, LibId>>,
    /// Register variables' types, by function entry and L1 value.
    values: BTreeMap<u64, BTreeMap<u32, LibId>>,
    /// Synthesised structs' user's versions (structs or unions), by the
    /// struct's identity.
    structs: BTreeMap<StructId, LibId>,
    /// The user's definitions of structs and unions (`struct timeval`),
    /// by key: each replaces the type library's record of its key
    /// wherever a library type refers to it.
    records: BTreeMap<String, LibId>,
}

impl UserTypes {
    /// None yet, over `types`: the table every type given later is in
    /// (a C scope's, [`Scope::into_types`](binbun_typedb::c::Scope::into_types)),
    /// on a target of `pointer`-bit pointers.
    pub fn new(types: TypeLibrary, pointer: u16) -> Self {
        Self {
            types,
            pointer,
            ..Self::default()
        }
    }

    /// The table the types are in.
    pub fn types(&self) -> &TypeLibrary {
        &self.types
    }

    /// Whether the user states no type.
    pub fn is_empty(&self) -> bool {
        self.prototypes.is_empty()
            && self.globals.is_empty()
            && self.frames.is_empty()
            && self.values.is_empty()
            && self.structs.is_empty()
            && self.records.is_empty()
    }

    /// States the prototype of the function at `entry`: `ty`, a function
    /// type.
    pub fn set_prototype(&mut self, entry: u64, ty: LibId) {
        self.prototypes.insert(entry, ty);
    }

    /// States the type of the global at `address`.
    pub fn set_global(&mut self, address: u64, ty: LibId) {
        self.globals.insert(address, ty);
    }

    /// States the type of the frame variable at `offset` (from the entry
    /// stack pointer) of the function at `function`.
    pub fn set_frame(&mut self, function: u64, offset: i64, ty: LibId) {
        self.frames.entry(function).or_default().insert(offset, ty);
    }

    /// States the type of the register variable of the function at
    /// `function` made of L1 `values`.
    pub fn set_values(&mut self, function: u64, values: &[u32], ty: LibId) {
        let stated = self.values.entry(function).or_default();
        for &value in values {
            stated.insert(value, ty);
        }
    }

    /// The prototype stated for the function at `entry`.
    pub fn prototype(&self, entry: u64) -> Option<LibId> {
        self.prototypes.get(&entry).copied()
    }

    /// States `ty`, a struct or union of key `key` (`struct timeval`),
    /// as the user's definition of that key: the type library's record
    /// of the key is it wherever a library type refers to it (a
    /// prototype's parameter, a field, a global's type). A type that is
    /// no struct or union is not taken.
    pub fn set_record(&mut self, key: &str, ty: LibId) {
        if let Some(LibType::Record(record)) = self.types.ty(ty)
            && record.key == key
        {
            self.records.insert(key.to_owned(), ty);
        }
    }

    /// The user's definition of the struct or union of key `key`.
    pub fn record(&self, key: &str) -> Option<LibId> {
        self.records.get(key).copied()
    }

    /// States `ty` (a struct or union) as the user's version of the
    /// synthesised struct `id`.
    pub fn set_struct(&mut self, id: StructId, ty: LibId) {
        self.structs.insert(id, ty);
    }

    /// The type stated for the global at `address`.
    pub fn global(&self, address: u64) -> Option<LibId> {
        self.globals.get(&address).copied()
    }

    /// The type stated for the frame variable at `offset` of the function
    /// at `function`.
    pub fn frame(&self, function: u64, offset: i64) -> Option<LibId> {
        self.frames.get(&function)?.get(&offset).copied()
    }

    /// The type stated for a register variable of the function at
    /// `function` made of one of `values`.
    pub fn value(&self, function: u64, values: impl IntoIterator<Item = u32>) -> Option<LibId> {
        let stated = self.values.get(&function)?;
        values
            .into_iter()
            .find_map(|value| stated.get(&value).copied())
    }

    /// Why a prototype of `ty` (of `types`) cannot be taken: L2 cannot
    /// hold one of its parameters or its return value as a value (a
    /// structure by value), or it is no function type. `pointer` is the
    /// target's pointer width in bits.
    ///
    /// # Errors
    ///
    /// The reason, as a sentence.
    pub fn check_prototype(types: &TypeLibrary, ty: LibId, pointer: u16) -> Result<(), String> {
        let Some(LibType::Function(signature)) = types.ty(ty) else {
            return Err("a prototype needs a parameter list".to_owned());
        };
        let mut converted = Types::new(pointer);
        Convert::new(types, &mut converted)
            .signature(signature)
            .map(|_| ())
            .ok_or_else(|| {
                "binbun holds parameters and return values in registers only: \
                 not a structure by value"
                    .to_owned()
            })
    }

    /// Why a variable's type `ty` (of `types`) for a variable `bits` wide
    /// cannot be taken (in a register: `value`): it has no size, another
    /// size, or (in a register) is no scalar or pointer. `pointer` is the
    /// target's pointer width in bits.
    ///
    /// # Errors
    ///
    /// The reason, as a sentence (with both sizes when they differ).
    ///
    /// ```
    /// use binbun::user::UserTypes;
    /// use binbun_typedb::c::{DataModel, Scope};
    ///
    /// let mut scope = Scope::new(DataModel::LP64, None);
    /// let pointer = scope.declaration("char *").unwrap().ty;
    /// let types = scope.into_types();
    /// assert_eq!(
    ///     UserTypes::check_variable(&types, pointer, Some(32), true, 64),
    ///     Err("the variable is 4 bytes; the type is 8 bytes".to_owned())
    /// );
    /// assert!(UserTypes::check_variable(&types, pointer, Some(64), true, 64).is_ok());
    /// ```
    pub fn check_variable(
        types: &TypeLibrary,
        ty: LibId,
        bits: Option<u64>,
        value: bool,
        pointer: u16,
    ) -> Result<(), String> {
        let mut table = Types::new(pointer);
        let mut convert = Convert::new(types, &mut table);
        let found = if value {
            convert.value(ty)
        } else {
            convert.any(ty)
        };
        let Some(id) = found else {
            return Err(if value {
                "a register holds a scalar or a pointer".to_owned()
            } else {
                "the type has no size".to_owned()
            });
        };
        drop(convert);
        let width = table.width(id);
        match bits {
            Some(bits) if width != Some(bits) => Err(format!(
                "the variable is {}; the type is {}",
                size(bits),
                width.map_or_else(|| "unsized".to_owned(), size)
            )),
            Some(_) | None => Ok(()),
        }
    }
}

/// A width of `bits` bits as a size: in bytes when whole (`4 bytes`),
/// else in bits.
fn size(bits: u64) -> String {
    match (bits % 8, bits / 8) {
        (0, 1) => "1 byte".to_owned(),
        (0, bytes) => format!("{bytes} bytes"),
        (_, _) if bits == 1 => "1 bit".to_owned(),
        (_, _) => format!("{bits} bits"),
    }
}

/// The C data model of `image`'s target, as its compilers lay types out.
pub fn data_model(image: &Image<'_>) -> DataModel {
    let arch = match image.machine {
        Machine::X86 => "x86",
        Machine::Arm => "arm",
        Machine::Aarch64 => "aarch64",
        Machine::X86_64 | Machine::Other => "x86_64",
    };
    let os = match image.format {
        Format::Pe => "windows",
        Format::Elf => "linux",
        Format::MachO => "macos",
    };
    DataModel::of(arch, os)
}

/// The user's types over an image's other declarations
/// ([`LibraryPrototypes`]): what the user states first.
#[derive(Clone, Debug)]
pub struct UserPrototypes<'a> {
    library: LibraryPrototypes<'a>,
    user: Arc<UserTypes>,
}

impl<'a> UserPrototypes<'a> {
    /// `user`'s types over `library`'s declarations, its definitions of
    /// structs and unions replacing the library's
    /// ([`LibraryPrototypes::defined_by`]).
    pub fn new(library: LibraryPrototypes<'a>, user: Arc<UserTypes>) -> Self {
        let library = if user.records.is_empty() {
            library
        } else {
            library.defined_by(Arc::clone(&user))
        };
        Self { library, user }
    }

    /// The user's types.
    pub fn user_types(&self) -> &UserTypes {
        &self.user
    }

    /// The type the user states for the function at `address`: for it,
    /// else for the function it is a thunk of.
    fn stated_type(&self, address: u64) -> Option<LibId> {
        self.user
            .prototype(address)
            .or_else(|| self.user.prototype(self.library.stands_for(address)))
    }

    /// The user's prototype of the function at `address`, converted, if
    /// stated (of it, or of the function it is a thunk of:
    /// [`LibraryPrototypes::stands_for`]) and L2 can hold it.
    fn stated(&self, address: u64, types: &mut Types) -> Option<Prototype> {
        let id = self.stated_type(address)?;
        let LibType::Function(signature) = self.user.types.ty(id)? else {
            return None;
        };
        let (signature, wide_result) = Convert::new(&self.user.types, types).declared(signature)?;
        // What a declaration says that C's type does not (`noreturn`, a
        // format string, `alloc_size`), where it has as many parameters.
        let declared = self.library.of(address, types).filter(|declared| {
            types
                .signature(declared.signature)
                .is_some_and(|s| s.parameters.len() == signature.parameters.len())
        });
        let (noreturn, format, format_arg, alloc_size) = declared.map_or_else(
            || (false, None, Vec::new(), None),
            |d| (d.noreturn, d.format, d.format_arg, d.alloc_size),
        );
        Some(Prototype {
            name: None,
            signature: types.intern(Type::Code(signature)),
            returns_stated: true,
            own: true,
            open: Open::default(),
            noreturn,
            format,
            format_arg,
            alloc_size,
            wide_result,
        })
    }
}

impl Prototypes for UserPrototypes<'_> {
    fn of(&self, address: u64, types: &mut Types) -> Option<Prototype> {
        self.stated(address, types)
            .or_else(|| self.library.of(address, types))
    }

    fn through(&self, slot: u64, types: &mut Types) -> Option<Prototype> {
        self.library.through(slot, types)
    }

    fn parameter_names(&self, address: u64) -> Vec<Option<String>> {
        let mut types = Types::new(64);
        if self.stated(address, &mut types).is_some()
            && let Some(LibType::Function(signature)) = self
                .stated_type(address)
                .and_then(|id| self.user.types.ty(id))
        {
            return signature.params.iter().map(|p| p.name.clone()).collect();
        }
        self.library.parameter_names(address)
    }

    fn parameter_names_through(&self, slot: u64) -> Vec<Option<String>> {
        self.library.parameter_names_through(slot)
    }

    fn system_call(&self, number: u64) -> Option<SystemCall> {
        self.library.system_call(number)
    }

    fn debug(&self, address: u64, types: &mut Types) -> Option<DebugStated> {
        let mut facts = self.library.debug(address, types)?;
        let mut probe = Types::new(64);
        if self.stated(address, &mut probe).is_some() {
            // Debug information's parameter names are for its prototype,
            // which the user's replaces.
            facts.parameters.clear();
        }
        Some(facts)
    }

    fn global(&self, address: u64, types: &mut Types) -> Option<TypeId> {
        self.user
            .global(address)
            .and_then(|id| Convert::new(&self.user.types, types).any(id))
            .or_else(|| self.library.global(address, types))
    }

    fn thread_pointer(&self, types: &mut Types) -> Option<TypeId> {
        self.library.thread_pointer(types)
    }

    fn user(&self, address: u64, types: &mut Types) -> UserStated {
        let mut facts = UserStated::default();
        let mut convert = Convert::new(&self.user.types, types);
        if let Some(frame) = self.user.frames.get(&address) {
            facts.frame = frame
                .iter()
                .filter_map(|(&offset, &id)| Some((offset, convert.any(id)?)))
                .collect();
        }
        if let Some(values) = self.user.values.get(&address) {
            facts.values = values
                .iter()
                .filter_map(|(&value, &id)| Some((value, convert.value(id)?)))
                .collect();
        }
        facts
    }

    fn stated_by_user(&self, address: u64) -> bool {
        self.user.prototype(address).is_some() || self.user.global(address).is_some()
    }

    fn user_structs(&self) -> Option<(Types, Vec<(StructId, TypeId)>)> {
        if self.user.structs.is_empty() {
            return None;
        }
        let mut types = Types::new(self.user.pointer);
        let mut convert = Convert::new(&self.user.types, &mut types).naming_incomplete();
        let stated = self
            .user
            .structs
            .iter()
            .filter_map(|(&id, &ty)| Some((id, convert.any(ty)?)))
            .collect();
        drop(convert);
        Some((types, stated))
    }
}
