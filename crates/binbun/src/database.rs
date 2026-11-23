//! One loaded executable as a program database ([`Database`]): its
//! recovered functions, their names, the type library for its target and
//! its imports' prototypes, and its debug information if given; each
//! function decompiled on demand, or every function as a stream; its
//! cross-references and strings, built once for the whole program when
//! first asked for; the user's types over every other declaration
//! ([`Database::set_user`]).

use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::fmt;
use std::ops::Range;
use std::sync::{Arc, Mutex, OnceLock, PoisonError, RwLock, TryLockError};

use binbun_ast::types::{Type as AstType, TypeId, Types};
use binbun_debuginfo::info::DebugModel;
use binbun_decompile::data::Data as _;
use binbun_decompile::itanium::Exceptions;
use binbun_decompile::prototype::Prototypes as _;
use binbun_decompile::typing::{GlobalShape, GlobalType};
use binbun_loader::{Image, Machine};
use binbun_print::c;
use binbun_print::c::Image as _;
use binbun_print::layout::render;
use binbun_print::style::Style;
use binbun_semantics::Declarations;
use binbun_typedb::{LibraryError, TypeLibrary};

use crate::analysis::{Seeds, analyse_corrected, names, type_library};
use crate::calls::CallGraph;
use crate::cfg::{Function, FunctionId, Program};
use crate::corrections::{self, Bounds, Corrections, Item};
use crate::data::ImageData;
use crate::debug::DebugInfo;
use crate::decompile::{
    self, Callers, ImageFacts, Interfaces, Options, Output, Prepared, View, callers_for,
    decompile_l1, exceptions, stream_parallel,
};
use crate::funclets;
use crate::lift::ImageEnvironment;
use crate::manglings::Manglings;
use crate::progress::Progress;
use crate::prototypes::{Imports, LibraryPrototypes};
use crate::references::References;
use crate::strings::{self, Literal};
use crate::summary::{Summaries, summaries};
use crate::user::{UserPrototypes, UserTypes, data_model};

/// What the whole-program caches are keyed by: the user's types' version,
/// the passes disabled, and whether under the reading view's assumption
/// about registers only passed on ([`View::assumes_arguments_set`]).
type CacheKey = (u64, Vec<String>, bool);

/// Why an image cannot be made a [`Database`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Its type library cannot be loaded ([`type_library`]).
    Library(LibraryError),
    /// binbun cannot decode its machine code yet.
    Unsupported(Machine),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Library(error) => write!(f, "type library: {error}"),
            Self::Unsupported(machine) => write!(f, "cannot decode {machine:?} code yet"),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Library(error) => Some(error),
            Self::Unsupported(_) => None,
        }
    }
}

/// A field of a global's type with the references into it
/// ([`Database::global_fields`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobalField {
    /// Its offset from the global's start, in bytes.
    pub offset: u64,
    /// Its size in bytes.
    pub bytes: u64,
    /// Its name as the C prints it (`field_4`, `unknown_8`; an array's
    /// element `[i]`; empty for a value's whole).
    pub name: String,
    /// How many references start in its bytes.
    pub references: usize,
}

/// One loaded executable: its functions as recovery found them, the names
/// of its addresses, the type library for its target, its imports and
/// data; functions are referred to by [`FunctionId`].
#[derive(Debug)]
pub struct Database<'a> {
    image: &'a Image<'a>,
    library: TypeLibrary,
    program: Program,
    /// The names of addresses, from symbols ([`names`]), and functions'
    /// from debug information where they have no symbol.
    names: BTreeMap<u64, String>,
    imports: Imports,
    /// What its symbols' and imports' manglings say ([`Manglings`]).
    manglings: Manglings,
    /// Its debug information, if given ([`Self::with_debug`]).
    debug: Option<DebugInfo>,
    /// The image's data, its addresses named by symbols, else (an import
    /// thunk) by the import.
    data: ImageData<'a>,
    /// Its exceptions' landing pads and how unwinding resumes
    /// ([`exceptions`]).
    exceptions: Exceptions,
    /// What every function does to registers and the stack, once computed.
    summaries: OnceLock<Summaries>,
    /// The cross-references, once built.
    references: OnceLock<References>,
    /// The call graph, once built.
    calls: OnceLock<CallGraph>,
    /// What callers read of each function, once computed per set of
    /// passes disabled and version of the user's types ([`Self::callers`]).
    /// Held only to look up or insert, never while one computes.
    callers: Mutex<BTreeMap<CacheKey, Arc<Callers>>>,
    /// Held while [`Self::callers`] computes (one at a time).
    computing: Mutex<()>,
    /// How far the whole-program pass running has got ([`Self::progress`]).
    progress: Progress,
    /// The user's types ([`Self::set_user`]) and their version.
    user: RwLock<(u64, Arc<UserTypes>)>,
    /// The user's corrections recovery took ([`Self::with_corrections`]).
    corrections: Corrections,
    /// The image's facts recovery started from.
    seeds: Seeds,
}

impl<'a> Database<'a> {
    /// The functions of `image` recovered from `seeds` ([`analyse`]), with
    /// the type library for its target ([`type_library`]).
    ///
    /// # Errors
    ///
    /// The type library cannot be loaded, or binbun cannot decode the
    /// image's machine code yet.
    pub fn new(image: &'a Image<'a>, seeds: Seeds) -> Result<Self, Error> {
        Self::with_debug(image, seeds, None)
    }

    /// The functions of `image` recovered from `seeds` ([`analyse`]), with
    /// the type library for its target ([`type_library`]) and the image's
    /// `debug` information, if given, as the strongest evidence of its
    /// functions' prototypes and names and their variables
    /// ([`DebugInfo`]).
    ///
    /// # Errors
    ///
    /// The type library cannot be loaded, or binbun cannot decode the
    /// image's machine code yet.
    pub fn with_debug(
        image: &'a Image<'a>,
        seeds: Seeds,
        debug: Option<DebugModel>,
    ) -> Result<Self, Error> {
        Self::with_corrections(image, seeds, debug, Corrections::default())
    }

    /// [`Self::with_debug`] with the user's `corrections` as seeds and
    /// constraints of recovery ([`analyse_corrected`]): with none, the
    /// same database.
    ///
    /// # Errors
    ///
    /// The type library cannot be loaded, or binbun cannot decode the
    /// image's machine code yet.
    pub fn with_corrections(
        image: &'a Image<'a>,
        seeds: Seeds,
        debug: Option<DebugModel>,
        corrections: Corrections,
    ) -> Result<Self, Error> {
        let library = type_library(image).map_err(Error::Library)?;
        let program = analyse_corrected(image, seeds, &library, &corrections)
            .map_err(|error| Error::Unsupported(error.0))?;
        let debug = debug.map(|model| DebugInfo::new(model, image));
        let mut names = names(image);
        if let Some(debug) = &debug {
            let taken = names.values().map(String::as_str).collect();
            let from_debug: Vec<(u64, String)> = debug
                .names(&taken)
                .into_iter()
                .filter(|&(address, _)| {
                    program.function_at(address).is_some()
                        || debug.model().globals.contains_key(&address)
                })
                .map(|(entry, name)| (entry, name.to_owned()))
                .collect();
            for (entry, name) in from_debug {
                names.entry(entry).or_insert(name);
            }
        }
        let imports = Imports::new(image, &program);
        // A driver's entry point that no symbol or debug information names
        // is its `DriverEntry`: what the system calls it as.
        if let Some(entry) = image.entry.filter(|&entry| imports.is_driver_entry(entry))
            && !names.contains_key(&entry)
            && !names.values().any(|name| name == "DriverEntry")
        {
            names.insert(entry, "DriverEntry".to_owned());
        }
        let manglings = Manglings::new(image);
        // Symbols first; an import thunk without one takes its import's.
        let mut data_names = names.clone();
        for (entry, name) in imports.thunk_names() {
            data_names.entry(entry).or_insert_with(|| name.to_owned());
        }
        // A thunk of one of the image's own functions without one takes
        // that function's (a PLT stub of an exported function).
        for (entry, _) in imports.own_thunks() {
            if let Some(name) = data_names.get(&imports.stands_for(entry)).cloned() {
                data_names.entry(entry).or_insert(name);
            }
        }
        let objects = debug.as_ref().map(DebugInfo::objects).unwrap_or_default();
        let exceptions = exceptions(image, imports.thunk_names(), imports.nothrow(&library));
        let data = ImageData::new(image, data_names, &objects, program.data());
        Ok(Self {
            image,
            library,
            program,
            names,
            imports,
            manglings,
            debug,
            data,
            exceptions,
            summaries: OnceLock::new(),
            references: OnceLock::new(),
            calls: OnceLock::new(),
            callers: Mutex::new(BTreeMap::new()),
            computing: Mutex::new(()),
            progress: Progress::default(),
            user: RwLock::new((0, Arc::new(UserTypes::default()))),
            corrections,
            seeds,
        })
    }

    /// The image.
    pub fn image(&self) -> &'a Image<'a> {
        self.image
    }

    /// The user's corrections recovery took.
    pub fn corrections(&self) -> &Corrections {
        &self.corrections
    }

    /// The image's facts recovery started from.
    pub fn seeds(&self) -> Seeds {
        self.seeds
    }

    /// Why the bytes at `address` cannot be `item` in the program as
    /// recovered ([`corrections::check_item`]).
    ///
    /// # Errors
    ///
    /// The reason, for the user.
    pub fn check_item(&self, address: u64, item: Item) -> Result<(), String> {
        corrections::check_item(self.image, &self.program, address, item)
    }

    /// Why the function at `entry` cannot have `bounds` in the program as
    /// recovered ([`corrections::check_bounds`]).
    ///
    /// # Errors
    ///
    /// The reason, for the user.
    pub fn check_bounds(&self, entry: u64, bounds: Bounds) -> Result<(), String> {
        corrections::check_bounds(self.image, &self.program, entry, bounds)
    }

    /// The recovered control flow: blocks and functions.
    pub fn program(&self) -> &Program {
        &self.program
    }

    /// The type library for the image's target.
    pub fn library(&self) -> &TypeLibrary {
        &self.library
    }

    /// The names of addresses, from symbols, and functions' from debug
    /// information where they have no symbol.
    pub fn names(&self) -> &BTreeMap<u64, String> {
        &self.names
    }

    /// The name of `address` ([`Self::names`]).
    pub fn name(&self, address: u64) -> Option<&str> {
        self.names.get(&address).map(String::as_str)
    }

    /// The debug information, if given.
    pub fn debug(&self) -> Option<&DebugInfo> {
        self.debug.as_ref()
    }

    /// The image's data, as lowering and the printer read it.
    pub fn data(&self) -> &ImageData<'a> {
        &self.data
    }

    /// Its exceptions' landing pads and how unwinding resumes, as the L2
    /// passes and the structure check read them.
    pub fn exceptions(&self) -> &Exceptions {
        &self.exceptions
    }

    /// The user's types ([`Self::set_user`]) over the prototypes of the
    /// image's imports (declared, else from their manglings) and of the
    /// functions it defines (debug information, declared where they
    /// interpose their exported name, else from their manglings).
    pub fn prototypes(&self) -> UserPrototypes<'_> {
        self.versioned().1
    }

    /// The declared prototypes without the user's types.
    pub fn declared(&self) -> LibraryPrototypes<'_> {
        self.imports
            .prototypes(&self.library, &self.manglings, self.debug.as_ref())
    }

    /// The user's types.
    pub fn user(&self) -> Arc<UserTypes> {
        let user = self.user.read().unwrap_or_else(PoisonError::into_inner);
        Arc::clone(&user.1)
    }

    /// Takes `user` as the user's types: every function decompiled from
    /// now on reads them, and what was found of the whole program under
    /// the old ones is computed again when next asked for, and dropped
    /// then (functions decompiled before are not: decompile again what
    /// the change reaches). It never waits for a computation in progress.
    pub fn set_user(&self, user: UserTypes) {
        let mut state = self.user.write().unwrap_or_else(PoisonError::into_inner);
        state.0 += 1;
        state.1 = Arc::new(user);
    }

    /// The version of the user's types and the prototypes with them, read
    /// together.
    fn versioned(&self) -> (u64, UserPrototypes<'_>) {
        let (version, user) = {
            let state = self.user.read().unwrap_or_else(PoisonError::into_inner);
            (state.0, Arc::clone(&state.1))
        };
        (version, UserPrototypes::new(self.declared(), user))
    }

    /// The registers and intrinsics of the image's architecture, if its
    /// code is lifted.
    pub fn declarations(&self) -> Option<&'static Declarations> {
        ImageEnvironment::new(self.image, &[])
            .ok()
            .map(|environment| environment.declarations())
    }

    /// The functions, in the order recovery made them.
    pub fn functions(&self) -> impl Iterator<Item = (FunctionId, &Function)> {
        self.program.functions.iter()
    }

    /// Function `id`.
    pub fn function(&self, id: FunctionId) -> Option<&Function> {
        self.program.functions.get(id)
    }

    /// The function that starts at `address`.
    pub fn function_at(&self, address: u64) -> Option<FunctionId> {
        self.program.function_at(address)
    }

    /// The function `wanted` names: a symbol, or a hexadecimal address
    /// (`0x` optional), of its entry or of the entry of one of its
    /// [`parts`](Function::parts) (a cold part's symbol names the function
    /// it is a part of).
    ///
    /// # Errors
    ///
    /// No symbol has the name and it is not an address, or no function
    /// or part starts there.
    pub fn find_function(&self, wanted: &str) -> Result<FunctionId, String> {
        let entry = self
            .names
            .iter()
            .find(|(_, name)| *name == wanted)
            .map(|(&address, _)| address)
            .or_else(|| u64::from_str_radix(wanted.trim_start_matches("0x"), 16).ok())
            .ok_or_else(|| format!("no function {wanted}"))?;
        self.function_at(entry)
            .or_else(|| {
                self.functions()
                    .find(|(_, function)| function.parts.binary_search(&entry).is_ok())
                    .map(|(id, _)| id)
            })
            .ok_or_else(|| format!("no function at {entry:#x}"))
    }

    /// What every function does to registers and the stack, by entry
    /// ([`summaries`]); computed once (by [`Self::references`], if that
    /// comes first).
    pub fn summaries(&self) -> &Summaries {
        self.summaries
            .get_or_init(|| summaries(self.image, &self.program))
    }

    /// Every reference to an address in the program, from code and data
    /// ([`References`]); built once, lifting each function once (on
    /// [`decompile::threads`] threads) and keeping the summaries that
    /// computes on the way.
    pub fn references(&self) -> &References {
        self.references.get_or_init(|| {
            let (references, summaries) = References::build(
                self.image,
                &self.program,
                decompile::threads(),
                &self.progress,
            );
            self.summaries.get_or_init(|| summaries);
            references
        })
    }

    /// How far the whole-program pass running ([`Self::references`], or
    /// a pass of [`Self::callers`]) has got, read from any thread.
    pub fn progress(&self) -> &Progress {
        &self.progress
    }

    /// The string literals of the image's data: those referred to, and
    /// those of at least `min` characters found by scanning
    /// ([`strings::strings`]).
    pub fn strings(&self, min: usize) -> Vec<Literal> {
        strings::strings(self.image, self.references(), &self.data, min)
    }

    /// Which function calls which ([`CallGraph`]), from the recovered
    /// control flow alone; built once.
    pub fn calls(&self) -> &CallGraph {
        self.calls
            .get_or_init(|| CallGraph::build(self.image, &self.program))
    }

    /// What the callers of each function read of it ([`callers`]), the
    /// passes `disabled`: computed once for the whole program (with the
    /// summaries and references, lifting on [`decompile::threads`]
    /// threads), so one function decompiled alone reads the same as in
    /// the whole program.
    pub fn callers(&self, disabled: &[String]) -> Arc<Callers> {
        self.callers_in(View::Exact, disabled)
    }

    /// [`Self::callers`] as `view` reads them: the reading view's under
    /// its assumption that a register a function only passes on holds no
    /// argument ([`callers`](decompile::callers)), kept apart from the
    /// exact ones.
    pub fn callers_in(&self, view: View, disabled: &[String]) -> Arc<Callers> {
        let (version, prototypes) = self.versioned();
        self.callers_with(version, &prototypes, disabled, view)
    }

    /// [`Self::callers_in`] of both views, the exact one's first: found
    /// together where neither is kept ([`callers_for`]), for little more
    /// than one costs.
    pub fn callers_both(&self, disabled: &[String]) -> [Arc<Callers>; 2] {
        let (version, prototypes) = self.versioned();
        let mut found = self
            .callers_of(
                version,
                &prototypes,
                disabled,
                &[View::Exact, View::Reading],
            )
            .into_iter();
        [
            found.next().unwrap_or_default(),
            found.next().unwrap_or_default(),
        ]
    }

    /// What [`Self::callers`] found with the passes `disabled` under the
    /// latest user's types it has computed for, without computing or
    /// waiting for a computation: `None` if none is kept, or one is in
    /// progress.
    pub fn known_callers(&self, disabled: &[String]) -> Option<Arc<Callers>> {
        // One in progress: not looked up meanwhile (it may be for newer
        // user types). Another thread looking one up does not count.
        if matches!(self.computing.try_lock(), Err(TryLockError::WouldBlock)) {
            return None;
        }
        let cache = self.callers.lock().unwrap_or_else(PoisonError::into_inner);
        cache
            .iter()
            .filter(|((_, other, assumed), _)| other.as_slice() == disabled && !assumed)
            .max_by_key(|((version, ..), _)| *version)
            .map(|(_, callers)| Arc::clone(callers))
    }

    /// [`Self::callers_in`] under the user's types of `version`,
    /// `prototypes`.
    fn callers_with(
        &self,
        version: u64,
        prototypes: &UserPrototypes<'_>,
        disabled: &[String],
        view: View,
    ) -> Arc<Callers> {
        self.callers_of(version, prototypes, disabled, &[view])
            .pop()
            .unwrap_or_default()
    }

    /// [`Self::callers_with`] of each of `views`, in its order: those not
    /// kept are found together, in one pass ([`callers_for`]), and kept.
    fn callers_of(
        &self,
        version: u64,
        prototypes: &UserPrototypes<'_>,
        disabled: &[String],
        views: &[View],
    ) -> Vec<Arc<Callers>> {
        let keys: Vec<CacheKey> = views
            .iter()
            .map(|view| (version, disabled.to_vec(), view.assumes_arguments_set()))
            .collect();
        let kept = |keys: &[CacheKey]| -> Option<Vec<Arc<Callers>>> {
            let cache = self.callers.lock().unwrap_or_else(PoisonError::into_inner);
            keys.iter()
                .map(|key| cache.get(key).map(Arc::clone))
                .collect()
        };
        if let Some(callers) = kept(&keys) {
            return callers;
        }
        let _computing = self
            .computing
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // Another thread may have computed them while this one waited.
        if let Some(callers) = kept(&keys) {
            return callers;
        }
        let missing: Vec<bool> = {
            let cache = self.callers.lock().unwrap_or_else(PoisonError::into_inner);
            let mut missing: Vec<bool> = keys
                .iter()
                .filter(|key| !cache.contains_key(*key))
                .map(|(.., assume)| *assume)
                .collect();
            missing.dedup();
            missing
        };
        let references = self.references();
        let found = callers_for(
            self.image,
            &self.program,
            self.summaries(),
            references,
            prototypes,
            &self.data,
            disabled,
            decompile::threads(),
            &missing,
            &self.progress,
        );
        let mut cache = self.callers.lock().unwrap_or_else(PoisonError::into_inner);
        // What older user types found is never asked for again.
        cache.retain(|(other, ..), _| *other >= version);
        for (assume, callers) in missing.into_iter().zip(found) {
            cache.insert((version, disabled.to_vec(), assume), Arc::new(callers));
        }
        keys.iter()
            .filter_map(|key| cache.get(key).map(Arc::clone))
            .collect()
    }

    /// The bytes of the data object (a data symbol with a size, an
    /// import's pointer slot) that holds `address`, if one does.
    pub fn object(&self, address: u64) -> Option<Range<u64>> {
        self.data
            .object(address)
            .map(|object| object.start..object.start.saturating_add(object.size))
    }

    /// The name of `address`: a symbol, else (an import thunk) its
    /// import's, else (an import's pointer slot) its import's with `_ptr`.
    pub fn data_name(&self, address: u64) -> Option<String> {
        self.data.symbol(address)
    }

    /// The first byte of the global object holding `address`: of the
    /// named object holding it ([`Self::object`]), else `address` itself
    /// (data no object names is a global at each address accessed).
    pub fn global_start(&self, address: u64) -> u64 {
        self.data
            .object(address)
            .map_or(address, |object| object.start)
    }

    /// The one type of the global object holding `address` over the whole
    /// program ([`Globals`](binbun_decompile::typing::Globals): every
    /// function's evidence joined, the user's
    /// type and debug information's above all), with the evidence for
    /// why; every function's C declares and accesses the global as it.
    /// From the whole-program callers pass with no pass disabled
    /// ([`Self::callers`], computed on first use). `None` where no
    /// function's code reaches the global (or none of it says more than
    /// its address).
    pub fn global_type(&self, address: u64) -> Option<GlobalType> {
        let start = self.global_start(address);
        self.callers(&[]).schemes.globals().get(start).cloned()
    }

    /// The C declaration of a global of type `ty` (found with `callers`,
    /// whose table holds the structs it names) named `name`, as every
    /// function's C declares it under `style`, without `extern` and the
    /// closing `;` (`struct struct_disable_priv_mode_1 current_user`); a
    /// declared type as the user or debug information states it now.
    /// `None` where the image's code is not lifted or the type is no
    /// longer declared.
    pub fn global_declaration(
        &self,
        callers: &Callers,
        ty: &GlobalType,
        name: &str,
        style: &Style,
    ) -> Option<String> {
        let declarations = self.declarations()?;
        let (types, id) = self.global_table(callers, ty)?;
        let long = self.data.long_width();
        let document = c::declaration(&types, id, name, declarations, style, long).ok()?;
        let text = render(&document, style);
        Some(text.trim_end().trim_end_matches(';').to_owned())
    }

    /// The type `ty` of a global (found with `callers`, whose table holds
    /// the structs it names) in a table of its own, with the structs it
    /// holds or points to, pointers the image's width: a declared type as
    /// the user or debug information states it now. `None` where a
    /// declared type is no longer declared.
    pub fn global_table(&self, callers: &Callers, ty: &GlobalType) -> Option<(Types, TypeId)> {
        let pointer = u16::from(data_model(self.image).pointer) * 8;
        if ty.shape == GlobalShape::Declared {
            let mut types = Types::new(pointer);
            let id = self.prototypes().global(ty.start, &mut types)?;
            Some((types, id))
        } else {
            ty.table(callers.schemes.structs(), pointer)
        }
    }

    /// The fields of a global of type `ty` (found with `callers`) as a
    /// hex view overlays them: a struct's members (named as the C names
    /// them; the bytes no access reaches too), an array's elements (`[i]`),
    /// else the whole value; each with how many references there are into
    /// its bytes ([`References::within`]: a binary search each, so a
    /// field's count costs a logarithm of the program's references). A
    /// reference counts where it starts: a 16-byte copy of two fields
    /// counts for the first.
    pub fn global_fields(&self, callers: &Callers, ty: &GlobalType) -> Vec<GlobalField> {
        let table = self.global_table(callers, ty);
        let mut fields = Vec::new();
        match table
            .as_ref()
            .and_then(|(types, id)| Some((types, types.get(*id)?)))
        {
            Some((types, AstType::Struct(aggregate) | AstType::Union(aggregate))) => {
                for member in &aggregate.fields {
                    let bytes = types.width(member.ty).map_or(0, |bits| bits / 8);
                    let name = member
                        .name
                        .clone()
                        .unwrap_or_else(|| format!("field_{:x}", member.offset));
                    fields.push((member.offset, bytes, name));
                }
            }
            Some((types, &AstType::Array { element, length })) => {
                let bytes = types.width(element).map_or(0, |bits| bits / 8);
                for index in 0..length.unwrap_or(0) {
                    fields.push((index.saturating_mul(bytes), bytes, format!("[{index}]")));
                }
            }
            Some(_) | None => fields.push((0, ty.size, String::new())),
        }
        let references = self.references();
        fields
            .into_iter()
            .filter(|&(_, bytes, _)| bytes > 0)
            .map(|(offset, bytes, name)| {
                let first = ty.start.saturating_add(offset);
                GlobalField {
                    offset,
                    bytes,
                    name,
                    references: references.within(first..first.saturating_add(bytes)).len(),
                }
            })
            .collect()
    }

    /// Function `id` decompiled under `options`, with the interfaces of
    /// the program's functions found once for the whole program
    /// ([`Self::callers`], with the summaries and the references), as the
    /// whole program decompiles it ([`Self::decompile_all`]), so it is the
    /// same; a later function (under the same passes disabled) costs only
    /// its own work.
    pub fn decompile(&self, id: FunctionId, options: &Options) -> Output {
        if self.function(id).is_none() {
            return Output {
                id,
                entry: 0,
                name: None,
                result: Err("not a function of the program".to_owned()),
            };
        }
        let (version, prototypes) = self.versioned();
        let (prepared, interfaces) =
            self.prepare_with(version, &prototypes, id, &options.disabled, options.view);
        self.output(id, prepared, &interfaces, &prototypes, options)
    }

    /// Function `id` in L1 as decompilation starts from it (the passes
    /// `disabled`), with the interfaces of the program's functions: what
    /// [`Self::decompile`] lowers.
    pub fn prepare(
        &self,
        id: FunctionId,
        disabled: &[String],
    ) -> (Result<Prepared, String>, Interfaces) {
        self.prepare_in(id, View::Exact, disabled)
    }

    /// [`Self::prepare`], with the interfaces as `view` reads them
    /// ([`Self::callers_in`]).
    pub fn prepare_in(
        &self,
        id: FunctionId,
        view: View,
        disabled: &[String],
    ) -> (Result<Prepared, String>, Interfaces) {
        let (version, prototypes) = self.versioned();
        self.prepare_with(version, &prototypes, id, disabled, view)
    }

    /// [`Self::prepare_in`] under the user's types of `version`,
    /// `prototypes`.
    fn prepare_with(
        &self,
        version: u64,
        prototypes: &UserPrototypes<'_>,
        id: FunctionId,
        disabled: &[String],
        view: View,
    ) -> (Result<Prepared, String>, Interfaces) {
        let callers = self.callers_with(version, prototypes, disabled, view);
        let prepared = decompile_l1(self.image, &self.program, id, self.summaries(), disabled);
        (prepared, Interfaces::of(&self.program, &callers))
    }

    /// Computes and keeps what decompiling function `id` (the passes
    /// `disabled`) reads of other functions ([`Self::decompile`]): the
    /// whole program's interfaces in both views ([`Self::callers_both`]),
    /// once for every function, so a later decompilation in either costs
    /// only its own work; the output is the same warmed or not.
    pub fn warm(&self, id: FunctionId, disabled: &[String]) {
        if self.function(id).is_some() {
            self.callers_both(disabled);
        }
    }

    /// Every function decompiled under `options` and given to `work`, on
    /// [`decompile::threads`] threads ([`Self::decompile_all_on`]).
    pub fn decompile_all<T: Send>(
        &self,
        options: &Options,
        work: impl Fn(Output) -> T + Sync,
        ready: impl FnMut(T),
    ) {
        self.decompile_all_on(options, decompile::threads(), work, ready);
    }

    /// Every function decompiled under `options` and given to `work`, on
    /// `threads` threads ([`stream_parallel`]), what `work` makes of each
    /// handed to `ready` callees first, as [`stream`](decompile::stream)
    /// hands them over: each is lifted once, and only those waiting for a
    /// callee (or for a thread) are held at a time. Each is decompiled as
    /// on one thread, so the results and their order are the same whatever
    /// the threads. What callers read ([`Self::callers`]) comes first: it
    /// builds the references, which compute the summaries on the way, so
    /// the functions are not lifted for the summaries alone.
    ///
    /// The funclets built into their functions' code (Microsoft x64,
    /// [`funclets::built_in`]) are not decompiled on their own: their code
    /// is their function's.
    pub fn decompile_all_on<T: Send>(
        &self,
        options: &Options,
        threads: usize,
        work: impl Fn(Output) -> T + Sync,
        ready: impl FnMut(T),
    ) {
        let (version, prototypes) = self.versioned();
        let callers = self.callers_with(version, &prototypes, &options.disabled, options.view);
        let summaries = self.summaries();
        let built_in = funclets::built_in(self.image, &self.program);
        let mut ready = ready;
        stream_parallel(
            self.image,
            &self.program,
            summaries,
            &callers,
            &options.disabled,
            threads,
            |id, prepared, interfaces| {
                let entry = self.function(id).map_or(0, |function| function.entry);
                (!built_in.contains(&entry))
                    .then(|| work(self.output(id, prepared, interfaces, &prototypes, options)))
            },
            |done| {
                if let Some(done) = done {
                    ready(done);
                }
            },
        );
    }

    /// Function `id`, `prepared` in L1 with its callees' `interfaces`,
    /// decompiled ([`decompile::decompile`]).
    fn output(
        &self,
        id: FunctionId,
        prepared: Result<Prepared, String>,
        interfaces: &Interfaces,
        prototypes: &UserPrototypes<'_>,
        options: &Options,
    ) -> Output {
        let entry = self.function(id).map_or(0, |function| function.entry);
        let name = self.data.symbol(entry);
        let facts = ImageFacts {
            prototypes,
            data: &self.data,
            exceptions: &self.exceptions,
        };
        let result = prepared.and_then(|prepared| {
            decompile::decompile(
                self.image,
                prepared,
                name.as_deref(),
                interfaces,
                &facts,
                options,
            )
        });
        Output {
            id,
            entry,
            name,
            result,
        }
    }
}
