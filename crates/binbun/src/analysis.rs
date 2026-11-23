//! What joins the loader, the type library and the control-flow recovery:
//! an image's seeds, what is known about its imports, the decoder for its
//! machine, and the names of its addresses; computed jumps and calls
//! resolved through the pointer slots they load or their tables
//! ([`resolve`]).

pub mod resolve;

use std::collections::BTreeMap;

use binbun_aarch64::{AArch64, Mode as AArch64Mode};
use binbun_loader::{EntryFrame, Format, HandlerTable, Image, Machine, ScopeAction, SymbolKind};
use binbun_ssa::constant::ReadOnly as _;
use binbun_typedb::{LibraryError, Mode as Space, TypeLibrary};
use binbun_x86::{Mode, X86};

use crate::analysis::resolve::TableResolver;
use crate::cfg::{Callee, Callees, Frame, Options, Program, Returns, Seed, SeedKind, recover};
use crate::corrections::Corrections;
use crate::memory::ImageMemory;

/// Which of an image's facts recovery starts from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seeds {
    /// Every function symbol and unwind table entry (and the landing pads
    /// of those functions), not only the entry point and exports.
    pub stated: bool,
    /// The targets of pointers to code stored in data, as weak seeds.
    pub pointers: bool,
}

impl Seeds {
    /// The entry point, the exported (dynamic) symbols and pointers to
    /// code: what a binary without symbol tables or unwind tables still
    /// shows. The rest must be found by following code.
    pub const ENTRY: Self = Self {
        stated: false,
        pointers: true,
    };
    /// Everything the file states.
    pub const ALL: Self = Self {
        stated: true,
        pointers: true,
    };
}

/// Where recovery starts.
pub fn seeds(image: &Image<'_>, seeds: Seeds) -> Vec<Seed> {
    let mut list = Vec::new();
    list.extend(
        image
            .entry
            .map(|entry| Seed::Function(entry, SeedKind::Entry)),
    );
    for symbol in &image.symbols {
        let exported = matches!(
            symbol.source,
            binbun_loader::SymbolSource::Dynamic | binbun_loader::SymbolSource::Export
        );
        if symbol.kind == SymbolKind::Function
            && image.is_code(symbol.address)
            && (exported || seeds.stated)
        {
            let kind = if exported {
                SeedKind::Export
            } else {
                SeedKind::Symbol
            };
            list.push(Seed::Function(symbol.address, kind));
        }
    }
    if seeds.stated {
        list.extend(
            image
                .unwind
                .iter()
                .filter(|entry| !entry.fragment && image.is_code(entry.start))
                .map(|entry| Seed::Function(entry.start, SeedKind::Unwind)),
        );
        list.extend(
            image
                .unwind
                .iter()
                .filter(|entry| !entry.fragment)
                .map(|entry| Seed::Extent {
                    function: entry.start,
                    end: entry.end,
                    frame: match entry.frame {
                        EntryFrame::Call => Frame::Call,
                        EntryFrame::Inside => Frame::Inside,
                        EntryFrame::Outermost => Frame::Outermost,
                    },
                }),
        );
        // Code split off a function (chained unwind information): a part
        // of whichever function enters it.
        list.extend(
            image
                .unwind
                .iter()
                .filter(|entry| entry.fragment)
                .map(|entry| Seed::Split {
                    start: entry.start,
                    end: entry.end,
                    owner: entry.split_from,
                }),
        );
        list.extend(image.landing_pads.iter().map(|pad| Seed::Code {
            function: pad.function,
            address: pad.address,
        }));
        list.extend(
            image
                .exception_tables
                .iter()
                .flat_map(|table| &table.call_sites)
                .filter_map(|site| {
                    Some(Seed::Unwind {
                        start: site.start,
                        end: site.end,
                        pad: site.landing_pad?,
                    })
                }),
        );
        // A funclet is code the runtime calls, even without an unwind
        // entry of its own (a leaf that jumps on to a destructor).
        list.extend(image.funclets.iter().flat_map(|funclet| {
            [
                Seed::Function(funclet.address, SeedKind::Unwind),
                Seed::Funclet {
                    function: funclet.function,
                    address: funclet.address,
                },
            ]
        }));
        list.extend(seh_ranges(image));
        list.extend(continuations(image));
    }
    if seeds.pointers {
        list.extend(
            image
                .code_pointers
                .iter()
                .map(|pointer| Seed::Function(pointer.target, SeedKind::Pointer)),
        );
    }
    // Every kind is kept: recovery merges the kinds of one address.
    list.sort_by_key(Seed::address);
    list
}

/// The guarded ranges of the image's `__try`/`__except` scopes as
/// [`Seed::Unwind`]s: an exception raised in a call in one goes to its
/// `__except` block (once the filter takes it). The scope table lists
/// inner scopes first; a range that overlaps one taken already (an outer
/// scope around it) is left out, since a range maps to one landing pad.
fn seh_ranges(image: &Image<'_>) -> Vec<Seed> {
    let mut seeds = Vec::new();
    for table in &image.frame_handlers {
        let HandlerTable::Scopes(scopes) = &table.table else {
            continue;
        };
        let mut taken: Vec<(u64, u64)> = Vec::new();
        for scope in scopes {
            let ScopeAction::Except { target, .. } = scope.action else {
                continue;
            };
            if taken
                .iter()
                .any(|&(start, end)| start < scope.end && scope.start < end)
            {
                continue;
            }
            taken.push((scope.start, scope.end));
            seeds.push(Seed::Unwind {
                start: scope.start,
                end: scope.end,
                pad: target,
            });
        }
    }
    seeds
}

/// Where the image's catch blocks go on, as `__CxxFrameHandler4`'s tables
/// say, as [`Seed::Code`]: code of the function, which the runtime jumps
/// to (none of its own code may).
fn continuations(image: &Image<'_>) -> Vec<Seed> {
    let mut seeds = Vec::new();
    for table in &image.frame_handlers {
        let HandlerTable::Cxx(cxx) = &table.table else {
            continue;
        };
        seeds.extend(
            cxx.tries
                .iter()
                .flat_map(|block| &block.catches)
                .flat_map(|catch| &catch.continuations)
                .map(|&address| Seed::Code {
                    function: table.function,
                    address,
                }),
        );
    }
    seeds
}

/// What the type library says about whether an image's imports (by slot)
/// and its named functions (by address: a symbol identifies a function as
/// much as an import's name does) return, and which pointer slots hold a
/// fixed code address once the image is loaded.
#[derive(Clone, Debug)]
pub struct ImageCallees<'a> {
    imports: BTreeMap<u64, Returns>,
    functions: BTreeMap<u64, Returns>,
    image: &'a Image<'a>,
    memory: ImageMemory<'a>,
}

impl<'a> ImageCallees<'a> {
    /// The imports and function symbols of `image`, looked up in `library`,
    /// and the functions `corrections` know not to return (a signature
    /// identified them; a symbol's own name says nothing over that).
    pub fn new(image: &'a Image<'a>, library: &TypeLibrary, corrections: &Corrections) -> Self {
        let returns = |module: Option<&str>, name: &str| match library
            .function(module, name)
            .and_then(|d| d.no_return)
            .map(|fact| fact.value)
        {
            Some(true) => Returns::No,
            Some(false) => Returns::Yes,
            None => Returns::Unknown,
        };
        let imports = image
            .imports
            .iter()
            .map(|import| {
                (
                    import.slot,
                    returns(import.library.as_deref(), &import.name),
                )
            })
            .collect();
        let mut functions: BTreeMap<u64, Returns> = image
            .symbols
            .iter()
            .filter(|symbol| symbol.kind == SymbolKind::Function)
            .map(|symbol| (symbol.address, returns(None, &symbol.name)))
            .filter(|&(_, returns)| returns != Returns::Unknown)
            .collect();
        functions.extend(
            corrections
                .no_return()
                .iter()
                .map(|&entry| (entry, Returns::No)),
        );
        Self {
            imports,
            functions,
            image,
            memory: ImageMemory::new(image),
        }
    }
}

impl Callees for ImageCallees<'_> {
    fn is_import(&self, slot: u64) -> bool {
        self.imports.contains_key(&slot)
    }

    fn slot(&self, slot: u64, size: u8) -> Option<u64> {
        self.memory
            .read(slot, u16::from(size))
            .map(|value| value.low_u64())
            .filter(|&address| self.image.is_code(address))
    }

    fn returns(&self, callee: Callee) -> Returns {
        match callee {
            Callee::Import(slot) => self.imports.get(&slot).copied().unwrap_or(Returns::Unknown),
            Callee::Address(address) => self
                .functions
                .get(&address)
                .copied()
                .unwrap_or(Returns::Unknown),
        }
    }
}

/// Why an image cannot be analysed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnsupportedMachine(pub Machine);

/// The type library for `image`: the built-in facts and the databases
/// (embedded, then those in the database directory) for its architecture
/// and operating system, and for kernel-mode code where it is a Windows
/// driver ([`Image::kernel`]: the kernel's exports, not Win32's). An ELF
/// file is taken to be for Linux (its OS ABI field is almost always 0,
/// which says nothing), a PE file for Windows, a Mach-O file for macOS.
///
/// # Errors
///
/// If a database in the database directory cannot be read or loaded.
pub fn type_library(image: &Image<'_>) -> Result<TypeLibrary, LibraryError> {
    let arch = match image.machine {
        Machine::X86 => "x86",
        Machine::X86_64 => "x86_64",
        Machine::Aarch64 => "aarch64",
        Machine::Arm => "arm",
        Machine::Other => return Ok(TypeLibrary::builtin()),
    };
    let os = match image.format {
        Format::Elf => "linux",
        Format::Pe => "windows",
        Format::MachO => "macos",
    };
    let space = if image.kernel {
        Space::Kernel
    } else {
        Space::User
    };
    TypeLibrary::for_mode(arch, os, space)
}

/// The x86 mode of `machine`.
///
/// # Errors
///
/// For any other machine.
pub fn x86_mode(machine: Machine) -> Result<Mode, UnsupportedMachine> {
    match machine {
        Machine::X86 => Ok(Mode::Bits32),
        Machine::X86_64 => Ok(Mode::Bits64),
        Machine::Aarch64 | Machine::Arm | Machine::Other => Err(UnsupportedMachine(machine)),
    }
}

/// Recovers `image`'s control flow from `seeds`, asking `library` about
/// the functions it calls.
///
/// Only code is decoded ([`Image::code_view`]): not the read-only data an
/// executable segment may map along with it.
///
/// Computed jumps and calls are resolved from the L1 of their function
/// ([`resolve`]): through the pointer slot they load the address from (a
/// PLT stub's GOT entry), or a jump's table. 32-bit x86 code is not
/// lifted, so its computed jumps and calls stay unresolved.
///
/// # Errors
///
/// When binbun cannot decode the image's machine code yet.
pub fn analyse(
    image: &Image<'_>,
    seeds: Seeds,
    library: &TypeLibrary,
) -> Result<Program, UnsupportedMachine> {
    analyse_corrected(image, seeds, library, &Corrections::default())
}

/// [`analyse`] with the user's `corrections` as seeds and constraints
/// ([`Corrections::seeds`]); with none, the same program.
///
/// # Errors
///
/// When binbun cannot decode the image's machine code yet.
pub fn analyse_corrected(
    image: &Image<'_>,
    seeds: Seeds,
    library: &TypeLibrary,
    corrections: &Corrections,
) -> Result<Program, UnsupportedMachine> {
    let mut seeds = self::seeds(image, seeds);
    if !corrections.is_empty() {
        seeds.extend(corrections.seeds());
        seeds.sort_by_key(Seed::address);
    }
    let callees = ImageCallees::new(image, library, corrections);
    let memory = image.code_view();
    let options = Options::default();
    let mut resolver = TableResolver::new(image);
    Ok(match image.machine {
        Machine::Aarch64 => recover(
            &AArch64,
            AArch64Mode::A64,
            &memory,
            &seeds,
            &callees,
            &mut resolver,
            &options,
        ),
        Machine::X86 | Machine::X86_64 | Machine::Arm | Machine::Other => recover(
            &X86,
            x86_mode(image.machine)?,
            &memory,
            &seeds,
            &callees,
            &mut resolver,
            &options,
        ),
    })
}

/// Names of addresses, from symbols and imports.
pub fn names(image: &Image<'_>) -> BTreeMap<u64, String> {
    let mut names = BTreeMap::new();
    for symbol in &image.symbols {
        names
            .entry(symbol.address)
            .or_insert_with(|| symbol.name.clone());
    }
    names
}
