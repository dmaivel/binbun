//! The user's edits to a binary ([`Edits`]): names of functions, globals
//! and variables, comments and bookmarks at addresses, how a number an
//! instruction uses is written ([`NumberForm`], the GUI's `H`, `R`), types as C
//! (functions' prototypes, globals', variables': [`Typed`]; the structs,
//! unions, enumerations and typedefs they name), and corrections of what
//! recovery found ([`Corrections`]: code, bytes undefined, data,
//! functions' bounds, the inputs of a re-analysis), each attached to what
//! survives re-analysis (an address; for a variable, its function's entry
//! and what it was made from: [`Variable`]), never to a printed name; and
//! their project file, TOML ([`Edits::load`], [`Edits::save`]).
//!
//! The project file is plain and diffable: one array of tables per kind of
//! edit (`[[function]]`, `[[global]]`, `[[variable]]`, `[[comment]]`,
//! `[[bookmark]]`, `[[number]]`, `[[type]]`, `[[item]]`, `[[bounds]]`), in
//! address order, addresses in hexadecimal.
//! It is written whole to a temporary file beside it, flushed to the
//! disk, then renamed over it, so
//! a crash leaves the old file or the new one, never a mix.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io;
use std::path::Path;

use binbun::corrections::{Bounds, Corrections, Data, Item, Unit};
use binbun_ast::ir::{Function as Ast, Origin, VarId, VarKind};
use binbun_semantics::Declarations;
use serde::{Deserialize, Serialize};

use crate::journal::wire;
use crate::number::canonical;
use crate::project;

/// The version of the project file's format, the one read and written.
const FORMAT: u32 = 1;

/// A variable of a function, by what survives re-analysis: the function's
/// entry and what the variable was made from ([`Origin`]: L1 values,
/// registers, stack slots, instructions), as text (`value 12`, `register
/// rdi`, `slot -24`, `instruction 0x4012a0`), sorted; a variable made from
/// none, by where it lives (`parameter 0`, `local`, `frame -24`). Several
/// variables of one function made from the same are told apart by their
/// `ordinal` among them.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Variable {
    /// Its function's entry.
    pub function: u64,
    /// What it was made from.
    #[serde(deserialize_with = "wire::texts")]
    pub origins: Vec<String>,
    /// Its place among the function's variables made from the same.
    pub ordinal: usize,
}

impl Variable {
    /// The frame slot (its offset from the stack pointer on entry) this
    /// variable is, as its origins say: its one slot (`slot -24`), or where
    /// it lives (`frame -24`) when made from nothing. A later ordinal is
    /// that slot too: the C may print only it, the first of the same not.
    pub fn slot(&self) -> Option<i64> {
        let mut slots = self
            .origins
            .iter()
            .filter_map(|origin| origin.strip_prefix("slot "));
        match (slots.next(), slots.next()) {
            (Some(slot), None) => slot.parse().ok(),
            (Some(_), Some(_)) => None,
            (None, _) => match self.origins.as_slice() {
                [only] => only.strip_prefix("frame ")?.parse().ok(),
                _ => None,
            },
        }
    }

    /// The identity of variable `var` of the L2 function `function`
    /// (registers named by `declarations`), if it has one.
    pub fn of(function: &Ast, var: VarId, declarations: &Declarations) -> Option<Self> {
        let own = origins(function, var, declarations)?;
        let ordinal = (0..var.0)
            .filter(|&other| origins(function, VarId(other), declarations).as_ref() == Some(&own))
            .count();
        Some(Self {
            function: function.address,
            origins: own,
            ordinal,
        })
    }

    /// The variable of the L2 function `function` (registers named by
    /// `declarations`) this is.
    ///
    /// # Errors
    ///
    /// No variable of the function was made from these origins (or not
    /// so many).
    pub fn resolve(&self, function: &Ast, declarations: &Declarations) -> Result<VarId, String> {
        (0..function.variables.len())
            .filter_map(|var| u32::try_from(var).ok().map(VarId))
            .filter(|&var| origins(function, var, declarations).as_ref() == Some(&self.origins))
            .nth(self.ordinal)
            .ok_or_else(|| {
                format!(
                    "no variable of the function at {:#x} is made from {}",
                    self.function,
                    self.origins.join(", ")
                )
            })
    }
}

/// What variable `var` of `function` was made from, as [`Variable`] says.
/// Not the register it was held in ([`Origin::Held`]): naming only, so an
/// edit made before it was recorded still finds its variable.
fn origins(function: &Ast, var: VarId, declarations: &Declarations) -> Option<Vec<String>> {
    let variable = function.variables.get(usize::try_from(var.0).ok()?)?;
    let register = |id| {
        declarations
            .info(id)
            .map_or_else(|| format!("#{}", id.0), |info| info.name.to_owned())
    };
    let mut origins: Vec<String> = variable
        .origins
        .iter()
        .filter_map(|origin| match *origin {
            Origin::Value(value) => Some(format!("value {}", value.0)),
            Origin::Instruction(address) => Some(format!("instruction {address:#x}")),
            Origin::Register(id) => Some(format!("register {}", register(id))),
            Origin::Held(_) => None,
            Origin::Slot(offset) => Some(format!("slot {offset}")),
            Origin::Block(block) => Some(format!("block {}", block.0)),
            Origin::Absorbed(block) => Some(format!("absorbed {}", block.0)),
            Origin::Proved => Some("proved".to_owned()),
        })
        .collect();
    origins.sort_unstable();
    origins.dedup();
    if origins.is_empty() {
        origins.push(match variable.kind {
            VarKind::Parameter => {
                let at = function.parameters.iter().position(|&p| p == var)?;
                format!("parameter {at}")
            }
            VarKind::Local => "local".to_owned(),
            VarKind::Global(address) => format!("global {address:#x}"),
            VarKind::Frame(offset) => format!("frame {offset}"),
            VarKind::Environment(id) => format!("environment {}", register(id)),
        });
    }
    Some(origins)
}

/// One edit, as [`Edits`] keeps it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Edit {
    /// The function at `entry` named `name`.
    Function {
        /// Its entry.
        entry: u64,
        /// Its name.
        name: String,
    },
    /// The global at `address` named `name`.
    Global {
        /// Its address.
        address: u64,
        /// Its name.
        name: String,
    },
    /// A variable named `name`.
    Variable {
        /// The variable.
        variable: Variable,
        /// Its name.
        name: String,
    },
    /// A comment at `address`.
    Comment {
        /// Where.
        address: u64,
        /// What it says.
        text: String,
    },
    /// A bookmark at `address` (the GUI's `Alt+M`), named `name`.
    Bookmark {
        /// Where.
        address: u64,
        /// Its name.
        name: String,
    },
    /// A frame slot named `name` where no variable of the C is exactly
    /// that slot (the listing's name of a stack variable, a frame
    /// member's).
    Slot {
        /// Its function's entry.
        function: u64,
        /// Its offset from the stack pointer on entry.
        offset: i64,
        /// Its name.
        name: String,
    },
    /// The number `value` the instruction at `address` uses, written in
    /// `form`.
    Number {
        /// The instruction.
        address: u64,
        /// The number, as its bits.
        value: u64,
        /// How it is written.
        form: NumberForm,
    },
    /// `typed` given the type C `c` states.
    Type {
        /// What is typed.
        typed: Typed,
        /// Its type as C: a prototype (`int main(int argc, char **argv)`)
        /// or a type (`char *`).
        c: String,
    },
    /// A struct, union, enumeration or typedef the user defined, by the
    /// key it defines (`struct pair`, `pair_t`).
    Definition {
        /// The key.
        key: String,
        /// Its definition as C.
        c: String,
    },
    /// What the bytes at `address` are (a correction of recovery).
    Item {
        /// Where.
        address: u64,
        /// What.
        item: Item,
    },
    /// The bounds of the function at `entry` (a correction of recovery).
    Bounds {
        /// Its entry.
        entry: u64,
        /// Its bounds.
        bounds: Bounds,
    },
}

/// What a user's type types.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Typed {
    /// The function at this entry: its prototype (for it and its
    /// callers).
    Prototype(u64),
    /// The global at this address.
    Global(u64),
    /// A variable: of the registers, by the L1 values it is made of; of
    /// the frame, by its slot (`slot -24`).
    Variable(Variable),
    /// A synthesised struct, by its identity (the function it is born in,
    /// its number there): the user's version of it (its definition as C)
    /// replaces its layout and name.
    Struct {
        /// The entry of the function it is born in.
        function: u64,
        /// Its number among the structs born there (from 1).
        k: u32,
    },
}

impl Typed {
    /// The function whose variable it is, if a variable.
    pub fn function(&self) -> Option<u64> {
        match self {
            Self::Variable(variable) => Some(variable.function),
            Self::Prototype(_) | Self::Global(_) | Self::Struct { .. } => None,
        }
    }
}

/// How a number is written (the listing's conversions; presentation only: the
/// listing and the C write the number so, nothing else changes).
/// Forms are only ever appended: the journal stores a form by its place.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NumberForm {
    /// Hexadecimal (`H`).
    Hex,
    /// Decimal.
    Decimal,
    /// A character constant (`R`).
    Char,
    /// By the names of the constants of the enumeration this type name
    /// names (`M`; `ACCESS_MASK`, `enum idtype_t`): the constant equal to
    /// it, or a set of flags' that it holds.
    Enum(#[serde(deserialize_with = "wire::text")] String),
}

impl NumberForm {
    /// Its name in the project file.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Hex => "hex",
            Self::Decimal => "decimal",
            Self::Char => "char",
            Self::Enum(_) => "enum",
        }
    }
}

impl fmt::Display for Edit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Function { entry, name } => write!(f, "function {entry:#x} named {name}"),
            Self::Global { address, name } => write!(f, "global {address:#x} named {name}"),
            Self::Variable { variable, name } => write!(
                f,
                "variable of {:#x} from {} named {name}",
                variable.function,
                variable.origins.join(", ")
            ),
            Self::Comment { address, text } => write!(f, "comment at {address:#x}: {text}"),
            Self::Bookmark { address, name } => write!(f, "bookmark {name} at {address:#x}"),
            Self::Slot {
                function,
                offset,
                name,
            } => write!(f, "frame slot {offset} of {function:#x} named {name}"),
            Self::Number {
                address,
                value,
                form,
            } => match form {
                NumberForm::Enum(name) => {
                    write!(f, "number {value:#x} at {address:#x} as enum {name}")
                }
                NumberForm::Hex | NumberForm::Decimal | NumberForm::Char => {
                    write!(f, "number {value:#x} at {address:#x} as {}", form.name())
                }
            },
            Self::Type { typed, c } => match typed {
                Typed::Prototype(entry) => write!(f, "prototype of {entry:#x}: {c}"),
                Typed::Global(address) => write!(f, "type of global {address:#x}: {c}"),
                Typed::Variable(variable) => write!(
                    f,
                    "type of the variable of {:#x} from {}: {c}",
                    variable.function,
                    variable.origins.join(", ")
                ),
                Typed::Struct { function, k } => {
                    write!(f, "struct {k} of {function:#x}: {c}")
                }
            },
            Self::Definition { key, .. } => write!(f, "definition of {key}"),
            Self::Item { address, item } => match item {
                Item::Code => write!(f, "code at {address:#x}"),
                Item::Undefined { size } => {
                    write!(f, "{size} bytes undefined at {address:#x}")
                }
                Item::Data(data) => {
                    write!(f, "{} {} at {address:#x}", data.count, data.unit.name())
                }
            },
            Self::Bounds { entry, bounds } => match bounds {
                Bounds::Function { end: None } => write!(f, "function at {entry:#x}"),
                Bounds::Function { end: Some(end) } => {
                    write!(f, "function at {entry:#x} ending at {end:#x}")
                }
                Bounds::Deleted => write!(f, "no function at {entry:#x}"),
            },
        }
    }
}

/// An edit whose identity does not resolve in the binary as analysed now:
/// kept (and saved), and reported.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Unresolved {
    /// The edit.
    pub edit: Edit,
    /// Why it does not resolve.
    pub why: String,
}

/// The user's edits, by identity.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Edits {
    functions: BTreeMap<u64, String>,
    globals: BTreeMap<u64, String>,
    variables: BTreeMap<Variable, String>,
    comments: BTreeMap<u64, String>,
    bookmarks: BTreeMap<u64, String>,
    slots: BTreeMap<(u64, i64), String>,
    numbers: BTreeMap<(u64, u64), NumberForm>,
    types: BTreeMap<Typed, String>,
    definitions: BTreeMap<String, String>,
    corrections: Corrections,
    signatures: BTreeMap<u64, Identified>,
}

/// What a library signature says of a function
/// as an edit: the pack, the library function
/// it is, how it matched, its prototype and facts from the type library;
/// or that the user rejected that match (no later run applies it again).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Identified {
    /// The pack and its revision (`musl-1.2.5@1`).
    #[serde(deserialize_with = "wire::text")]
    pub pack: String,
    /// The library (`musl`).
    #[serde(deserialize_with = "wire::text")]
    pub library: String,
    /// Its version (`1.2.5`).
    #[serde(deserialize_with = "wire::text")]
    pub version: String,
    /// The library function's name.
    #[serde(deserialize_with = "wire::text")]
    pub name: String,
    /// The object it comes from (`src/string/strcpy.o`).
    #[serde(deserialize_with = "wire::text")]
    pub object: String,
    /// How it matched.
    pub how: Matched,
    /// The library's prototype, as C, if the pack has one.
    #[serde(deserialize_with = "wire::opt_text")]
    pub prototype: Option<String>,
    /// Whether the type library says it never returns.
    pub no_return: bool,
    /// Whether the user rejected the match.
    pub rejected: bool,
}

/// How a signature matched a function.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Matched {
    /// Its identity is the library function's, and nothing else fits.
    Exact,
    /// It behaves as the library function on every state that ran, and
    /// every other candidate was ruled out.
    Behaviour {
        /// The states that agreed.
        states: u32,
        /// The candidates ruled out.
        ruled_out: u32,
    },
}

impl fmt::Display for Matched {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact => f.write_str("exact"),
            Self::Behaviour { states, ruled_out } => write!(
                f,
                "behaviour: {states} of {states} states agreed, {ruled_out} ruled out"
            ),
        }
    }
}

impl Edits {
    /// The name the user gave the function at `entry`.
    pub fn function(&self, entry: u64) -> Option<&str> {
        self.functions.get(&entry).map(String::as_str)
    }

    /// The functions named, by entry, with their names.
    pub fn functions(&self) -> impl Iterator<Item = (u64, &str)> {
        self.functions
            .iter()
            .map(|(&entry, name)| (entry, name.as_str()))
    }

    /// The name the user gave the global at `address`.
    pub fn global(&self, address: u64) -> Option<&str> {
        self.globals.get(&address).map(String::as_str)
    }

    /// The name the user gave the function or global at `address`.
    pub fn name(&self, address: u64) -> Option<&str> {
        self.function(address).or_else(|| self.global(address))
    }

    /// The name the user gave `variable`.
    pub fn variable(&self, variable: &Variable) -> Option<&str> {
        self.variables.get(variable).map(String::as_str)
    }

    /// The variables of the function at `entry` the user named, with
    /// their names.
    pub fn variables_of(&self, entry: u64) -> impl Iterator<Item = (&Variable, &str)> {
        self.variables
            .iter()
            .filter(move |(variable, _)| variable.function == entry)
            .map(|(variable, name)| (variable, name.as_str()))
    }

    /// The user's comment at `address`.
    pub fn comment(&self, address: u64) -> Option<&str> {
        self.comments.get(&address).map(String::as_str)
    }

    /// The comments, by address.
    pub fn comments(&self) -> &BTreeMap<u64, String> {
        &self.comments
    }

    /// The bookmark at `address`, its name.
    pub fn bookmark(&self, address: u64) -> Option<&str> {
        self.bookmarks.get(&address).map(String::as_str)
    }

    /// The bookmarks' names, by address.
    pub fn bookmarks(&self) -> &BTreeMap<u64, String> {
        &self.bookmarks
    }

    /// The name the user gave the frame slot at `offset` (from the stack
    /// pointer on entry) of the function at `function` as a slot.
    pub fn slot(&self, function: u64, offset: i64) -> Option<&str> {
        self.slots.get(&(function, offset)).map(String::as_str)
    }

    /// How the number `value` the instruction at `address` uses is
    /// written, if the user said (of `value` at another width too: the
    /// listing's `0FFFFFFFFh` is the C's `-1`: one [`canonical`] number).
    pub fn number(&self, address: u64, value: u64) -> Option<NumberForm> {
        self.numbers.get(&(address, value)).cloned().or_else(|| {
            let canon = canonical(value);
            self.numbers
                .range((address, 0)..=(address, u64::MAX))
                .find(|((_, stated), _)| canonical(*stated) == canon)
                .map(|(_, form)| form.clone())
        })
    }

    /// The forms of numbers, by instruction and value.
    pub fn numbers(&self) -> &BTreeMap<(u64, u64), NumberForm> {
        &self.numbers
    }

    /// The user's types as C, by what they type.
    pub fn types(&self) -> &BTreeMap<Typed, String> {
        &self.types
    }

    /// The user's type of `typed`, as C.
    pub fn type_of(&self, typed: &Typed) -> Option<&str> {
        self.types.get(typed).map(String::as_str)
    }

    /// The user's definitions as C, by the key each defines.
    pub fn definitions(&self) -> &BTreeMap<String, String> {
        &self.definitions
    }

    /// The user's corrections of what recovery found: the inputs of a
    /// re-analysis.
    pub fn corrections(&self) -> &Corrections {
        &self.corrections
    }

    /// Every edit: functions, globals, variables, comments, bookmarks,
    /// frame slots, numbers, types, definitions, items, bounds, each in
    /// order.
    pub fn all(&self) -> impl Iterator<Item = Edit> + '_ {
        let functions = self.functions.iter().map(|(&entry, name)| Edit::Function {
            entry,
            name: name.clone(),
        });
        let globals = self.globals.iter().map(|(&address, name)| Edit::Global {
            address,
            name: name.clone(),
        });
        let variables = self
            .variables
            .iter()
            .map(|(variable, name)| Edit::Variable {
                variable: variable.clone(),
                name: name.clone(),
            });
        let comments = self.comments.iter().map(|(&address, text)| Edit::Comment {
            address,
            text: text.clone(),
        });
        let bookmarks = self
            .bookmarks
            .iter()
            .map(|(&address, name)| Edit::Bookmark {
                address,
                name: name.clone(),
            });
        let slots = self
            .slots
            .iter()
            .map(|(&(function, offset), name)| Edit::Slot {
                function,
                offset,
                name: name.clone(),
            });
        let numbers = self
            .numbers
            .iter()
            .map(|(&(address, value), form)| Edit::Number {
                address,
                value,
                form: form.clone(),
            });
        let types = self.types.iter().map(|(typed, c)| Edit::Type {
            typed: typed.clone(),
            c: c.clone(),
        });
        let definitions = self.definitions.iter().map(|(key, c)| Edit::Definition {
            key: key.clone(),
            c: c.clone(),
        });
        let items = self
            .corrections
            .items()
            .iter()
            .map(|(&address, &item)| Edit::Item { address, item });
        let bounds = self
            .corrections
            .functions()
            .iter()
            .map(|(&entry, &bounds)| Edit::Bounds { entry, bounds });
        functions
            .chain(globals)
            .chain(variables)
            .chain(comments)
            .chain(bookmarks)
            .chain(slots)
            .chain(numbers)
            .chain(types)
            .chain(definitions)
            .chain(items)
            .chain(bounds)
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.functions.is_empty()
            && self.globals.is_empty()
            && self.variables.is_empty()
            && self.comments.is_empty()
            && self.bookmarks.is_empty()
            && self.slots.is_empty()
            && self.numbers.is_empty()
            && self.types.is_empty()
            && self.definitions.is_empty()
            && self.corrections.is_empty()
            && self.signatures.is_empty()
    }

    /// Names the function at `entry` `name` (`None`: its own name again).
    pub(crate) fn set_function(&mut self, entry: u64, name: Option<String>) {
        set(&mut self.functions, entry, name);
    }

    /// Names the global at `address` `name` (`None`: its own name again).
    pub(crate) fn set_global(&mut self, address: u64, name: Option<String>) {
        set(&mut self.globals, address, name);
    }

    /// Names `variable` `name` (`None`: the printer's name again).
    pub(crate) fn set_variable(&mut self, variable: Variable, name: Option<String>) {
        set(&mut self.variables, variable, name);
    }

    /// Comments `address` with `text` (`None`: no comment).
    pub(crate) fn set_comment(&mut self, address: u64, text: Option<String>) {
        set(&mut self.comments, address, text);
    }

    /// Bookmarks `address` as `name` (`None`: no bookmark).
    pub(crate) fn set_bookmark(&mut self, address: u64, name: Option<String>) {
        set(&mut self.bookmarks, address, name);
    }

    /// Names the frame slot at `offset` (from the stack pointer on entry)
    /// of the function at `function` `name` (`None`: the listing's name
    /// again).
    pub(crate) fn set_slot(&mut self, function: u64, offset: i64, name: Option<String>) {
        set(&mut self.slots, (function, offset), name);
    }

    /// Writes the number `value` the instruction at `address` uses in
    /// `form` (`None`: as the listing and the printer choose), in place of
    /// a form stated for it at another width ([`canonical`]: the C's `-1`
    /// and the listing's `0FFFFFFFFh` are one number, with one form).
    pub(crate) fn set_number(&mut self, address: u64, value: u64, form: Option<NumberForm>) {
        let canon = canonical(value);
        let stated: Vec<u64> = self
            .numbers
            .range((address, 0)..=(address, u64::MAX))
            .map(|(&(_, stated), _)| stated)
            .filter(|&stated| canonical(stated) == canon)
            .collect();
        for stated in stated {
            self.numbers.remove(&(address, stated));
        }
        if let Some(form) = form {
            self.numbers.insert((address, value), form);
        }
    }

    /// Types `typed` as C `c` states (`None`: as analysis types it).
    pub(crate) fn set_type(&mut self, typed: Typed, c: Option<String>) {
        set(&mut self.types, typed, c);
    }

    /// Defines `key` as C `c` (`None`: no longer the user's).
    pub(crate) fn set_definition(&mut self, key: String, c: Option<String>) {
        set(&mut self.definitions, key, c);
    }

    /// Takes `corrections` as the user's corrections of recovery.
    pub(crate) fn set_corrections(&mut self, corrections: Corrections) {
        self.corrections = corrections;
        for (&entry, identified) in &self.signatures {
            self.corrections
                .set_no_return(entry, identified.no_return && !identified.rejected);
        }
    }

    /// What a signature says of the function at `entry`.
    pub fn signature(&self, entry: u64) -> Option<&Identified> {
        self.signatures.get(&entry)
    }

    /// What signatures say, by entry.
    pub fn signatures(&self) -> &BTreeMap<u64, Identified> {
        &self.signatures
    }

    /// Says what a signature says of the function at `entry` (`None`:
    /// nothing); a match of a function that never returns is a correction
    /// of recovery ([`Corrections::no_return`]).
    pub(crate) fn set_signature(&mut self, entry: u64, identified: Option<Identified>) {
        let no_return = identified
            .as_ref()
            .is_some_and(|i| i.no_return && !i.rejected);
        self.corrections.set_no_return(entry, no_return);
        match identified {
            Some(identified) => self.signatures.insert(entry, identified),
            None => self.signatures.remove(&entry),
        };
    }

    /// The edits in the project file at `path`; none if there is no file.
    ///
    /// # Errors
    ///
    /// The file cannot be read, or is not a project file.
    pub fn load(path: &Path) -> Result<Self, String> {
        match fs::read_to_string(path) {
            Ok(text) => Self::parse(&text).map_err(|error| format!("{}: {error}", path.display())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(format!("{}: {error}", path.display())),
        }
    }

    /// The edits of a project file's `text`.
    ///
    /// # Errors
    ///
    /// It is not TOML, not this format (a later version, or none), or an
    /// address is not hexadecimal.
    pub fn parse(text: &str) -> Result<Self, String> {
        let file: ProjectFile = toml::from_str(text).map_err(|error| error.to_string())?;
        project::check_format(file.format.into(), FORMAT)?;
        let mut edits = Self::default();
        for named in file.functions {
            edits.functions.insert(address(&named.address)?, named.name);
        }
        for named in file.globals {
            edits.globals.insert(address(&named.address)?, named.name);
        }
        for entry in file.variables {
            let mut origins = entry.origins;
            origins.sort_unstable();
            origins.dedup();
            let variable = Variable {
                function: address(&entry.function)?,
                origins,
                ordinal: entry.ordinal,
            };
            edits.variables.insert(variable, entry.name);
        }
        for comment in file.comments {
            edits
                .comments
                .insert(address(&comment.address)?, comment.text);
        }
        for bookmark in file.bookmarks {
            edits
                .bookmarks
                .insert(address(&bookmark.address)?, bookmark.name);
        }
        for slot in file.slots {
            edits
                .slots
                .insert((address(&slot.function)?, slot.offset), slot.name);
        }
        for number in file.numbers {
            edits.numbers.insert(
                (address(&number.address)?, address(&number.value)?),
                number.form,
            );
        }
        for entry in file.types {
            match (entry.name, entry.function, entry.global, entry.structure) {
                (None, Some(function), None, Some(k)) => {
                    edits.types.insert(
                        Typed::Struct {
                            function: address(&function)?,
                            k,
                        },
                        entry.c,
                    );
                }
                (Some(key), None, None, None) => {
                    edits.definitions.insert(key, entry.c);
                }
                (None, Some(function), None, None) if entry.origins.is_empty() => {
                    edits
                        .types
                        .insert(Typed::Prototype(address(&function)?), entry.c);
                }
                (None, Some(function), None, None) => {
                    let mut origins = entry.origins;
                    origins.sort_unstable();
                    origins.dedup();
                    let variable = Variable {
                        function: address(&function)?,
                        origins,
                        ordinal: entry.ordinal,
                    };
                    edits.types.insert(Typed::Variable(variable), entry.c);
                }
                (None, None, Some(global), None) => {
                    edits
                        .types
                        .insert(Typed::Global(address(&global)?), entry.c);
                }
                _ => {
                    return Err(format!(
                        "a type needs one of name, function or global: {:?}",
                        entry.c
                    ));
                }
            }
        }
        edits.corrections = corrections(file.items, file.bounds)?;
        for entry in file.signatures {
            let function = address(&entry.function)?;
            edits.set_signature(function, Some(entry.identified()?));
        }
        Ok(edits)
    }

    /// The project file's text.
    ///
    /// # Errors
    ///
    /// TOML cannot hold a name or comment (it can: strings are escaped).
    pub fn to_toml(&self) -> Result<String, String> {
        let named = |map: &BTreeMap<u64, String>| {
            map.iter()
                .map(|(&address, name)| Named {
                    address: format!("{address:#x}"),
                    name: name.clone(),
                })
                .collect()
        };
        let file = ProjectFile {
            format: FORMAT,
            functions: named(&self.functions),
            globals: named(&self.globals),
            variables: self
                .variables
                .iter()
                .map(|(variable, name)| VariableEntry {
                    function: format!("{:#x}", variable.function),
                    origins: variable.origins.clone(),
                    ordinal: variable.ordinal,
                    name: name.clone(),
                })
                .collect(),
            comments: self
                .comments
                .iter()
                .map(|(&address, text)| CommentEntry {
                    address: format!("{address:#x}"),
                    text: text.clone(),
                })
                .collect(),
            bookmarks: named(&self.bookmarks),
            slots: self
                .slots
                .iter()
                .map(|(&(function, offset), name)| SlotEntry {
                    function: format!("{function:#x}"),
                    offset,
                    name: name.clone(),
                })
                .collect(),
            numbers: self
                .numbers
                .iter()
                .map(|(&(address, value), form)| NumberEntry {
                    address: format!("{address:#x}"),
                    value: format!("{value:#x}"),
                    form: form.clone(),
                })
                .collect(),
            types: self
                .definitions
                .iter()
                .map(|(key, c)| TypeEntry {
                    name: Some(key.clone()),
                    c: c.clone(),
                    ..TypeEntry::default()
                })
                .chain(self.types.iter().map(|(typed, c)| {
                    let mut entry = TypeEntry {
                        c: c.clone(),
                        ..TypeEntry::default()
                    };
                    match typed {
                        Typed::Prototype(entry_address) => {
                            entry.function = Some(format!("{entry_address:#x}"));
                        }
                        Typed::Global(address) => entry.global = Some(format!("{address:#x}")),
                        Typed::Variable(variable) => {
                            entry.function = Some(format!("{:#x}", variable.function));
                            entry.origins.clone_from(&variable.origins);
                            entry.ordinal = variable.ordinal;
                        }
                        &Typed::Struct { function, k } => {
                            entry.function = Some(format!("{function:#x}"));
                            entry.structure = Some(k);
                        }
                    }
                    entry
                }))
                .collect(),
            items: item_entries(&self.corrections),
            bounds: bounds_entries(&self.corrections),
            signatures: self
                .signatures
                .iter()
                .map(|(&function, identified)| SignatureEntry::of(function, identified))
                .collect(),
        };
        toml::to_string(&file).map_err(|error| error.to_string())
    }

    /// Writes the project file to `path`, crash-safely: whole to a
    /// temporary file beside it, flushed to the disk, renamed over it, and
    /// the directory's entry flushed where the platform allows.
    ///
    /// # Errors
    ///
    /// The file cannot be written.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        project::write_safely(path, &self.to_toml()?)
    }
}

/// Sets `key` to `value` in `map`, or removes it.
fn set<K: Ord>(map: &mut BTreeMap<K, String>, key: K, value: Option<String>) {
    match value {
        Some(value) => map.insert(key, value),
        None => map.remove(&key),
    };
}

/// The corrections a project file's `items` and `bounds` state.
fn corrections(items: Vec<ItemEntry>, bounds: Vec<BoundsEntry>) -> Result<Corrections, String> {
    let mut corrections = Corrections::default();
    for entry in items {
        let item = match (entry.kind.as_str(), entry.size, entry.count) {
            ("code", None, None) => Item::Code,
            ("undefined", Some(size), None) if size > 0 => Item::Undefined { size },
            (kind, None, count) => {
                let unit =
                    Unit::named(kind).ok_or_else(|| format!("not a kind of item: {kind:?}"))?;
                let count = count.unwrap_or(1);
                if count == 0 {
                    return Err(format!("an item of no {kind}s"));
                }
                Item::Data(Data { unit, count })
            }
            (kind, _, _) => return Err(format!("a {kind:?} item's size or count is wrong")),
        };
        corrections.set_item(address(&entry.address)?, Some(item));
    }
    for entry in bounds {
        let bounds = match (entry.deleted, entry.end) {
            (true, None) => Bounds::Deleted,
            (false, end) => Bounds::Function {
                end: end.as_deref().map(address).transpose()?,
            },
            (true, Some(_)) => return Err("a function deleted has no end".to_owned()),
        };
        corrections.set_bounds(address(&entry.function)?, Some(bounds));
    }
    Ok(corrections)
}

/// `corrections`' items as a project file's entries.
fn item_entries(corrections: &Corrections) -> Vec<ItemEntry> {
    corrections
        .items()
        .iter()
        .map(|(&at, &item)| {
            let (kind, size, count) = match item {
                Item::Code => ("code", None, None),
                Item::Undefined { size } => ("undefined", Some(size), None),
                Item::Data(data) => (
                    data.unit.name(),
                    None,
                    (data.count != 1).then_some(data.count),
                ),
            };
            ItemEntry {
                address: format!("{at:#x}"),
                kind: kind.to_owned(),
                size,
                count,
            }
        })
        .collect()
}

/// `corrections`' functions' bounds as a project file's entries.
fn bounds_entries(corrections: &Corrections) -> Vec<BoundsEntry> {
    corrections
        .functions()
        .iter()
        .map(|(&entry, &bounds)| BoundsEntry {
            function: format!("{entry:#x}"),
            end: match bounds {
                Bounds::Function { end } => end.map(|end| format!("{end:#x}")),
                Bounds::Deleted => None,
            },
            deleted: bounds == Bounds::Deleted,
        })
        .collect()
}

/// The address `text` spells (hexadecimal, `0x` optional).
pub(crate) fn address(text: &str) -> Result<u64, String> {
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
    u64::from_str_radix(digits, 16).map_err(|_| format!("not a hexadecimal address: {text:?}"))
}

/// The project file.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectFile {
    /// Its format's version ([`FORMAT`]).
    format: u32,
    /// Functions named.
    #[serde(default, rename = "function", skip_serializing_if = "Vec::is_empty")]
    functions: Vec<Named>,
    /// Globals named.
    #[serde(default, rename = "global", skip_serializing_if = "Vec::is_empty")]
    globals: Vec<Named>,
    /// Variables named.
    #[serde(default, rename = "variable", skip_serializing_if = "Vec::is_empty")]
    variables: Vec<VariableEntry>,
    /// Comments.
    #[serde(default, rename = "comment", skip_serializing_if = "Vec::is_empty")]
    comments: Vec<CommentEntry>,
    /// Bookmarks.
    #[serde(default, rename = "bookmark", skip_serializing_if = "Vec::is_empty")]
    bookmarks: Vec<Named>,
    /// Frame slots named.
    #[serde(default, rename = "slot", skip_serializing_if = "Vec::is_empty")]
    slots: Vec<SlotEntry>,
    /// Numbers' forms.
    #[serde(default, rename = "number", skip_serializing_if = "Vec::is_empty")]
    numbers: Vec<NumberEntry>,
    /// Types and definitions.
    #[serde(default, rename = "type", skip_serializing_if = "Vec::is_empty")]
    types: Vec<TypeEntry>,
    /// What bytes are (corrections of recovery).
    #[serde(default, rename = "item", skip_serializing_if = "Vec::is_empty")]
    items: Vec<ItemEntry>,
    /// Functions' bounds (corrections of recovery).
    #[serde(default, rename = "bounds", skip_serializing_if = "Vec::is_empty")]
    bounds: Vec<BoundsEntry>,
    /// What library signatures say of functions.
    #[serde(default, rename = "signature", skip_serializing_if = "Vec::is_empty")]
    signatures: Vec<SignatureEntry>,
}

/// What a library signature says of the function at `function`
/// ([`Identified`]): `how` is `exact` or `behaviour` (with `states` and
/// `ruled_out`).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignatureEntry {
    /// The function's entry, in hexadecimal.
    function: String,
    pack: String,
    library: String,
    version: String,
    name: String,
    object: String,
    how: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    states: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ruled_out: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    prototype: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    no_return: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    rejected: bool,
}

impl SignatureEntry {
    /// The entry of `identified`, the function at `function`'s.
    fn of(function: u64, identified: &Identified) -> Self {
        let (how, states, ruled_out) = match identified.how {
            Matched::Exact => ("exact", None, None),
            Matched::Behaviour { states, ruled_out } => {
                ("behaviour", Some(states), Some(ruled_out))
            }
        };
        Self {
            function: format!("{function:#x}"),
            pack: identified.pack.clone(),
            library: identified.library.clone(),
            version: identified.version.clone(),
            name: identified.name.clone(),
            object: identified.object.clone(),
            how: how.to_owned(),
            states,
            ruled_out,
            prototype: identified.prototype.clone(),
            no_return: identified.no_return,
            rejected: identified.rejected,
        }
    }

    /// What it says.
    fn identified(self) -> Result<Identified, String> {
        let how = match (self.how.as_str(), self.states, self.ruled_out) {
            ("exact", None, None) => Matched::Exact,
            ("behaviour", Some(states), Some(ruled_out)) => {
                Matched::Behaviour { states, ruled_out }
            }
            _ => {
                return Err(format!(
                    "a signature's how is `exact`, or `behaviour` with states and ruled_out: {}",
                    self.how
                ));
            }
        };
        Ok(Identified {
            pack: self.pack,
            library: self.library,
            version: self.version,
            name: self.name,
            object: self.object,
            how,
            prototype: self.prototype,
            no_return: self.no_return,
            rejected: self.rejected,
        })
    }
}

/// What the bytes at an address are: `code`, `undefined` (`size` bytes),
/// or data of a unit (`byte`, `word`, `dword`, `qword`, `string`,
/// `utf16`), `count` of them (1 if not given).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ItemEntry {
    /// The address, in hexadecimal.
    address: String,
    /// What it is.
    kind: String,
    /// The bytes undefined.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
    /// How many units of data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    count: Option<u64>,
}

/// A function's bounds: a function at `function`, ending at `end` if
/// given; none there if `deleted`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundsEntry {
    /// Its entry, in hexadecimal.
    function: String,
    /// The address after its last byte, in hexadecimal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    end: Option<String>,
    /// Whether no function starts there.
    #[serde(default, skip_serializing_if = "is_false")]
    deleted: bool,
}

/// Whether `value` is false.
#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's skip_serializing_if passes a reference"
)]
fn is_false(value: &bool) -> bool {
    !*value
}

/// A name at an address.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Named {
    /// The address, in hexadecimal.
    address: String,
    /// The name.
    name: String,
}

/// A variable's name.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariableEntry {
    /// Its function's entry, in hexadecimal.
    function: String,
    /// What it was made from ([`Variable::origins`]).
    origins: Vec<String>,
    /// Its place among its function's variables made from the same.
    #[serde(default, skip_serializing_if = "is_zero")]
    ordinal: usize,
    /// The name.
    name: String,
}

/// A comment at an address.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommentEntry {
    /// The address, in hexadecimal.
    address: String,
    /// What it says.
    text: String,
}

/// A frame slot's name.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SlotEntry {
    /// Its function's entry, in hexadecimal.
    function: String,
    /// Its offset from the stack pointer on entry.
    offset: i64,
    /// The name.
    name: String,
}

/// How a number an instruction uses is written.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NumberEntry {
    /// The instruction's address, in hexadecimal.
    address: String,
    /// The number's bits, in hexadecimal.
    value: String,
    /// How it is written.
    form: NumberForm,
}

/// A type as C: a definition (`name`), a function's prototype
/// (`function`), a variable's (`function`, `origins`, `ordinal`), a
/// global's (`global`), the user's version of a synthesised struct
/// (`function`, `struct`).
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TypeEntry {
    /// The key a definition defines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    /// The function (its prototype, or its variable's), in hexadecimal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    function: Option<String>,
    /// The global's address, in hexadecimal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    global: Option<String>,
    /// What the variable was made from ([`Variable::origins`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    origins: Vec<String>,
    /// Its place among its function's variables made from the same.
    #[serde(default, skip_serializing_if = "is_zero")]
    ordinal: usize,
    /// The synthesised struct's number among those born in `function`.
    #[serde(default, rename = "struct", skip_serializing_if = "Option::is_none")]
    structure: Option<u32>,
    /// The type as C.
    c: String,
}

/// Whether `value` is 0.
#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's skip_serializing_if passes a reference"
)]
fn is_zero(value: &usize) -> bool {
    *value == 0
}

#[cfg(test)]
mod tests {
    use binbun_ast::ir::{Function as Ast, Origin, VarKind, Variable as AstVariable};
    use binbun_ast::types::{Evidence, Type, Types};
    use binbun_semantics::ir::RegisterId;
    use binbun_semantics::{Declarations, RegisterInfo};
    use binbun_ssa::ir::Value;

    use super::Variable;

    const DECLARATIONS: Declarations = Declarations {
        registers: &[RegisterInfo {
            name: "rdi",
            width: 64,
        }],
        intrinsics: &[],
        sites: &[],
    };

    /// A function of one local made from L1 value 3, and `held` among its
    /// origins if given.
    fn function(held: Option<RegisterId>) -> Ast {
        let mut function = Ast::new(0x1000, Types::new(64));
        let ty = function.types.intern(Type::Int(64));
        let mut origins = vec![Origin::Value(Value(3))];
        origins.extend(held.map(Origin::Held));
        function.add_var(AstVariable {
            kind: VarKind::Local,
            name: None,
            ty,
            evidence: Evidence::Default,
            origins,
        });
        function
    }

    /// The register a local was held in names it in the C and nothing
    /// more: an edit made of it before that was recorded (a project
    /// saved by an earlier version) still finds it, and one made after
    /// is the same edit.
    #[test]
    fn the_register_a_local_was_held_in_is_no_part_of_its_identity() {
        let before = function(None);
        let after = function(Some(RegisterId(0)));
        let var = binbun_ast::ir::VarId(0);
        let identity = Variable::of(&before, var, &DECLARATIONS).unwrap();
        assert_eq!(
            Variable::of(&after, var, &DECLARATIONS),
            Some(identity.clone())
        );
        assert_eq!(identity.resolve(&after, &DECLARATIONS), Ok(var));
    }
}
