//! The writes a client makes ([`Write`]): each as data (the `edit` of
//! `edits.apply`), and what one does to a session ([`Write::apply`]).

use binbun::Database;
use binbun::cfg::{FunctionId, SeedKind, SeedKinds};
use binbun::corrections::{Bounds, Corrections, Data, Item, Unit};
use binbun_session::{Error, MemberEdit, NumberForm, Session, Typed, Variable};
use serde::{Deserialize, Serialize};

use crate::fault::{Fault, FaultKind};
use crate::hex;
use crate::types::Viewed;

/// A variable as a client names it: its identity
/// ([`binbun_session::Variable`]: what it was made from, which survives
/// re-analysis) and the view whose document it was read from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VariableRef {
    /// Its function's entry.
    #[serde(with = "hex")]
    pub function: u64,
    /// What it was made from.
    pub origins: Vec<String>,
    /// Its place among the function's variables made from the same.
    pub ordinal: usize,
    /// The view it was read in.
    pub view: Viewed,
}

impl VariableRef {
    /// Its identity.
    pub fn identity(&self) -> Variable {
        Variable {
            function: self.function,
            origins: self.origins.clone(),
            ordinal: self.ordinal,
        }
    }
}

/// A change to a struct's member (`MemberEdit`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Member {
    /// Its name is this.
    Rename(String),
    /// Its type is this C type, as wide as it was.
    Retype(String),
    /// Its type is this C type, of any width the layout holds.
    Resize(String),
}

/// A correction of recovery, as a script states it at an address.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Correction {
    /// Code from here (the GUI's `C`).
    Code {
        /// Where.
        #[serde(with = "hex")]
        address: u64,
    },
    /// `count` units of `unit` (`byte`, `word`, `dword`, `qword`,
    /// `string`, `utf16`) here (the GUI's `D`, `*`).
    Data {
        /// Where.
        #[serde(with = "hex")]
        address: u64,
        /// The unit's name.
        unit: String,
        /// How many.
        count: u64,
    },
    /// The string the bytes here start, C or UTF-16 by what they are
    /// (the GUI's `A`).
    String {
        /// Where.
        #[serde(with = "hex")]
        address: u64,
    },
    /// `size` bytes from here typed as nothing (the GUI's `U`).
    Undefine {
        /// Where.
        #[serde(with = "hex")]
        address: u64,
        /// How many bytes.
        size: u64,
    },
    /// The user's item starting here, if any, dropped.
    Clear {
        /// Where.
        #[serde(with = "hex")]
        address: u64,
    },
    /// A function starting here (the GUI's `P`), ending at `end` if given.
    Function {
        /// Its entry.
        #[serde(with = "hex")]
        entry: u64,
        /// The address after its last byte.
        #[serde(default, with = "hex::option")]
        end: Option<u64>,
    },
    /// The function at `entry` ending at `end` (`None`: where recovery
    /// ends it).
    End {
        /// Its entry.
        #[serde(with = "hex")]
        entry: u64,
        /// The address after its last byte.
        #[serde(default, with = "hex::option")]
        end: Option<u64>,
    },
    /// No function at `entry` (Delete Function; one only the user made
    /// is unmade).
    Delete {
        /// Its entry.
        #[serde(with = "hex")]
        entry: u64,
    },
}

/// A write.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "write", rename_all = "snake_case")]
pub enum Write {
    /// The function at `entry` named `name` (`None`: its own again).
    FunctionName {
        /// Its entry.
        #[serde(with = "hex")]
        entry: u64,
        /// The name.
        name: Option<String>,
    },
    /// The function starting at `address` named, else the global there.
    Name {
        /// Where.
        #[serde(with = "hex")]
        address: u64,
        /// The name.
        name: Option<String>,
    },
    /// A variable named.
    VariableName {
        /// The variable.
        variable: VariableRef,
        /// The name.
        name: Option<String>,
    },
    /// A variable typed as C (as wide as it is).
    VariableType {
        /// The variable.
        variable: VariableRef,
        /// Its type as C.
        c: Option<String>,
    },
    /// A frame slot of the function at `entry` named in the listing.
    SlotName {
        /// The function's entry.
        #[serde(with = "hex")]
        entry: u64,
        /// Its offset from the stack pointer on entry.
        offset: i64,
        /// The name.
        name: Option<String>,
    },
    /// A comment (`\n` between lines; `None`: none).
    Comment {
        /// Where.
        #[serde(with = "hex")]
        address: u64,
        /// What it says.
        text: Option<String>,
    },
    /// A bookmark.
    Bookmark {
        /// Where.
        #[serde(with = "hex")]
        address: u64,
        /// Its name.
        name: Option<String>,
    },
    /// The number `value` the instruction at `address` uses written in
    /// `form` (`None`: as chosen).
    NumberForm {
        /// The instruction.
        #[serde(with = "hex")]
        address: u64,
        /// The number, as its bits.
        #[serde(with = "hex")]
        value: u64,
        /// How it is written.
        form: Option<NumberForm>,
    },
    /// The function at `entry` given the prototype C `c`.
    Prototype {
        /// Its entry.
        #[serde(with = "hex")]
        entry: u64,
        /// The prototype.
        c: Option<String>,
    },
    /// The global at `address` typed.
    GlobalType {
        /// Where.
        #[serde(with = "hex")]
        address: u64,
        /// Its type as C.
        c: Option<String>,
    },
    /// A synthesised struct (born in `function`, its `k`th) given the
    /// user's definition.
    StructType {
        /// The function it is born in.
        #[serde(with = "hex")]
        function: u64,
        /// Its number there, from 1.
        k: u32,
        /// Its definition as C.
        c: Option<String>,
    },
    /// The struct, union, enumeration or typedef C defines.
    Define {
        /// The C.
        c: String,
    },
    /// The user's definition of `key` dropped.
    Undefine {
        /// What it defines (`struct pair`).
        key: String,
    },
    /// A member of the struct `key` changed.
    Member {
        /// The struct (`struct pair`).
        key: String,
        /// The member's name.
        member: String,
        /// The change.
        edit: Member,
    },
    /// A correction of recovery.
    Correction {
        /// The correction.
        correction: Correction,
    },
    /// The library signature's match of the function at `entry` rejected
    /// (`Session::reject_signature`).
    RejectSignature {
        /// Its entry.
        #[serde(with = "hex")]
        entry: u64,
    },
}

/// What a write did, besides changing the edits.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Applied {
    /// The key a definition defined.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Whether it corrected recovery (the binary is to be analysed
    /// anew).
    #[serde(default)]
    pub corrected: bool,
}

impl Write {
    /// The undo step's label of a write made alone.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::FunctionName { .. } => "Rename function",
            Self::Name { .. } => "Rename",
            Self::VariableName { .. } => "Rename variable",
            Self::VariableType { .. } | Self::GlobalType { .. } | Self::StructType { .. } => {
                "Set type"
            }
            Self::SlotName { .. } => "Rename frame slot",
            Self::Comment { .. } => "Comment",
            Self::Bookmark { .. } => "Bookmark",
            Self::NumberForm { .. } => "Number form",
            Self::Prototype { .. } => "Set prototype",
            Self::Define { .. } => "Define type",
            Self::Undefine { .. } => "Undefine type",
            Self::Member { .. } => "Edit member",
            Self::Correction { .. } => "Correct recovery",
            Self::RejectSignature { .. } => "Reject signature",
        }
    }

    /// Makes it in `session` (in the group open there, if one is).
    ///
    /// # Errors
    ///
    /// An address no segment holds, once the image is parsed
    /// ([`FaultKind::InvalidAddress`]); the session refuses it: no such
    /// function or variable, C refused, a correction that cannot apply, a
    /// change that cannot be made or that the share does not take
    /// ([`FaultKind::ReadOnly`]).
    pub fn apply(&self, session: &Session) -> Result<Applied, Fault> {
        self.mapped(session)?;
        match self {
            Self::FunctionName { entry, name } => {
                session
                    .rename_function(*entry, name.as_deref())
                    .map_err(refused(None))?;
            }
            Self::Name { address, name } => {
                rename(session, *address, name.as_deref())?;
            }
            Self::VariableName { variable, name } => {
                rename_variable(session, variable, name.as_deref())?;
            }
            Self::VariableType { variable, c } => {
                session
                    .set_type(Typed::Variable(variable.identity()), c.as_deref())
                    .map_err(refused(c.as_deref()))?;
            }
            Self::SlotName {
                entry,
                offset,
                name,
            } => {
                function(session, *entry)?;
                session
                    .rename_slot(*entry, *offset, name.as_deref())
                    .map_err(refused(None))?;
            }
            Self::Comment { address, text } => {
                session
                    .comment(*address, text.as_deref())
                    .map_err(refused(None))?;
            }
            Self::Bookmark { address, name } => {
                session
                    .bookmark(*address, name.as_deref())
                    .map_err(refused(None))?;
            }
            Self::NumberForm {
                address,
                value,
                form,
            } => {
                number_form(session, *address, *value, form.as_ref())?;
            }
            Self::Prototype { entry, c } => {
                function(session, *entry)?;
                session
                    .set_type(Typed::Prototype(*entry), c.as_deref())
                    .map_err(refused(c.as_deref()))?;
            }
            Self::GlobalType { address, c } => {
                session
                    .set_type(Typed::Global(*address), c.as_deref())
                    .map_err(refused(c.as_deref()))?;
            }
            Self::StructType { function, k, c } => {
                session
                    .set_type(
                        Typed::Struct {
                            function: *function,
                            k: *k,
                        },
                        c.as_deref(),
                    )
                    .map_err(refused(c.as_deref()))?;
            }
            Self::Define { c } => {
                let (key, _) = session.define(c).map_err(refused(Some(c)))?;
                return Ok(Applied {
                    key: Some(key),
                    corrected: false,
                });
            }
            Self::Undefine { key } => {
                session.undefine(key).map_err(refused(None))?;
            }
            Self::Member { key, member, edit } => {
                let (edit, c) = match edit {
                    Member::Rename(name) => (MemberEdit::Rename(name.clone()), name),
                    Member::Retype(c) => (MemberEdit::Retype(c.clone()), c),
                    Member::Resize(c) => (MemberEdit::Resize(c.clone()), c),
                };
                session
                    .edit_member(key, member, &edit)
                    .map_err(refused(Some(c)))?;
            }
            Self::Correction { correction } => {
                let corrections = correction.made(session)?;
                session
                    .set_corrections(&corrections)
                    .map_err(refused(None))?;
                return Ok(Applied {
                    key: None,
                    corrected: true,
                });
            }
            Self::RejectSignature { entry } => return reject(session, *entry),
        }
        Ok(Applied::default())
    }

    /// Checks a segment holds the address it writes at, if it writes at
    /// one (any address before the image is parsed).
    ///
    /// # Errors
    ///
    /// [`FaultKind::InvalidAddress`] if none does.
    fn mapped(&self, session: &Session) -> Result<(), Fault> {
        let (Self::Name { address, .. }
        | Self::Comment { address, .. }
        | Self::Bookmark { address, .. }
        | Self::NumberForm { address, .. }
        | Self::GlobalType { address, .. }) = self
        else {
            return Ok(());
        };
        if session
            .image()
            .is_some_and(|image| !image.is_mapped(*address))
        {
            return Err(Fault::new(
                FaultKind::InvalidAddress,
                format!("no segment holds {address:#x}"),
            ));
        }
        Ok(())
    }
}

/// Rejects the signature match of the function at `entry`: a function
/// the match said never returns may again, so recovery is corrected.
fn reject(session: &Session, entry: u64) -> Result<Applied, Fault> {
    let no_return = session.signature(entry).is_some_and(|s| s.no_return);
    session.reject_signature(entry).map_err(refused(None))?;
    Ok(Applied {
        key: None,
        corrected: no_return,
    })
}

/// Whether a function starts at `address` (none known before the
/// functions are recovered).
fn is_function(session: &Session, address: u64) -> bool {
    session
        .database()
        .is_some_and(|database| database.function_at(address).is_some())
}

/// Names `address` `name`: the function there if one starts there, else
/// the global. The session's fault if it does not make the change.
fn rename(session: &Session, address: u64, name: Option<&str>) -> Result<(), Fault> {
    let renamed = if is_function(session, address) {
        session.rename_function(address, name)
    } else {
        session.rename_global(address, name)
    };
    renamed.map(drop).map_err(refused(None))
}

/// The session's refusal as a fault; `c`, the C it refused.
fn refused(c: Option<&str>) -> impl FnOnce(Error) -> Fault + '_ {
    move |error| Fault::session(&error, c)
}

/// Checks a function starts at `entry`.
///
/// # Errors
///
/// [`FaultKind::NotAnalysed`] before the functions are recovered,
/// [`FaultKind::NoFunction`] if none starts there.
fn function(session: &Session, entry: u64) -> Result<FunctionId, Fault> {
    let database = session.database().ok_or_else(|| {
        Fault::new(
            FaultKind::NotAnalysed,
            "the functions are not recovered yet",
        )
    })?;
    database.function_at(entry).ok_or_else(|| {
        Fault::new(
            FaultKind::NoFunction,
            format!("no function starts at {entry:#x}"),
        )
    })
}

/// Names `variable` `name`: found in its function's document of its view
/// (decompiled first if it is not).
fn rename_variable(
    session: &Session,
    variable: &VariableRef,
    name: Option<&str>,
) -> Result<(), Fault> {
    let id = function(session, variable.function)?;
    let view = variable.view.view();
    let document = session
        .document_view(id, view)
        .map_err(|message| Fault::new(FaultKind::Decompile, message))?;
    let declarations = session
        .database()
        .and_then(Database::declarations)
        .ok_or_else(|| Fault::new(FaultKind::NotAnalysed, "the declarations are not read yet"))?;
    let var = variable
        .identity()
        .resolve(&document.decompiled.l2, declarations)
        .map_err(|why| Fault::new(FaultKind::NoVariable, why))?;
    session
        .rename_variable_in(id, view, var, name)
        .map_err(|error| Fault::session(&error, None))?;
    Ok(())
}

/// Writes the number `value` the instruction at `address` uses in `form`
/// (`None`: as chosen): refused for an enumeration `session` does not know.
/// The session's fault if it does not make the change.
fn number_form(
    session: &Session,
    address: u64,
    value: u64,
    form: Option<&NumberForm>,
) -> Result<(), Fault> {
    if let Some(NumberForm::Enum(name)) = form
        && session.enumeration(name).is_none()
    {
        return Err(Fault::new(
            FaultKind::CDeclaration,
            format!("{name} names no enumeration"),
        ));
    }
    session
        .number(address, value, form.cloned())
        .map_err(refused(None))?;
    Ok(())
}

impl Correction {
    /// The user's corrections with this one made.
    ///
    /// # Errors
    ///
    /// [`FaultKind::NotAnalysed`] before the functions are recovered;
    /// [`FaultKind::Correction`] for a unit that is none, an empty item,
    /// or bytes that start no string.
    fn made(&self, session: &Session) -> Result<Corrections, Fault> {
        let refused = |message: String| Fault::new(FaultKind::Correction, message);
        let mut corrections = session.corrections();
        match *self {
            Self::Code { address } => corrections.set_item(address, Some(Item::Code)),
            Self::Data {
                address,
                ref unit,
                count,
            } => {
                let unit = Unit::named(unit).ok_or_else(|| {
                    refused(format!(
                        "no unit {unit:?} (byte, word, dword, qword, string, utf16)"
                    ))
                })?;
                if count == 0 {
                    return Err(refused("an item of no units".to_owned()));
                }
                corrections.set_item(address, Some(Item::Data(Data { unit, count })));
            }
            Self::String { address } => {
                let image = session.image().ok_or_else(|| {
                    Fault::new(FaultKind::NotAnalysed, "the image is not parsed yet")
                })?;
                let bytes = image
                    .segment(address)
                    .and_then(|segment| {
                        let offset = usize::try_from(address - segment.start).ok()?;
                        segment.bytes.get(offset..)
                    })
                    .unwrap_or_default();
                let data = Data::string(address, bytes)
                    .ok_or_else(|| refused(format!("no string starts at {address:#x}")))?;
                corrections.set_item(address, Some(Item::Data(data)));
            }
            Self::Undefine { address, size } => {
                if size == 0 {
                    return Err(refused("no bytes to undefine".to_owned()));
                }
                corrections.set_item(address, Some(Item::Undefined { size }));
            }
            Self::Clear { address } => corrections.set_item(address, None),
            Self::Function { entry, end } => {
                corrections.set_bounds(entry, Some(Bounds::Function { end }));
            }
            Self::End { entry, end } => {
                function(session, entry)?;
                corrections.set_bounds(entry, Some(Bounds::Function { end }));
            }
            Self::Delete { entry } => {
                let id = function(session, entry)?;
                // A function only the user made goes with the user's word.
                let mut user = SeedKinds::default();
                user.insert(SeedKind::User);
                let only_users = session
                    .database()
                    .and_then(|database| database.function(id))
                    .is_some_and(|f| f.seeds == user);
                let user_made = corrections.bounds(entry).is_some();
                corrections.set_bounds(
                    entry,
                    (!(only_users && user_made)).then_some(Bounds::Deleted),
                );
            }
        }
        Ok(corrections)
    }
}
