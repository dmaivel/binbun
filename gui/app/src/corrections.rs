//! The corrections of recovery from the listing and the hex view (`C`,
//! `U`, `D`, `A`, `*`, `P`, Edit Function, Delete Function): each
//! command plans its correction at the cursor, or over the bytes the
//! listing's or the hex view's selection holds
//! (`binbun_gui_view::corrections`), which the session takes as an
//! undoable edit and analyses the binary again with; why one cannot apply
//! is what the palette says beside it ([`Refusals`]), and an `Array…` or
//! `Edit Function…` asks for its count or end in the prompt.

use std::time::Instant;

use binbun::corrections::Corrections;
use binbun_gui_view::commands::{Command, Refusals};
use binbun_gui_view::corrections::{At, Op, array_count, function_end, plan};
use gpui_kit::{Context, Window};

use crate::workspace::{PromptKind, TabKind, Workspace};

impl Workspace {
    /// Whether the focused pane shows the listing, as text or as the graph
    /// (not as the hex view).
    pub fn shows_listing(&self) -> bool {
        let id = self.layout.focused();
        matches!(self.layout.active(id), Some(TabKind::Listing)) && !self.shows_hex(id)
    }

    /// Where a correction applies: the row a context menu is about, else
    /// the selection's first byte, else the cursor's address.
    fn correction_address(&self) -> Option<u64> {
        self.menu_subject
            .or_else(|| self.selected_bytes().map(|(start, _)| start))
            .or_else(|| self.current_address())
    }

    /// Calls `f` with what a correction at `address` needs (the selection
    /// too, if it starts there and no row's menu is open) and the
    /// corrections there are, once the listing is built.
    fn at<R>(&self, address: u64, f: impl FnOnce(At<'_>, &Corrections) -> R) -> Option<R> {
        let session = self.session.as_ref()?;
        let database = session.database()?;
        let listing = self.listing.as_ref()?;
        let corrections = session.corrections();
        let selection = self
            .selected_bytes()
            .filter(|&(start, _)| start == address && self.menu_subject.is_none())
            .map(|(_, end)| end);
        Some(f(
            At {
                listing: listing.lines(),
                database,
                address,
                selection,
            },
            &corrections,
        ))
    }

    /// Why each correction cannot apply at the cursor.
    pub fn refusals(&self) -> Refusals {
        const UNBUILT: Option<&str> = Some("the listing is not built yet");
        let unbuilt = Refusals {
            code: UNBUILT,
            undefine: UNBUILT,
            data: UNBUILT,
            string: UNBUILT,
            array: UNBUILT,
            function: UNBUILT,
            end: UNBUILT,
            delete: UNBUILT,
        };
        let Some(address) = self.correction_address() else {
            return unbuilt;
        };
        self.at(address, |at, corrections| {
            let refused = |op| plan(op, at, corrections).err();
            Refusals {
                code: refused(Op::Code),
                undefine: refused(Op::Undefine),
                data: refused(Op::Data),
                string: refused(Op::String),
                array: refused(Op::Array(1)),
                function: refused(Op::Function),
                end: function_end(at)
                    .map_or(Some("not in a function"), |(_, end)| refused(Op::End(end))),
                delete: refused(Op::Delete),
            }
        })
        .unwrap_or(unbuilt)
    }

    /// Runs `command` if it is a correction of recovery (`D` only in the
    /// listing and the hex view); whether it was one.
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "every other command is not a correction"
    )]
    pub fn correction_command(
        &mut self,
        command: Command,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> bool {
        let id = self.layout.focused();
        let op = match command {
            Command::MakeCode => Op::Code,
            Command::Undefine => Op::Undefine,
            Command::Data if self.shows_listing() || self.shows_hex(id) => Op::Data,
            Command::MakeString => Op::String,
            Command::MakeFunction => Op::Function,
            Command::DeleteFunction => Op::Delete,
            Command::MakeArray => {
                if let Some(address) = self.correction_address() {
                    let count = self.at(address, |at, _| array_count(at)).unwrap_or(1);
                    self.open_prompt(
                        PromptKind::Array(address),
                        &count.to_string(),
                        "",
                        window,
                        cx,
                    );
                }
                return true;
            }
            Command::EditFunction => {
                if let Some(address) = self.correction_address()
                    && let Some((_, end)) = self.at(address, |at, _| function_end(at)).flatten()
                {
                    self.open_prompt(
                        PromptKind::FunctionEnd(address),
                        &format!("{end:X}"),
                        "",
                        window,
                        cx,
                    );
                }
                return true;
            }
            _ => return false,
        };
        // Never a silent no-op: why it does not apply is said.
        let done = self
            .correction_address()
            .ok_or_else(|| "no address at the cursor".to_owned())
            .and_then(|address| self.correct(op, address));
        if let Err(error) = done {
            self.error = Some(error);
        }
        true
    }

    /// Makes the correction `op` at `address`: the session takes it and
    /// analyses the binary again.
    ///
    /// # Errors
    ///
    /// It cannot apply there (why).
    pub fn correct(&mut self, op: Op, address: u64) -> Result<(), String> {
        let after = self
            .at(address, |at, corrections| plan(op, at, corrections))
            .ok_or("the listing is not built yet")?
            .map_err(str::to_owned)?;
        let session = self.session.as_mut().ok_or("no binary is open")?;
        if session.corrections() == after {
            return Err("nothing to change there".to_owned());
        }
        session.correct(after)?;
        self.clocks.corrected = Some(Instant::now());
        // An edit pins a preview tab.
        let id = self.layout.focused();
        self.pin_active(id);
        Ok(())
    }
}

/// The count `*`'s prompt holds: a positive decimal number.
///
/// # Errors
///
/// It is not one.
pub fn array_count_typed(text: &str) -> Result<u64, String> {
    text.trim()
        .parse::<u64>()
        .ok()
        .filter(|&count| count > 0)
        .ok_or_else(|| format!("not a count: {text:?}"))
}

/// The address Edit Function's prompt holds: hexadecimal, as the listing
/// writes it (`0x` or a trailing `h` allowed).
///
/// # Errors
///
/// It is not one.
pub fn address_typed(text: &str) -> Result<u64, String> {
    let digits = text.trim();
    let digits = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
        .unwrap_or(digits);
    let digits = digits.strip_suffix(['h', 'H']).unwrap_or(digits);
    u64::from_str_radix(digits, 16).map_err(|_| format!("not an address: {text:?}"))
}
