//! What colour each token draws in: a listing role's, a C token kind's and
//! a Python token kind's (the console's) theme colour; names binbun made
//! up (`v17`, `sub_401000`) at the theme's automatic-name opacity and casts
//! at its cast opacity, both full strength unless a theme fades them.
//! An editor coloured so asks [`runs`] for its style runs.

use std::ops::Range;

use binbun_gui_view::CTokenKind;
use binbun_gui_view::cdoc::CSpan;
use binbun_gui_view::console::python::Kind as PyKind;
use binbun_gui_view::listing::{Role, Token};
use gpui_kit::HighlightStyle;

use crate::theme::{Theme, hsla};

/// The colours of the listing's and the C's tokens.
pub trait Highlight {
    /// A listing role's colour: each on the theme's role nearest in
    /// meaning (code names a function's, data names a constant's, imports
    /// a keyword's, stack variables a parameter's); mnemonics by the
    /// instruction's flow (a jump's, a call's, a return's, padding's).
    fn role(&self, role: Role) -> u32;

    /// A listing token's colour: its role's ([`Self::role`]), at the
    /// automatic-name opacity for a name binbun made up.
    fn token(&self, token: &Token) -> u32;

    /// A C token kind's colour: keywords (of control flow apart), types
    /// (builtin apart), functions, locals, parameters, globals, fields,
    /// macros and literals each their own.
    fn c_kind(&self, kind: CTokenKind) -> u32;

    /// A C token's colour: its kind's ([`Self::c_kind`]), at the cast
    /// opacity in a cast and the automatic-name opacity for a name binbun
    /// made up (both where both).
    fn c(&self, span: &CSpan) -> u32;

    /// A Python token kind's colour, by the C kind nearest in meaning:
    /// keywords (of control flow apart), builtins as builtin types,
    /// classes as types, decorators as macros, `True`/`False`/`None` as
    /// keywords.
    fn python(&self, kind: PyKind) -> u32;
}

impl Highlight for Theme {
    fn role(&self, role: Role) -> u32 {
        match role {
            Role::Space => self.editor_foreground,
            Role::Prefix | Role::OpcodeBytes | Role::AutoComment => self.comment,
            Role::Mnemonic => self.mnemonic,
            Role::JumpMnemonic => self.mnemonic_jump,
            Role::CallMnemonic => self.mnemonic_call,
            Role::ReturnMnemonic => self.mnemonic_return,
            Role::PaddingMnemonic => self.mnemonic_nop,
            Role::Register => self.register,
            Role::Number => self.number,
            Role::Punctuation | Role::Keyword => self.punctuation,
            // Size words and segments dimmed.
            Role::OperandKeyword => self.comment_doc,
            Role::DataXref => self.data_xref,
            Role::Directive | Role::String => self.string,
            Role::CodeName => self.function,
            Role::DataName => self.constant,
            Role::ImportName => self.keyword,
            Role::LocalName => self.parameter,
            Role::Comment => self.hint,
            Role::CodeXref => self.code_xref,
        }
    }

    fn token(&self, token: &Token) -> u32 {
        let color = self.role(token.role);
        if token.automatic {
            faded(color, self.auto_name_alpha)
        } else {
            color
        }
    }

    fn c_kind(&self, kind: CTokenKind) -> u32 {
        match kind {
            CTokenKind::ControlKeyword => self.keyword_control,
            CTokenKind::Keyword => self.keyword,
            CTokenKind::Type => self.type_,
            CTokenKind::BuiltinType => self.type_builtin,
            CTokenKind::Function => self.function,
            CTokenKind::Local => self.variable,
            CTokenKind::Parameter => self.parameter,
            CTokenKind::Global => self.global,
            CTokenKind::Field => self.field,
            CTokenKind::Macro => self.macro_,
            CTokenKind::Number => self.number,
            CTokenKind::String => self.string,
            CTokenKind::Operator => self.operator,
            CTokenKind::Punctuation => self.punctuation,
            CTokenKind::Comment => self.comment,
            CTokenKind::Label => self.label,
        }
    }

    fn c(&self, span: &CSpan) -> u32 {
        let mut color = self.c_kind(span.kind);
        if span.cast {
            color = faded(color, self.cast_alpha);
        }
        if span.automatic {
            color = faded(color, self.auto_name_alpha);
        }
        color
    }

    fn python(&self, kind: PyKind) -> u32 {
        self.c_kind(match kind {
            PyKind::ControlKeyword => CTokenKind::ControlKeyword,
            PyKind::Keyword | PyKind::Constant => CTokenKind::Keyword,
            PyKind::Builtin => CTokenKind::BuiltinType,
            PyKind::Function => CTokenKind::Function,
            PyKind::Class => CTokenKind::Type,
            PyKind::Decorator => CTokenKind::Macro,
            PyKind::String => CTokenKind::String,
            PyKind::Number => CTokenKind::Number,
            PyKind::Comment => CTokenKind::Comment,
            PyKind::Operator => CTokenKind::Operator,
            PyKind::Punctuation => CTokenKind::Punctuation,
        })
    }
}

/// `c` (`0xRRGGBBAA`) with its alpha multiplied by `opacity` (0 to 1).
fn faded(c: u32, opacity: f32) -> u32 {
    let alpha = u8::try_from(c & 0xff).unwrap_or(u8::MAX);
    let alpha = (f32::from(alpha) * opacity.clamp(0.0, 1.0)).round();
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "clamped to 0..=255 above"
    )]
    let alpha = alpha as u8;
    (c & 0xffff_ff00) | u32::from(alpha)
}

/// The style runs covering `range` that an editor's highlighter gives:
/// each of `tokens` (ordered, apart, each with its colour) in its colour
/// where it meets `range`, the text between unstyled.
pub fn runs(
    tokens: impl IntoIterator<Item = (Range<usize>, u32)>,
    range: &Range<usize>,
) -> Vec<(Range<usize>, HighlightStyle)> {
    let mut out = Vec::new();
    let mut at = range.start;
    for (token, colour) in tokens {
        let start = token.start.max(at);
        let end = token.end.min(range.end);
        if start >= end {
            continue;
        }
        if at < start {
            out.push((at..start, HighlightStyle::default()));
        }
        out.push((
            start..end,
            HighlightStyle {
                color: Some(hsla(colour)),
                ..HighlightStyle::default()
            },
        ));
        at = end;
    }
    if at < range.end {
        out.push((at..range.end, HighlightStyle::default()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::faded;

    #[test]
    fn fading_scales_only_the_alpha() {
        assert_eq!(faded(0x1122_33ff, 0.5), 0x1122_3380);
        assert_eq!(faded(0x1122_3380, 0.5), 0x1122_3340);
        assert_eq!(faded(0x1122_33ff, 1.5), 0x1122_33ff);
        assert_eq!(faded(0x1122_33ff, 0.0), 0x1122_3300);
    }
}
