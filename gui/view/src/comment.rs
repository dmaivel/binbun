//! The comment field: `;` types a comment in place at
//! the end of the cursor's line, in the listing at the comment column
//! after the operands (`; text`), in the C after the statement
//! (`// text`). A comment is at an instruction's address (an item's, in
//! the listing): the listing's line's, the C line's
//! ([`CDocument::comment_address`]). Enter commits, Escape cancels,
//! Shift+Enter breaks the line; an empty comment removes it.

use std::collections::BTreeMap;

use crate::cdoc::CDocument;

/// A comment being typed in place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommentField {
    /// The address the comment is at.
    pub address: u64,
    /// The comment before the edit (empty if none).
    pub original: String,
    /// The text so far, its lines apart by `\n`.
    pub text: String,
}

impl CommentField {
    /// A field over the comment at `address` among `comments` (the
    /// user's, by address), its text the comment's.
    pub fn open(address: u64, comments: &BTreeMap<u64, String>) -> Self {
        let original = comments.get(&address).cloned().unwrap_or_default();
        Self {
            address,
            text: original.clone(),
            original,
        }
    }

    /// A field over the comment typed on line `n` of `doc`, at the address
    /// [`CDocument::comment_address`] says; `None` on a line made from no
    /// instruction.
    pub fn in_c(doc: &CDocument, n: usize, comments: &BTreeMap<u64, String>) -> Option<Self> {
        Some(Self::open(doc.comment_address(n)?, comments))
    }

    /// The lines the field takes as typed (one at the least).
    pub fn lines(&self) -> usize {
        self.text.split('\n').count()
    }

    /// What committing does: `None` if the comment would not change, else
    /// the comment to set (`Some(None)`: none, the text being empty).
    /// Each line loses its trailing blanks and the trailing empty lines
    /// go.
    pub fn commit(&self) -> Option<Option<String>> {
        let text = normalized(&self.text);
        (text.as_deref().unwrap_or("") != self.original).then_some(text)
    }
}

/// `text` as a comment: each line without its trailing blanks (and a
/// carriage return), the empty lines at its end dropped; `None` if
/// nothing is left.
pub fn normalized(text: &str) -> Option<String> {
    let lines: Vec<&str> = text.split('\n').map(str::trim_end).collect();
    let used = lines.iter().rposition(|line| !line.is_empty())? + 1;
    Some(lines.get(..used)?.join("\n"))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use binbun::cfg::FunctionId;
    use binbun_ast::ir::{Function as Ast, Node, StmtId};
    use binbun_ast::types::Types;
    use binbun_print::document::TokenKind;
    use binbun_semantics::core::Id as _;
    use binbun_session::View;
    use binbun_ssa::ir::Function as L1;

    use super::{CommentField, normalized};
    use crate::cdoc::{CDocument, CSpan};

    #[test]
    fn a_field_opens_on_the_comment_and_commits_only_a_change() {
        let comments = BTreeMap::from([(0x10, "loop head".to_owned())]);
        let mut field = CommentField::open(0x10, &comments);
        assert_eq!((field.text.as_str(), field.lines()), ("loop head", 1));
        // Unchanged, or changed only by trailing blanks: nothing to do.
        assert_eq!(field.commit(), None);
        field.text = "loop head  \n\n".to_owned();
        assert_eq!(field.commit(), None);
        // Shift+Enter: a second line.
        field.text = "loop head\ncounts down".to_owned();
        assert_eq!(field.lines(), 2);
        assert_eq!(
            field.commit(),
            Some(Some("loop head\ncounts down".to_owned()))
        );
        // Emptied (blanks only): the comment goes.
        field.text = " \n ".to_owned();
        assert_eq!(field.commit(), Some(None));
        // No comment there yet: empty, and empty commits nothing.
        let fresh = CommentField::open(0x20, &comments);
        assert_eq!((fresh.original.as_str(), fresh.commit()), ("", None));
    }

    #[test]
    fn normalized_drops_trailing_blanks_and_empty_lines_only() {
        assert_eq!(normalized(""), None);
        assert_eq!(normalized("\n  \n"), None);
        assert_eq!(normalized("  a  "), Some("  a".to_owned()));
        assert_eq!(normalized("a\r\n\nb\n\n"), Some("a\n\nb".to_owned()));
    }

    /// A line's tokens: their kinds, and the address of each user's
    /// comment among them.
    type Tokens = &'static [(TokenKind, Option<u64>)];

    /// `if (x)` (made from 0x10 and 0x30) with comments at 0x10 (two
    /// lines) and 0x20, `y = 1;` (0x30, its first line elsewhere, and
    /// 0x40), `return;` (none), as the session prints and the view shows
    /// them.
    fn commented() -> CDocument {
        let lines: [(&str, Tokens); 6] = [
            (
                "if (x) // one",
                &[(TokenKind::Keyword, None), (TokenKind::Comment, Some(0x10))],
            ),
            ("       // two", &[(TokenKind::Comment, Some(0x10))]),
            ("       // three", &[(TokenKind::Comment, Some(0x20))]),
            ("    y = 1;", &[(TokenKind::Keyword, None)]),
            (
                "return; /* own */",
                &[(TokenKind::Keyword, None), (TokenKind::Comment, None)],
            ),
            ("}", &[(TokenKind::Punctuation, None)]),
        ];
        let text = lines.iter().map(|(t, _)| *t).collect::<Vec<_>>().join("\n");
        let mut spans = Vec::new();
        let mut comments = BTreeMap::new();
        let mut at = 0;
        for (k, (line, tokens)) in lines.iter().enumerate() {
            // A statement over the code, a comment over each `//`.
            let code = line
                .find(" //")
                .or_else(|| line.find(" /*"))
                .unwrap_or(line.len());
            let indent = line.len() - line.trim_start().len();
            for &(kind, address) in *tokens {
                let range = if kind == TokenKind::Comment {
                    let from = line.find("//").or_else(|| line.find("/*")).unwrap();
                    at + from..at + line.len()
                } else {
                    at + indent..at + code
                };
                if let Some(address) = address {
                    comments.insert(spans.len(), address);
                }
                let node = (kind != TokenKind::Comment)
                    .then(|| Node::Stmt(StmtId(u32::try_from(k).unwrap())));
                spans.push(CSpan {
                    range,
                    kind,
                    node,
                    automatic: false,
                    cast: false,
                });
            }
            at += line.len() + 1;
        }
        let l2 = Ast::new(0, Types::new(64));
        let mut doc = CDocument::from_parts(
            FunctionId::from_raw(0),
            0,
            View::Exact,
            text,
            spans,
            BTreeMap::new(),
            &l2,
            &L1::default(),
        );
        doc.comments = comments;
        doc.lines[0].addresses = vec![0x10, 0x30];
        doc.lines[3].addresses = vec![0x30, 0x40];
        doc
    }

    #[test]
    fn a_c_lines_comment_is_its_first_shown_else_its_first_own_instructions() {
        let doc = commented();
        let comments = BTreeMap::from([(0x10, "one\ntwo".to_owned()), (0x20, "three".to_owned())]);
        // A line showing two comments edits the first one's, from any of
        // its lines.
        for n in 0..3 {
            assert_eq!(doc.comment_owner(n), 0);
            assert_eq!(doc.comment_lines(n), 0..3);
            let field = CommentField::in_c(&doc, n, &comments).unwrap();
            assert_eq!((field.address, field.text.as_str()), (0x10, "one\ntwo"));
        }
        // Code before the comments.
        assert_eq!(&doc.line_text(0)[..doc.code_end(0)], "if (x)");
        assert_eq!(doc.code_end(3), doc.line_text(3).len());
        // A line without a comment: its lowest instruction it is the
        // first line of (0x30's first line is the `if`'s).
        let field = CommentField::in_c(&doc, 3, &comments).unwrap();
        assert_eq!((field.address, field.text.as_str()), (0x40, ""));
        assert_eq!(doc.comment_lines(3), 3..4);
        // The printer's own comment is no user's; a line of no
        // instruction takes none.
        assert_eq!(doc.comment_lines(4), 4..5);
        assert_eq!(doc.code_end(4), doc.line_text(4).len());
        assert_eq!(CommentField::in_c(&doc, 4, &comments), None);
        assert_eq!(CommentField::in_c(&doc, 5, &comments), None);
    }
}
