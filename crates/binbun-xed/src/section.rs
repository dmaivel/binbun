//! Datafiles as a sequence of `NAME()::` sections.
//!
//! A line containing `::` starts a section (XED's `nonterminal_start_pattern`).
//! Its header is `NAME()` or `TYPE NAME()`, where `TYPE` names what a lookup
//! nonterminal returns (`xed_reg_enum_t rFLAGS()::`).

use crate::lines::{Line, lines};
use crate::{Error, ErrorKind};

/// A datafile split into logical lines.
///
/// Every structure parsed from it borrows from it; only lines joined from
/// continuations own their text.
#[derive(Debug, Clone)]
pub struct Datafile<'src> {
    lines: Vec<Line<'src>>,
}

impl<'src> Datafile<'src> {
    /// Splits `source` into logical lines.
    pub fn new(source: &'src str) -> Self {
        Self {
            lines: lines(source).collect(),
        }
    }

    /// The logical lines, in order.
    pub fn lines(&self) -> &[Line<'src>] {
        &self.lines
    }

    /// The sections, in order. Sections with the same name are not merged.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::OutsideSection`] if a line precedes the first header, and
    /// [`ErrorKind::MalformedHeader`] for a header that is not `[TYPE] NAME()::`.
    pub fn sections(&self) -> Result<Vec<Section<'_>>, Error> {
        let mut sections: Vec<Section<'_>> = Vec::new();
        let mut body_start = 0;
        for (index, line) in self.lines.iter().enumerate() {
            if !line.text().contains("::") {
                if sections.is_empty() {
                    return Err(Error::new(line.number, ErrorKind::OutsideSection));
                }
                continue;
            }
            if let Some(previous) = sections.last_mut() {
                previous.body = self.lines.get(body_start..index).unwrap_or_default();
            }
            sections.push(Section {
                header: Header::parse(line)?,
                body: &[],
            });
            body_start = index + 1;
        }
        if let Some(last) = sections.last_mut() {
            last.body = self.lines.get(body_start..).unwrap_or_default();
        }
        Ok(sections)
    }
}

/// One `[TYPE] NAME()::` section and the lines up to the next header.
#[derive(Debug, Clone, Copy)]
pub struct Section<'a> {
    /// The section header.
    pub header: Header<'a>,
    /// Lines after the header, up to the next header or the end of the file.
    pub body: &'a [Line<'a>],
}

/// A section header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header<'a> {
    /// Line number of the header.
    pub line: u32,
    /// Section name without the trailing `()`.
    pub name: &'a str,
    /// What a lookup nonterminal returns, e.g. `xed_reg_enum_t`.
    pub return_type: Option<&'a str>,
}

impl<'a> Header<'a> {
    fn parse(line: &'a Line<'_>) -> Result<Self, Error> {
        let malformed = || Error::new(line.number, ErrorKind::MalformedHeader);
        let (before, _after) = line.text().split_once("::").ok_or_else(malformed)?;
        let mut words = before.split_whitespace();
        let (return_type, name) = match (words.next(), words.next(), words.next()) {
            (Some(name), None, None) => (None, name),
            (Some(return_type), Some(name), None) => (Some(return_type), name),
            _ => return Err(malformed()),
        };
        let name = name
            .strip_suffix("()")
            .filter(|name| !name.is_empty())
            .ok_or_else(malformed)?;
        Ok(Self {
            line: line.number,
            name,
            return_type,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Datafile;
    use crate::ErrorKind;
    use crate::lines::Line;

    #[test]
    fn splits_sections_and_reads_return_types() {
        let file = Datafile::new("A()::\na 1\na 2\nxed_reg_enum_t B():: # note\nb\nC()::\n");
        let sections = file.sections().unwrap();
        let summary: Vec<_> = sections
            .iter()
            .map(|section| {
                let body: Vec<&str> = section.body.iter().map(Line::text).collect();
                (section.header.name, section.header.return_type, body)
            })
            .collect();
        assert_eq!(
            summary,
            [
                ("A", None, vec!["a 1", "a 2"]),
                ("B", Some("xed_reg_enum_t"), vec!["b"]),
                ("C", None, vec![]),
            ]
        );
    }

    #[test]
    fn rejects_content_before_the_first_header() {
        let error = Datafile::new("stray\nA()::\n").sections().unwrap_err();
        assert_eq!((error.line, error.kind), (1, ErrorKind::OutsideSection));
    }

    #[test]
    fn rejects_headers_without_parentheses_or_with_extra_words() {
        for header in ["A::", "a b C()::", "()::"] {
            let error = Datafile::new(header).sections().unwrap_err();
            assert_eq!(error.kind, ErrorKind::MalformedHeader, "{header}");
        }
    }
}
