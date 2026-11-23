//! Logical lines, as XED's generator sees them (`genutil.process_continuations`).
//!
//! - Everything from `#` to the end of a physical line is a comment.
//! - Surrounding whitespace is trimmed and blank lines are skipped.
//! - A cleaned line ending in `\` loses the `\`, the next *raw* physical line
//!   is appended to it unchanged, and the result is cleaned again. So a comment
//!   on a continued line hides the rest of that line, and the next line's
//!   indentation is kept.

use std::borrow::Cow;

/// One logical line of a datafile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line<'src> {
    /// 1-based number of the first physical line.
    pub number: u32,
    /// Text without comments or surrounding whitespace. Borrowed unless it
    /// was assembled from continuation lines.
    pub text: Cow<'src, str>,
}

impl Line<'_> {
    /// The line's text.
    pub fn text(&self) -> &str {
        &self.text
    }
}

/// Iterator over the logical lines of `source`.
pub fn lines(source: &str) -> Lines<'_> {
    Lines {
        physical: source.lines().zip(1..),
    }
}

/// Iterator returned by [`lines`].
#[derive(Debug, Clone)]
pub struct Lines<'src> {
    physical: std::iter::Zip<std::str::Lines<'src>, std::ops::RangeFrom<u32>>,
}

impl<'src> Iterator for Lines<'src> {
    type Item = Line<'src>;

    fn next(&mut self) -> Option<Line<'src>> {
        loop {
            let (raw, number) = self.physical.next()?;
            let first = clean(raw);
            if first.is_empty() {
                continue;
            }
            let Some(head) = first.strip_suffix('\\') else {
                return Some(Line {
                    number,
                    text: Cow::Borrowed(first),
                });
            };
            // Continuations are rare (a few dozen lines per file); only they allocate.
            let mut text = head.to_owned();
            for (raw, _) in self.physical.by_ref() {
                text.push_str(raw);
                let (start, end) = clean_bounds(&text);
                let continued = text
                    .get(start..end)
                    .is_some_and(|code| code.ends_with('\\'));
                text.truncate(if continued { end - 1 } else { end });
                text.drain(..start);
                if !continued {
                    break;
                }
            }
            if text.is_empty() {
                continue;
            }
            return Some(Line {
                number,
                text: Cow::Owned(text),
            });
        }
    }
}

fn clean(raw: &str) -> &str {
    let (start, end) = clean_bounds(raw);
    raw.get(start..end).unwrap_or_default()
}

/// Byte range of `raw` without its comment and surrounding whitespace.
fn clean_bounds(raw: &str) -> (usize, usize) {
    let code = raw.split_once('#').map_or(raw, |(code, _comment)| code);
    let without_trailing = code.trim_end();
    let end = without_trailing.len();
    (end - without_trailing.trim_start().len(), end)
}

#[cfg(test)]
mod tests {
    use super::lines;

    fn texts(source: &str) -> Vec<(u32, String)> {
        lines(source)
            .map(|line| (line.number, line.text.into_owned()))
            .collect()
    }

    #[test]
    fn strips_comments_and_blank_lines() {
        let source = "# header\n\n  ICLASS : ADD   # trailing\n\t\nCPL : 3\n";
        assert_eq!(
            texts(source),
            [(3, "ICLASS : ADD".into()), (5, "CPL : 3".into())]
        );
    }

    #[test]
    fn joins_continuations_without_a_separator() {
        let source = "A: x \\\n   y \\ # comment\nz\nB";
        assert_eq!(texts(source), [(1, "A: x    y z".into()), (4, "B".into())]);
    }

    #[test]
    fn a_trailing_continuation_at_end_of_input_keeps_its_text() {
        assert_eq!(texts("A \\"), [(1, "A ".into())]);
    }

    #[test]
    fn a_continued_line_whose_next_line_is_blank_ends_there() {
        // XED cleans the next line too, so a blank or comment-only line adds nothing.
        assert_eq!(
            texts("A\\\n# only a comment\nB"),
            [(1, "A".into()), (3, "B".into())]
        );
    }
}
