//! A laid out function graph as SVG, in One Dark: blocks with their text,
//! edges coloured by kind with arrowheads, a terminal mark under each
//! block no edge leaves (a headless view of what the GUI draws).

use std::fmt::Write as _;

use crate::graph::cfg::{EdgeKind, Exit, FunctionGraph, Target};
use crate::graph::layout::{Layout, Size};

/// Text metrics for the blocks.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Metrics {
    /// A character's advance.
    pub char_width: f32,
    /// A line's height.
    pub line_height: f32,
    /// Space between a block's border and its text.
    pub padding: f32,
    /// The room under a block for its terminal mark.
    pub mark: f32,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            char_width: 7.8,
            line_height: 17.0,
            padding: 6.0,
            mark: 18.0,
        }
    }
}

impl Metrics {
    /// The size of a block of `chars` columns, `lines` lines, ending as
    /// `exit` (its mark's room included).
    pub fn size(&self, chars: usize, lines: usize, exit: Exit) -> Size {
        let n = |n: usize| f32::from(u16::try_from(n).unwrap_or(u16::MAX));
        let mark = if exit == Exit::Edges { 0.0 } else { self.mark };
        Size {
            width: n(chars) * self.char_width + 2.0 * self.padding,
            height: n(lines.max(1)) * self.line_height + 2.0 * self.padding + mark,
        }
    }
}

const BACKGROUND: &str = "#282c34";
const SURFACE: &str = "#2f343e";
const BORDER: &str = "#464b57";
const TEXT: &str = "#dce0e5";
const MUTED: &str = "#878a98";
const TAKEN: &str = "#a1c181";
const NOT_TAKEN: &str = "#d07277";
const PLAIN: &str = "#878a98";
const UNWIND: &str = "#c0966b";

fn colour(kind: EdgeKind) -> &'static str {
    match kind {
        EdgeKind::Taken => TAKEN,
        EdgeKind::NotTaken => NOT_TAKEN,
        EdgeKind::Jump | EdgeKind::Next | EdgeKind::Case => PLAIN,
        EdgeKind::Unwind => UNWIND,
    }
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// `graph` laid out as `layout`, each block with the lines of `text`
/// (none drawn if `text` is shorter), a tail call's mark with the name
/// `name` gives its target, as an SVG document.
pub fn render(
    graph: &FunctionGraph,
    layout: &Layout,
    text: &[Vec<String>],
    metrics: &Metrics,
    name: &dyn Fn(Target) -> String,
) -> String {
    let margin = 16.0;
    let mut out = String::new();
    let _ = writeln!(
        out,
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="{v} {v} {w} {h}" font-family="monospace" font-size="13">"#,
        w = layout.width + 2.0 * margin,
        h = layout.height + 2.0 * margin,
        v = -margin,
    );
    let _ = writeln!(out, "<defs>");
    for c in [TAKEN, NOT_TAKEN, PLAIN, UNWIND] {
        let _ = writeln!(
            out,
            r#"<marker id="a{id}" viewBox="0 0 8 8" refX="8" refY="4" markerWidth="8" markerHeight="8" orient="auto" markerUnits="userSpaceOnUse"><path d="M0,0 L8,4 L0,8 z" fill="{c}"/></marker>"#,
            id = c.trim_start_matches('#'),
        );
    }
    let _ = writeln!(out, "</defs>");
    let _ = writeln!(
        out,
        r#"<rect x="{v}" y="{v}" width="100%" height="100%" fill="{BACKGROUND}"/>"#,
        v = -margin
    );
    for (i, rect) in layout.nodes.iter().enumerate() {
        let exit = graph.blocks.get(i).map_or(Exit::Edges, |b| b.exit);
        let mark = if exit == Exit::Edges {
            0.0
        } else {
            metrics.mark
        };
        let height = rect.height - mark;
        let _ = writeln!(
            out,
            r#"<rect x="{}" y="{}" width="{}" height="{height}" fill="{SURFACE}" stroke="{BORDER}" stroke-width="1"/>"#,
            rect.x, rect.y, rect.width
        );
        for (k, line) in text.get(i).into_iter().flatten().enumerate() {
            let y = rect.y
                + metrics.padding
                + metrics.line_height * f32::from(u16::try_from(k + 1).unwrap_or(u16::MAX))
                - 4.0;
            let _ = writeln!(
                out,
                r#"<text x="{}" y="{y}" fill="{TEXT}" xml:space="preserve">{}</text>"#,
                rect.x + metrics.padding,
                escape(line)
            );
        }
        if exit != Exit::Edges {
            terminal(
                &mut out,
                exit,
                rect.x + rect.width / 2.0,
                rect.y + height,
                name,
            );
        }
    }
    for (edge, route) in graph.edges.iter().zip(&layout.edges) {
        let c = colour(edge.kind);
        let points: Vec<String> = route
            .points
            .iter()
            .map(|p| format!("{},{}", p.x, p.y))
            .collect();
        let _ = writeln!(
            out,
            r#"<polyline points="{}" fill="none" stroke="{c}" stroke-width="1.5" marker-end="url(#a{})"/>"#,
            points.join(" "),
            c.trim_start_matches('#')
        );
    }
    let _ = writeln!(out, "</svg>");
    out
}

/// The terminal mark of a block ending as `exit`, under its bottom's
/// middle `(x, y)`: a stub, capped for an end, dashed with `?` for an
/// unknown target, with an arrowhead and the target's name for a tail
/// call; a word for what is not a return.
fn terminal(out: &mut String, exit: Exit, x: f32, y: f32, name: &dyn Fn(Target) -> String) {
    let stub = 8.0;
    let dash = if exit == Exit::Unknown {
        r#" stroke-dasharray="2,2""#
    } else {
        ""
    };
    let _ = writeln!(
        out,
        r#"<line x1="{x}" y1="{y}" x2="{x}" y2="{}" stroke="{MUTED}" stroke-width="1.5"{dash}/>"#,
        y + stub
    );
    let label = |out: &mut String, text: &str| {
        let _ = writeln!(
            out,
            r#"<text x="{}" y="{}" fill="{MUTED}" font-size="11">{}</text>"#,
            x + 8.0,
            y + stub + 3.0,
            escape(text)
        );
    };
    let cap = |out: &mut String| {
        let _ = writeln!(
            out,
            r#"<line x1="{}" y1="{}" x2="{}" y2="{}" stroke="{MUTED}" stroke-width="1.5"/>"#,
            x - 5.0,
            y + stub,
            x + 5.0,
            y + stub
        );
    };
    match exit {
        Exit::Edges => {}
        Exit::Return => cap(out),
        Exit::NoReturn(_) => {
            cap(out);
            label(out, "noreturn");
        }
        Exit::Stop => {
            cap(out);
            label(out, "stop");
        }
        Exit::Unknown => label(out, "?"),
        Exit::Tail(target) => {
            let _ = writeln!(
                out,
                r#"<path d="M{},{} L{},{} L{x},{} z" fill="{MUTED}"/>"#,
                x - 3.5,
                y + stub - 1.0,
                x + 3.5,
                y + stub - 1.0,
                y + stub + 4.0
            );
            label(out, &name(target));
        }
    }
}
