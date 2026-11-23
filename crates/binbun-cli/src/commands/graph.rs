//! `binbun graph`: one function's control-flow graph laid out as the GUI
//! lays it out ([`binbun::graph`]), measured, and drawn as SVG.

use std::fmt::Write as _;
use std::time::Instant;

use binbun::analysis::Seeds;
use binbun::graph::layout::{Size, Spacing, layout};
use binbun::graph::svg::{Metrics, render};
use binbun::graph::{FunctionGraph, Target, block_line, measure};
use binbun::listing::{Listing, Options};

use super::{USAGE, database, load, read};

/// `graph FILE FUNCTION [--svg OUT]`: the function's blocks and edges, the
/// layout's time, size and faults (none expected), and with `--svg` the
/// drawing written to `OUT`.
pub fn graph(args: &[String]) -> Result<String, String> {
    let mut svg = None;
    let mut positional = Vec::new();
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--svg" => svg = Some(args.next().ok_or_else(|| USAGE.to_owned())?),
            _ if arg.starts_with("--") => return Err(USAGE.to_owned()),
            _ => positional.push(arg.as_str()),
        }
    }
    let [path, wanted] = positional[..] else {
        return Err(USAGE.to_owned());
    };
    let data = read(path)?;
    let image = load(path, &data)?;
    let db = database(path, &image, Seeds::ALL)?;
    let id = db.find_function(wanted)?;
    let listing = Listing::build(&db, &Options::default());
    let started = Instant::now();
    let graph =
        FunctionGraph::build(&db, &listing, id).ok_or_else(|| format!("no function {wanted}"))?;
    let built = started.elapsed();
    let text: Vec<Vec<String>> = graph
        .blocks
        .iter()
        .map(|b| {
            b.lines
                .iter()
                .map(|&n| block_line(listing.render(&db, n)).rendered.text())
                .collect()
        })
        .collect();
    let metrics = Metrics::default();
    let sizes: Vec<Size> = text
        .iter()
        .zip(&graph.blocks)
        .map(|(lines, block)| {
            let chars = lines.iter().map(|l| l.chars().count()).max().unwrap_or(0);
            metrics.size(chars, lines.len(), block.exit)
        })
        .collect();
    let edges = graph.layout_edges();
    let started = Instant::now();
    let laid = layout(&sizes, &edges, 0, &Spacing::default());
    let laid_out = started.elapsed();
    let quality = measure(&laid, &edges);
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{} blocks, {} edges ({} back); model {:.2} ms, layout {:.2} ms; {:.0} x {:.0}",
        graph.blocks.len(),
        graph.edges.len(),
        laid.edges.iter().filter(|r| r.back).count(),
        built.as_secs_f64() * 1e3,
        laid_out.as_secs_f64() * 1e3,
        laid.width,
        laid.height,
    );
    let _ = writeln!(
        out,
        "crossings {}, overlapping {}, touching {}, through nodes {}, along borders {}, shared ports {}, overlapping nodes {}, detached {}",
        quality.crossings,
        quality.overlapping,
        quality.touching,
        quality.through_nodes,
        quality.along_borders,
        quality.shared_ports,
        quality.overlapping_nodes,
        quality.detached,
    );
    if let Some(svg) = svg {
        let name = |target: Target| {
            let address = match target {
                Target::Address(a) | Target::Import(a) => a,
            };
            listing.describe(address)
        };
        std::fs::write(svg, render(&graph, &laid, &text, &metrics, &name))
            .map_err(|e| format!("{svg}: {e}"))?;
    }
    Ok(out)
}
