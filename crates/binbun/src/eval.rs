//! How well recovery found an image's functions against what the file
//! states, the sanity of the graph it built ([`evaluate`]), and how much
//! of the recovered code lifts ([`lifting`]).

use std::collections::BTreeSet;

use binbun_loader::{Image, SymbolKind};

use crate::cfg::{Destination, Exit, FunctionId, Program};
use crate::lift::{ImageEnvironment, Kind, decode_and_lift, lift_function};
use crate::summary::Summaries;

/// How well recovery found an image's functions, and the sanity of what it
/// built.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Evaluation {
    /// Function starts the file states (function symbols and unwind entries
    /// in code).
    pub truth: usize,
    /// Functions recovered, and the parts joined into them
    /// ([`Function::parts`](crate::cfg::Function::parts)).
    pub found: usize,
    /// Recovered functions whose start the file states.
    pub correct: usize,
    /// Blocks and decoded instructions.
    pub blocks: usize,
    /// Instructions decoded into blocks.
    pub instructions: u64,
    /// Bytes of code covered by functions' blocks.
    pub covered: u64,
    /// Bytes of code ([`Image::code`]).
    pub code: u64,
    /// Overlapping instructions recorded.
    pub conflicts: usize,
    /// Jumps and calls with unresolved destinations.
    pub unresolved_jumps: usize,
    /// Unresolved calls.
    pub unresolved_calls: usize,
    /// Computed jumps resolved to tables.
    pub tables: usize,
    /// Of those, the tables whose end was inferred.
    pub inferred_tables: usize,
    /// Functions found not to return.
    pub non_returning: usize,
    /// Import thunks: functions whose only block jumps to an import (PLT
    /// stubs, PE import thunks). They count among those found.
    pub thunks: usize,
    /// Blocks that overlap another block without a recorded conflict
    /// (should be 0).
    pub unexplained_overlaps: usize,
    /// Direct jump targets in code with no block starting there (should be
    /// 0).
    pub missing_targets: usize,
}

impl Evaluation {
    /// The share of stated function starts that were found.
    pub fn recall(&self) -> f64 {
        ratio(self.correct, self.truth)
    }

    /// The share of found functions whose start the file states.
    pub fn precision(&self) -> f64 {
        ratio(self.correct, self.found)
    }
}

fn ratio(part: usize, whole: usize) -> f64 {
    if whole == 0 {
        1.0
    } else {
        // Counts are far below 2^52.
        #[expect(clippy::cast_precision_loss, reason = "counts are far below 2^52")]
        let (part, whole) = (part as f64, whole as f64);
        part / whole
    }
}

/// The starts of the functions of `program`, and of the parts joined into
/// them (a cold part with its own unwind entry is found, as a part).
fn found_starts(program: &Program) -> BTreeSet<u64> {
    program
        .functions
        .values()
        .flat_map(|f| core::iter::once(f.entry).chain(f.parts.iter().copied()))
        .collect()
}

/// Compares `program` with what `image` states.
pub fn evaluate(image: &Image<'_>, program: &Program) -> Evaluation {
    let truth: BTreeSet<u64> = image
        .symbols
        .iter()
        .filter(|s| s.kind == SymbolKind::Function)
        .map(|s| s.address)
        .chain(image.unwind.iter().filter(|u| !u.fragment).map(|u| u.start))
        .filter(|&address| image.is_code(address))
        .collect();
    let found = found_starts(program);

    let mut evaluation = Evaluation {
        truth: truth.len(),
        found: found.len(),
        correct: truth.intersection(&found).count(),
        blocks: program.blocks.len(),
        conflicts: program.conflicts.len(),
        non_returning: program.functions.values().filter(|f| !f.returns).count(),
        thunks: program
            .functions
            .values()
            .filter(|f| match f.blocks.as_slice() {
                [only] => program
                    .blocks
                    .get(*only)
                    .is_some_and(|block| matches!(block.exit, Exit::Jump(Destination::Import(_)))),
                _ => false,
            })
            .count(),
        code: image.code.iter().map(|range| range.end - range.start).sum(),
        ..Evaluation::default()
    };
    for (id, block) in program.blocks.iter() {
        evaluation.instructions += u64::from(block.instructions);
        if let Some(table) = program.table(id) {
            evaluation.tables += 1;
            evaluation.inferred_tables += usize::from(table.inferred);
        }
        match block.exit {
            Exit::Call { callee, .. } if callee.is_unresolved() => evaluation.unresolved_calls += 1,
            Exit::Jump(destination) | Exit::Branch(destination)
                if destination.is_unresolved() && program.table(id).is_none() =>
            {
                evaluation.unresolved_jumps += 1;
            }
            Exit::Jump(Destination::Address(target))
            | Exit::Branch(Destination::Address(target))
                if image.is_code(target) && program.block_at(target).is_none() =>
            {
                evaluation.missing_targets += 1;
            }
            Exit::Jump(_)
            | Exit::Branch(_)
            | Exit::Call { .. }
            | Exit::Next
            | Exit::Return
            | Exit::Stop
            | Exit::Invalid
            | Exit::Limit => {}
        }
    }

    // Overlaps: consecutive blocks by address, unless a conflict explains
    // them.
    let conflicted: BTreeSet<u64> = program
        .conflicts
        .iter()
        .flat_map(|c| [c.instruction, c.block])
        .collect();
    let mut previous: Option<(u64, u64)> = None;
    for (_, id) in program.blocks_by_address() {
        let Some(block) = program.blocks.get(id) else {
            continue;
        };
        if let Some((start, end)) = previous
            && block.start < end
            && !conflicted.contains(&block.start)
            && !conflicted.contains(&start)
            && !conflicted_range(&conflicted, start, end)
        {
            evaluation.unexplained_overlaps += 1;
        }
        if previous.is_none_or(|(_, end)| block.end > end) {
            previous = Some((block.start, block.end));
        }
    }

    // Coverage: the union of the functions' blocks.
    let mut ranges: Vec<(u64, u64)> = program
        .functions
        .values()
        .flat_map(|f| f.blocks.iter())
        .filter_map(|&id| program.blocks.get(id))
        .map(|b| (b.start, b.end))
        .collect();
    ranges.sort_unstable();
    let mut reach = 0;
    for (start, end) in ranges {
        let start = start.max(reach);
        if end > start {
            evaluation.covered += end - start;
            reach = end;
        }
    }
    evaluation
}

/// Whether a conflict lies within `start..end`.
fn conflicted_range(conflicted: &BTreeSet<u64>, start: u64, end: u64) -> bool {
    conflicted.range(start..end).next().is_some()
}

/// How much of the recovered code lifts: its instructions to L0, its
/// functions to L1.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Lifting {
    /// Instructions decoded into blocks (each block once).
    pub instructions: u64,
    /// Of those, the instructions lifted with their semantics.
    pub semantics: u64,
    /// Of those, the instructions without semantics lifted as their
    /// over-approximation (`lift_opaque`).
    pub opaque: u64,
    /// Functions recovered.
    pub functions: usize,
    /// Of those, the functions tried in L1 (all of them, or a sample:
    /// [`lifting`]).
    pub tried: usize,
    /// Of those, the functions that build in L1.
    pub built: usize,
}

impl Lifting {
    /// The share of recovered instructions lifted with their semantics.
    pub fn lifted(&self) -> f64 {
        // Instruction counts are far below 2^52.
        #[expect(clippy::cast_precision_loss, reason = "counts are far below 2^52")]
        let (part, whole) = (self.semantics as f64, self.instructions.max(1) as f64);
        part / whole
    }

    /// The share of the functions tried that build in L1.
    pub fn l1(&self) -> f64 {
        ratio(self.built, self.tried)
    }
}

/// How much of `program` (recovered from `image`) lifts: every instruction
/// of its blocks to L0 (with its semantics, as its over-approximation, or
/// not), and at most `sample` of its functions to L1 ([`lift_function`],
/// without summaries): all of them if there are no more, else `sample`
/// spread evenly over the functions in address order (the same ones on
/// every run). `None` if the image's code is not lifted.
pub fn lifting(image: &Image<'_>, program: &Program, sample: usize) -> Option<Lifting> {
    ImageEnvironment::new(image, &[]).ok()?;
    let mut lifting = Lifting {
        functions: program.functions.len(),
        ..Lifting::default()
    };
    for (_, block) in program.blocks.iter() {
        lifting.instructions += u64::from(block.instructions);
        let mut address = block.start;
        for _ in 0..block.instructions {
            let Ok(lifted) = decode_and_lift(image, address) else {
                break;
            };
            match lifted.semantics {
                Ok((_, Kind::Semantics)) => lifting.semantics += 1,
                Ok((_, Kind::Opaque)) => lifting.opaque += 1,
                Err(_) => {}
            }
            address = lifted.next;
        }
    }
    let mut functions: Vec<(u64, FunctionId)> = program
        .functions
        .iter()
        .map(|(id, function)| (function.entry, id))
        .collect();
    functions.sort_unstable();
    let count = functions.len();
    let tried = count.min(sample);
    let summaries = Summaries::new();
    for k in 0..tried {
        let Some(&(_, id)) = functions.get(k * count / tried) else {
            continue;
        };
        lifting.tried += 1;
        lifting.built += usize::from(lift_function(image, program, id, &summaries).is_ok());
    }
    Some(lifting)
}
