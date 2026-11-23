//! Loop tests simplification uncovers: [`LoopHeads`].

use binbun_ast::ir::Function;
use binbun_semantics::core::pass::{Changed, Cx, Pass, Refusal};

use super::refine::loop_head;
use crate::pass::{L2Env, size};

/// The pass `loop-heads`: `while (1) { if (c) break; … }` is `while (!c)
/// { … }`, as refinement makes it where the test begins the body at
/// structuring. Simplification may uncover one refinement could not see:
/// a copy before the test, coalesced away (`-O0` code reloading its
/// counter, `i = j; if (n <= i) break;`). The loop rules after it (`for`
/// formation, exit conditions) read a `while`'s condition, not a `break`.
///
/// Exact: the test left the loop at the start of each iteration, where
/// the condition is evaluated, and a `continue` goes there in both; the
/// loop's statement takes the `if`'s provenance, as refinement's does.
///
/// Preserves nothing. Fuel: a unit per statement and expression.
#[derive(Clone, Copy, Debug, Default)]
pub struct LoopHeads;

impl<'e> Pass<Function, L2Env<'e>> for LoopHeads {
    fn name(&self) -> &'static str {
        "loop-heads"
    }

    fn run(
        &mut self,
        function: &mut Function,
        cx: &mut Cx<'_, Function, L2Env<'e>>,
    ) -> Result<Changed, Refusal> {
        cx.fuel.spend(size(function))?;
        let mut work = function.body.clone();
        let mut changed = false;
        while let Some(id) = work.pop() {
            changed |= loop_head(function, id);
            if let Some(stmt) = function.stmt(id) {
                work.extend(stmt.blocks().flatten().copied());
            }
        }
        Ok(changed.into())
    }
}
