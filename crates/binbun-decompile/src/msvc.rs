//! Exception handling under Microsoft x64 (structured exception handling,
//! `__C_specific_handler`): what is particular to it, beside the
//! ABI-neutral `Try` of L2 ([`binbun_ast::ir::Stmt::Try`]) and the
//! Itanium module ([`crate::itanium`]), whose passes it shares.
//!
//! - **What an `__except` block receives**: the runtime unwinds to it (code
//!   of the function, with the function's frame) with the exception's
//!   code as the return value (`rax`), which lowering gives as the first
//!   value an L1 `Op::Landing` receives, the exception object
//!   ([`crate::itanium::exception_value`]). [`ExceptionCodes`]
//!   (`exception-codes`, after `catch-dispatch`) says it is the code
//!   ([`ExceptionValue::Code`], `GetExceptionCode()`) in a function whose
//!   handlers are all `__except`s.
//! - **What a `__finally` block receives**: its funclet, built into the
//!   function (`binbun::funclets`), is entered with `rcx` the first value
//!   its landing receives; [`ExceptionCodes`] says it is
//!   `AbnormalTermination()` ([`ExceptionValue::Abnormal`]) in a function
//!   whose handlers are all `__finally` blocks ([`HandlerKind::Finally`]).
//!   (Where both kinds are, which landing a value is of is not known
//!   here, and it stays the exception object.)
//! - **Handlers**: an `__except` block's landing pad has one action,
//!   [`HandlerKind::Except`] with its scope's filter (built by the caller
//!   from the scope tables, as the Itanium chains are), which catch
//!   dispatch makes the `Try`'s handler as it does a catch-all.
//! - **Funclets** (filters, `__finally` blocks, C++ catch blocks): separate
//!   functions in the binary that the runtime calls with the function's
//!   establisher frame (`rdx`: the stack pointer after the function's
//!   prologue, or its frame register's base), so `[rdx + k]` in a funclet
//!   is the function's frame at the same offset from that base. They are
//!   joined to their function in the control flow (`binbun::cfg`'s
//!   funclets), and all but filters are built into its L1
//!   (`binbun::funclets`): a `__finally` block's or an unwind funclet's
//!   landing pad is a cleanup's ([`HandlerKind::Finally`],
//!   [`HandlerKind::Cleanup`]) whose end resumes unwinding (a call to the
//!   function's exception handling data, which no code calls,
//!   [`crate::itanium::Exceptions::resume`]),
//!   a try block's catch blocks are the actions of a pad whose selector
//!   the runtime chooses (catch dispatch makes them the `Try`'s handlers
//!   as for a landing pad), and a catch block returns to its
//!   continuation. A filter funclet is named by address in its `__except`.

use binbun_ast::ir::{ExceptionValue, Expr, Function, HandlerKind, Stmt};
use binbun_semantics::core::pass::{Changed, Cx, Pass, Refusal};

use crate::pass::L2Env;

/// Exception codes (pass `exception-codes`, see the module documentation).
/// Runs after catch dispatch. Preserves nothing.
#[derive(Clone, Copy, Debug, Default)]
pub struct ExceptionCodes;

impl<'e> Pass<Function, L2Env<'e>> for ExceptionCodes {
    fn name(&self) -> &'static str {
        "exception-codes"
    }

    fn run(
        &mut self,
        function: &mut Function,
        _: &mut Cx<'_, Function, L2Env<'e>>,
    ) -> Result<Changed, Refusal> {
        let (mut excepts, mut finallies) = (false, false);
        for stmt in &function.stmts {
            if let Stmt::Try { handlers, .. } = stmt {
                for handler in handlers {
                    match handler.kind {
                        HandlerKind::Except(_) => excepts = true,
                        HandlerKind::Finally => finallies = true,
                        HandlerKind::Landing(_)
                        | HandlerKind::Catch(_)
                        | HandlerKind::CatchAll
                        | HandlerKind::Cleanup
                        | HandlerKind::Unexpected(_) => return Ok(Changed::No),
                    }
                }
            }
        }
        let to = match (excepts, finallies) {
            (true, false) => ExceptionValue::Code,
            (false, true) => ExceptionValue::Abnormal,
            (true, true) | (false, false) => return Ok(Changed::No),
        };
        let mut changed = false;
        for expr in &mut function.exprs {
            if let Expr::Exception { value, .. } = expr
                && *value == ExceptionValue::Object
            {
                *value = to;
                changed = true;
            }
        }
        Ok(changed.into())
    }
}
