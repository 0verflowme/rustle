#![feature(rustc_private)]

extern crate rustc_hir;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint;
use clippy_utils::source::SpanRangeExt;
use rustc_hir::intravisit::FnKind;
use rustc_hir::{self as hir, Body, FnDecl};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::def_id::LocalDefId;
use rustc_span::Span;

const ASYNC_FN_LINE_THRESHOLD: u64 = 120;

dylint_linting::declare_late_lint! {
    /// ### What it does
    ///
    /// Warns when an async function body is large enough to become an implicit
    /// state-machine module.
    ///
    /// ### Why is this bad?
    ///
    /// Rust async functions compile into state machines. Large async functions
    /// tend to mix protocol decisions, queue accounting, I/O, tracing, and
    /// cleanup in one body. That makes tunnel behavior hard to audit and weakens
    /// mutation tests because many branches share one setup path.
    ///
    /// ### Known problems
    ///
    /// This is intentionally heuristic. Long integration tests can trip it; the
    /// intended response is to extract named state transitions or helper actions,
    /// not to mechanically split code at arbitrary line numbers.
    pub OVERSIZED_ASYNC_STATE_MACHINE,
    Warn,
    "large async function should be split into explicit state transitions or I/O actions"
}

impl<'tcx> LateLintPass<'tcx> for OversizedAsyncStateMachine {
    fn check_fn(
        &mut self,
        cx: &LateContext<'tcx>,
        kind: FnKind<'tcx>,
        _decl: &'tcx FnDecl<'tcx>,
        body: &'tcx Body<'tcx>,
        _span: Span,
        def_id: LocalDefId,
    ) {
        if !matches!(kind.asyncness(), hir::IsAsync::Async(_)) {
            return;
        }

        let mut line_count = 0_u64;
        let too_large = body.value.span.check_source_text(cx, |src| {
            for line in source_body_without_outer_braces(src).lines() {
                if source_line_has_code(line) {
                    line_count = line_count.saturating_add(1);
                }
            }
            line_count > ASYNC_FN_LINE_THRESHOLD
        });

        if too_large {
            span_lint(
                cx,
                OVERSIZED_ASYNC_STATE_MACHINE,
                cx.tcx.def_span(def_id),
                format!(
                    "async function has {line_count} code lines; split state transitions and I/O actions below {ASYNC_FN_LINE_THRESHOLD}"
                ),
            );
        }
    }
}

fn source_body_without_outer_braces(src: &str) -> &str {
    let trimmed = src.trim();
    if trimmed.as_bytes().first().copied() == Some(b'{')
        && trimmed.as_bytes().last().copied() == Some(b'}')
    {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    }
}

fn source_line_has_code(line: &str) -> bool {
    let line = line.trim();
    !line.is_empty() && !line.starts_with("//")
}

#[test]
fn strips_outer_body_braces() {
    assert_eq!(source_body_without_outer_braces("{\n    let x = 1;\n}"), "\n    let x = 1;\n");
}

#[test]
fn recognizes_code_lines() {
    assert!(!source_line_has_code(""));
    assert!(!source_line_has_code("   // comment"));
    assert!(source_line_has_code("let x = 1;"));
}
