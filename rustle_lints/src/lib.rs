#![feature(rustc_private)]

extern crate rustc_hir;
extern crate rustc_lint;
extern crate rustc_session;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint;
use clippy_utils::source::SpanRangeExt;
use rustc_hir::intravisit::FnKind;
use rustc_hir::{self as hir, Body, Expr, FnDecl, Stmt};
use rustc_lint::{LateContext, LateLintPass, LintStore};
use rustc_span::Span;
use rustc_span::def_id::LocalDefId;

const ASYNC_FN_LINE_THRESHOLD: u64 = 120;

dylint_linting::dylint_library!();

rustc_session::declare_lint! {
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

rustc_session::declare_lint! {
    /// ### What it does
    ///
    /// Warns on direct `.unwrap()` and `.expect(...)` calls.
    ///
    /// ### Why is this bad?
    ///
    /// Tunnel runtime paths should return or handle recoverable failures instead
    /// of turning them into production panics.
    ///
    /// ### Known problems
    ///
    /// This is name-based and may flag non-standard methods named `unwrap` or
    /// `expect`.
    pub PRODUCTION_PANIC_METHOD,
    Warn,
    "unwrap/expect can panic in production tunnel paths"
}

rustc_session::declare_lint! {
    /// ### What it does
    ///
    /// Warns on `let _ = ...?;`.
    ///
    /// ### Why is this bad?
    ///
    /// The `?` already preserves the failure path, so binding the successful
    /// value to `_` only obscures intent. Prefer calling the expression directly
    /// or assigning a named value that documents why the success payload matters.
    ///
    /// ### Known problems
    ///
    /// This is source-text based, so it intentionally avoids generated code and
    /// only catches the simple source-written discard pattern.
    pub QUESTION_MARK_DISCARD,
    Warn,
    "discarding a question-mark expression with `let _ =` obscures success-path intent"
}

struct RustleLints;

rustc_session::impl_lint_pass!(
    RustleLints => [
        OVERSIZED_ASYNC_STATE_MACHINE,
        PRODUCTION_PANIC_METHOD,
        QUESTION_MARK_DISCARD
    ]
);

#[unsafe(no_mangle)]
pub fn register_lints(sess: &rustc_session::Session, lint_store: &mut LintStore) {
    dylint_linting::init_config(sess);
    lint_store.register_lints(&[
        OVERSIZED_ASYNC_STATE_MACHINE,
        PRODUCTION_PANIC_METHOD,
        QUESTION_MARK_DISCARD,
    ]);
    lint_store.register_late_pass(|_| Box::new(RustleLints));
}

impl<'tcx> LateLintPass<'tcx> for RustleLints {
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

    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        if expr.span.from_expansion() {
            return;
        }

        let hir::ExprKind::MethodCall(segment, _receiver, _args, _span) = expr.kind else {
            return;
        };
        if segment.ident.span.from_expansion() {
            return;
        }

        let method_name = segment.ident.name.as_str();
        if !is_panic_method(&method_name) {
            return;
        }
        if !is_source_written_method_call(cx, expr, method_name) {
            return;
        }

        let call = if method_name == "expect" {
            ".expect(...)"
        } else {
            ".unwrap()"
        };

        span_lint(
            cx,
            PRODUCTION_PANIC_METHOD,
            segment.ident.span,
            format!("production code should not call `{call}`; return or handle the failure"),
        );
    }

    fn check_stmt(&mut self, cx: &LateContext<'tcx>, stmt: &'tcx Stmt<'tcx>) {
        if stmt.span.from_expansion() || !is_question_mark_discard(cx, stmt) {
            return;
        }

        span_lint(
            cx,
            QUESTION_MARK_DISCARD,
            stmt.span,
            "do not discard a question-mark expression with `let _ =`; call it directly or name the value",
        );
    }
}

fn is_panic_method(method_name: &str) -> bool {
    matches!(method_name, "unwrap" | "expect")
}

fn is_source_written_method_call(cx: &LateContext<'_>, expr: &Expr<'_>, method_name: &str) -> bool {
    let needle = format!(".{method_name}");
    expr.span.check_source_text(cx, |src| src.contains(&needle))
}

fn is_question_mark_discard(cx: &LateContext<'_>, stmt: &Stmt<'_>) -> bool {
    stmt.span.check_source_text(cx, |src| {
        let normalized = src.split_whitespace().collect::<String>();
        normalized.starts_with("let_=") && normalized.ends_with("?;")
    })
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
    assert_eq!(
        source_body_without_outer_braces("{\n    let x = 1;\n}"),
        "\n    let x = 1;\n"
    );
}

#[test]
fn recognizes_code_lines() {
    assert!(!source_line_has_code(""));
    assert!(!source_line_has_code("   // comment"));
    assert!(source_line_has_code("let x = 1;"));
}

#[test]
fn recognizes_panic_methods() {
    assert!(is_panic_method("unwrap"));
    assert!(is_panic_method("expect"));
    assert!(!is_panic_method("unwrap_or"));
}

#[test]
fn recognizes_question_mark_discards_from_source_text() {
    fn check(src: &str) -> bool {
        let normalized = src.split_whitespace().collect::<String>();
        normalized.starts_with("let_=") && normalized.ends_with("?;")
    }

    assert!(check("let _ = expand_target_routes(&args.targets)?;"));
    assert!(check("let _ =\n    write_packets().await?;"));
    assert!(!check("expand_target_routes(&args.targets)?;"));
    assert!(!check("let _ = sender.send(value);"));
}

#[test]
fn ui() {
    dylint_testing::ui_test(env!("CARGO_PKG_NAME"), "ui");
}
