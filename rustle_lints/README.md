# rustle_lints

Rustle-specific Dylint checks for production tunnel robustness.

## Lints

- `oversized_async_state_machine`: warns when an async function is large enough
  to hide protocol decisions, queue accounting, I/O, tracing, and cleanup inside
  one generated future.
- `production_panic_method`: warns on direct `.unwrap()` and `.expect(...)`
  calls. Runtime tunnel paths should return or handle recoverable failures
  instead of turning them into production panics.
- `question_mark_discard`: warns on `let _ = ...?;` because the failure path is
  already handled by `?`, and discarding the success value through `_` obscures
  intent.

Both lints are heuristic audit warnings. Review findings in context before
forcing mechanical rewrites.
