# rustle_lints

### What it does

Warns when an async function is large enough to become an implicit protocol
state machine.

### Why is this bad?

Rustle's highest-risk production code lives in tunnel loops, helper bootstrap,
remote stream pumps, and scheduler paths. Large async functions in those areas
hide too many responsibilities behind one future: protocol decisions, buffer
accounting, I/O, timeout policy, tracing, and cleanup. That makes failure
behavior harder to audit and makes mutation tests less meaningful.

### Known problems

This is a heuristic audit lint. Long integration-test helpers may trip it.
Warnings should be reviewed by humans before forcing a split.

### Example

```rust
async fn tunnel_loop() {
    // many protocol branches, queue updates, I/O calls, and cleanup cases
}
```

Use instead:

```rust
async fn tunnel_loop() {
    while let Some(event) = next_event().await {
        handle_event(event).await;
    }
}

async fn handle_event(event: Event) {
    // named transition/action
}
```
