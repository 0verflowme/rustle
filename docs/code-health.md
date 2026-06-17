# Code Health Framework

Rustle needs a way to keep useful code visible and make questionable code cheap
to challenge. Static reachability alone is not enough: a stale helper can still
be referenced by a stale lab, and one giant entrypoint can make unrelated code
look alive. The framework therefore combines graph evidence, verification
evidence, documentation evidence, and structural pressure.

Run the current analyzer with:

```sh
python3 scripts/code-health.py
```

`scripts/verify-local.sh` also runs the analyzer without
`--fail-on-review-score`; this catches analyzer crashes and keeps the report
fresh without making score changes fail the build. Ubuntu CI publishes
`target/code-health` as the `code-health-report` artifact for PR review.

It writes:

- `target/code-health/report.md` for the review heatmap.
- `target/code-health/heatmap.tsv` for sorting/filtering.
- `target/code-health/graph.json` for graph experiments and visualization.

## Model

The analyzer builds a directed graph with these node types:

- Rust items parsed from `src/**/*.rs` and `agent-bootstrap/src/**/*.rs`.
- Verification/lab scripts from `scripts/`.
- File summaries that aggregate item-level evidence.

Edges come from Rust calls/type mentions, module-qualified calls such as
`agent_runtime::run`, and script-to-script references. The configured roots in
`code-health.toml` define production entrypoints and verification script
entrypoints. Reachability from those roots is a strong positive signal, but not
the only one.

Each node receives evidence from:

- Production graph reachability.
- Test graph reachability and `#[test]`/`#[cfg(test)]` location.
- Documentation references in README and `docs/`.
- Script references from smoke, bench, and release gates.
- Domain intent from `code-health.toml`: core, platform, compatibility,
  experimental, lab, and release.
- Structural cost: file size, item size, item count, and unreachable LOC.

The output is a heatmap of review candidates. A high score means “explain,
test, document, split, or remove”; it does not mean automatic deletion.

## Why This Beats Raw Dead Code Checks

`cargo clippy` and the compiler catch many unreferenced private items, but they
cannot answer whether a referenced island still matters. Rustle has intentional
lanes that look suspicious without context:

- Platform-specific code can be inactive on the current host.
- Hidden lab commands are reachable only through verification scripts.
- `direct-tcpip` compatibility is not the preferred architecture but is still a
  benchmark and fallback reference point.
- QUIC paths are experimental and should have explicit proof/TTL rather than
  silently accumulating.

The graph view lets us ask better questions:

- Which code is reachable only from labs or tests?
- Which large nodes have weak production, test, or documentation evidence?
- Which files are doing too many unrelated jobs?
- Which experimental or compatibility lanes lack a current proof point?

## Graph Algorithms To Add Next

The first implementation includes reachability and PageRank. These are enough
to make review heat visible, but the useful next steps are:

- Strongly connected component condensation to find feature islands. A whole
  island with no production path is a stronger removal candidate than one
  unreferenced helper.
- Betweenness centrality to find choke points that should be stabilized before
  refactors.
- Community detection over the item graph to discover accidental subsystems
  inside `src/main.rs`.
- Similarity hashing over item bodies to find redundant implementations that
  are both referenced.
- Time decay using git history so old, low-evidence code gets hotter while
  freshly introduced code starts as “watch” rather than “delete.”

## Workflow

Use the heatmap in review:

1. Run `python3 scripts/code-health.py` or `scripts/verify-local.sh`.
2. Open `target/code-health/report.md`.
3. For each high-scoring node, choose one action:
   - Keep and add evidence: tests, docs, or a domain entry.
   - Move/split if it is useful but structurally expensive.
   - Remove if the graph island has no current purpose.
   - Add an expiry note when an experimental lane is intentionally temporary.
4. Review the non-blocking CI artifact on pull requests.
5. Later, gate only on score regressions or newly introduced high-score nodes.

Do not make the first CI version fail the build. A failing gate with noisy
heuristics teaches everyone to bypass it. Start by publishing the artifact, then
raise the bar once the report has been calibrated against real cleanup work.

## Current Rustle-Specific Signals

For this repo, the highest-value cleanup visibility is expected around:

- `src/main.rs`, because it owns CLI parsing, SSH connection setup, route
  management, agent startup, labs, DNS/TUN loop orchestration, and tests in one
  large file.
- Experimental QUIC paths, because they are intentionally not the public
  default and need clear proof points.
- Compatibility `direct-tcpip` paths, because they are useful for comparison but
  should not quietly become the architecture.
- Lab and benchmark scripts, because a script referenced by another stale script
  can look alive even if no verification root reaches it.

## Limits

The analyzer is intentionally conservative:

- It uses regex parsing, not `rustc`, so Rust macro expansion and dynamic trait
  dispatch are approximate.
- It does not know runtime traffic paths unless those paths are represented by
  tests, docs, scripts, or graph roots.
- It does not delete code or make deletion decisions.
- It should be calibrated by changing `code-health.toml`, not by suppressing
  findings inline unless the code already has a clear reason to be exempt.
