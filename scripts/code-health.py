#!/usr/bin/env python3
"""Static code-health heatmap for Rustle.

This is intentionally a heuristic analyzer. It produces review candidates and
structural hotspots; it does not decide that code is safe to delete.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import math
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11 fallback.
    tomllib = None


RUST_ITEM_RE = re.compile(
    r"^\s*(?P<vis>pub(?:\([^)]*\))?\s+)?"
    r"(?:(?P<async>async)\s+)?"
    r"(?P<kind>fn|struct|enum|trait|const|static|type)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)?"
)
IMPL_RE = re.compile(
    r"^\s*impl(?:\s*<[^>{}]+>)?\s+"
    r"(?:(?P<trait>[A-Za-z_][A-Za-z0-9_:<>]*)\s+for\s+)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)
ATTR_RE = re.compile(r"^\s*#\[(?P<attr>.+)\]\s*$")
MOD_TEST_RE = re.compile(r"^\s*mod\s+tests\s*\{")
MOD_RE = re.compile(r"^\s*(?:pub\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;")
CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:::<[^>]+>)?\s*\(")
PATH_CALL_RE = re.compile(
    r"(?=\b([A-Za-z_][A-Za-z0-9_]*)::([A-Za-z_][A-Za-z0-9_]*)\s*(?:::<[^>]+>)?\s*\()"
)
PATH_REF_RE = re.compile(
    r"(?=\b([A-Za-z_][A-Za-z0-9_]*)::([A-Za-z_][A-Za-z0-9_]*)\b)"
)
METHOD_CALL_RE = re.compile(r"\.([A-Za-z_][A-Za-z0-9_]*)\s*(?:::<[^>]+>)?\s*\(")
TOKEN_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
SCRIPT_REF_RE = re.compile(r"(?:scripts/)?([A-Za-z0-9_.-]+\.(?:sh|py|ps1))")

RUST_KEYWORDS = {
    "as",
    "async",
    "await",
    "break",
    "const",
    "continue",
    "crate",
    "dyn",
    "else",
    "enum",
    "false",
    "fn",
    "for",
    "if",
    "impl",
    "in",
    "let",
    "loop",
    "match",
    "mod",
    "move",
    "mut",
    "pub",
    "ref",
    "return",
    "self",
    "Self",
    "static",
    "struct",
    "super",
    "trait",
    "true",
    "type",
    "unsafe",
    "use",
    "where",
    "while",
}

METHOD_CALL_SKIP = {
    "as_ref",
    "as_mut",
    "borrow",
    "borrow_mut",
    "clone",
    "context",
    "default",
    "expect",
    "into",
    "is_empty",
    "is_err",
    "is_none",
    "is_ok",
    "is_some",
    "len",
    "lock",
    "map",
    "ok",
    "take",
    "to_owned",
    "unwrap",
    "with_context",
}


DEFAULT_CONFIG: dict[str, Any] = {
    "roots": {
        "production": ["src/main.rs::main", "agent-bootstrap/src/main.rs::main"],
        "verification_scripts": ["scripts/verify-local.sh", "scripts/verify-release-candidate.sh"],
        "documentation": [
            "README.md",
            "docs/architecture.md",
            "docs/code-health.md",
            "docs/performance.md",
            "docs/release.md",
            "docs/status.md",
            "docs/troubleshooting.md",
        ],
    },
    "thresholds": {
        "hot_file_loc": 1000,
        "hot_item_loc": 120,
        "large_file_loc": 2500,
        "large_item_loc": 300,
    },
    "domains": {},
}


@dataclass
class RustItem:
    id: str
    path: str
    name: str
    kind: str
    start_line: int
    end_line: int
    loc: int
    visibility: str
    attrs: list[str]
    in_test: bool
    owner: str | None = None
    trait_impl: str | None = None
    domain: str = "uncategorized"
    docs_refs: int = 0
    script_refs: int = 0
    inbound: int = 0
    outbound: int = 0
    pagerank: float = 0.0
    production_reachable: bool = False
    test_reachable: bool = False
    review_score: int = 0
    reasons: list[str] = field(default_factory=list)


@dataclass
class ScriptNode:
    id: str
    path: str
    name: str
    loc: int
    domain: str = "uncategorized"
    docs_refs: int = 0
    script_refs: int = 0
    inbound: int = 0
    outbound: int = 0
    pagerank: float = 0.0
    production_reachable: bool = False
    test_reachable: bool = False
    review_score: int = 0
    reasons: list[str] = field(default_factory=list)


@dataclass
class FileSummary:
    path: str
    loc: int
    item_count: int
    test_item_count: int
    domain: str
    docs_refs: int
    script_refs: int
    unreachable_item_count: int
    unreachable_loc: int
    max_item_loc: int
    review_score: int
    structure_score: int
    last_touched_days: int | None
    commit_count: int
    reasons: list[str]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a static code-health graph and heatmap for Rustle."
    )
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--config", type=Path, default=None)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--top", type=int, default=40)
    parser.add_argument(
        "--fail-on-review-score",
        type=int,
        default=None,
        help="Exit non-zero when any review candidate reaches this score.",
    )
    return parser.parse_args()


def load_config(root: Path, config_path: Path | None) -> dict[str, Any]:
    config = json.loads(json.dumps(DEFAULT_CONFIG))
    path = config_path or root / "code-health.toml"
    if not path.exists():
        return config
    if tomllib is None:
        raise SystemExit("code-health.toml requires Python 3.11+ tomllib")
    with path.open("rb") as fh:
        loaded = tomllib.load(fh)
    deep_merge(config, loaded)
    return config


def deep_merge(base: dict[str, Any], update: dict[str, Any]) -> None:
    for key, value in update.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            deep_merge(base[key], value)
        else:
            base[key] = value


def rel(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def tracked_files(root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        return sorted(
            p
            for p in root.rglob("*")
            if p.is_file()
            and not any(part in {".git", "target", "dist"} for part in p.parts)
        )
    files = []
    for line in result.stdout.splitlines():
        path = root / line
        if path.is_file():
            files.append(path)
    return sorted(files)


def rust_child_module_candidates(path: Path, module: str) -> list[Path]:
    if path.name in {"main.rs", "lib.rs", "mod.rs"}:
        module_root = path.parent
    else:
        module_root = path.parent / path.stem
    return [module_root / f"{module}.rs", module_root / module / "mod.rs"]


def test_only_rust_paths(root: Path, paths: list[Path]) -> set[str]:
    declared_paths = {path.resolve(): rel(root, path) for path in paths}
    test_only: set[str] = set()
    for path in paths:
        attrs: list[str] = []
        for line in read_text(path).splitlines():
            attr = ATTR_RE.match(line)
            if attr:
                attrs.append(attr.group("attr"))
                continue
            match = MOD_RE.match(line)
            if match and any(attr_marks_test(item) for item in attrs):
                module = match.group(1)
                for candidate in rust_child_module_candidates(path, module):
                    declared = declared_paths.get(candidate.resolve())
                    if declared is not None:
                        test_only.add(declared)
            if line.strip() and not line.lstrip().startswith("//"):
                attrs = []
    return test_only


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def attr_marks_test(attr: str) -> bool:
    normalized = re.sub(r"\s+", "", attr)
    return (
        normalized == "test"
        or normalized.endswith("::test")
        or normalized.startswith("test(")
        or normalized.startswith("cfg(test)")
        or normalized.startswith("cfg_attr(test,")
    )


def strip_strings(line: str) -> str:
    output: list[str] = []
    quote: str | None = None
    escaped = False
    for ch in line:
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            output.append(" ")
        elif ch == '"':
            quote = ch
            output.append(" ")
        else:
            output.append(ch)
    return "".join(output)


def find_block_end(lines: list[str], start: int) -> int:
    depth = 0
    seen_open = False
    for idx in range(start, len(lines)):
        logical = strip_strings(lines[idx])
        for ch in logical:
            if ch == "{":
                depth += 1
                seen_open = True
            elif ch == "}":
                depth -= 1
        if seen_open and depth <= 0:
            return idx
        if not seen_open and ";" in logical:
            return idx
    return start


def test_ranges(lines: list[str]) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    attrs: list[str] = []
    for idx, line in enumerate(lines):
        attr = ATTR_RE.match(line)
        if attr:
            attrs.append(attr.group("attr"))
            continue
        if MOD_TEST_RE.match(line) and any(attr_marks_test(item) for item in attrs):
            ranges.append((idx, find_block_end(lines, idx)))
        if line.strip() and not line.lstrip().startswith("//"):
            attrs = []
    return ranges


def line_in_ranges(line_index: int, ranges: list[tuple[int, int]]) -> bool:
    return any(start <= line_index <= end for start, end in ranges)


def parse_rust_items(
    root: Path,
    paths: list[Path],
    config: dict[str, Any],
    test_only_paths: set[str],
) -> list[RustItem]:
    items: list[RustItem] = []
    for path in paths:
        file_rel = rel(root, path)
        lines = read_text(path).splitlines()
        ranges = test_ranges(lines)
        attrs: list[str] = []
        for idx, line in enumerate(lines):
            file_is_test_only = file_rel in test_only_paths
            attr = ATTR_RE.match(line)
            if attr:
                attrs.append(attr.group("attr"))
                continue
            impl_match = IMPL_RE.match(line)
            match = RUST_ITEM_RE.match(line)
            if impl_match:
                match = None
                kind = "impl"
                name = impl_match.group("name")
                trait_impl = impl_match.group("trait")
                end_idx = find_block_end(lines, idx)
                item_attrs = list(attrs)
                in_test = file_is_test_only or line_in_ranges(idx, ranges) or any(
                    attr_marks_test(item) for item in item_attrs
                )
                item = RustItem(
                    id=f"rust:{file_rel}::{name}:{idx + 1}",
                    path=file_rel,
                    name=name,
                    kind=kind,
                    start_line=idx + 1,
                    end_line=end_idx + 1,
                    loc=max(1, end_idx - idx + 1),
                    visibility="",
                    attrs=item_attrs,
                    in_test=in_test,
                    owner=name,
                    trait_impl=trait_impl,
                )
                item.domain = classify(config, file_rel, name)
                items.append(item)
                attrs = []
                continue
            if match:
                kind = match.group("kind")
                name = match.group("name") or f"anonymous_{idx + 1}"
                if name in RUST_KEYWORDS or name == "_":
                    attrs = []
                    continue
                end_idx = find_block_end(lines, idx)
                item_attrs = list(attrs)
                in_test = file_is_test_only or line_in_ranges(idx, ranges) or any(
                    attr_marks_test(item) for item in item_attrs
                )
                item = RustItem(
                    id=f"rust:{file_rel}::{name}:{idx + 1}",
                    path=file_rel,
                    name=name,
                    kind=kind,
                    start_line=idx + 1,
                    end_line=end_idx + 1,
                    loc=max(1, end_idx - idx + 1),
                    visibility=(match.group("vis") or "").strip(),
                    attrs=item_attrs,
                    in_test=in_test,
                )
                item.domain = classify(config, file_rel, name)
                items.append(item)
                attrs = []
                continue
            if line.strip() and not line.lstrip().startswith("//"):
                attrs = []
    impls = [item for item in items if item.kind == "impl"]
    for item in items:
        if item.kind == "fn":
            owners = [
                impl
                for impl in impls
                if impl.path == item.path
                and impl.start_line < item.start_line
                and item.end_line < impl.end_line
            ]
            if owners:
                item.owner = owners[-1].name
                item.trait_impl = owners[-1].trait_impl
                item.domain = classify(config, item.path, item.owner)
    return items


def classify(config: dict[str, Any], path: str, name: str = "") -> str:
    domains = config.get("domains", {})
    for domain, rules in domains.items():
        for pattern in rules.get("file_patterns", []):
            if fnmatch.fnmatch(path, pattern):
                return domain
        for pattern in rules.get("name_patterns", []):
            if fnmatch.fnmatch(name, pattern):
                return domain
    return "uncategorized"


def rust_item_body(root: Path, item: RustItem) -> str:
    lines = read_text(root / item.path).splitlines()
    return "\n".join(lines[item.start_line - 1 : item.end_line])


def build_rust_edges(root: Path, items: list[RustItem]) -> dict[str, set[str]]:
    edges: dict[str, set[str]] = defaultdict(set)
    by_name: dict[str, list[RustItem]] = defaultdict(list)
    by_module_and_name: dict[tuple[str, str], list[RustItem]] = defaultdict(list)
    by_owner_and_name: dict[tuple[str, str], list[RustItem]] = defaultdict(list)
    by_type_name: dict[str, list[RustItem]] = defaultdict(list)
    for item in items:
        by_name[item.name].append(item)
        module = Path(item.path).stem
        by_module_and_name[(module, item.name)].append(item)
        if item.owner:
            by_owner_and_name[(item.owner, item.name)].append(item)
        if item.kind in {"struct", "enum", "trait", "type"}:
            by_type_name[item.name].append(item)

    for item in items:
        body = rust_item_body(root, item)
        for module, name in PATH_REF_RE.findall(body):
            targets = by_owner_and_name.get((module, name)) or by_module_and_name.get((module, name), [])
            for target in targets:
                if target.id != item.id:
                    edges[item.id].add(target.id)
        for module, name in PATH_CALL_RE.findall(body):
            targets = by_owner_and_name.get((module, name)) or by_module_and_name.get((module, name), [])
            for target in targets:
                if target.id != item.id:
                    edges[item.id].add(target.id)
        if item.kind == "fn" and item.owner:
            for target in by_type_name.get(item.owner, []):
                if target.id != item.id:
                    edges[item.id].add(target.id)
            for target in by_name.get(item.owner, []):
                if target.kind == "impl" and target.path == item.path and target.id != item.id:
                    edges[item.id].add(target.id)
        for name in CALL_RE.findall(body):
            if name in RUST_KEYWORDS:
                continue
            candidates = by_name.get(name, [])
            if len(candidates) == 1 and candidates[0].id != item.id:
                edges[item.id].add(candidates[0].id)
            elif len(candidates) > 1:
                scoped = [
                    target
                    for target in candidates
                    if target.id != item.id and target.path == item.path and target.in_test == item.in_test
                ]
                if len(scoped) <= 8:
                    for target in scoped:
                        edges[item.id].add(target.id)
        for name in METHOD_CALL_RE.findall(body):
            if name in METHOD_CALL_SKIP:
                continue
            candidates = [
                candidate
                for candidate in by_name.get(name, [])
                if candidate.kind == "fn" and candidate.owner and not candidate.in_test
            ]
            if len(candidates) == 1 and candidates[0].id != item.id:
                edges[item.id].add(candidates[0].id)
            elif 1 < len(candidates) <= 8:
                for target in candidates:
                    if target.id != item.id and (target.path == item.path or target.visibility):
                        edges[item.id].add(target.id)
        for token in TOKEN_RE.findall(body):
            if token in RUST_KEYWORDS or not token[:1].isupper():
                continue
            candidates = by_name.get(token, [])
            if len(candidates) == 1 and candidates[0].id != item.id:
                edges[item.id].add(candidates[0].id)
            elif candidates:
                for target in candidates:
                    if target.id != item.id and target.path == item.path:
                        edges[item.id].add(target.id)
        for token in TOKEN_RE.findall(body):
            if token in RUST_KEYWORDS or "_" not in token:
                continue
            candidates = [
                candidate
                for candidate in by_name.get(token, [])
                if candidate.kind == "fn" and candidate.id != item.id and candidate.in_test == item.in_test
            ]
            if len(candidates) == 1:
                edges[item.id].add(candidates[0].id)
    for item in items:
        if item.kind != "fn" or not item.trait_impl or not item.owner:
            continue
        for target in by_type_name.get(item.owner, []):
            if target.id != item.id:
                edges[target.id].add(item.id)
    return edges


def parse_script_nodes(root: Path, paths: list[Path], config: dict[str, Any]) -> list[ScriptNode]:
    nodes: list[ScriptNode] = []
    for path in paths:
        file_rel = rel(root, path)
        text = read_text(path)
        node = ScriptNode(
            id=f"script:{file_rel}",
            path=file_rel,
            name=Path(file_rel).name,
            loc=len(text.splitlines()),
            domain=classify(config, file_rel, Path(file_rel).name),
        )
        nodes.append(node)
    return nodes


def build_script_edges(root: Path, scripts: list[ScriptNode]) -> dict[str, set[str]]:
    by_name = {script.name: script for script in scripts}
    by_path = {script.path: script for script in scripts}
    edges: dict[str, set[str]] = defaultdict(set)
    for script in scripts:
        text = read_text(root / script.path)
        for match in SCRIPT_REF_RE.finditer(text):
            name = match.group(1)
            target = by_name.get(name) or by_path.get(f"scripts/{name}")
            if target and target.id != script.id:
                edges[script.id].add(target.id)
        for target in scripts:
            if target.id != script.id and target.path in text:
                edges[script.id].add(target.id)
    return edges


def documentation_text(root: Path, config: dict[str, Any]) -> str:
    chunks: list[str] = []
    for entry in config.get("roots", {}).get("documentation", []):
        path = root / entry
        if path.exists():
            chunks.append(read_text(path))
    return "\n".join(chunks)


def script_text(root: Path, scripts: list[ScriptNode]) -> str:
    return "\n".join(read_text(root / script.path) for script in scripts)


def add_reference_counts(
    root: Path,
    config: dict[str, Any],
    items: list[RustItem],
    scripts: list[ScriptNode],
) -> None:
    docs = documentation_text(root, config)
    scripts_blob = script_text(root, scripts)
    for item in items:
        item.docs_refs = docs.count(item.name) + docs.count(item.path)
        item.script_refs = scripts_blob.count(item.name) + scripts_blob.count(item.path)
    for script in scripts:
        script.docs_refs = docs.count(script.name) + docs.count(script.path)
        script.script_refs = max(0, scripts_blob.count(script.name) + scripts_blob.count(script.path) - 1)


def reachable_from(edges: dict[str, set[str]], roots: set[str]) -> set[str]:
    seen: set[str] = set()
    queue = deque(sorted(roots))
    while queue:
        node = queue.popleft()
        if node in seen:
            continue
        seen.add(node)
        for target in sorted(edges.get(node, set())):
            if target not in seen:
                queue.append(target)
    return seen


def pagerank(edges: dict[str, set[str]], node_ids: set[str], iterations: int = 30) -> dict[str, float]:
    if not node_ids:
        return {}
    count = len(node_ids)
    rank = {node: 1.0 / count for node in node_ids}
    damping = 0.85
    base = (1.0 - damping) / count
    for _ in range(iterations):
        next_rank = {node: base for node in node_ids}
        sink_rank = sum(rank[node] for node in node_ids if not edges.get(node))
        sink_share = damping * sink_rank / count
        for node in node_ids:
            next_rank[node] += sink_share
        for node, targets in edges.items():
            targets = {target for target in targets if target in node_ids}
            if not targets:
                continue
            share = damping * rank.get(node, 0.0) / len(targets)
            for target in targets:
                next_rank[target] += share
        rank = next_rank
    return rank


def root_item_ids(items: list[RustItem], configured_roots: list[str]) -> set[str]:
    roots: set[str] = set()
    for root in configured_roots:
        path, _, name = root.partition("::")
        for item in items:
            if item.path == path and item.name == name:
                roots.add(item.id)
    return roots


def root_script_ids(scripts: list[ScriptNode], configured_roots: list[str]) -> set[str]:
    roots = set()
    for root in configured_roots:
        for script in scripts:
            if script.path == root:
                roots.add(script.id)
    return roots


def annotate_graph(
    items: list[RustItem],
    scripts: list[ScriptNode],
    edges: dict[str, set[str]],
    config: dict[str, Any],
) -> None:
    all_nodes = {item.id for item in items} | {script.id for script in scripts}
    inbound = Counter()
    for source, targets in edges.items():
        for target in targets:
            inbound[target] += 1
    ranks = pagerank(edges, all_nodes)

    prod_roots = root_item_ids(items, config.get("roots", {}).get("production", [])) | root_script_ids(
        scripts, config.get("roots", {}).get("verification_scripts", [])
    )
    test_roots = {item.id for item in items if item.in_test}
    prod_reachable = reachable_from(edges, prod_roots)
    test_reachable = reachable_from(edges, test_roots)

    for item in items:
        item.inbound = inbound[item.id]
        item.outbound = len(edges.get(item.id, set()))
        item.pagerank = ranks.get(item.id, 0.0)
        item.production_reachable = item.id in prod_reachable
        item.test_reachable = item.id in test_reachable or item.in_test
    for script in scripts:
        script.inbound = inbound[script.id]
        script.outbound = len(edges.get(script.id, set()))
        script.pagerank = ranks.get(script.id, 0.0)
        script.production_reachable = script.id in prod_reachable
        script.test_reachable = script.id in test_reachable


def score_rust_item(item: RustItem, thresholds: dict[str, Any]) -> None:
    score = 0
    reasons: list[str] = []
    if item.in_test:
        item.review_score = 0
        item.reasons = ["test code"]
        return
    trait_callback = item.kind == "fn" and item.trait_impl is not None
    if not item.production_reachable and not item.test_reachable:
        if trait_callback:
            score += 8
            reasons.append(f"{item.trait_impl} trait callback")
        else:
            score += 35
            reasons.append("not reachable from production or test roots")
    elif not item.production_reachable:
        score += 16
        reasons.append("not reachable from production roots")
    if item.inbound == 0 and item.kind != "impl" and not trait_callback:
        score += 12
        reasons.append("no static inbound references")
    if item.docs_refs == 0 and item.script_refs == 0:
        score += 6
        reasons.append("no docs or script evidence")
    if item.loc >= int(thresholds.get("hot_item_loc", 120)):
        score += min(18, 6 + item.loc // 80)
        reasons.append(f"large item ({item.loc} loc)")
    if any("allow(dead_code)" in attr for attr in item.attrs):
        score += 14
        reasons.append("dead_code allow attribute")
    if item.domain in {"experimental", "compatibility", "lab"} and not item.production_reachable:
        score += 6
        reasons.append(f"{item.domain} lane needs explicit intent")
    if item.domain == "core" and item.production_reachable:
        score -= 18
    if item.domain == "platform":
        score -= 8
        reasons.append("platform-gated code")
    if item.production_reachable:
        score -= 35
    if item.test_reachable:
        score -= 10
    if item.docs_refs:
        score -= min(10, item.docs_refs)
    if item.script_refs:
        score -= min(8, item.script_refs)
    item.review_score = max(0, min(100, score))
    item.reasons = reasons or ["evidence present"]


def score_script(script: ScriptNode, thresholds: dict[str, Any]) -> None:
    score = 0
    reasons: list[str] = []
    if not script.production_reachable:
        score += 28
        reasons.append("not reachable from verification script roots")
    if script.inbound == 0:
        score += 10
        reasons.append("no static inbound script references")
    if script.docs_refs == 0:
        score += 6
        reasons.append("not referenced by docs")
    if script.loc >= int(thresholds.get("hot_item_loc", 120)):
        score += min(14, 4 + script.loc // 120)
        reasons.append(f"large script ({script.loc} loc)")
    if script.domain in {"lab", "experimental"} and not script.production_reachable:
        score += 4
        reasons.append(f"{script.domain} lane needs explicit intent")
    if script.production_reachable:
        score -= 24
    if script.docs_refs:
        score -= min(10, script.docs_refs)
    if script.script_refs:
        score -= min(10, script.script_refs)
    script.review_score = max(0, min(100, score))
    script.reasons = reasons or ["evidence present"]


def git_file_stats(root: Path, path: str) -> tuple[int | None, int]:
    result = subprocess.run(
        ["git", "log", "--format=%ct", "--", path],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    timestamps = [int(line) for line in result.stdout.splitlines() if line.strip().isdigit()]
    if not timestamps:
        return None, 0
    days = int((time.time() - timestamps[0]) / 86400)
    return max(0, days), len(timestamps)


def file_summaries(
    root: Path,
    config: dict[str, Any],
    items: list[RustItem],
    scripts: list[ScriptNode],
    all_files: list[Path],
) -> list[FileSummary]:
    by_path: dict[str, list[RustItem]] = defaultdict(list)
    for item in items:
        by_path[item.path].append(item)
    script_by_path = {script.path: script for script in scripts}
    docs = documentation_text(root, config)
    scripts_blob = script_text(root, scripts)
    summaries: list[FileSummary] = []
    relevant_exts = {".rs", ".sh", ".py", ".ps1", ".md", ".toml"}
    for path in all_files:
        if path.suffix not in relevant_exts and path.name not in {"README.md", "Cargo.toml"}:
            continue
        file_rel = rel(root, path)
        text = read_text(path)
        file_items = by_path.get(file_rel, [])
        script = script_by_path.get(file_rel)
        docs_refs = docs.count(file_rel) + docs.count(path.name)
        script_refs = scripts_blob.count(file_rel) + scripts_blob.count(path.name)
        if script:
            script_refs = max(0, script_refs - 1)
        unreachable_items = [
            item for item in file_items if not item.production_reachable and not item.in_test
        ]
        unreachable_loc = sum(item.loc for item in unreachable_items)
        max_item_loc = max((item.loc for item in file_items), default=script.loc if script else 0)
        item_scores = [item.review_score for item in file_items]
        if script:
            item_scores.append(script.review_score)
        review_score = max(item_scores, default=0)
        if file_items:
            review_score = max(
                review_score,
                min(100, int(70 * (unreachable_loc / max(1, sum(item.loc for item in file_items))))),
            )
        loc = len(text.splitlines())
        thresholds = config.get("thresholds", {})
        structure_score = 0
        reasons: list[str] = []
        if loc >= int(thresholds.get("hot_file_loc", 1000)):
            structure_score += min(45, 15 + loc // 350)
            reasons.append(f"large file ({loc} loc)")
        if len(file_items) >= 80:
            structure_score += 25
            reasons.append(f"many parsed items ({len(file_items)})")
        if max_item_loc >= int(thresholds.get("large_item_loc", 300)):
            structure_score += min(30, 10 + max_item_loc // 120)
            reasons.append(f"large item ({max_item_loc} loc)")
        if unreachable_loc > 0:
            reasons.append(f"{unreachable_loc} loc outside production reach")
        days, commit_count = git_file_stats(root, file_rel)
        summaries.append(
            FileSummary(
                path=file_rel,
                loc=loc,
                item_count=len(file_items),
                test_item_count=sum(1 for item in file_items if item.in_test),
                domain=classify(config, file_rel, path.stem),
                docs_refs=docs_refs,
                script_refs=script_refs,
                unreachable_item_count=len(unreachable_items),
                unreachable_loc=unreachable_loc,
                max_item_loc=max_item_loc,
                review_score=review_score,
                structure_score=max(0, min(100, structure_score)),
                last_touched_days=days,
                commit_count=commit_count,
                reasons=reasons or ["no structural hotspot"],
            )
        )
    return summaries


def write_outputs(
    root: Path,
    output: Path,
    items: list[RustItem],
    scripts: list[ScriptNode],
    summaries: list[FileSummary],
    edges: dict[str, set[str]],
    top: int,
) -> None:
    output.mkdir(parents=True, exist_ok=True)
    nodes = [asdict(item) for item in items] + [asdict(script) for script in scripts]
    graph = {
        "generated_by": "scripts/code-health.py",
        "nodes": nodes,
        "edges": [
            {"source": source, "target": target}
            for source, targets in sorted(edges.items())
            for target in sorted(targets)
        ],
        "files": [asdict(summary) for summary in summaries],
    }
    (output / "graph.json").write_text(json.dumps(graph, indent=2, sort_keys=True), encoding="utf-8")
    write_tsv(output / "heatmap.tsv", items, scripts, summaries)
    write_markdown(output / "report.md", root, items, scripts, summaries, top)


def write_tsv(
    path: Path,
    items: list[RustItem],
    scripts: list[ScriptNode],
    summaries: list[FileSummary],
) -> None:
    rows = [
        [
            "score",
            "type",
            "path",
            "line",
            "name",
            "domain",
            "production_reachable",
            "test_reachable",
            "inbound",
            "docs_refs",
            "script_refs",
            "loc",
            "reasons",
        ]
    ]
    for item in sorted(items, key=lambda value: value.review_score, reverse=True):
        rows.append(
            [
                str(item.review_score),
                f"rust:{item.kind}",
                item.path,
                str(item.start_line),
                item.name,
                item.domain,
                str(item.production_reachable),
                str(item.test_reachable),
                str(item.inbound),
                str(item.docs_refs),
                str(item.script_refs),
                str(item.loc),
                "; ".join(item.reasons),
            ]
        )
    for script in sorted(scripts, key=lambda value: value.review_score, reverse=True):
        rows.append(
            [
                str(script.review_score),
                "script",
                script.path,
                "1",
                script.name,
                script.domain,
                str(script.production_reachable),
                str(script.test_reachable),
                str(script.inbound),
                str(script.docs_refs),
                str(script.script_refs),
                str(script.loc),
                "; ".join(script.reasons),
            ]
        )
    for summary in sorted(summaries, key=lambda value: value.structure_score, reverse=True):
        rows.append(
            [
                str(summary.structure_score),
                "file-structure",
                summary.path,
                "1",
                Path(summary.path).name,
                summary.domain,
                "",
                "",
                "",
                str(summary.docs_refs),
                str(summary.script_refs),
                str(summary.loc),
                "; ".join(summary.reasons),
            ]
        )
    path.write_text("\n".join("\t".join(cell.replace("\t", " ") for cell in row) for row in rows), encoding="utf-8")


def md_table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return "_No rows._\n"
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(cell.replace("|", "\\|") for cell in row) + " |")
    return "\n".join(lines) + "\n"


def write_markdown(
    path: Path,
    root: Path,
    items: list[RustItem],
    scripts: list[ScriptNode],
    summaries: list[FileSummary],
    top: int,
) -> None:
    review_nodes = sorted(
        [node for node in [*items, *scripts] if node.review_score > 0],
        key=lambda node: (node.review_score, node.loc),
        reverse=True,
    )
    structural = sorted(summaries, key=lambda item: item.structure_score, reverse=True)
    hot_files = sorted(summaries, key=lambda item: item.review_score, reverse=True)
    domain_counts = Counter(item.domain for item in items) + Counter(script.domain for script in scripts)
    unreachable_loc = sum(item.loc for item in items if not item.production_reachable and not item.in_test)
    rust_loc = sum(item.loc for item in items if not item.in_test)
    lines = [
        "# Code Health Heatmap",
        "",
        "This report is heuristic. A high score means review the code and gather intent; it does not mean delete automatically.",
        "",
        "## Summary",
        "",
        f"- Rust items parsed: {len(items)}",
        f"- Script nodes parsed: {len(scripts)}",
        f"- Non-test Rust LOC inside parsed items: {rust_loc}",
        f"- Non-test Rust LOC outside production reach: {unreachable_loc}",
        f"- Files summarized: {len(summaries)}",
        "",
        "## Domain Mix",
        "",
        md_table(["Domain", "Nodes"], [[domain, str(count)] for domain, count in sorted(domain_counts.items())]),
        "## Highest Review Scores",
        "",
        md_table(
            ["Score", "Node", "Domain", "Reach", "Refs", "LOC", "Reasons"],
            [
                [
                    str(node.review_score),
                    node_label(node),
                    node.domain,
                    reach_label(node),
                    f"in={node.inbound}, docs={node.docs_refs}, scripts={node.script_refs}",
                    str(node.loc),
                    "; ".join(node.reasons[:3]),
                ]
                for node in review_nodes[:top]
            ],
        ),
        "## File Review Heatmap",
        "",
        md_table(
            ["Score", "File", "Domain", "LOC", "Unreachable LOC", "Refs", "Reasons"],
            [
                [
                    str(summary.review_score),
                    summary.path,
                    summary.domain,
                    str(summary.loc),
                    str(summary.unreachable_loc),
                    f"docs={summary.docs_refs}, scripts={summary.script_refs}",
                    "; ".join(summary.reasons[:3]),
                ]
                for summary in hot_files[:top]
            ],
        ),
        "## Structural Hotspots",
        "",
        md_table(
            ["Score", "File", "LOC", "Items", "Max Item LOC", "Reasons"],
            [
                [
                    str(summary.structure_score),
                    summary.path,
                    str(summary.loc),
                    str(summary.item_count),
                    str(summary.max_item_loc),
                    "; ".join(summary.reasons[:3]),
                ]
                for summary in structural[:top]
                if summary.structure_score > 0
            ],
        ),
        "## Artifacts",
        "",
        f"- JSON graph: `{path.parent.relative_to(root) / 'graph.json'}`",
        f"- TSV heatmap: `{path.parent.relative_to(root) / 'heatmap.tsv'}`",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def node_label(node: RustItem | ScriptNode) -> str:
    if isinstance(node, RustItem):
        return f"{node.path}:{node.start_line} `{node.name}`"
    return f"{node.path}:1 `{node.name}`"


def reach_label(node: RustItem | ScriptNode) -> str:
    labels = []
    if node.production_reachable:
        labels.append("prod")
    if node.test_reachable:
        labels.append("test")
    return ",".join(labels) or "none"


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    config = load_config(root, args.config)
    output = (args.output or root / "target" / "code-health").resolve()
    files = tracked_files(root)
    rust_paths = [
        path
        for path in files
        if path.suffix == ".rs" and (rel(root, path).startswith("src/") or rel(root, path).startswith("agent-bootstrap/src/"))
    ]
    test_only_paths = test_only_rust_paths(root, rust_paths)
    script_paths = [
        path
        for path in files
        if rel(root, path).startswith("scripts/") and path.suffix in {".sh", ".py", ".ps1"}
    ]
    items = parse_rust_items(root, rust_paths, config, test_only_paths)
    scripts = parse_script_nodes(root, script_paths, config)
    add_reference_counts(root, config, items, scripts)
    edges = build_rust_edges(root, items)
    script_edges = build_script_edges(root, scripts)
    for source, targets in script_edges.items():
        edges[source].update(targets)
    annotate_graph(items, scripts, edges, config)
    thresholds = config.get("thresholds", {})
    for item in items:
        score_rust_item(item, thresholds)
    for script in scripts:
        score_script(script, thresholds)
    summaries = file_summaries(root, config, items, scripts, files)
    write_outputs(root, output, items, scripts, summaries, edges, args.top)
    max_score = max([item.review_score for item in items] + [script.review_score for script in scripts], default=0)
    print(f"code-health: wrote {output / 'report.md'}")
    print(f"code-health: max review score={max_score}")
    if args.fail_on_review_score is not None and max_score >= args.fail_on_review_score:
        print(
            f"code-health: max review score {max_score} exceeds threshold {args.fail_on_review_score}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
