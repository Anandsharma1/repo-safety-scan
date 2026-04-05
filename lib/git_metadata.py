#!/usr/bin/env python3
"""Scan .git/ metadata for hostile directives that execute on common git ops.

Background: a malicious repo can carry `.git/config` with directives like
`core.sshCommand`, `core.fsmonitor`, `core.hooksPath`, or `includeIf` that
run attacker code the moment any git command touches the workspace. This
class of bug is what GHSA-j4h9-wv2m-wrf7 is about.

Also flags `.gitattributes` / `.git/info/attributes` entries with `filter=`
(smudge/clean scripts) and any content in `.git/hooks/` (which we strip
during ingest, but the presence itself is a signal).

Handles git-worktree / submodule layout where `.git` is a FILE pointing at
the real gitdir via `gitdir: <path>`.

Outputs JSON to stdout. Exit code is always 0 — findings are in the output.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

# Canonical dotted key -> (severity, why)
# Subsection wildcard '*' matches any subsection name.
HOSTILE_KEYS: list[tuple[str, str, str]] = [
    ("core.sshCommand",      "critical", "core.sshCommand runs on any git-over-ssh operation"),
    ("core.fsmonitor",       "high",     "core.fsmonitor runs on any git status/add/commit"),
    ("core.hooksPath",       "high",     "core.hooksPath redirects hook dir (bypasses our hooks-off)"),
    ("core.pager",           "medium",   "core.pager runs when git output is paginated"),
    ("core.editor",          "medium",   "core.editor runs on commit/rebase/tag -a"),
    ("core.askpass",         "medium",   "core.askpass runs on credential prompts"),
    ("credential.helper",    "medium",   "credential.helper runs on auth flows"),
    ("credential.*.helper",  "medium",   "credential.<url>.helper runs on auth flows"),
    ("include.path",         "medium",   "include.path can chain-load arbitrary config files"),
    ("includeIf.*.path",     "high",     "includeIf can chain-load hostile config on condition"),
    ("filter.*.clean",       "high",     "filter.<name>.clean runs an arbitrary command on checkout/add"),
    ("filter.*.smudge",      "high",     "filter.<name>.smudge runs an arbitrary command on checkout/add"),
    ("filter.*.process",     "high",     "filter.<name>.process runs an arbitrary command during path handling"),
]

HOSTILE_KEYS_VALUE_GATED: list[tuple[str, re.Pattern, str, str]] = [
    # (canonical_key, value_regex_that_makes_it_hostile, severity, why)
    ("protocol.allow", re.compile(r"^\s*always\s*$"), "medium", "protocol.allow=always enables dangerous URL protocols (ext, file, ftp, ...)"),
    ("protocol.*.allow", re.compile(r"^\s*always\s*$"), "medium", "protocol.<name>.allow=always enables dangerous URL protocols (ext, file, ftp, ...)"),
]

GITATTR_FILTERS = re.compile(r"\bfilter\s*=\s*([A-Za-z0-9_\-]+)")

SECTION_RE = re.compile(r'^\s*\[\s*([A-Za-z][A-Za-z0-9\-]*)(?:\s+"([^"]*)")?\s*\]\s*(?:[#;].*)?$')
# Also accept the `[section.subsection]` dotted form (older style)
SECTION_DOTTED_RE = re.compile(r'^\s*\[\s*([A-Za-z][A-Za-z0-9\-]*)\.([A-Za-z][A-Za-z0-9.\-_]*)\s*\]\s*(?:[#;].*)?$')
KV_RE = re.compile(r'^\s*([A-Za-z][A-Za-z0-9\-]*)\s*=\s*(.*?)\s*(?:[#;].*)?$')


def canonical_key(section: str, subsection: str | None, key: str) -> str:
    """Dotted key for display; subsection may contain dots (e.g. URLs)."""
    section = section.lower()
    key = key.lower()
    if subsection:
        return f"{section}.{subsection}.{key}"
    return f"{section}.{key}"


def _canonical_tuple(section: str, subsection: str | None, key: str) -> tuple[str, str | None, str]:
    return (section.lower(), subsection, key.lower())


def _pattern_tuple(pattern: str) -> tuple[str, str | None, str]:
    """Parse a pattern like 'section.key' or 'section.*.key' into a tuple.
    '*' in the middle position means 'any subsection'. None means 'no subsection'."""
    parts = pattern.split(".")
    if len(parts) == 2:
        return (parts[0].lower(), None, parts[1].lower())
    if len(parts) == 3:
        sub = None if parts[1] == "" else (None if parts[1] == "*" and False else parts[1])
        # '*' is the wildcard sentinel
        sub = "*" if parts[1] == "*" else parts[1].lower()
        return (parts[0].lower(), sub, parts[2].lower())
    raise ValueError(f"unsupported pattern: {pattern}")


def key_matches(canonical_t: tuple[str, str | None, str], pattern: str) -> bool:
    p_sec, p_sub, p_key = _pattern_tuple(pattern)
    c_sec, c_sub, c_key = canonical_t
    if p_sec != c_sec or p_key != c_key:
        return False
    if p_sub is None:
        # Pattern says "no subsection"
        return c_sub is None
    if p_sub == "*":
        # Wildcard — require some subsection present
        return c_sub is not None
    # Specific subsection match
    return c_sub is not None and p_sub == c_sub.lower()


def scan_git_config(cfg_path: Path) -> list[dict]:
    findings: list[dict] = []
    if not cfg_path.is_file():
        return findings
    try:
        text = cfg_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    section: str | None = None
    subsection: str | None = None
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.rstrip()
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue

        m_dot = SECTION_DOTTED_RE.match(line)
        m_sec = SECTION_RE.match(line) if not m_dot else None
        if m_dot:
            section, subsection = m_dot.group(1), m_dot.group(2)
            continue
        if m_sec:
            section, subsection = m_sec.group(1), m_sec.group(2)
            continue

        m_kv = KV_RE.match(line)
        if not m_kv or section is None:
            continue
        key, value = m_kv.group(1), m_kv.group(2)
        canonical = canonical_key(section, subsection, key)
        canonical_t = _canonical_tuple(section, subsection, key)

        hit = False
        for pattern, sev, why in HOSTILE_KEYS:
            if key_matches(canonical_t, pattern):
                findings.append({
                    "rule": "hostile-gitconfig",
                    "severity": sev,
                    "file": str(cfg_path),
                    "line": lineno,
                    "match": stripped[:240],
                    "canonical_key": canonical,
                    "why": why,
                })
                hit = True
                break
        if hit:
            continue

        for pattern, value_re, sev, why in HOSTILE_KEYS_VALUE_GATED:
            if key_matches(canonical_t, pattern) and value_re.search(value or ""):
                findings.append({
                    "rule": "hostile-gitconfig",
                    "severity": sev,
                    "file": str(cfg_path),
                    "line": lineno,
                    "match": stripped[:240],
                    "canonical_key": canonical,
                    "why": why,
                })
                break

    return findings


def scan_gitattributes(root: Path, git_dir: Path | None) -> list[dict]:
    findings = []
    candidates = list(root.rglob(".gitattributes"))
    # Repository-local attributes can also live in info/attributes under the
    # resolved gitdir (either .git/info/attributes or bare-repo info/attributes).
    info_attr = (git_dir / "info" / "attributes") if git_dir is not None else None
    if info_attr is not None and info_attr.is_file():
        candidates.append(info_attr)

    for ga in candidates:
        try:
            text = ga.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            m = GITATTR_FILTERS.search(line)
            if m:
                findings.append({
                    "rule": "gitattributes-filter",
                    "severity": "medium",
                    "file": str(ga),
                    "line": lineno,
                    "match": line.strip()[:240],
                    "why": f"filter={m.group(1)} may shell out via .git/config clean/smudge commands",
                })
    return findings


def scan_git_hooks(git_dir: Path) -> list[dict]:
    findings = []
    hooks_dir = git_dir / "hooks"
    if not hooks_dir.is_dir():
        return findings
    for entry in hooks_dir.iterdir():
        if entry.is_file() and not entry.name.endswith(".sample"):
            findings.append({
                "rule": "git-hook-present",
                "severity": "high",
                "file": str(entry),
                "line": 1,
                "match": entry.name,
                "why": "executable hook present in .git/hooks/ (ingest should strip these)",
            })
    return findings


def resolve_git_dir(src: Path) -> Path | None:
    """Return the real git dir for `src`, handling .git-as-file (worktree/submodule).

    Returns None if no git metadata is present.
    """
    dot_git = src / ".git"
    if dot_git.is_dir():
        return dot_git
    if dot_git.is_file():
        try:
            content = dot_git.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            return None
        # Format: "gitdir: <path>" (path may be relative to parent of .git file)
        for line in content.splitlines():
            line = line.strip()
            if line.lower().startswith("gitdir:"):
                rel_or_abs = line.split(":", 1)[1].strip()
                candidate = Path(rel_or_abs)
                if not candidate.is_absolute():
                    candidate = (dot_git.parent / candidate).resolve()
                if candidate.is_dir():
                    return candidate
        return None
    # Bare repo: src itself is the git dir
    if (src / "HEAD").is_file() and (src / "config").is_file() and (src / "objects").is_dir():
        return src
    return None


def main() -> int:
    if len(sys.argv) != 2:
        print(json.dumps({"error": "usage: git_metadata.py <src-dir>"}))
        return 0
    src = Path(sys.argv[1]).resolve()
    git_dir = resolve_git_dir(src)

    findings: list[dict] = []
    if git_dir is not None:
        findings += scan_git_config(git_dir / "config")
        findings += scan_git_config(git_dir / "config.worktree")
        findings += scan_git_hooks(git_dir)
    findings += scan_gitattributes(src, git_dir)

    print(json.dumps({
        "tool": "git_metadata",
        "src": str(src),
        "git_dir": str(git_dir) if git_dir else None,
        "git_dir_kind": _git_dir_kind(src, git_dir),
        "findings": findings,
        "findings_count": len(findings),
    }, indent=2))
    return 0


def _git_dir_kind(src: Path, git_dir: Path | None) -> str:
    if git_dir is None:
        return "none"
    dot_git = src / ".git"
    if dot_git.is_dir():
        return "dir"
    if dot_git.is_file():
        return "worktree-or-submodule"
    if git_dir == src:
        return "bare"
    return "unknown"


if __name__ == "__main__":
    sys.exit(main())
