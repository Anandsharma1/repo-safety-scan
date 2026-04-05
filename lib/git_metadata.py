#!/usr/bin/env python3
"""Scan .git/ metadata for hostile directives that execute on common git ops.

Background: a malicious repo can carry `.git/config` with directives like
`core.sshCommand`, `core.fsmonitor`, `core.hooksPath`, or `includeIf` that
run attacker code the moment any git command touches the workspace. This
class of bug is what GHSA-j4h9-wv2m-wrf7 is about.

Also flags `.gitattributes` with `filter=` (smudge/clean scripts) and any
content in `.git/hooks/` (which we strip during ingest, but the presence
itself is a signal).

Outputs JSON to stdout. Exit code is always 0 — findings are in the output.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

HOSTILE_CONFIG_KEYS = [
    # key_regex, severity, why
    (r"(?i)^\s*sshCommand\s*=",      "critical", "core.sshCommand runs on any git-over-ssh operation"),
    (r"(?i)^\s*fsmonitor\s*=",       "high",     "core.fsmonitor runs on any git status/add/commit"),
    (r"(?i)^\s*hooksPath\s*=",       "high",     "core.hooksPath redirects hook dir (bypasses our hooks-off)"),
    (r"(?i)^\s*pager\s*=",           "medium",   "core.pager runs when git output is paginated"),
    (r"(?i)^\s*editor\s*=",          "medium",   "core.editor runs on commit/rebase/tag -a"),
    (r"(?i)^\s*askpass\s*=",         "medium",   "core.askpass runs on credential prompts"),
    (r"(?i)^\s*\[includeIf\b",       "high",     "includeIf can chain-load hostile config on condition"),
    (r"(?i)^\s*\[include\b",         "medium",   "include can chain-load arbitrary config files"),
    (r"(?i)^\s*credentialHelper\s*=","medium",   "credential.helper runs on auth flows"),
    (r"(?i)^\s*protocol\.[^=]+\.allow\s*=\s*always", "medium", "enables dangerous URL protocols"),
]

GITATTR_FILTERS = re.compile(r"\bfilter\s*=\s*([A-Za-z0-9_\-]+)")


def scan_git_config(cfg_path: Path) -> list[dict]:
    findings = []
    if not cfg_path.is_file():
        return findings
    try:
        text = cfg_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue
        for pat, sev, why in HOSTILE_CONFIG_KEYS:
            if re.search(pat, line):
                findings.append({
                    "rule": "hostile-gitconfig",
                    "severity": sev,
                    "file": str(cfg_path),
                    "line": lineno,
                    "match": stripped[:240],
                    "why": why,
                })
                break
    return findings


def scan_gitattributes(root: Path) -> list[dict]:
    findings = []
    for ga in list(root.rglob(".gitattributes"))[:200]:
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


def main() -> int:
    if len(sys.argv) != 2:
        print(json.dumps({"error": "usage: git_metadata.py <src-dir>"}))
        return 0
    src = Path(sys.argv[1]).resolve()
    git_dir = src / ".git"

    findings: list[dict] = []
    findings += scan_git_config(git_dir / "config")
    findings += scan_gitattributes(src)
    findings += scan_git_hooks(git_dir)

    print(json.dumps({
        "tool": "git_metadata",
        "src": str(src),
        "findings": findings,
        "findings_count": len(findings),
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
