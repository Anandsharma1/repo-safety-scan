#!/usr/bin/env python3
"""Render a unified markdown report from all scanner outputs in artifacts/.

Consumes JSON outputs from: git_metadata.py, gitleaks, semgrep, osv-scanner,
guarddog, cisco skill-scanner. Tool-missing/error conditions are surfaced,
not hidden.

Writes to stdout. Exit 0 always.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
SEV_EMOJI = {"critical": "[CRIT]", "high": "[HIGH]", "medium": "[MED ]", "low": "[LOW ]", "info": "[INFO]", "unknown": "[?   ]"}


def load_json(path: Path) -> dict | list | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception as e:
        return {"_load_error": str(e)}


def norm_sev(s: str | None) -> str:
    if not s:
        return "unknown"
    s = s.strip().lower()
    if s in SEV_ORDER:
        return s
    # Semgrep: ERROR/WARNING/INFO; Gitleaks: no severity; OSV: HIGH/MED/LOW
    return {"error": "high", "warning": "medium"}.get(s, "unknown" if s not in SEV_ORDER else s)


def collect_findings(art: Path) -> tuple[list[dict], dict]:
    """Return (findings, tool_status) where tool_status[tool] is 'ok'|'missing'|'error'|'no-findings'."""
    all_findings: list[dict] = []
    status: dict[str, str] = {}

    # git_metadata (always runs)
    gm = load_json(art / "git_metadata.json")
    if gm is None:
        status["git_metadata"] = "missing"
    elif isinstance(gm, dict) and "_load_error" in gm:
        status["git_metadata"] = f"error: {gm['_load_error']}"
    else:
        for f in gm.get("findings", []):
            all_findings.append({**f, "tool": "git_metadata"})
        status["git_metadata"] = "ok" if gm.get("findings") else "no-findings"

    # gitleaks (JSON array of findings, or empty/object if no findings)
    gl = load_json(art / "gitleaks.json")
    if gl is None:
        status["gitleaks"] = _tool_status(art, "gitleaks")
    elif isinstance(gl, dict) and "_load_error" in gl:
        status["gitleaks"] = f"error: {gl['_load_error']}"
    else:
        items = gl if isinstance(gl, list) else []
        for it in items:
            all_findings.append({
                "tool": "gitleaks",
                "rule": it.get("RuleID") or it.get("Description") or "secret",
                "severity": "high",
                "file": it.get("File", ""),
                "line": it.get("StartLine", 0),
                "match": (it.get("Secret") or it.get("Match") or "")[:240],
                "why": it.get("Description", "secret leaked in git history/tree"),
            })
        status["gitleaks"] = "ok" if items else "no-findings"

    # semgrep
    sg = load_json(art / "semgrep.json")
    if sg is None:
        status["semgrep"] = _tool_status(art, "semgrep")
    elif isinstance(sg, dict) and "_load_error" in sg:
        status["semgrep"] = f"error: {sg['_load_error']}"
    else:
        results = sg.get("results", []) if isinstance(sg, dict) else []
        for r in results:
            extra = r.get("extra", {}) or {}
            all_findings.append({
                "tool": "semgrep",
                "rule": r.get("check_id", "semgrep-rule"),
                "severity": norm_sev(extra.get("severity")),
                "file": r.get("path", ""),
                "line": (r.get("start", {}) or {}).get("line", 0),
                "match": (extra.get("lines") or "")[:240],
                "why": (extra.get("message") or "")[:400],
            })
        status["semgrep"] = "ok" if results else "no-findings"
        # Errors inside semgrep output
        sg_errors = sg.get("errors", []) if isinstance(sg, dict) else []
        if sg_errors:
            status["semgrep"] += f" ({len(sg_errors)} scanner errors)"

    # osv-scanner
    osv = load_json(art / "osv.json")
    if osv is None:
        status["osv-scanner"] = _tool_status(art, "osv-scanner")
    elif isinstance(osv, dict) and "_load_error" in osv:
        status["osv-scanner"] = f"error: {osv['_load_error']}"
    else:
        vulns_total = 0
        for res in osv.get("results", []) if isinstance(osv, dict) else []:
            for pkg in res.get("packages", []):
                for v in pkg.get("vulnerabilities", []):
                    vulns_total += 1
                    sev = "unknown"
                    for s in v.get("severity", []) or []:
                        sev_score = (s.get("score") or "").lower()
                        if "critical" in sev_score: sev = "critical"; break
                        if "high" in sev_score: sev = "high"
                        elif sev == "unknown" and "medium" in sev_score: sev = "medium"
                        elif sev == "unknown" and "low" in sev_score: sev = "low"
                    all_findings.append({
                        "tool": "osv-scanner",
                        "rule": v.get("id", "OSV"),
                        "severity": sev,
                        "file": (res.get("source", {}) or {}).get("path", ""),
                        "line": 0,
                        "match": (pkg.get("package", {}) or {}).get("name", "") + "@" + (pkg.get("package", {}) or {}).get("version", ""),
                        "why": (v.get("summary") or "")[:400],
                    })
        status["osv-scanner"] = "ok" if vulns_total else "no-findings"

    # guarddog (JSON schema is {"name/version": {"findings": [...], ...}} per scan)
    gd = load_json(art / "guarddog.json")
    if gd is None:
        status["guarddog"] = _tool_status(art, "guarddog")
    elif isinstance(gd, dict) and "_load_error" in gd:
        status["guarddog"] = f"error: {gd['_load_error']}"
    else:
        count = 0
        if isinstance(gd, dict):
            for pkg, data in gd.items():
                if not isinstance(data, dict): continue
                for rid, details in (data.get("results") or {}).items():
                    if not details: continue
                    count += 1
                    msg = details if isinstance(details, str) else json.dumps(details)[:400]
                    all_findings.append({
                        "tool": "guarddog",
                        "rule": rid,
                        "severity": "high",
                        "file": pkg,
                        "line": 0,
                        "match": pkg,
                        "why": msg[:400],
                    })
        status["guarddog"] = "ok" if count else "no-findings"

    # cisco skill-scanner
    ss = load_json(art / "skill_scanner.json")
    if ss is None:
        status["skill-scanner"] = _tool_status(art, "skill-scanner")
    elif isinstance(ss, dict) and "_load_error" in ss:
        status["skill-scanner"] = f"error: {ss['_load_error']}"
    else:
        # Unknown schema — try common shapes
        items = []
        if isinstance(ss, dict):
            items = ss.get("findings") or ss.get("results") or ss.get("issues") or []
            if not items and isinstance(ss.get("report"), dict):
                items = ss["report"].get("findings") or []
        elif isinstance(ss, list):
            items = ss
        for it in items if isinstance(items, list) else []:
            all_findings.append({
                "tool": "skill-scanner",
                "rule": (it.get("rule") or it.get("id") or it.get("check") or "skill-scanner-rule") if isinstance(it, dict) else "skill-scanner-rule",
                "severity": norm_sev(it.get("severity") if isinstance(it, dict) else None),
                "file": (it.get("file") or it.get("path") or "") if isinstance(it, dict) else "",
                "line": (it.get("line") or 0) if isinstance(it, dict) else 0,
                "match": str(it)[:240] if not isinstance(it, dict) else str(it.get("match", ""))[:240],
                "why": (it.get("message") or it.get("description") or "")[:400] if isinstance(it, dict) else "",
            })
        status["skill-scanner"] = "ok" if items else "no-findings"

    return all_findings, status


def _tool_status(art: Path, tool: str) -> str:
    """Inspect errors.log to differentiate missing vs failed vs not-run."""
    err_log = art / "errors.log"
    if not err_log.is_file():
        return "not-run"
    text = err_log.read_text(encoding="utf-8", errors="replace")
    if f"{tool}: not installed" in text:
        return "missing (install to enable)"
    if f"{tool} failed" in text:
        return "failed (see errors.log)"
    return "not-run"


def verdict(findings: list[dict]) -> tuple[str, str]:
    """Return (verdict, explanation)."""
    sev_counts = {s: 0 for s in SEV_ORDER}
    for f in findings:
        sev_counts[norm_sev(f.get("severity"))] += 1
    if sev_counts["critical"] > 0:
        return "CRITICAL", f"{sev_counts['critical']} critical finding(s); do not run outside a locked-down sandbox"
    if sev_counts["high"] >= 5:
        return "HIGH", f"{sev_counts['high']} high-severity findings; manual review required before running"
    if sev_counts["high"] >= 1:
        return "HIGH", f"{sev_counts['high']} high-severity finding(s); manual review required"
    if sev_counts["medium"] >= 3:
        return "MEDIUM", f"{sev_counts['medium']} medium-severity findings; review recommended"
    if sev_counts["medium"] >= 1 or sev_counts["low"] >= 5:
        return "LOW", "limited findings; skim the evidence before running"
    return "LOW", "no material findings from the scanners that ran (not a certification of safety)"


SANDBOX_RECIPE = """```bash
# No network, read-only FS, no capabilities, no privesc
podman run --rm -it \\
  --network=none --read-only --cap-drop=ALL \\
  --security-opt=no-new-privileges \\
  -v "$(pwd):/src:ro,Z" -w /src \\
  python:3.12-slim bash
```"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--artifacts", required=True)
    args = ap.parse_args()

    art = Path(args.artifacts)
    findings, status = collect_findings(art)
    findings.sort(key=lambda f: (SEV_ORDER.get(norm_sev(f.get("severity")), 9), f.get("tool", ""), f.get("file", "")))

    verdict_level, verdict_why = verdict(findings)

    out = []
    out.append(f"# Safety Report: {args.target}")
    out.append("")
    out.append(f"**Mode:** `{args.mode}`  ")
    out.append(f"**Verdict:** **{verdict_level}** — {verdict_why}")
    out.append("")
    out.append("> Not a safety certification. Scanners catch obvious malice; a clean report does not prove a repo is safe.")
    out.append("")

    # Tool status
    out.append("## Scanners")
    out.append("")
    out.append("| Tool | Status |")
    out.append("|---|---|")
    for tool, st in status.items():
        out.append(f"| `{tool}` | {st} |")
    out.append("")

    # Skill manifest inventory (skill mode only)
    manifest = load_json(art / "skill_manifest.json")
    if isinstance(manifest, dict) and manifest.get("manifests"):
        out.append(f"## Skill Manifests Detected ({manifest.get('count', 0)})")
        out.append("")
        out.append("| Manifest | Name | Description |")
        out.append("|---|---|---|")
        for m in manifest["manifests"]:
            name = (m.get("name") or "").replace("|", "\\|")[:60]
            desc = (m.get("description") or "").replace("|", "\\|").replace("\n", " ")[:120]
            out.append(f"| `{m.get('manifest','')}` | {name} | {desc} |")
        out.append("")

    # Top concerns (highest severity first, cap 10)
    if findings:
        out.append("## Top Concerns")
        out.append("")
        for i, f in enumerate(findings[:10], start=1):
            sev = norm_sev(f.get("severity"))
            loc = f.get("file", "")
            if f.get("line"):
                loc = f"{loc}:{f['line']}"
            out.append(f"{i}. `{SEV_EMOJI.get(sev, '[?]')}` **{f.get('rule', '?')}** ({f.get('tool', '?')}) — `{loc}`")
            if f.get("why"):
                out.append(f"   - {f['why']}")
            if f.get("match"):
                out.append(f"   - evidence: `{f['match'][:160]}`")
        out.append("")

        # Full evidence
        out.append("<details><summary>All findings (%d)</summary>" % len(findings))
        out.append("")
        out.append("| Sev | Tool | Rule | Location | Evidence |")
        out.append("|---|---|---|---|---|")
        for f in findings:
            sev = norm_sev(f.get("severity"))
            loc = f.get("file", "")
            if f.get("line"):
                loc = f"{loc}:{f['line']}"
            ev = (f.get("match") or "").replace("|", "\\|").replace("\n", " ")[:100]
            out.append(f"| {sev} | {f.get('tool','?')} | `{f.get('rule','?')}` | `{loc}` | `{ev}` |")
        out.append("")
        out.append("</details>")
        out.append("")
    else:
        out.append("## Findings")
        out.append("")
        out.append("_No findings from the scanners that ran. See Scanners table for what actually executed._")
        out.append("")

    # If user still wants to run it
    out.append("## If You Decide to Run This Code")
    out.append("")
    out.append(SANDBOX_RECIPE)
    out.append("")
    out.append("For runs that need network: use a separate netns with an egress allowlist, or Firecracker/gVisor.")
    out.append("")

    out.append("---")
    out.append(f"_Report generated by repo-safety-scan (mode={args.mode})._")

    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
