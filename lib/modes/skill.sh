#!/usr/bin/env bash
# skill mode — agent-skill-pack scan (Claude Code / Codex / Cursor / MCP).
#
# Primary engine: Cisco skill-scanner (reuses what they built).
# Secondary: semgrep with skill-specific custom rules (prompt injection,
# hook abuse, dangerous tool registrations).
#
# Also runs gitleaks (skills commonly contain curl/wget + env access).
#
# Inputs (env vars, set by bin/repo-safety-scan):
#   RSS_SRC    path to ingested source tree
#   RSS_ART    path to artifacts dir
#   RSS_RULES  path to custom rules dir
#   RSS_MODE   "skill"
set -uo pipefail

: "${RSS_SRC:?RSS_SRC must be set}"
: "${RSS_ART:?RSS_ART must be set}"
: "${RSS_RULES:?RSS_RULES must be set}"

ERR_LOG="$RSS_ART/errors.log"
: > "$ERR_LOG"

have() { command -v "$1" >/dev/null 2>&1; }
note() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
log_missing() { echo "$1: not installed" >> "$ERR_LOG"; note "skipping $1 (not installed)"; }
log_failed()  { echo "$1 failed (exit $2)" >> "$ERR_LOG"; note "$1 failed (exit $2)"; }

run_skill_scanner() {
    # Cisco's skill-scanner is the primary detector in this mode. It's required
    # by design — we don't reimplement its analyzers.
    if ! have skill-scanner; then
        log_missing skill-scanner
        note "install with: pip install cisco-ai-skill-scanner"
        return 0
    fi
    note "cisco skill-scanner: scanning (primary engine for this mode)..."
    # skill-scanner's CLI surface can vary; try a reasonable invocation and
    # fall back to a permissive form.
    if ! skill-scanner "$RSS_SRC" --format json -o "$RSS_ART/skill_scanner.json" \
           > "$RSS_ART/skill_scanner.log" 2>&1; then
        # retry without -o flag, write stdout to file
        skill-scanner "$RSS_SRC" --format json > "$RSS_ART/skill_scanner.json" \
           2>> "$RSS_ART/skill_scanner.log" || log_failed "skill-scanner" $?
    fi
}

run_semgrep_skill() {
    if ! have semgrep; then log_missing semgrep; return 0; fi
    note "semgrep: skill-specific rules..."
    semgrep scan \
        --config "$RSS_RULES/semgrep_custom/skill_threats.yml" \
        --config "$RSS_RULES/semgrep_custom/malice.yml" \
        --json --output "$RSS_ART/semgrep.json" \
        --metrics=off --quiet --timeout 30 --timeout-threshold 3 \
        "$RSS_SRC" > "$RSS_ART/semgrep.log" 2>&1
    rc=$?
    if [[ $rc -gt 1 ]]; then log_failed semgrep $rc; fi
}

run_gitleaks() {
    if ! have gitleaks; then log_missing gitleaks; return 0; fi
    note "gitleaks: secrets scan..."
    if [[ -e "$RSS_SRC/.git" ]]; then
        gitleaks detect --source "$RSS_SRC" --no-banner \
            --report-format json --report-path "$RSS_ART/gitleaks.json" \
            --log-opts="--all" > "$RSS_ART/gitleaks.log" 2>&1
    else
        gitleaks detect --source "$RSS_SRC" --no-banner --no-git \
            --report-format json --report-path "$RSS_ART/gitleaks.json" \
            > "$RSS_ART/gitleaks.log" 2>&1
    fi
    rc=$?
    if [[ $rc -gt 1 ]]; then log_failed gitleaks $rc; fi
}

check_skill_manifests() {
    # Emit a manifest inventory JSON for the report — confirms we're actually
    # looking at skill content, and shows any unusual declarations.
    python3 - <<'PY' "$RSS_SRC" "$RSS_ART/skill_manifest.json"
import json, os, sys, re
from pathlib import Path

src = Path(sys.argv[1])
out = Path(sys.argv[2])

manifests = []
# Common skill locations
for pat in [".claude/skills", ".claude/commands", ".claude/hooks",
            ".codex/skills", ".cursor/rules",
            "skills", "commands"]:
    d = src / pat
    if d.is_dir():
        for entry in sorted(d.rglob("*")):
            if entry.is_file() and entry.name in ("SKILL.md", "skill.yaml", "skill.yml",
                                                   "command.md", "rules.md",
                                                   "package.json", "manifest.json"):
                manifests.append(str(entry.relative_to(src)))

# Top-level SKILL.md (common for skill-repo root)
for skill_md in list(src.rglob("SKILL.md"))[:50]:
    rel = str(skill_md.relative_to(src))
    if rel not in manifests:
        manifests.append(rel)

# Extract frontmatter names/descriptions for visibility
skills = []
for m in manifests:
    p = src / m
    try:
        text = p.read_text(encoding="utf-8", errors="replace")[:8192]
    except OSError:
        continue
    fm_match = re.match(r"^---\s*\n(.*?)\n---\s*", text, re.DOTALL)
    meta = {}
    if fm_match:
        for line in fm_match.group(1).splitlines():
            k, _, v = line.partition(":")
            if k and v:
                meta[k.strip()] = v.strip().strip('"').strip("'")
    skills.append({"manifest": m, "name": meta.get("name"), "description": meta.get("description")})

print(f"found {len(skills)} skill manifest(s)", file=sys.stderr)
with open(out, "w") as f:
    json.dump({"manifests": skills, "count": len(skills)}, f, indent=2)
PY
}

# -------- Run --------
check_skill_manifests
run_skill_scanner &
pid_ss=$!
run_semgrep_skill &
pid_sg=$!
run_gitleaks &
pid_gl=$!

wait "$pid_ss" 2>/dev/null
wait "$pid_sg" 2>/dev/null
wait "$pid_gl" 2>/dev/null

exit 0
