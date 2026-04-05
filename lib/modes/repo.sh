#!/usr/bin/env bash
# repo mode — general source-repo scan.
#
# Runs in parallel: gitleaks (secrets, full history), semgrep (public rulesets
# + custom malice rules), osv-scanner (known CVEs), guarddog (conditional on
# PyPI/npm/Go manifests). Also triggers cisco skill-scanner if skill-like
# folders are detected.
#
# Inputs (env vars, set by bin/repo-safety-scan):
#   RSS_SRC    path to ingested source tree
#   RSS_ART    path to artifacts dir (tool JSON outputs go here)
#   RSS_RULES  path to custom rules dir
#   RSS_MODE   "repo"
#
# Every tool failure is non-fatal: we log to $RSS_ART/errors.log and keep going.
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

run_gitleaks() {
    if ! have gitleaks; then log_missing gitleaks; return 0; fi
    note "gitleaks: scanning (with --log-opts=--all for full history)..."
    # detect mode scans entire repo; --no-git disabled so history is included
    if [[ -d "$RSS_SRC/.git" ]]; then
        gitleaks detect --source "$RSS_SRC" --no-banner \
            --report-format json --report-path "$RSS_ART/gitleaks.json" \
            --log-opts="--all" \
            > "$RSS_ART/gitleaks.log" 2>&1
    else
        # no git — scan working tree only
        gitleaks detect --source "$RSS_SRC" --no-banner --no-git \
            --report-format json --report-path "$RSS_ART/gitleaks.json" \
            > "$RSS_ART/gitleaks.log" 2>&1
    fi
    rc=$?
    # gitleaks exits 1 when leaks found, 0 when clean, >1 on error
    if [[ $rc -gt 1 ]]; then log_failed gitleaks $rc; fi
}

run_semgrep() {
    if ! have semgrep; then log_missing semgrep; return 0; fi
    note "semgrep: scanning (public rulesets + custom malice rules)..."
    # Configs: public malice-relevant rulesets + our custom ones.
    # Use --metrics=off to avoid network calls. --error to treat findings as non-fatal via rc.
    semgrep scan \
        --config "p/trailofbits" \
        --config "p/r2c-security-audit" \
        --config "p/supply-chain" \
        --config "$RSS_RULES/semgrep_custom" \
        --json --output "$RSS_ART/semgrep.json" \
        --metrics=off --quiet --timeout 30 --timeout-threshold 3 \
        "$RSS_SRC" > "$RSS_ART/semgrep.log" 2>&1
    rc=$?
    # semgrep: 0=no findings, 1=findings, 2=error
    if [[ $rc -gt 1 ]]; then log_failed semgrep $rc; fi
}

run_osv() {
    if ! have osv-scanner; then log_missing osv-scanner; return 0; fi
    note "osv-scanner: scanning dependencies..."
    osv-scanner scan source --format json --output "$RSS_ART/osv.json" \
        "$RSS_SRC" > "$RSS_ART/osv.log" 2>&1
    rc=$?
    # osv-scanner: 0=no vulns, 1=vulns, >1=error
    if [[ $rc -gt 1 ]]; then log_failed osv-scanner $rc; fi
}

run_guarddog() {
    # guarddog has per-ecosystem commands. Only run if relevant manifests present.
    local ran=0
    if ! have guarddog; then
        # only complain if we would have run it
        if [[ -f "$RSS_SRC/pyproject.toml" || -f "$RSS_SRC/setup.py" || -f "$RSS_SRC/package.json" || -f "$RSS_SRC/go.mod" ]]; then
            log_missing guarddog
        fi
        return 0
    fi
    local combined="{}"
    if [[ -f "$RSS_SRC/pyproject.toml" || -f "$RSS_SRC/setup.py" ]]; then
        note "guarddog pypi: scanning local project..."
        guarddog pypi scan "$RSS_SRC" --output-format json > "$RSS_ART/guarddog_pypi.json" 2> "$RSS_ART/guarddog_pypi.log" || log_failed "guarddog pypi" $?
        ran=1
    fi
    if [[ -f "$RSS_SRC/package.json" ]]; then
        note "guarddog npm: scanning local project..."
        guarddog npm scan "$RSS_SRC" --output-format json > "$RSS_ART/guarddog_npm.json" 2> "$RSS_ART/guarddog_npm.log" || log_failed "guarddog npm" $?
        ran=1
    fi
    if [[ -f "$RSS_SRC/go.mod" ]]; then
        note "guarddog go: scanning local project..."
        guarddog go scan "$RSS_SRC" --output-format json > "$RSS_ART/guarddog_go.json" 2> "$RSS_ART/guarddog_go.log" || log_failed "guarddog go" $?
        ran=1
    fi
    # Merge available guarddog outputs into a single file for render_report.
    if [[ $ran -eq 1 ]]; then
        python3 - <<'PY' "$RSS_ART"
import json, os, sys
art = sys.argv[1]
merged = {}
for name in ("guarddog_pypi.json","guarddog_npm.json","guarddog_go.json"):
    p = os.path.join(art, name)
    if not os.path.isfile(p): continue
    try:
        with open(p) as f: data = json.load(f)
        if isinstance(data, dict): merged.update(data)
    except Exception:
        pass
with open(os.path.join(art, "guarddog.json"), "w") as f:
    json.dump(merged, f)
PY
    fi
}

maybe_run_skill_scanner_inline() {
    # If repo contains skill-like content, invoke Cisco skill-scanner inline.
    local trigger=0
    for d in ".claude/skills" ".claude/commands" ".codex/skills" ".cursor/rules"; do
        [[ -d "$RSS_SRC/$d" ]] && trigger=1
    done
    if find "$RSS_SRC" -maxdepth 3 -name "SKILL.md" -print -quit 2>/dev/null | grep -q .; then
        trigger=1
    fi
    if [[ $trigger -eq 0 ]]; then return 0; fi

    note "repo contains skill-like content — auto-invoking cisco skill-scanner..."
    if have skill-scanner; then
        skill-scanner "$RSS_SRC" --format json -o "$RSS_ART/skill_scanner.json" \
            > "$RSS_ART/skill_scanner.log" 2>&1 || log_failed "skill-scanner" $?
    else
        log_missing skill-scanner
    fi
}

# -------- Run in parallel --------
run_gitleaks &
pid_gl=$!
run_semgrep &
pid_sg=$!
run_osv &
pid_osv=$!
run_guarddog &
pid_gd=$!

wait "$pid_gl" 2>/dev/null
wait "$pid_sg" 2>/dev/null
wait "$pid_osv" 2>/dev/null
wait "$pid_gd" 2>/dev/null

# Sequential after the parallel batch (cheap, <10s normally)
maybe_run_skill_scanner_inline

exit 0
