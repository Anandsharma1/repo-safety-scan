---
name: repo-safety-scan
description: Use when the user wants to scan a downloaded GitHub repo, local directory, or agent-skill pack for malicious code — secret exfiltration, backdoors, install-time mischief, hostile git metadata, or prompt-injection patterns in skill files. Triggered by phrases like "scan this repo", "is this safe to run", "check for malware", "audit this code", "review this skill before I install it".
---

# repo-safety-scan

Triage-level malicious-code scanner. Composes existing scanners (Cisco
skill-scanner, Semgrep, Gitleaks, OSV-Scanner, Guarddog) with malice-focused
custom rules and a hostile-git-metadata check, then produces a single
verdict report.

## When to use

- User has just cloned or downloaded a repo and asks if it's safe to run.
- User is about to install an agent skill (Claude / Codex / Cursor / MCP)
  and wants to audit it first.
- User mentions specific concerns: leaked secrets, backdoors, obfuscated
  payloads, exfiltration, prompt injection, hostile `.git/config`.

**Do not use** for general code-quality review or CVE-only scans — those
are different jobs (see `/security-review` or `osv-scanner` alone).

## Modes

| Mode | When | Primary tools |
|---|---|---|
| `repo` (default) | General source repo / downloaded code | gitleaks, semgrep (public + custom malice rules), osv-scanner, guarddog (if manifests), git-metadata scan |
| `skill` | Agent-skill packs (`.claude/`, `.codex/`, `.cursor/`, MCP servers, SKILL.md present) | **Cisco skill-scanner (primary)**, semgrep skill-specific rules, gitleaks, manifest inventory |

`repo` mode auto-detects skill-like content and also invokes Cisco
skill-scanner inline when it finds it.

## Invocation

```bash
# Default mode = repo
bin/repo-safety-scan <url-or-path>

# Explicit mode
bin/repo-safety-scan repo  <url-or-path>
bin/repo-safety-scan skill <url-or-path>

# Keep workdir (default: auto-cleanup if we made a /tmp dir)
bin/repo-safety-scan repo <path> --out ./scan-results --keep
```

Targets: HTTPS/SSH git URLs **or** local directory paths.

## Safety guarantees (always on)

- **No target code execution.** Never runs `pip install` / `npm install` /
  `setup.py` / `make` / `docker build`.
- **Git hooks disabled on clone** (`core.hooksPath=/dev/null`); no
  submodules; shallow history; 500 MB size cap.
- **Git metadata scan** (`.git/config`, `.gitattributes`, `.git/hooks/`) runs
  regardless of mode — catches GHSA-j4h9-wv2m-wrf7-class attacks.

## How Claude should use this skill

1. **Confirm intent.** Before scanning, confirm with the user what they
   want scanned (URL or path) and which mode. If they don't say, default
   to `repo` and mention you're doing so.
2. **Run the CLI.** Execute `bin/repo-safety-scan <mode> <target> --keep`
   via the Bash tool. Capture the workdir path from the output.
3. **Read the report.** `$WORKDIR/report.md` has the verdict, top concerns,
   and scanner status. Quote the verdict and top concerns to the user.
4. **Surface missing scanners.** If the Scanners table shows tools as
   `missing`, tell the user what to install — see `references/installation.md`.
   A scan missing 4/5 scanners is a thin scan; say so.
5. **Offer the sandbox recipe** only if the verdict is MEDIUM or higher.
6. **Never certify "safe".** The scanner is a triage filter. Use language
   like "no material findings from the scanners that ran" — not "safe".

## Output

Single markdown report at `$WORKDIR/report.md` containing:

- Verdict (LOW / MEDIUM / HIGH / CRITICAL) with reasoning.
- Scanners table (which tools ran, which were missing).
- Top Concerns (highest severity first, capped at 10, with file:line + evidence).
- Full findings table (collapsed `<details>`).
- Sandbox recipe for if the user proceeds.

Raw scanner JSON outputs stay in `$WORKDIR/artifacts/` for deeper triage.

## Prerequisites

The skill will run even when scanners are missing — it just does less.
For a full `repo` scan install: `semgrep`, `gitleaks`, `osv-scanner`,
`guarddog` (pip). For `skill` mode install: `cisco-ai-skill-scanner` (pip)
in addition. See `references/installation.md`.

## References

- `references/threat_taxonomy.md` — what we look for and why
- `references/installation.md` — scanner install commands
- `references/triage_playbook.md` — how to read the report
