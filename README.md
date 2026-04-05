# repo-safety-scan

Triage-level malicious-code scanner for downloaded GitHub repos and
agent-skill packs. Composes existing scanners with malice-focused custom
rules and a hostile-git-metadata check, then produces a single verdict
report with file:line evidence.

> Not a safety certification. Scanners catch obvious malice; a clean report
> does not prove a repo is safe.

## Why this exists

When you `git clone` something from a stranger, you want a fast answer to
*"is this safe to run?"* The detection engines already exist (Semgrep,
Gitleaks, OSV-Scanner, Guarddog, Cisco's skill-scanner). The orchestration
into a single go/no-go verdict for a developer who just cloned something
does not. This fills that gap.

Two target shapes are supported with distinct threat models:

| Mode | When to use | Primary detectors |
|---|---|---|
| `repo` *(default)* | Any downloaded source tree | Gitleaks, Semgrep (public + custom malice rules), OSV-Scanner, Guarddog (if manifests present), hostile-git-metadata scan |
| `skill` | Agent-skill packs (`.claude/`, `.codex/`, `.cursor/`, MCP servers, `SKILL.md` present) | **Cisco skill-scanner (primary)**, Semgrep skill-specific rules, Gitleaks, manifest inventory |

`repo` mode auto-detects skill-like content (`.claude/skills/`,
`SKILL.md`, etc.) and also invokes Cisco skill-scanner inline.

## Quick start

```bash
# Default mode is 'repo'
bin/repo-safety-scan <url-or-path>

# Explicit modes
bin/repo-safety-scan repo  <url-or-path>
bin/repo-safety-scan skill <url-or-path>

# Keep the workdir (default: auto-clean if we made a /tmp dir)
bin/repo-safety-scan repo <path> --out ./scan-results --keep
```

Targets: HTTPS/SSH git URLs **or** local directory paths.

The scanner runs whatever is installed. Missing scanners appear as
`missing (install to enable)` in the report and do not block a scan.
For full coverage, install the prerequisites:

```bash
pip install semgrep guarddog cisco-ai-skill-scanner
# gitleaks and osv-scanner: see references/installation.md (native binaries)
```

## Safety guarantees (always on)

- **No target code execution.** Never runs `pip install` / `npm install` /
  `setup.py` / `make` / `docker build`. Clone-only ingest.
- **Git hooks disabled on clone.** `core.hooksPath=/dev/null`, no
  submodules, shallow history, 500 MB size cap.
- **Hostile-git-metadata scan runs regardless of mode.** Parses
  `.git/config`, `.git/info/attributes`, and `.gitattributes` with
  section-aware matching; flags `core.sshCommand`, `core.fsmonitor`,
  `core.hooksPath`, `credential.helper`, `credential.<url>.helper`,
  `[protocol "ext"] allow = always`, `includeIf`, `filter.*.clean/smudge`,
  and similar directives — the GHSA-j4h9-wv2m-wrf7 attack class.
- **Worktree/submodule aware.** If `.git` is a file pointing at an
  external gitdir, the scanner resolves it and includes its config,
  `config.worktree`, and `info/attributes` in the scan.

## How the scanner itself is hardened

The target repo's text is **untrusted input**. READMEs, comments, and
docstrings can contain prompt-injection content. The scanner:

- Consumes tool output as structured JSON, never as free-form text
- Uses deterministic rules to produce the verdict; the LLM layer (if
  present in the consuming skill) can only downgrade findings to
  false-positive, never invent or upgrade them
- Reports findings with file:line + rule-id + evidence snippet pulled
  from the source at the reported line

Still, run the scanner itself inside a container when pointing it at
untrusted content. See `references/installation.md` for a podman recipe.

## Repository layout

```
SKILL.md                             Claude Code skill manifest
bin/repo-safety-scan                 portable CLI dispatcher
lib/git_metadata.py                  section-aware .git/config scanner (always on)
lib/render_report.py                 unified markdown report generator
lib/modes/repo.sh                    general-repo scan mode
lib/modes/skill.sh                   agent-skill-pack scan mode
rules/semgrep_custom/malice.yml      custom malice patterns (reverse shells, exfil, pickle, etc.)
rules/semgrep_custom/skill_threats.yml skill-specific rules (prompt injection, hook abuse, etc.)
references/threat_taxonomy.md        what we look for and why
references/installation.md           prerequisite install commands
references/triage_playbook.md        how to read the report
tests/run_tests.sh                   regression tests (synthetic fixtures)
```

## Testing

```bash
bash tests/run_tests.sh
```

32 regression tests covering every rule path and parser bug fixed to
date. Synthetic fixtures for hostile gitconfig variations, `.git`-as-file
(worktrees/submodules), guarddog schema shapes, semgrep evidence
fallback, and skill-hook-network-call true-positive vs false-positive
discrimination.

## Limitations

- **Not a safety certification.** A LOW verdict means "the scanners that
  ran found nothing material," not "safe."
- **Static-only.** No dynamic analysis or install-script detonation
  (that's OpenSSF Package Analysis territory).
- **No provenance check.** Doesn't look at repo age / stars / maintainer
  account age (planned).
- **Scanners carry their own false-positive profiles.** Public rulesets
  like `p/trailofbits` include code-quality patterns that aren't malice;
  use the triage playbook to separate signal from noise.

## Acknowledgements

This scanner is **composition, not reinvention.** It orchestrates and
reuses the detection engines built by others. All tools below are invoked
via their public CLIs with no modifications.

**Detection engines wrapped as subprocesses:**

- [Cisco AI Defense — `skill-scanner`](https://github.com/cisco-ai-defense/skill-scanner)
  (PyPI: [`cisco-ai-skill-scanner`](https://pypi.org/project/cisco-ai-skill-scanner/))
  — primary engine for `skill` mode; auto-invoked in `repo` mode when
  skill-like content is detected.
- [Semgrep (Semgrep Inc., formerly r2c)](https://github.com/semgrep/semgrep)
  — pattern-matching engine used with public rulesets plus our custom
  rules. Apache-2.0.
- [Gitleaks](https://github.com/gitleaks/gitleaks) (Zachary Rice)
  — secret scanning across working tree and full git history. MIT.
- [OSV-Scanner](https://github.com/google/osv-scanner) (Google)
  — known-vulnerable-dependency detection. Apache-2.0.
- [Guarddog](https://github.com/DataDog/guarddog) (Datadog)
  — malicious-package heuristics for PyPI / npm / Go / RubyGems / GitHub
  Actions / VS Code extensions. Apache-2.0.

**Public rulesets consumed via `semgrep --config`:**

- [`p/trailofbits`](https://semgrep.dev/p/trailofbits) — Trail of Bits
- [`p/r2c-security-audit`](https://semgrep.dev/p/r2c-security-audit) — Semgrep / r2c
- [`p/supply-chain`](https://semgrep.dev/p/supply-chain) — Semgrep

**Prior art that shaped the design (referenced, not embedded):**

- [gl0bal01/malware-analysis-claude-skills](https://github.com/gl0bal01/malware-analysis-claude-skills)
  — forensic-triage workflow; our suggested escalation path for samples
  that need detonation.
- [anthropics/claude-code-security-review](https://github.com/anthropics/claude-code-security-review)
  and the [Claude Code `/security-review`](https://docs.anthropic.com/en/docs/claude-code/security)
  command — complementary vulnerability-review layer (different job,
  runs alongside).
- [Repello AI — Claude Code Skill Security](https://repello.ai/blog/claude-code-skill-security)
  — threat-model article that informed our skill-specific rules.
- [OpenSSF Package Analysis](https://github.com/ossf/package-analysis)
  — the architectural model for future sandboxed detonation.
- [GHSA-j4h9-wv2m-wrf7](https://github.com/advisories/GHSA-j4h9-wv2m-wrf7)
  — the hostile-repo-config bug in Claude Code that drives the
  always-on git-metadata scan.

## License

Not yet declared. Treat as "all rights reserved" until a LICENSE file is
added. (MIT or Apache-2.0 are natural fits given the dependencies; will
pick one before tagging a release.)
