# Threat Taxonomy

What `repo-safety-scan` looks for, why each category matters, and which
scanner catches it.

| Category | Concrete patterns | Caught by |
|---|---|---|
| **Secret exfiltration** | `os.environ` → outbound HTTP; reads of `~/.ssh`, `~/.aws`, `.env`, `~/.netrc`, keychains, browser profiles, crypto wallets | `malice.yml` (py-credential-file-read, py-env-to-outbound-http), gitleaks, public semgrep rules |
| **Reverse shells / backdoors** | `socket`+`subprocess`, `/dev/tcp/`, `bash -i >&`, `pty.spawn`, `nc -e`, `powershell -enc` | `malice.yml` (py-reverse-shell-socket-subprocess, bash-reverse-shell) |
| **Obfuscation / packed payloads** | `exec(base64.b64decode(...))`, `eval(atob(...))`, hex/rot payloads, runtime-downloaded code | `malice.yml` (py-exec-base64-obfuscation, py-exec-compile-runtime-download) |
| **Install-time mischief** | `setup.py`/`postinstall`/`preinstall` with network I/O; `package.json` scripts fetching binaries | `malice.yml` (py-install-time-network), guarddog |
| **Hostile git metadata** | `.git/config` `core.sshCommand`/`core.fsmonitor`/`includeIf`/`core.hooksPath`; `.gitattributes` with `filter=`; `.git/hooks/` content (GHSA-j4h9-wv2m-wrf7 class) | `lib/git_metadata.py` (always on) |
| **Unsafe deserialization** | `pickle.load/loads`, `torch.load(weights_only=False)`, `joblib.load`, `yaml.load` without SafeLoader | `malice.yml` (py-unsafe-pickle-load, py-torch-load-without-weights-only) |
| **Persistence** | Writes to shell rc, cron, systemd, launchd, registry Run keys, startup folders | `malice.yml` (py-shell-rc-persistence) |
| **Prompt injection (skill)** | Skill instructions attempting to redefine role, ignore system prompt, or reveal it | `skill_threats.yml` (skill-prompt-injection-role-switch) |
| **Skill hook abuse** | `.claude/hooks/*` or `.codex/hooks/*` with outbound network calls | `skill_threats.yml` (skill-hook-network-call) |
| **Packed skill payloads** | Long base64 strings embedded in SKILL.md / skill.yaml | `skill_threats.yml` (skill-contains-base64-payload) |
| **Skill → credential access** | Skill instruction files referencing `~/.ssh`, `~/.aws`, exfiltration language | `skill_threats.yml` (skill-instructs-credential-read) |
| **Destructive skill ops** | `rm -rf /`, fork bombs, disk-wipers embedded in skill text | `skill_threats.yml` (skill-instructs-rm-rf) |
| **MCP server unrestricted exec** | MCP server registering raw shell tools or unvalidated command execution | `skill_threats.yml` (mcp-server-dangerous-tool) |
| **Known-vulnerable dependencies** | CVEs in declared deps (pyproject, package.json, go.sum, etc.) | osv-scanner |
| **Malicious packages** | PyPI/npm/Go packages matching known-bad patterns (typosquats, suspicious postinstall) | guarddog, cisco skill-scanner |
| **Secrets in git history** | API keys, tokens, certs committed to any branch / tag / note | gitleaks (with `--log-opts=--all`) |
| **Skill-format threats** | Prompt injection, tool-registration abuse, agent-skill-specific patterns | Cisco skill-scanner (primary in skill mode) |

## What we deliberately DON'T cover

- **Generic code vulnerabilities** (SQL injection, XSS, path traversal, weak
  crypto). Use `p/r2c-security-audit`, `p/trailofbits` (already pulled in
  for `repo` mode), Bandit, or the Claude Code `/security-review` command.
- **Dynamic behavior.** We never execute the target. Runtime detonation
  (OpenSSF Package Analysis style) is Phase 3.
- **Provenance signals** (repo age, stars, maintainer age). Phase 2 —
  requires GitHub API access.
- **README-vs-behavior diffing** (does the code do what the docs say?).
  Phase 2 — requires LLM triage pass.

## Why rules-first, LLM-second

All verdicts in this scanner are rule-derived. If an LLM triage pass is
added later, its job is to *downgrade* false positives, never to invent or
upgrade findings. Rationale: the target repo is untrusted input; its
README/comments/code can contain prompt-injection text. Never let repo text
drive an LLM's control flow.
