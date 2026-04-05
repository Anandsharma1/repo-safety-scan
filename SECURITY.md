# Security Policy

## Reporting a vulnerability in repo-safety-scan

**Use GitHub's private vulnerability reporting:**
https://github.com/Anandsharma1/repo-safety-scan/security/advisories/new

Do **not** file public issues for security bugs. Public issues are fine
for false positives, false negatives, and missing coverage — those are
tuning problems, not vulnerabilities.

Best-effort response. This is a personal OSS project; there is no paid
support or SLA.

## What's in scope

Issues in this scanner's own code paths:

- **Sandbox-escape / code-execution via the target repo.** The scanner
  reads untrusted repo content; any path where the target can cause
  host-side code execution is in scope. Examples: command injection in
  `bin/repo-safety-scan`, path traversal via `--out`, git clone
  side-effects that bypass `core.hooksPath=/dev/null`.
- **Prompt injection surviving into downstream LLMs.** The scanner is
  designed so that target-repo text never drives LLM control flow;
  findings are delivered as structured JSON. If you can break that
  invariant — e.g., make a finding's `why`/`match` field carry prompt
  instructions that an LLM consumer would execute — that's in scope.
- **Verdict manipulation.** If a crafted repo can cause the scanner to
  emit **LOW** / **CRITICAL** contrary to its actual findings
  (e.g., by crashing a sub-scanner in a way that hides real hits, or
  poisoning `render_report.py` with a crafted scanner JSON), that's in
  scope.
- **Parser / ingest bugs.** `.git/config` parser misreading hostile
  directives, symlink traversal during ingest, size-cap bypass, etc.

## What's out of scope

- **False positives and false negatives.** File a public issue with
  a minimal fixture; include the target's relevant snippet.
- **Bugs in the tools we wrap** — report those to the respective
  upstream projects (Cisco `skill-scanner`, Semgrep, Gitleaks,
  OSV-Scanner, Guarddog).
- **Requests for new rules / new threat categories.** File a public
  issue.
- **"The scanner didn't detect X on repo Y."** That's a coverage issue,
  not a vulnerability. File it publicly.

## Scanner hardening posture

The scanner itself consumes hostile content. Defensive invariants:

- Target repo code is never executed (no `pip install` / `npm install` /
  `setup.py` / `make` / `docker build`).
- Git hooks are disabled on clone (`core.hooksPath=/dev/null`);
  submodules are not recursed; clone depth is capped; a 500 MB size cap
  is enforced.
- `.git/config` is parsed with section-aware matching; hostile
  directives are reported, not executed.
- Scanner output is structured (JSON + markdown with fenced evidence
  snippets). The LLM consumer layer is expected to treat all finding
  fields as data, not instructions.

If you find a place where these invariants can be violated, please
report it via the private advisory flow above.

## Please run the scanner itself inside a container

Even with the hardening above, a scanner that reads untrusted content
is attack surface. See `references/installation.md` for a podman recipe.
