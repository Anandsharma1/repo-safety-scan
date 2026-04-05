# Triage Playbook — How to read the report

The report has four sections. Read them in order:

## 1. Verdict

One of:

| Verdict | Meaning | Action |
|---|---|---|
| **CRITICAL** | ≥1 critical finding (hostile git config, reverse shell, exec-base64, exfil to outbound HTTP, GHSA-class repo config) | **Do not run outside a locked-down sandbox.** Re-check the specific finding file:line. |
| **HIGH** | ≥1 high-severity finding (secrets in tree/history, cred-file read, install-time network, unusual MCP tool) | **Manual review before running.** Walk the top concerns. |
| **MEDIUM** | 3+ medium findings, or ≥1 medium finding (e.g., pickle load, env-http, shell-rc persistence) | **Skim evidence.** Decide per-concern whether it's intended. |
| **LOW** | Few/no findings from scanners that ran | **Not a certification of safety.** Check which scanners ran — a LOW with 4/5 scanners missing is a thin scan. |

## 2. Scanners

Confirms which tools actually ran. Entries:

- `ok` — ran, produced findings
- `no-findings` — ran, found nothing (good)
- `missing (install to enable)` — tool not installed
- `failed (see errors.log)` — tool ran but crashed

**A verdict derived from 1–2 scanners is weak.** If scanners are missing,
install them (`references/installation.md`) and rerun.

## 3. Top Concerns

Up to 10 findings, highest severity first, with:

- `[SEV]` severity marker
- **rule-id** (which detector fired)
- **tool** that produced it
- `file:line` — where to look
- why it matters
- evidence snippet

**Triage each concern:**

1. **Open the file at the exact line.** The evidence snippet is short;
   the surrounding code often resolves whether it's intentional.
2. **Ask: is this reachable?** Dead code, test fixtures, and
   example/demo files produce benign-looking "malware" patterns.
   Check if the file is imported, run, or packaged.
3. **Ask: does the README disclose this behavior?** A tool that reads
   `~/.aws/credentials` is fine if it's an AWS SDK wrapper and says so;
   it's exfiltration if the README claims "local-only."
4. **Ask: is the destination known?** For network calls, who's the other
   end? `pypi.org`, official release hosts, etc. are different from
   pastebin / discord webhook / raw IPs.

## 4. All findings (collapsed)

Every rule hit from every scanner. Use this to:

- Look for clusters (5 hits from one file = that file is the problem).
- Check if a pattern repeats across files (a single import being flagged
  everywhere may be a rule tuning issue, not malice).

## Common false-positive patterns

| You see | It might be | Check |
|---|---|---|
| `pickle.load` in an ML repo | Loading model weights | Is the file coming from HuggingFace or a trusted CDN? Is `weights_only=True` set? |
| `subprocess` + `socket` in tests | Testing a TCP server | Is it under `tests/` or `test_*.py`? |
| Base64 string in SKILL.md | An example payload *being documented* | Read surrounding text — is it labeled as an example? |
| `~/.aws/credentials` reference in a deploy script | CI script mounting AWS creds | Check the repo's stated purpose |
| `exec(...)` in a dynamic-dispatch codebase | Plugin loader | Check whether the input to exec is controlled |

## When the report says LOW but you're still uneasy

`LOW` is the weakest verdict — it means "the scanners we ran found nothing
material." It's not a clean bill of health. Consider:

- Run with more scanners installed.
- Run a deeper audit (CodeQL with custom suspicious-pattern queries).
- Run in a sandbox (see report's sandbox recipe).
- Read the code yourself for sensitive operations.

## When to escalate

If the repo is CRITICAL or HIGH and you still want to run it:

1. Use the sandbox recipe from the report.
2. Disable outbound network unless the code's stated purpose needs it.
3. Use a throwaway container identity — not your user account.
4. Capture process/file/network logs; review post-run.

For truly suspicious content, consider the forensic workflow in
`gl0bal01/malware-analysis-claude-skills` rather than running here.
