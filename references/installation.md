# Installing the scanners

`repo-safety-scan` orchestrates existing tools rather than reimplementing
them. Install the scanners you want to enable. Missing tools are flagged
in the report but don't block a scan.

## `repo` mode (recommended minimum)

```bash
# Semgrep — pattern matching (public rulesets + custom malice rules)
pip install semgrep

# Gitleaks — secrets in working tree + git history
#   macOS:   brew install gitleaks
#   Linux:   https://github.com/gitleaks/gitleaks/releases (static binary)
#   Go:      go install github.com/gitleaks/gitleaks/v8@latest

# OSV-Scanner — known-vulnerable dependencies
#   macOS:   brew install osv-scanner
#   Linux:   https://github.com/google/osv-scanner/releases
#   Go:      go install github.com/google/osv-scanner/cmd/osv-scanner@v2
```

## `repo` mode (extra, ecosystem-specific)

```bash
# Guarddog — malicious PyPI/npm/Go package heuristics
#   Only runs if pyproject.toml / setup.py / package.json / go.mod present
pip install guarddog
```

## `skill` mode (required)

```bash
# Cisco skill-scanner — primary engine for agent-skill packs
pip install cisco-ai-skill-scanner
```

## Verifying installation

```bash
# Should all print a version number
semgrep --version
gitleaks version
osv-scanner --version
guarddog --version
skill-scanner --version
```

## Network access during scan

Semgrep pulls registry rulesets (`p/trailofbits`, `p/r2c-security-audit`,
`p/supply-chain`) on first use. You can pre-cache them with
`semgrep scan --config p/trailofbits --config p/r2c-security-audit --config p/supply-chain --help`
on a trusted machine.

Gitleaks, OSV-Scanner, Guarddog, and skill-scanner do not require network
access at scan time (beyond Guarddog's initial rule fetch).

`--metrics=off` is passed to semgrep so it does not phone home.

## Running the scanner in a container (recommended)

The scanner itself reads hostile content — running it in a container
limits blast radius.

```bash
# Minimal sandbox for the scanner
podman run --rm -it \
  --network=bridge \
  -v "$(pwd):/src" \
  -v "$(pwd)/repo-safety-scan:/scanner:ro" \
  python:3.12-slim bash -c "
    apt-get update && apt-get install -y git curl && \
    pip install semgrep cisco-ai-skill-scanner && \
    /scanner/bin/repo-safety-scan repo /src
  "
```
