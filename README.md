# CI/CD Pipeline Security Auditor

A Python CLI that scans GitHub Actions workflows for suspected secrets, mutable dependencies, injection patterns, and risky permissions before deployment.

## What this actually is

A security lab built around vulnerable configurations, detection rules, and verified fixes. The scanner reads YAML without executing workflow commands. All sample credentials are fake.

## What it checks

- Suspected hardcoded credentials in fields and inline assignments.
- External actions and reusable workflows without full commit pins; containers without SHA-256 digests.
- Untrusted GitHub expressions interpolated into shell scripts.
- Broad token permissions, privileged PR checkouts, and self-hosted PR runners.

Findings include a rule ID, severity, source location, and suggested fix. Output: terminal, JSON, or SARIF. Configuration values are omitted from reports.

## Setup — Windows / VS Code

Install Python 3.14, open this folder, and run:

```powershell
py -3.14 -m venv .venv314
.\.venv314\Scripts\python.exe -m pip install -r requirements.txt
```

## Run the lab

```powershell
# Vulnerable example: 4 findings, exit 1
.\.venv314\Scripts\python.exe auditor.py examples\insecure.yml

# Corrected example: 0 findings, exit 0
.\.venv314\Scripts\python.exe auditor.py examples\secure.yml

# Save a report
.\.venv314\Scripts\python.exe auditor.py examples\insecure.yml --format json --output reports\scan.json

# Regression tests
.\.venv314\Scripts\python.exe -m unittest discover -s tests -v
```

Pass files or directories; directories are searched recursively for YAML. With no target, the CLI scans `.github/workflows`. `--fail-on high` changes the threshold; `--fail-on none` reports findings without failing. Exit codes: **0** below threshold, **1** findings at/above threshold, **2** incomplete scan or input/output error.

Other YAML pipelines: `--kind generic` provides **secret heuristics only**, not GitLab/Azure-specific security analysis. Jenkinsfiles are unsupported.

## Results

**39 regression tests passed locally on Windows.** Basic lab: 4 → 0 findings. Advanced lab: 7 → 0. The active CI configuration also passes its local scan. See [full report](REPORT.md) and [captured evidence](reports/execution-log.json).

## GitHub Actions

`.github/workflows/audit.yml` runs tests and audits active workflows on pushes and pull requests. After publishing, make **Audit and regression tests** a required check in repository rules. Hosted CI and branch protection have not been exercised or configured here.

## Limits

Pattern-based findings need review. No credential validation, Git-history scan, full shell/data-flow analysis, transitive dependency scan, or SHA provenance verification. YAML aliases/merges and unsupported tags fail explicitly. Files are limited to 2 MiB. A clean scan is not proof of security.

## Project structure

```text
auditor.py            Scanner and CLI
examples/             Vulnerable/corrected YAML pairs
tests/                Behavioral regression tests
.github/workflows/    CI security check
reports/              Captured local results
REPORT.md             Methodology, findings, fixes, limitations
requirements.txt      Pinned dependency
```
