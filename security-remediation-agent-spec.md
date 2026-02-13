# Security Remediation Agent — Implementation Spec

## Overview

Build a reusable GitHub Actions workflow and supporting Python agent that automatically remediates IaC security findings from **Checkov** and **Trivy**. The agent uses the **Anthropic API** (Claude) to generate minimal, targeted fixes for each finding, then verifies the fixes by re-running the scanner.

This is designed to plug into existing CI/CD pipelines that already run Checkov and/or Trivy as reusable workflows.

**Dependency vulnerabilities (SCA) are explicitly out of scope** — those should be handled by Renovate or Dependabot, not an LLM. If Trivy vulnerability scan results are passed in, the agent flags them in the PR summary without attempting remediation.

---

## Architecture

```
Scanner (Checkov / Trivy IaC / Trivy Vuln)
        │
        ▼
   Output Parser (per-tool adapter)
        │
        ▼
   Normalized Findings Format
        │
        ▼
   Triage (config-driven: fix / skip / human / ignore)
        │
        ▼
   Remediation Agent (Claude API, batched by file)
        │
        ▼
   Verification Loop (re-run scanner → retry if still failing)
        │
        ▼
   Commit fixes to PR branch + post PR summary comment
```

### Key design principles

1. **Tool-agnostic core** — Scanners are abstracted behind parser adapters that emit a normalized finding format. Adding a new scanner means writing one parser function.
2. **Batch by file** — Multiple findings in the same file are sent to Claude in a single API call. This gives Claude full file context, avoids conflicting edits, and reduces cost.
3. **Config-driven triage** — A YAML config file controls which checks are auto-fixed, auto-skipped (with reason), escalated to humans, or ignored entirely. Anything not listed defaults to "let Claude try."
4. **Verify then retry** — After remediation, the scanner re-runs against modified files. Still-failing checks get one retry with additional context telling Claude what it tried before. After that, failures escalate to human review.
5. **Agent never merges** — It commits to the PR branch and posts a summary comment. A human must review and approve.

---

## File Structure

```
.github/
├── workflows/
│   └── security-remediation.yml      # Reusable workflow (workflow_call)
├── scripts/
│   └── security_remediation_agent.py  # Python agent
└── security-remediation-config.yaml   # Triage rules
```

---

## 1. Reusable Workflow: `.github/workflows/security-remediation.yml`

This is a `workflow_call` workflow. Calling workflows run their scanner, upload results as an artifact, then call this workflow.

### Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `scanner` | yes | — | Scanner type: `checkov`, `trivy-iac`, or `trivy-vuln` |
| `results_artifact` | yes | — | Name of the uploaded artifact containing scan results |
| `results_file` | yes | — | Path to the results JSON file within the artifact |
| `config_file` | no | `.github/security-remediation-config.yaml` | Path to triage config |
| `dry_run` | no | `false` | If true, post comment only, don't commit |
| `max_findings` | no | `20` | Cap on findings to process (cost control) |
| `model` | no | `claude-sonnet-4-20250514` | Anthropic model to use |

### Secrets

| Secret | Required | Description |
|---|---|---|
| `anthropic_api_key` | yes | Anthropic API key |

### Workflow steps

1. **Checkout** the repo at the PR's head ref (needs `contents: write`)
2. **Download** the scan results artifact
3. **Install Python 3.12**, `anthropic`, `pyyaml`
4. **Install the scanner binary** for verification (Checkov via pip, Trivy via apt)
5. **Run the remediation agent** Python script
6. **Commit and push** if fixes were applied (as `security-remediation-bot`)
7. **Post PR comment** with the summary markdown (needs `pull-requests: write`)

### Caller example

```yaml
jobs:
  checkov-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Checkov
        uses: bridgecrewio/checkov-action@v12
        with:
          output_format: json
          output_file_path: reports/checkov_results.json
          soft_fail: true
      - uses: actions/upload-artifact@v4
        with:
          name: checkov-results
          path: reports/checkov_results.json

  remediate:
    needs: checkov-scan
    uses: ./.github/workflows/security-remediation.yml
    with:
      scanner: checkov
      results_artifact: checkov-results
      results_file: reports/checkov_results.json
    secrets:
      anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
```

### Full workflow YAML

```yaml
name: Security Finding Remediation

on:
  workflow_call:
    inputs:
      scanner:
        description: "Scanner that produced the results (checkov, trivy-iac, trivy-vuln)"
        required: true
        type: string
      results_artifact:
        description: "Name of the uploaded artifact containing scan results"
        required: true
        type: string
      results_file:
        description: "Path to results file within the artifact"
        required: true
        type: string
      config_file:
        description: "Path to remediation config YAML"
        required: false
        type: string
        default: ".github/security-remediation-config.yaml"
      dry_run:
        description: "If true, only post a PR comment with proposed fixes, don't commit"
        required: false
        type: boolean
        default: false
      max_findings:
        description: "Max number of findings to attempt remediation on"
        required: false
        type: number
        default: 20
      model:
        description: "Anthropic model to use"
        required: false
        type: string
        default: "claude-sonnet-4-20250514"
    secrets:
      anthropic_api_key:
        required: true

jobs:
  remediate:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}
          fetch-depth: 0

      - name: Download scan results
        uses: actions/download-artifact@v4
        with:
          name: ${{ inputs.results_artifact }}

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install dependencies
        run: pip install anthropic pyyaml

      - name: Install scanner for verification
        run: |
          case "${{ inputs.scanner }}" in
            checkov)
              pip install checkov
              ;;
            trivy-iac|trivy-vuln)
              sudo apt-get install -y wget apt-transport-https gnupg lsb-release
              wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
              echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/trivy.list
              sudo apt-get update && sudo apt-get install -y trivy
              ;;
          esac

      - name: Run remediation agent
        id: remediate
        env:
          ANTHROPIC_API_KEY: ${{ secrets.anthropic_api_key }}
          SCANNER: ${{ inputs.scanner }}
          RESULTS_FILE: ${{ inputs.results_file }}
          CONFIG_FILE: ${{ inputs.config_file }}
          DRY_RUN: ${{ inputs.dry_run }}
          MAX_FINDINGS: ${{ inputs.max_findings }}
          MODEL: ${{ inputs.model }}
        run: python .github/scripts/security_remediation_agent.py

      - name: Commit fixes
        if: inputs.dry_run == false && steps.remediate.outputs.fixes_applied > 0
        run: |
          git config user.name "security-remediation-bot"
          git config user.email "security-bot@users.noreply.github.com"
          git add -A
          git commit -m "fix(security): auto-remediate ${{ steps.remediate.outputs.fixes_applied }} finding(s)

          Scanner: ${{ inputs.scanner }}
          Fixes: ${{ steps.remediate.outputs.fixed_ids }}
          Skips: ${{ steps.remediate.outputs.skipped_ids }}

          Co-authored-by: Claude <noreply@anthropic.com>"
          git push

      - name: Post PR comment
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const summary = fs.readFileSync('remediation_summary.md', 'utf8');
            await github.rest.issues.createComment({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
              body: summary
            });
```

---

## 2. Python Agent: `.github/scripts/security_remediation_agent.py`

### Dependencies

- `anthropic` — Anthropic Python SDK
- `pyyaml` — config file parsing
- Standard library: `json`, `os`, `subprocess`, `sys`, `pathlib`, `dataclasses`, `enum`, `textwrap`

### Normalized Finding Model

Every scanner's output is parsed into this common dataclass:

```python
@dataclass
class Finding:
    tool: str           # "checkov", "trivy-iac", "trivy-vuln"
    check_id: str       # e.g. "CKV_AWS_18", "AVD-AWS-0089", "CVE-2024-1234"
    severity: str       # "CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"
    file_path: str      # relative path to the offending file
    start_line: int
    end_line: int
    resource: str       # e.g. "aws_s3_bucket.data"
    title: str
    description: str
    guideline_url: str
    code_block: str     # extracted snippet with surrounding context
    action: Action      # set by triage: FIX, SKIP, HUMAN, IGNORE
    action_reason: str  # reason for skip/human
```

### Scanner Parsers

Three parser functions, registered in a `PARSERS` dict:

- **`parse_checkov(raw: dict) -> list[Finding]`** — Handles Checkov JSON output. Checkov wraps results differently depending on whether one or multiple frameworks ran (single dict vs list of dicts). Iterates `results.failed_checks[]`.
- **`parse_trivy_iac(raw: dict) -> list[Finding]`** — Handles Trivy JSON output for `Results[].Misconfigurations[]`.
- **`parse_trivy_vuln(raw: dict) -> list[Finding]`** — Handles Trivy JSON for `Results[].Vulnerabilities[]`. Immediately sets `action=HUMAN` with a message to use Renovate/Dependabot. Includes installed version, fixed version, and severity in the description.

Adding a new scanner = writing a new parser function + registering it in `PARSERS`.

### Triage Logic

Config-driven, four tiers:

1. **`ignore`** — Finding is dropped entirely, not even mentioned in summary.
2. **`auto_skip`** — Agent adds an inline skip annotation with the configured reason (e.g., `#checkov:skip=CKV_AWS_144:Cross-region replication not required`).
3. **`require_human`** — Finding goes straight to the "Requires Human Review" section of the summary. Used for IAM, security groups, and anything where automated changes are risky.
4. **`auto_fix`** — Agent attempts to fix the IaC.
5. **Default (unlisted)** — Agent attempts to fix (configurable to `human` instead via `default_action`).

Dependency vuln findings (`trivy-vuln`) always go to HUMAN regardless of config.

### Claude API Integration

#### System prompt

The system prompt instructs Claude to:
- Make **minimal changes** — fix only what's needed, don't refactor
- Preserve existing comments and formatting
- For skips: add `#checkov:skip=<ID>:<reason>` above the resource (Checkov) or report that the ID should be added to `.trivyignore` (Trivy)
- Return structured JSON: `{ "action": "fix"|"skip", "reason": "...", "files": [{"path": "...", "content": "..."}] }`
- Err on the side of caution — if unsure, skip and explain

#### Batching

Findings are grouped by file path. Single-finding files get individual API calls; multi-finding files get a batch prompt that lists all findings and asks Claude to address all of them in one response. This ensures Claude sees the full file context and avoids conflicting edits.

#### Retry prompt

When a fix doesn't pass verification, the retry prompt includes:
```
IMPORTANT: A previous fix attempt for this finding DID NOT WORK. The scanner
still reports the check as failing after the last attempt.

Previous attempt reason: {prev_reason}

Please try a DIFFERENT approach. Carefully re-read the check description and
guideline to understand exactly what the scanner expects.
```

### Verification Loop

After all findings are remediated, the agent re-runs the scanner against only the modified files:

```
Remediate all findings (grouped by file)
         │
         ▼
    Re-run scanner against modified files
         │
         ├── All checks passing? → Done ✅
         │
         ├── New checks introduced? → Escalate to HUMAN immediately
         │   (regression detection)
         │
         └── Checks still failing?
                    │
                    ▼
              Retry with context (up to max_retry_attempts, default 1)
                    │
                    ▼
              Re-scan again
                    │
                    ├── Fixed? → Done ✅
                    └── Still failing? → Escalate to HUMAN
```

Scanner runners:
- **Checkov**: `checkov --file <path> --output json --compact --quiet`
- **Trivy IaC**: `trivy config --format json --quiet <directory>` (Trivy scans directories, so we collect unique parent dirs of modified files)

Both parse output back through the same parser functions and return a set of still-failing check IDs.

### PR Comment / Summary

The agent writes `remediation_summary.md` which gets posted as a PR comment. Sections:

- **✅ Fixed** — Check ID, description, and what the agent did (marked "verified" if verification ran)
- **⏭️ Skipped** — Check ID and reason
- **⚠️ Requires Human Review** — IaC findings that were escalated
- **📦 Dependency Vulnerabilities** — Trivy vuln findings with a note to use Renovate/Dependabot
- **❌ Remediation Failed** — Findings where the agent couldn't produce a passing fix
- **🔇 Ignored** — Count of findings that matched the ignore list

### GitHub Actions Outputs

The script writes to `$GITHUB_OUTPUT`:
- `fixes_applied` — integer count
- `fixed_ids` — comma-separated check IDs that were fixed
- `skipped_ids` — comma-separated check IDs that were skipped

---

## 3. Config File: `.github/security-remediation-config.yaml`

```yaml
# Default behavior for checks not listed in any category.
# Options: "agent_decide" (attempt fix), "human" (flag for review)
default_action: agent_decide

# Verification settings
verify_after_fix: true
max_retry_attempts: 1

# Checks to automatically fix — generally safe, well-understood remediations
auto_fix:
  # Checkov - S3
  - CKV_AWS_18   # S3 access logging
  - CKV_AWS_19   # S3 default encryption
  - CKV_AWS_21   # S3 versioning
  - CKV_AWS_53   # S3 block public ACLs
  - CKV_AWS_54   # S3 block public policy
  - CKV_AWS_55   # S3 ignore public ACLs
  - CKV_AWS_56   # S3 restrict public buckets
  - CKV2_AWS_6   # S3 public access block

  # Checkov - RDS
  - CKV_AWS_16   # RDS encryption at rest
  - CKV_AWS_17   # RDS logging enabled
  - CKV_AWS_118  # RDS enhanced monitoring
  - CKV_AWS_133  # RDS auto minor version upgrade
  - CKV_AWS_145  # RDS encryption at rest (Aurora)
  - CKV_AWS_162  # RDS IAM authentication
  - CKV_AWS_226  # RDS deletion protection
  - CKV_AWS_354  # RDS performance insights

  # Checkov - General
  - CKV_AWS_260  # Security group no unrestricted ingress to port 22
  - CKV_AWS_338  # CloudWatch log group retention

  # Trivy IaC
  - AVD-AWS-0089  # S3 encryption
  - AVD-AWS-0090  # S3 versioning
  - AVD-AWS-0132  # RDS encryption

# Checks to skip with a reason (agent adds inline skip annotation)
auto_skip:
  CKV_AWS_144: "Cross-region replication not required — single-region architecture"
  CKV_AWS_241: "Kinesis encryption managed at application layer"

# Checks that require human review — never auto-remediated
# Typically IAM, security groups, and network config
require_human:
  - CKV_AWS_23   # Security group allows open ingress
  - CKV_AWS_24   # Security group open to SSH
  - CKV_AWS_26   # SNS topic encryption
  - CKV_AWS_33   # KMS key rotation
  - CKV_AWS_40   # IAM policy with wildcard resource
  - CKV_AWS_49   # IAM policy no full admin
  - CKV_AWS_61   # IAM policy no * principal
  - CKV_AWS_109  # IAM no permission management
  - CKV_AWS_110  # IAM no write without constraint
  - CKV_AWS_111  # IAM no wildcard resource with write

# Checks to completely ignore (not even reported)
ignore: []
```

---

## 4. Dependency Vulnerabilities: Use Renovate

Dependency version bumps are **not handled by this agent**. LLMs editing `go.mod` or `package.json` directly is fragile — they don't have access to `go mod tidy`, can't resolve transitive dependency conflicts, and can't regenerate lock files.

Instead, use **Renovate** with vulnerability alerts enabled. Suggested config (`renovate.json`):

```json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "vulnerabilityAlerts": { "enabled": true },
  "osvVulnerabilityAlerts": true,
  "packageRules": [
    {
      "matchUpdateTypes": ["patch"],
      "matchCategories": ["security"],
      "automerge": true
    }
  ]
}
```

If Trivy vuln results are passed to this agent (`scanner: trivy-vuln`), it will parse the results and include them in the PR summary as informational items with a note to use Renovate/Dependabot, but will not attempt any changes.

---

## 5. Future Considerations

- **Additional scanner adapters** — The parser pattern makes it straightforward to add `tfsec`, `semgrep`, `kics`, etc. Each is just a function that returns `list[Finding]`.
- **Trivy `.trivyignore` handling** — For Trivy skips, the agent should append to a `.trivyignore` file rather than inline comments, since Trivy uses file-based skip mechanisms.
- **Cost controls** — With Sonnet, each finding costs roughly $0.01–0.05 per API call. The `max_findings` cap (default 20) keeps a single run well under $1. Consider logging token usage.
- **Caching** — If the same check ID keeps failing across PRs on the same resource, consider caching the remediation pattern.
- **PR comment deduplication** — If the workflow runs multiple times on the same PR (e.g., on push), consider editing the existing comment rather than posting a new one.

---

## 6. Full Python Agent Source

The complete agent source is below. Place it at `.github/scripts/security_remediation_agent.py`.

```python
"""
Security finding remediation agent.

Parses IaC misconfiguration results from Checkov or Trivy, normalizes them
into a common format, and uses Claude to fix or skip each finding.

Dependency vulnerabilities (SCA) are intentionally out of scope — use
Renovate or Dependabot for those. If Trivy vuln results are passed in,
the agent will flag them in the summary without attempting remediation.
"""

import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from textwrap import dedent

import anthropic
import yaml


# ---------------------------------------------------------------------------
# Normalized finding model
# ---------------------------------------------------------------------------

class Action(str, Enum):
    FIX = "fix"
    SKIP = "skip"
    HUMAN = "human"
    IGNORE = "ignore"


@dataclass
class Finding:
    tool: str
    check_id: str
    severity: str
    file_path: str
    start_line: int
    end_line: int
    resource: str
    title: str
    description: str = ""
    guideline_url: str = ""
    code_block: str = ""
    action: Action | None = None
    action_reason: str = ""


@dataclass
class RemediationResult:
    finding: Finding
    action: Action
    reason: str
    diff_summary: str = ""
    success: bool = False


@dataclass
class VerificationResult:
    still_failing: list[str]
    newly_introduced: list[str]
    resolved: list[str]
    scan_error: str = ""


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def parse_checkov(raw: dict) -> list[Finding]:
    findings: list[Finding] = []
    results = raw if isinstance(raw, list) else [raw]

    for result_block in results:
        for check in result_block.get("results", {}).get("failed_checks", []):
            f = Finding(
                tool="checkov",
                check_id=check.get("check_id", ""),
                severity=check.get("severity", "UNKNOWN"),
                file_path=check.get("file_path", "").lstrip("/"),
                start_line=check.get("file_line_range", [0, 0])[0],
                end_line=check.get("file_line_range", [0, 0])[1],
                resource=check.get("resource", ""),
                title=check.get("name", ""),
                description=check.get("name", ""),
                guideline_url=check.get("guideline", ""),
                code_block=_extract_code_block(
                    check.get("file_path", "").lstrip("/"),
                    check.get("file_line_range", [0, 0]),
                ),
            )
            findings.append(f)

    return findings


def parse_trivy_iac(raw: dict) -> list[Finding]:
    findings: list[Finding] = []
    for result in raw.get("Results", []):
        target = result.get("Target", "")
        for misconf in result.get("Misconfigurations", []):
            findings.append(Finding(
                tool="trivy-iac",
                check_id=misconf.get("ID", "") or misconf.get("AVDID", ""),
                severity=misconf.get("Severity", "UNKNOWN"),
                file_path=target,
                start_line=misconf.get("CauseMetadata", {}).get("StartLine", 0),
                end_line=misconf.get("CauseMetadata", {}).get("EndLine", 0),
                resource=misconf.get("CauseMetadata", {}).get("Resource", ""),
                title=misconf.get("Title", ""),
                description=misconf.get("Description", ""),
                guideline_url=misconf.get("PrimaryURL", ""),
                code_block=_extract_code_block(
                    target,
                    [
                        misconf.get("CauseMetadata", {}).get("StartLine", 0),
                        misconf.get("CauseMetadata", {}).get("EndLine", 0),
                    ],
                ),
            ))
    return findings


def parse_trivy_vuln(raw: dict) -> list[Finding]:
    findings: list[Finding] = []
    for result in raw.get("Results", []):
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities", []):
            fixed_ver = vuln.get("FixedVersion", "N/A")
            findings.append(Finding(
                tool="trivy-vuln",
                check_id=vuln.get("VulnerabilityID", ""),
                severity=vuln.get("Severity", "UNKNOWN"),
                file_path=target,
                start_line=0,
                end_line=0,
                resource=vuln.get("PkgName", ""),
                title=f"{vuln.get('VulnerabilityID', '')}: {vuln.get('PkgName', '')}",
                description=(
                    f"{vuln.get('Description', '')} "
                    f"[installed: {vuln.get('InstalledVersion', '?')}, "
                    f"fix: {fixed_ver}]"
                ),
                guideline_url=vuln.get("PrimaryURL", ""),
                action=Action.HUMAN,
                action_reason=f"Dependency vulnerability — use Renovate/Dependabot (fix available: {fixed_ver})",
            ))
    return findings


PARSERS = {
    "checkov": parse_checkov,
    "trivy-iac": parse_trivy_iac,
    "trivy-vuln": parse_trivy_vuln,
}


def _extract_code_block(file_path: str, line_range: list[int], context: int = 3) -> str:
    try:
        p = Path(file_path)
        if not p.exists():
            return ""
        lines = p.read_text().splitlines()
        start = max(0, line_range[0] - 1 - context)
        end = min(len(lines), line_range[1] + context)
        numbered = [f"{i+1:4d} | {lines[i]}" for i in range(start, end)]
        return "\n".join(numbered)
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass
class Config:
    auto_fix: list[str] = field(default_factory=list)
    auto_skip: dict[str, str] = field(default_factory=dict)
    require_human: list[str] = field(default_factory=list)
    ignore: list[str] = field(default_factory=list)
    default_action: str = "agent_decide"
    verify_after_fix: bool = True
    max_retry_attempts: int = 1


def load_config(path: str) -> Config:
    p = Path(path)
    if not p.exists():
        print(f"⚠️  Config file not found at {path}, using defaults")
        return Config()
    raw = yaml.safe_load(p.read_text()) or {}
    return Config(
        auto_fix=raw.get("auto_fix", []),
        auto_skip=raw.get("auto_skip", {}),
        require_human=raw.get("require_human", []),
        ignore=raw.get("ignore", []),
        default_action=raw.get("default_action", "agent_decide"),
        verify_after_fix=raw.get("verify_after_fix", True),
        max_retry_attempts=raw.get("max_retry_attempts", 1),
    )


def triage(finding: Finding, config: Config) -> Action:
    if finding.tool == "trivy-vuln":
        return Action.HUMAN
    cid = finding.check_id
    if cid in config.ignore:
        return Action.IGNORE
    if cid in config.auto_skip:
        finding.action_reason = config.auto_skip[cid]
        return Action.SKIP
    if cid in config.require_human:
        return Action.HUMAN
    if cid in config.auto_fix:
        return Action.FIX
    return Action.FIX


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

class ScannerRunner:

    @staticmethod
    def run_checkov(target_files: list[str]) -> tuple[set[str], str]:
        failing_ids: set[str] = set()
        file_args = []
        for f in target_files:
            if Path(f).exists():
                file_args.extend(["--file", f])
        if not file_args:
            return failing_ids, ""

        cmd = ["checkov", *file_args, "--output", "json", "--compact", "--quiet"]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            output = result.stdout
            if not output.strip():
                return failing_ids, ""
            raw = json.loads(output)
            findings = parse_checkov(raw)
            failing_ids = {f.check_id for f in findings}
            return failing_ids, ""
        except subprocess.TimeoutExpired:
            return failing_ids, "Checkov verification timed out after 300s"
        except (json.JSONDecodeError, FileNotFoundError) as e:
            return failing_ids, f"Checkov verification failed: {e}"

    @staticmethod
    def run_trivy_iac(target_files: list[str]) -> tuple[set[str], str]:
        failing_ids: set[str] = set()
        target_dirs = list({str(Path(f).parent) for f in target_files if Path(f).exists()})
        if not target_dirs:
            return failing_ids, ""

        all_findings: list[Finding] = []
        for target_dir in target_dirs:
            cmd = ["trivy", "config", "--format", "json", "--quiet", target_dir]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if result.stdout.strip():
                    raw = json.loads(result.stdout)
                    all_findings.extend(parse_trivy_iac(raw))
            except subprocess.TimeoutExpired:
                return failing_ids, f"Trivy verification timed out for {target_dir}"
            except (json.JSONDecodeError, FileNotFoundError) as e:
                return failing_ids, f"Trivy verification failed: {e}"

        failing_ids = {f.check_id for f in all_findings}
        return failing_ids, ""


SCANNER_RUNNERS = {
    "checkov": ScannerRunner.run_checkov,
    "trivy-iac": ScannerRunner.run_trivy_iac,
}


def verify_fixes(
    scanner: str,
    original_check_ids: set[str],
    modified_files: list[str],
) -> VerificationResult:
    runner = SCANNER_RUNNERS.get(scanner)
    if not runner:
        return VerificationResult(
            still_failing=[], newly_introduced=[], resolved=[],
            scan_error=f"No verification runner for scanner: {scanner}",
        )

    print(f"  🔍 Re-scanning {len(modified_files)} file(s) with {scanner}...")
    current_failures, error = runner(modified_files)

    if error:
        return VerificationResult(
            still_failing=list(original_check_ids),
            newly_introduced=[], resolved=[], scan_error=error,
        )

    return VerificationResult(
        still_failing=list(original_check_ids & current_failures),
        newly_introduced=list(current_failures - original_check_ids),
        resolved=list(original_check_ids - current_failures),
    )


# ---------------------------------------------------------------------------
# Claude remediation
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = dedent("""\
    You are a security remediation agent integrated into a CI/CD pipeline.
    Your job is to fix infrastructure-as-code security findings.

    RULES:
    1. When fixing IaC (Terraform, CloudFormation, Dockerfiles, Kubernetes manifests, etc.):
       - Make the MINIMAL change needed to satisfy the check.
       - Do NOT refactor, rename, or restructure anything beyond what's needed.
       - Preserve all existing comments and formatting style.
       - If the fix requires a new resource (e.g., a logging bucket), add it in the same file
         near the resource that needs it.

    2. When adding a skip/ignore comment:
       - For Checkov: add `#checkov:skip=<CHECK_ID>:<reason>` on the line ABOVE the resource block.
       - For Trivy: report that the check ID should be added to `.trivyignore`.
       - Always include a clear, specific reason — never just "not applicable."

    3. Output your response as JSON with this structure:
       {
         "action": "fix" | "skip",
         "reason": "brief explanation of what you did and why",
         "files": [
           {
             "path": "relative/path/to/file",
             "content": "entire updated file content"
           }
         ]
       }

    4. If you cannot confidently fix the issue, set action to "skip" and explain why
       in the reason field. Err on the side of caution.
""")

RETRY_ADDENDUM = dedent("""\

    IMPORTANT: A previous fix attempt for this finding DID NOT WORK. The scanner
    still reports the check as failing after the last attempt.

    Previous attempt reason: {prev_reason}

    Please try a DIFFERENT approach. Carefully re-read the check description and
    guideline to understand exactly what the scanner expects.
""")


def build_remediation_prompt(finding: Finding, file_content: str, retry_context: str | None = None) -> str:
    prompt = f"""Fix the following security finding.

**Scanner:** {finding.tool}
**Check ID:** {finding.check_id}
**Severity:** {finding.severity}
**Description:** {finding.description}
**Resource:** {finding.resource}
**File:** {finding.file_path} (lines {finding.start_line}-{finding.end_line})
**Guideline:** {finding.guideline_url}

Here is the full file content:

```
{file_content}
```
"""
    if finding.action == Action.SKIP:
        prompt += f"\nThis check should be SKIPPED (not fixed). Add the appropriate skip/ignore annotation.\nReason for skipping: {finding.action_reason}\n"
    if retry_context:
        prompt += retry_context
    return prompt


def build_batch_prompt(findings: list[Finding], file_content: str, retry_context: str | None = None) -> str:
    file_path = findings[0].file_path
    findings_desc = "\n\n".join(
        f"### Finding {i+1}\n"
        f"- **Check ID:** {f.check_id}\n"
        f"- **Severity:** {f.severity}\n"
        f"- **Description:** {f.description}\n"
        f"- **Resource:** {f.resource}\n"
        f"- **Lines:** {f.start_line}-{f.end_line}\n"
        f"- **Action:** {'SKIP (add skip comment, reason: ' + f.action_reason + ')' if f.action == Action.SKIP else 'FIX'}\n"
        f"- **Guideline:** {f.guideline_url}"
        for i, f in enumerate(findings)
    )

    prompt = f"""Fix ALL of the following security findings in a single file.

**File:** {file_path}
**Scanner:** {findings[0].tool}

{findings_desc}

Here is the full file content:

```
{file_content}
```

Address ALL findings above. Return a single JSON response covering all fixes.
"""
    if retry_context:
        prompt += retry_context
    return prompt


def call_claude(client: anthropic.Anthropic, model: str, prompt: str, max_tokens: int = 8192) -> dict:
    response = client.messages.create(
        model=model, max_tokens=max_tokens, system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )
    response_text = response.content[0].text
    if "```json" in response_text:
        response_text = response_text.split("```json")[1].split("```")[0]
    elif "```" in response_text:
        response_text = response_text.split("```")[1].split("```")[0]
    return json.loads(response_text.strip())


def apply_file_changes(result: dict) -> list[str]:
    modified = []
    for file_change in result.get("files", []):
        p = Path(file_change["path"])
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(file_change["content"])
        modified.append(str(p))
    return modified


def remediate_finding(client, finding, model, retry_context=None):
    try:
        file_content = Path(finding.file_path).read_text()
    except FileNotFoundError:
        return RemediationResult(finding=finding, action=Action.HUMAN, reason=f"File not found: {finding.file_path}"), []

    prompt = build_remediation_prompt(finding, file_content, retry_context)
    try:
        result = call_claude(client, model, prompt)
        modified = apply_file_changes(result)
        return RemediationResult(
            finding=finding, action=Action(result["action"]),
            reason=result["reason"], diff_summary=f"Modified {len(modified)} file(s)", success=True,
        ), modified
    except (json.JSONDecodeError, KeyError, IndexError) as e:
        return RemediationResult(finding=finding, action=Action.HUMAN, reason=f"Failed to parse response: {e}"), []
    except anthropic.APIError as e:
        return RemediationResult(finding=finding, action=Action.HUMAN, reason=f"API error: {e}"), []


def remediate_batch(client, findings, model, retry_context=None):
    file_path = findings[0].file_path
    try:
        file_content = Path(file_path).read_text()
    except FileNotFoundError:
        return [RemediationResult(finding=f, action=Action.HUMAN, reason="File not found") for f in findings], []

    prompt = build_batch_prompt(findings, file_content, retry_context)
    try:
        result = call_claude(client, model, prompt)
        modified = apply_file_changes(result)
        return [
            RemediationResult(finding=f, action=Action(result.get("action", "fix")),
                              reason=result.get("reason", ""), diff_summary="Batch fix", success=True)
            for f in findings
        ], modified
    except Exception as e:
        return [RemediationResult(finding=f, action=Action.HUMAN, reason=f"Batch failed: {e}") for f in findings], []


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def remediate_and_verify(client, scanner, by_file, model, config):
    all_results = []
    all_modified_files = []
    findings_by_id = {}
    last_reasons = {}

    # Initial pass
    print("\n📝 Pass 1: Initial remediation")
    for file_path, file_findings in by_file.items():
        print(f"  🔧 {file_path} ({len(file_findings)} finding(s))")
        for f in file_findings:
            findings_by_id[f.check_id] = f

        if len(file_findings) == 1:
            result, modified = remediate_finding(client, file_findings[0], model)
            all_results.append(result)
            all_modified_files.extend(modified)
            if result.success:
                last_reasons[file_findings[0].check_id] = result.reason
        else:
            results, modified = remediate_batch(client, file_findings, model)
            all_results.extend(results)
            all_modified_files.extend(modified)
            for r in results:
                if r.success:
                    last_reasons[r.finding.check_id] = r.reason

    if not config.verify_after_fix:
        print("\n⏭️  Verification disabled")
        return all_results

    fixed_check_ids = {r.finding.check_id for r in all_results if r.action == Action.FIX and r.success}
    if not fixed_check_ids:
        print("\n⏭️  No fixes to verify")
        return all_results

    modified_files = list(set(all_modified_files))

    for attempt in range(1, config.max_retry_attempts + 2):
        label = "Verification" if attempt == 1 else f"Retry {attempt - 1}"
        print(f"\n🔍 {label}: re-scanning {len(modified_files)} file(s)...")

        verification = verify_fixes(scanner, fixed_check_ids, modified_files)

        if verification.scan_error:
            print(f"  ⚠️  Scanner error: {verification.scan_error}")
            break

        print(f"  ✅ Resolved: {len(verification.resolved)}")
        print(f"  ❌ Still failing: {len(verification.still_failing)}")
        if verification.newly_introduced:
            print(f"  🆕 Newly introduced: {len(verification.newly_introduced)}")

        if not verification.still_failing and not verification.newly_introduced:
            print("  🎉 All fixes verified!")
            break

        for new_id in verification.newly_introduced:
            all_results.append(RemediationResult(
                finding=Finding(
                    tool=scanner, check_id=new_id, severity="UNKNOWN",
                    file_path="(introduced by fix)", start_line=0, end_line=0,
                    resource="", title=f"Regression: {new_id}",
                ),
                action=Action.HUMAN,
                reason="New finding introduced during remediation — requires manual review",
            ))

        if attempt > config.max_retry_attempts:
            print(f"\n⚠️  Max retries ({config.max_retry_attempts}) exhausted")
            for check_id in verification.still_failing:
                for r in all_results:
                    if r.finding.check_id == check_id and r.action == Action.FIX:
                        r.action = Action.HUMAN
                        r.reason = (
                            f"Fix attempted but still failing after "
                            f"{config.max_retry_attempts} retry(ies). Last: {r.reason}"
                        )
                        r.success = False
            break

        # Retry
        print(f"\n🔄 Retrying {len(verification.still_failing)} check(s)...")
        retry_findings: dict[str, list[Finding]] = {}
        for check_id in verification.still_failing:
            f = findings_by_id.get(check_id)
            if f:
                retry_findings.setdefault(f.file_path, []).append(f)

        for file_path, file_findings in retry_findings.items():
            prev_reason = last_reasons.get(file_findings[0].check_id, "unknown")
            retry_ctx = RETRY_ADDENDUM.format(prev_reason=prev_reason)

            if len(file_findings) == 1:
                result, modified = remediate_finding(client, file_findings[0], model, retry_context=retry_ctx)
                all_results = [r for r in all_results if r.finding.check_id != file_findings[0].check_id]
                all_results.append(result)
                modified_files = list(set(modified_files + modified))
                if result.success:
                    last_reasons[file_findings[0].check_id] = result.reason
            else:
                results, modified = remediate_batch(client, file_findings, model, retry_context=retry_ctx)
                retry_ids = {f.check_id for f in file_findings}
                all_results = [r for r in all_results if r.finding.check_id not in retry_ids]
                all_results.extend(results)
                modified_files = list(set(modified_files + modified))
                for r in results:
                    if r.success:
                        last_reasons[r.finding.check_id] = r.reason

        fixed_check_ids = {cid for cid in verification.still_failing}

    return all_results


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def generate_summary(results, verification_ran):
    fixed = [r for r in results if r.action == Action.FIX and r.success]
    skipped = [r for r in results if r.action == Action.SKIP and r.success]
    human = [r for r in results if r.action == Action.HUMAN]
    ignored = [r for r in results if r.action == Action.IGNORE]
    failed = [r for r in results if not r.success and r.action not in (Action.HUMAN, Action.IGNORE)]

    dep_vulns = [r for r in human if r.finding.tool == "trivy-vuln"]
    iac_human = [r for r in human if r.finding.tool != "trivy-vuln"]

    lines = ["## 🔐 Security Remediation Summary\n"]

    if fixed:
        status = "✅ verified" if verification_ran else "✅"
        lines.append(f"### {status} Fixed ({len(fixed)})")
        for r in fixed:
            lines.append(f"- `{r.finding.check_id}` — {r.finding.description}")
            lines.append(f"  - _{r.reason}_")
        lines.append("")

    if skipped:
        lines.append(f"### ⏭️ Skipped ({len(skipped)})")
        for r in skipped:
            lines.append(f"- `{r.finding.check_id}` — {r.reason}")
        lines.append("")

    if iac_human:
        lines.append(f"### ⚠️ Requires Human Review ({len(iac_human)})")
        for r in iac_human:
            lines.append(f"- `{r.finding.check_id}` in `{r.finding.file_path}` — {r.reason}")
        lines.append("")

    if dep_vulns:
        lines.append(f"### 📦 Dependency Vulnerabilities ({len(dep_vulns)})")
        lines.append("> These should be addressed via **Renovate** or **Dependabot**, not by this agent.\n")
        for r in dep_vulns:
            lines.append(f"- `{r.finding.check_id}` — {r.finding.resource}")
            lines.append(f"  - {r.finding.description}")
        lines.append("")

    if failed:
        lines.append(f"### ❌ Remediation Failed ({len(failed)})")
        for r in failed:
            lines.append(f"- `{r.finding.check_id}` — {r.reason}")
        lines.append("")

    if ignored:
        lines.append(f"### 🔇 Ignored ({len(ignored)})")
        lines.append(f"- {len(ignored)} finding(s) matched ignore list")
        lines.append("")

    lines.append("---")
    lines.append("*Automated by security-remediation-agent*")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    scanner = os.environ.get("SCANNER", "checkov")
    results_file = os.environ.get("RESULTS_FILE", "checkov_results.json")
    config_file = os.environ.get("CONFIG_FILE", ".github/security-remediation-config.yaml")
    dry_run = os.environ.get("DRY_RUN", "false").lower() == "true"
    max_findings = int(os.environ.get("MAX_FINDINGS", "20"))
    model = os.environ.get("MODEL", "claude-sonnet-4-20250514")

    results_path = Path(results_file)
    if not results_path.exists():
        print(f"❌ Results file not found: {results_file}")
        sys.exit(1)

    raw = json.loads(results_path.read_text())

    parser = PARSERS.get(scanner)
    if not parser:
        print(f"❌ Unknown scanner: {scanner}. Supported: {list(PARSERS.keys())}")
        sys.exit(1)

    findings = parser(raw)
    print(f"📋 Parsed {len(findings)} finding(s) from {scanner}")

    if not findings:
        print("✅ No findings to remediate!")
        _set_outputs(0, "", "")
        Path("remediation_summary.md").write_text("## 🔐 Security Remediation Summary\n\n✅ No findings!")
        return

    config = load_config(config_file)
    for f in findings:
        if f.action is None:
            f.action = triage(f, config)

    actionable = [f for f in findings if f.action != Action.IGNORE][:max_findings]
    ignored = [f for f in findings if f.action == Action.IGNORE]
    human_review = [f for f in actionable if f.action == Action.HUMAN]
    to_remediate = [f for f in actionable if f.action in (Action.FIX, Action.SKIP)]

    print(f"  → {len(to_remediate)} to remediate, {len(human_review)} for human review, {len(ignored)} ignored")

    if dry_run:
        print("🏃 Dry run — skipping remediation")
        all_results = [RemediationResult(f, Action.HUMAN, "Dry run") for f in to_remediate]
    else:
        by_file: dict[str, list[Finding]] = {}
        for f in to_remediate:
            by_file.setdefault(f.file_path, []).append(f)
        client = anthropic.Anthropic()
        all_results = remediate_and_verify(client, scanner, by_file, model, config)

    all_results.extend(
        RemediationResult(f, Action.HUMAN, f.action_reason or "Flagged for human review")
        for f in human_review
    )
    all_results.extend(RemediationResult(f, Action.IGNORE, "In ignore list") for f in ignored)

    summary = generate_summary(all_results, verification_ran=config.verify_after_fix)
    Path("remediation_summary.md").write_text(summary)
    print(summary)

    fixed = [r for r in all_results if r.action == Action.FIX and r.success]
    skipped = [r for r in all_results if r.action == Action.SKIP and r.success]
    _set_outputs(
        len(fixed),
        ", ".join(r.finding.check_id for r in fixed),
        ", ".join(r.finding.check_id for r in skipped),
    )


def _set_outputs(fixes_applied, fixed_ids, skipped_ids):
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a") as f:
            f.write(f"fixes_applied={fixes_applied}\n")
            f.write(f"fixed_ids={fixed_ids}\n")
            f.write(f"skipped_ids={skipped_ids}\n")


if __name__ == "__main__":
    main()
```
