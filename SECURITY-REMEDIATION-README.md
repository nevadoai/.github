# Security Remediation Agent

AI-powered automatic remediation of IaC security findings from Checkov and Trivy.

## Overview

The security remediation agent uses Claude (Anthropic API) to automatically fix infrastructure-as-code security issues found by Checkov and Trivy scanners. It:

- ✅ **Fixes** common, safe security issues automatically (S3 encryption, versioning, logging, etc.)
- ⏭️ **Skips** checks that don't apply to your environment (with inline comments explaining why)
- ⚠️ **Flags** risky changes (IAM policies, security groups) for human review
- 🔍 **Verifies** all fixes by re-running the scanner
- 🔄 **Retries** failed fixes with additional context
- 📝 **Comments** on PRs with a detailed summary

## Files

- **`.github/workflows/security-remediation.yml`** - Reusable workflow
- **`.github/scripts/security_remediation_agent.py`** - Python agent that calls Claude API
- **`.github/security-remediation-config.yaml`** - Configuration for triage rules

## Quick Start

### 1. Add API Key Secret

Add your Anthropic API key as a repository secret:

```
Repository Settings → Secrets and variables → Actions → New repository secret
Name: ANTHROPIC_API_KEY
Value: sk-ant-...
```

### 2. Update Your IaC Security Workflow

Modify your existing security scan workflow to:
1. Output JSON results from Checkov/Trivy
2. Upload JSON results as artifacts
3. Call the remediation workflow

See `iac-security-scan-with-remediation-example.yml` for a complete example.

### 3. Enable in Calling Workflow

Example usage in a repository:

```yaml
name: Security Scan
on: [pull_request]

permissions:
  contents: write      # Required to commit fixes
  pull-requests: write # Required to comment on PRs

jobs:
  iac-scan:
    uses: nevadoai/.github/.github/workflows/iac-security-scan-with-remediation-example.yml@main
    with:
      enable-auto-remediation: true
      remediation-dry-run: false  # Set to true to test without committing
    secrets:
      anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
```

## Configuration

Edit `.github/security-remediation-config.yaml` to control which checks are auto-fixed:

```yaml
# Default behavior for unlisted checks
default_action: agent_decide  # or "human" to be more conservative

# Checks that are safe to auto-fix
auto_fix:
  - CKV_AWS_18   # S3 access logging
  - CKV_AWS_19   # S3 encryption
  - CKV_AWS_21   # S3 versioning
  # ... add more

# Checks to auto-skip with a reason
auto_skip:
  CKV_AWS_144: "Cross-region replication not required — single-region architecture"

# Checks that require human review (IAM, security groups, etc.)
require_human:
  - CKV_AWS_40   # IAM policy with wildcard resource
  - CKV_AWS_49   # IAM policy no full admin
  # ... add more

# Checks to completely ignore
ignore: []
```

## How It Works

### 1. **Scanning**
Your workflow runs Checkov or Trivy and uploads JSON results as artifacts.

### 2. **Parsing**
The agent downloads results and normalizes findings into a common format.

### 3. **Triage**
Each finding is categorized based on config:
- `auto_fix` - Agent will attempt to fix
- `auto_skip` - Agent adds skip annotation with reason
- `require_human` - Escalated to human review
- `ignore` - Completely filtered out
- Unlisted checks use `default_action`

### 4. **Remediation**
- Findings are **batched by file** (multiple findings in same file → single API call)
- Claude receives full file content + all findings for that file
- Claude returns modified file(s) with minimal changes

### 5. **Verification**
- Scanner re-runs against modified files
- Still-failing checks get **one retry** with context about previous attempt
- New findings introduced by fixes are flagged as regressions

### 6. **Commit & Comment**
- Fixed files are committed to PR branch
- Summary comment posted to PR showing:
  - ✅ Fixed (with verification status)
  - ⏭️ Skipped (with reasons)
  - ⚠️ Requires Human Review
  - ❌ Remediation Failed

## Workflow Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `scanner` | yes | - | `checkov`, `trivy-iac`, or `trivy-vuln` |
| `results_artifact` | yes | - | Name of artifact containing scan results |
| `results_file` | yes | - | Path to JSON file within artifact |
| `config_file` | no | `.github/security-remediation-config.yaml` | Path to config |
| `dry_run` | no | `false` | If true, only comment, don't commit |
| `max_findings` | no | `20` | Cap on findings to process (cost control) |
| `model` | no | `claude-sonnet-4-20250514` | Anthropic model to use |

## Cost Considerations

- **Sonnet 4.5**: ~$0.01-0.05 per finding
- **Default cap**: 20 findings per run = ~$0.20-1.00 per PR
- Batching multiple findings per file reduces cost
- Configure `auto_skip` and `ignore` to reduce unnecessary API calls

## Dependency Vulnerabilities

**Out of scope** - The agent will NOT fix dependency vulnerabilities (SCA findings from Trivy).

Use **Renovate** or **Dependabot** for dependency updates instead. If Trivy vulnerability results are passed to the agent, they'll be listed in the PR comment with a note to use automated dependency management.

## Testing

### Test with Dry Run Mode

```yaml
with:
  dry_run: true  # Only posts PR comment, doesn't commit
```

### Test with Sample Data

A sample Checkov output file is available at `/tmp/checkov_sample_output.json` with 5 realistic findings:
- 3 S3 issues (encryption, logging, versioning, public access)
- 1 IAM issue (wildcard resource)

## Troubleshooting

### "Results file not found"
- Ensure your scanner job uploaded JSON results as an artifact
- Check artifact name matches `results_artifact` input
- Verify `results_file` path is correct

### "No verification runner for scanner"
- Only `checkov` and `trivy-iac` support verification
- `trivy-vuln` findings go straight to human review

### "Scanner verification failed"
- Scanner binary not installed (workflow should install it)
- File paths may be incorrect (check working directory)

### "API error"
- Check ANTHROPIC_API_KEY secret is set correctly
- Verify API key has sufficient credits
- Check for rate limiting

## Security Considerations

1. **The agent never merges** - It only commits to PR branch. A human must review and approve.
2. **Verification is enabled by default** - Fixes are re-scanned to ensure they work.
3. **Risky changes flagged** - IAM, security groups, and network configs require human review.
4. **Audit trail** - All fixes are committed with clear messages and co-authored by Claude.
5. **Limited scope** - Max 20 findings per run to prevent runaway costs.

## Extending

### Add a New Scanner

1. Write a parser function in `security_remediation_agent.py`:
   ```python
   def parse_my_scanner(raw: dict) -> list[Finding]:
       # Parse scanner output into Finding objects
       ...
   ```

2. Register it:
   ```python
   PARSERS = {
       "my-scanner": parse_my_scanner,
   }
   ```

3. Add verification runner (optional):
   ```python
   SCANNER_RUNNERS = {
       "my-scanner": ScannerRunner.run_my_scanner,
   }
   ```

### Add New Check IDs

Edit `security-remediation-config.yaml`:
- Add to `auto_fix` if safe to remediate automatically
- Add to `require_human` if risky
- Add to `auto_skip` with a reason if you want to suppress

## Support

For issues or questions:
- Check the workflow logs for detailed error messages
- Review the agent's output in the "Run remediation agent" step
- See `remediation_summary.md` artifact for the full summary
- Open an issue in the repository

---

**Powered by Claude (Anthropic)**
