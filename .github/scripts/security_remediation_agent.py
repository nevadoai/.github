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
