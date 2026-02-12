# Nevado AI - Organization GitHub Configuration

This repository contains organization-wide GitHub configurations and reusable workflows.

## Versioning & Security

**Important:** For supply chain security, always reference workflows using version tags or commit SHAs, never `@main`.

```yaml
# ✅ GOOD - Use version tag (recommended)
uses: nevadoai/.github/.github/workflows/golang-security-scan.yml@v1.0.0

# ✅ GOOD - Use commit SHA (most secure)
uses: nevadoai/.github/.github/workflows/golang-security-scan.yml@d12758d

# ❌ BAD - Don't use @main (supply chain risk)
uses: nevadoai/.github/.github/workflows/golang-security-scan.yml@main
```

**Current Version:** `v1.0.0` ([Release Notes](https://github.com/nevadoai/.github/releases/tag/v1.0.0))

### Permissions

**All reusable workflows declare their own permissions following the principle of least privilege.** You don't need to grant any permissions in your calling workflow - the reusable workflows request only what they need:

- `contents: read` - To checkout code
- `security-events: write` - To upload SARIF results to GitHub Security tab (only jobs that need it)
- `pull-requests: write` - For dependency review comments on PRs (only dependency-review jobs)

This is more secure than granting broad permissions at the workflow level.

## Reusable Workflows

### Auto-Approve After AI Review

Enables AI-assisted code review with automatic approval when Copilot finds no issues.

**How it works:**
1. PR is opened
2. GitHub Copilot automatically reviews the code
3. If no issues found → Auto-approved using the other team member's token
4. If issues found → Comment posted, manual review required

**Usage in your repo:**

Create `.github/workflows/auto-approve.yml`:

```yaml
name: Auto Approve

on:
  pull_request_review:
    types: [submitted]

jobs:
  auto-approve:
    if: github.event.review.user.login == 'copilot-pull-request-reviewer'
    uses: nevadoai/.github/.github/workflows/auto-approve-after-ai-review.yml@v1.0.0
    secrets: inherit
```

**Required Org Secrets:**
- `TYLER_APPROVE_PAT` - Tyler's PAT for approving Josh's PRs
- `JOSH_APPROVE_PAT` - Josh's PAT for approving Tyler's PRs

See [AI Auto-Approval Setup](https://github.com/nevadoai/command-center/blob/main/docs/AI_AUTO_APPROVAL_SETUP.md) for detailed setup instructions.

---

### Golang Security & Vulnerability Scan

Comprehensive security scanning for Go projects using multiple tools.

**Features:**
- `govulncheck`: Official Go vulnerability scanner
- `gosec`: Security checker for Go code patterns
- `trivy`: Comprehensive vulnerability scanner
- Dependency review for pull requests

**Usage in your repo:**

Create `.github/workflows/security-scan.yml`:

```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:

jobs:
  golang-scan:
    uses: nevadoai/.github/.github/workflows/golang-security-scan.yml@v1.0.0
    with:
      go-version: '1.21'  # Optional, defaults to '1.21'
      working-directory: '.'  # Optional, defaults to '.'
      severity: 'MEDIUM'  # Optional: LOW, MEDIUM, HIGH, CRITICAL
```

**What it scans:**
- Known vulnerabilities in Go dependencies
- Security issues in Go code (hardcoded credentials, weak crypto, etc.)
- Secrets accidentally committed
- Configuration issues

---

### Node.js Security & Vulnerability Scan

Security scanning for all Node.js projects including React apps, Express APIs, Lambda functions, and more.

**Features:**
- `npm/yarn/pnpm audit`: Built-in dependency vulnerability scanning
- `trivy`: Comprehensive vulnerability scanner
- `retire.js`: Detects vulnerable JavaScript libraries
- Dependency review for pull requests

**Usage in your repo:**

Create `.github/workflows/security-scan.yml`:

```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:

jobs:
  nodejs-scan:
    uses: nevadoai/.github/.github/workflows/nodejs-security-scan.yml@v1.0.0
    with:
      node-version: '20'  # Optional, defaults to '20'
      package-manager: 'npm'  # Optional: npm, yarn, or pnpm
      working-directory: '.'  # Optional
      severity: 'MEDIUM'  # Optional: LOW, MEDIUM, HIGH, CRITICAL
      audit-level: 'moderate'  # Optional: low, moderate, high, critical
```

**For Lambda Functions:**

Scan a specific Lambda function directory:

```yaml
jobs:
  lambda-scan:
    uses: nevadoai/.github/.github/workflows/nodejs-security-scan.yml@v1.0.0
    with:
      working-directory: './lambda/my-function'
      node-version: '20'
```

Or scan multiple Lambda functions:

```yaml
jobs:
  auth-lambda:
    uses: nevadoai/.github/.github/workflows/nodejs-security-scan.yml@v1.0.0
    with:
      working-directory: './lambda/auth'

  api-lambda:
    uses: nevadoai/.github/.github/workflows/nodejs-security-scan.yml@v1.0.0
    with:
      working-directory: './lambda/api'
```

**What it scans:**
- Vulnerable npm/yarn/pnpm packages
- Known security issues in JavaScript libraries
- Secrets accidentally committed
- Configuration issues

**Project types supported:**
- React/Next.js/Vue applications
- Express/Fastify/NestJS APIs
- AWS Lambda functions
- Node.js CLI tools
- Any project with a `package.json`

---

### IaC Security & Vulnerability Scan

Security scanning for Infrastructure as Code (Terraform, CloudFormation, etc.).

**Features:**
- `tfsec`: Terraform static analysis
- `checkov`: Multi-cloud IaC security scanner
- `trivy`: Comprehensive IaC vulnerability scanner
- `cfn-lint`: CloudFormation linting and validation
- Terraform validation

**Usage in your repo:**

Create `.github/workflows/security-scan.yml`:

```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:

jobs:
  iac-scan:
    uses: nevadoai/.github/.github/workflows/iac-security-scan.yml@v1.0.0
    with:
      working-directory: '.'  # Optional
      terraform-directory: './terraform'  # Optional
      cloudformation-directory: './cloudformation'  # Optional
      severity: 'MEDIUM'  # Optional: LOW, MEDIUM, HIGH, CRITICAL
      skip-tfsec: false  # Optional
      skip-checkov: false  # Optional
      skip-cfn-lint: false  # Optional
```

**What it scans:**
- Terraform security misconfigurations
- CloudFormation template issues
- AWS, Azure, GCP security best practices
- Kubernetes manifest security issues
- Secrets in IaC files
- Compliance violations (CIS, PCI-DSS, HIPAA, etc.)

---

### Policy as Code - OPA/Conftest

Enforce **SOC2 compliance** and security policies on infrastructure code using Open Policy Agent (OPA). Designed to align with **Drata monitoring** requirements.

**Features:**
- **SOC2-Focused Terraform Policies**: Pre-built policies mapped to SOC2 Trust Services Criteria
- **Drata Integration**: Policies align with Drata's compliance monitoring requirements
- Automatic enforcement across all repos before code is deployed
- Comprehensive coverage of AWS security requirements for SOC2 audits
- Kubernetes and Docker security policies included
- Custom policy enforcement for project-specific rules

**Centralized Policies Included:**

This repo includes comprehensive policies in the [`policies/`](./policies) directory:

- **Terraform** (`terraform.rego`): **SOC2 Compliance for AWS Infrastructure**
  - Organized by SOC2 Trust Services Criteria (CC6.1, CC6.6, CC6.7, CC7.2, A1.2)
  - **Encryption at Rest**: S3, RDS, EBS, DynamoDB, EFS, EKS
  - **Encryption in Transit**: Load balancers, ALB, API Gateway must use HTTPS
  - **Access Control**: No public access to databases, proper security group rules
  - **IAM Least Privilege**: No wildcard permissions, prefer roles over users
  - **Logging & Monitoring**: CloudTrail, VPC Flow Logs, CloudWatch integration
  - **Backup & Recovery**: S3 versioning, RDS backups with 7+ day retention
  - **Drata-Specific**: GuardDuty, AWS Config, Security Hub, CloudWatch integration
  - All violations reference specific SOC2 criteria (e.g., `[SOC2-CC6.1]`)

- **Kubernetes** (`kubernetes.rego`): Container and cluster security
  - Non-root containers, privilege restrictions
  - Resource limits and requests
  - Image tag policies (no `latest`)
  - Pod security (no hostNetwork/hostPID)
  - RBAC restrictions
  - Health checks and labels

- **Docker** (`docker.rego`): Dockerfile security
  - No root user, explicit image versions
  - No hardcoded secrets
  - Package management best practices
  - Health checks and metadata

**Basic Usage (Uses SOC2 Policies Automatically):**

Create `.github/workflows/policy-check.yml`:

```yaml
name: SOC2 Policy Check

on:
  push:
    branches: [main]
  pull_request:

jobs:
  soc2-policy-check:
    uses: nevadoai/.github/.github/workflows/policy-as-code.yml@v1.0.0
    with:
      config-directory: './terraform'  # Directory containing your Terraform files
      # SOC2 org policies are used automatically by default
```

Policy violations will show which SOC2 criteria failed:
```
FAIL - [SOC2-CC6.1] S3 bucket 'my-bucket' must have server-side encryption enabled for data at rest
FAIL - [SOC2-CC7.2] VPC 'main-vpc' must have VPC Flow Logs enabled for network monitoring
WARN - [DRATA] CloudTrail 'main' should send logs to CloudWatch Logs for Drata monitoring
```

**Advanced Options:**

```yaml
jobs:
  policy-check:
    uses: nevadoai/.github/.github/workflows/policy-as-code.yml@v1.0.0
    with:
      config-directory: './infrastructure'
      fail-on-warn: true  # Fail on warnings, not just errors
      policy-directory: './custom-policies'  # Override with custom policies
      use-org-policies: false  # Disable org policies if using custom
      namespaces: 'terraform,kubernetes'  # Test specific namespaces only
```

**Testing Multiple Directories:**

```yaml
jobs:
  terraform-policy:
    uses: nevadoai/.github/.github/workflows/policy-as-code.yml@v1.0.0
    with:
      config-directory: './terraform'

  k8s-policy:
    uses: nevadoai/.github/.github/workflows/policy-as-code.yml@v1.0.0
    with:
      config-directory: './k8s'
```

**Creating Custom Project Policies:**

If you need additional project-specific policies, create `./policy/*.rego` files in your repo:

```yaml
jobs:
  policy-check:
    uses: nevadoai/.github/.github/workflows/policy-as-code.yml@v1.0.0
    with:
      policy-directory: './policy'  # Use local policies
      config-directory: './infrastructure'
```

**Policy Examples:**

See the [`policies/`](./policies) directory for complete examples. All policies reference SOC2 criteria:

```rego
package terraform

import rego.v1

# SOC2 CC6.1 - Encryption at rest requirement (DENY - hard requirement)
deny contains msg if {
    some name
    resource := input.resource.aws_s3_bucket[name]
    not resource.server_side_encryption_configuration
    msg := sprintf("[SOC2-CC6.1] S3 bucket '%s' must have server-side encryption enabled for data at rest", [name])
}

# SOC2 A1.2 - Backup requirement (DENY - hard requirement)
deny contains msg if {
    some name
    resource := input.resource.aws_db_instance[name]
    resource.backup_retention_period < 7
    msg := sprintf("[SOC2-A1.2] RDS instance '%s' must have backup retention period of at least 7 days", [name])
}

# Drata integration recommendation (WARN - best practice)
warn contains msg if {
    some name
    resource := input.resource.aws_cloudtrail[name]
    not resource.cloud_watch_logs_group_arn
    msg := sprintf("[DRATA] CloudTrail '%s' should send logs to CloudWatch Logs for Drata monitoring", [name])
}
```

**Understanding Policy Results:**
- `FAIL` with `[SOC2-XX.X]`: Violates SOC2 requirement - must be fixed for audit compliance
- `WARN` with `[SOC2-XX.X]`: SOC2 best practice recommendation
- `WARN` with `[DRATA]`: Recommended for Drata monitoring integration

**Resources:**
- [Organization Policies Documentation](./policies/README.md)
- [Conftest Documentation](https://www.conftest.dev/)
- [OPA Policy Language Guide](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [Rego Playground](https://play.openpolicyagent.org/)

---

## Combining Multiple Scans

You can combine multiple security scans in a single workflow:

```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:

jobs:
  golang-scan:
    uses: nevadoai/.github/.github/workflows/golang-security-scan.yml@v1.0.0
    with:
      go-version: '1.21'

  nodejs-scan:
    uses: nevadoai/.github/.github/workflows/nodejs-security-scan.yml@v1.0.0
    with:
      working-directory: './lambda'

  iac-scan:
    uses: nevadoai/.github/.github/workflows/iac-security-scan.yml@v1.0.0
    with:
      terraform-directory: './infrastructure'

  policy-check:
    uses: nevadoai/.github/.github/workflows/policy-as-code.yml@v1.0.0
    with:
      config-directory: './infrastructure'
```

## Security Scan Results

All security scan results are uploaded to GitHub's Security tab where you can:
- View detailed vulnerability reports
- Track security issues over time
- Integrate with GitHub's Dependabot alerts
- Export results in SARIF format
