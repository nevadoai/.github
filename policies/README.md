# Nevado AI - Organization Policy Repository

This directory contains centralized Open Policy Agent (OPA) policies for the organization. These policies are automatically used by the `policy-as-code.yml` reusable workflow to enforce SOC2 compliance and security best practices across all repositories.

**Drata Integration**: These policies are designed to align with Drata's SOC2 monitoring requirements, ensuring infrastructure code meets compliance standards before deployment.

## Available Policies

### Terraform Policies (`terraform.rego`)

**SOC2-focused policies for AWS Terraform configurations**

Organized by SOC2 Trust Services Criteria to align with audit requirements and Drata monitoring:

#### SOC2 CC6.1 - Data Security & Encryption at Rest
All data at rest must be encrypted:
- **S3 buckets**: Server-side encryption required
- **RDS databases**: Storage encryption required
- **EBS volumes**: Encryption required (standalone and EC2-attached)
- **DynamoDB tables**: Server-side encryption required
- **EFS file systems**: Encryption required
- **EKS clusters**: Secrets encryption required

#### SOC2 CC6.1 - Data Security & Encryption in Transit
Data transmitted over public networks must be encrypted:
- **Load Balancers**: Must use HTTPS (not HTTP)
- **ALB Listeners**: Must use HTTPS (not HTTP)
- **API Gateway**: X-Ray tracing enabled for monitoring

#### SOC2 CC6.1 - Access Control
Systems must be restricted to authorized users only:
- **Security Groups**: No SSH (22) or RDP (3389) from 0.0.0.0/0
- **RDS Databases**: Must not be publicly accessible
- **S3 Buckets**: All public access blocks must be enabled (ACLs, policies, etc.)
- **Network Security**: No wildcard security group rules from internet

#### SOC2 CC6.1 - IAM & Least Privilege
Implement least privilege access control:
- **IAM Policies**: No wildcard permissions (Action: *, Resource: *)
- **IAM Role Policies**: No wildcard permissions
- **IAM Users**: Discouraged (use roles with temporary credentials instead)
- **IAM Access Keys**: Should not be managed in Terraform

#### SOC2 CC6.6 & CC7.2 - Logging and Monitoring
All system activities must be logged and monitored:
- **S3 Buckets**: Access logging required
- **CloudTrail**: Must be enabled, multi-region, with log file validation
- **VPC**: Flow Logs required for network monitoring
- **EC2**: Detailed monitoring required
- **RDS**: CloudWatch Logs export required
- **Lambda**: X-Ray tracing required

#### SOC2 A1.2 - Backup and Recovery (Availability)
Systems must have backup and recovery procedures:
- **S3 Buckets**: Versioning required
- **RDS**: Automated backups with 7+ day retention required
- **RDS**: Multi-AZ deployment recommended
- **DynamoDB**: Point-in-time recovery required

#### SOC2 CC6.1 - Secure Configuration
Systems must be securely configured:
- **Security Groups**: No all-protocol access from internet
- **EC2 Instances**: IMDSv2 recommended
- **EKS Clusters**: Public endpoint access must be restricted with CIDR lists

#### SOC2 CC6.7 - Change Management & Tagging
Resources must be properly tagged for tracking:
- **EC2, RDS, S3**: Tags recommended for change management

#### Drata-Specific Integration Checks
Additional checks for Drata monitoring integration:
- **CloudTrail**: Send logs to CloudWatch for Drata monitoring
- **GuardDuty**: Should be enabled for threat detection
- **AWS Config**: Should be enabled for compliance monitoring
- **Security Hub**: Should be enabled for centralized security findings

All policies include references to specific SOC2 Trust Services Criteria (e.g., `[SOC2-CC6.1]`) in error messages to help with audit trail and compliance documentation.

### Kubernetes Policies (`kubernetes.rego`)

Enforces Kubernetes security best practices:

**Container Security:**
- Must run as non-root user
- No privileged containers
- Privilege escalation disabled
- Read-only root filesystem recommended

**Resource Management:**
- Memory limits required
- CPU limits required
- Requests recommended

**Image Security:**
- No `latest` tags allowed
- Explicit image tags required
- ImagePullPolicy: Always recommended

**Pod Security:**
- No hostNetwork, hostPID, hostIPC
- Security contexts required

**RBAC:**
- No wildcard permissions
- No anonymous/unauthenticated bindings

**Best Practices:**
- Liveness and readiness probes recommended
- Labels required
- Network policies recommended

### Docker Policies (`docker.rego`)

Enforces Dockerfile security and best practices:

**Base Image Security:**
- No `latest` tags
- Explicit versions required

**User Security:**
- Must include USER instruction
- Must not run as root (user root or UID 0)

**Secrets:**
- No hardcoded passwords, secrets, API keys, or tokens

**Best Practices:**
- Use COPY instead of ADD when appropriate
- HEALTHCHECK recommended
- Clean up package manager caches
- Use WORKDIR instead of RUN cd
- Maintainer/authors label recommended
- Minimize layers

## Using These Policies

### Default Usage (Recommended)

The policies in this repository are used by default. Simply call the workflow:

```yaml
name: Policy Check

on:
  push:
    branches: [main]
  pull_request:

jobs:
  policy-check:
    uses: nevadoai/.github/.github/workflows/policy-as-code.yml@main
    with:
      config-directory: '.'  # Directory to scan
```

### Customizing Severity

You can choose to fail on warnings:

```yaml
jobs:
  policy-check:
    uses: nevadoai/.github/.github/workflows/policy-as-code.yml@main
    with:
      config-directory: './infrastructure'
      fail-on-warn: true  # Fail build on warnings
```

### Using Custom Policies

If you need project-specific policies in addition to org policies, create a local `./policy` directory:

```yaml
jobs:
  policy-check:
    uses: nevadoai/.github/.github/workflows/policy-as-code.yml@main
    with:
      policy-directory: './policy'  # Use local policies instead
      config-directory: './infrastructure'
```

### Testing Specific Namespaces

Target specific policy namespaces:

```yaml
jobs:
  terraform-policy:
    uses: nevadoai/.github/.github/workflows/policy-as-code.yml@main
    with:
      config-directory: './terraform'
      namespaces: 'terraform'  # Only run terraform policies

  k8s-policy:
    uses: nevadoai/.github/.github/workflows/policy-as-code.yml@main
    with:
      config-directory: './k8s'
      namespaces: 'kubernetes'  # Only run kubernetes policies
```

## Policy Syntax

Policies are written in Rego, OPA's policy language. All policies include SOC2 Trust Services Criteria references in their error messages.

### Basic Structure

```rego
package namespace_name

import rego.v1

# Deny rules fail the check (hard requirements)
deny contains msg if {
    condition_is_true
    msg := "[SOC2-XX.X] Error message explaining what's wrong and which SOC2 control"
}

# Warn rules show warnings but don't fail (recommendations)
warn contains msg if {
    condition_is_true
    msg := "[SOC2-XX.X] Warning message explaining the recommendation"
}
```

### Example SOC2 Policy

```rego
package terraform

import rego.v1

# SOC2 CC6.1 - Data Security: Ensure S3 buckets have encryption at rest
deny contains msg if {
    some name
    resource := input.resource.aws_s3_bucket[name]
    not resource.server_side_encryption_configuration
    msg := sprintf("[SOC2-CC6.1] S3 bucket '%s' must have server-side encryption enabled for data at rest", [name])
}

# SOC2 A1.2 - Availability: Ensure S3 buckets have versioning for recovery
deny contains msg if {
    some name
    resource := input.resource.aws_s3_bucket[name]
    not resource.versioning
    not has_s3_versioning(name)
    msg := sprintf("[SOC2-A1.2] S3 bucket '%s' must have versioning enabled for data recovery", [name])
}

# Helper function to check for separate versioning resource
has_s3_versioning(bucket_name) if {
    some name
    resource := input.resource.aws_s3_bucket_versioning[name]
    resource.bucket == bucket_name
    resource.versioning_configuration[_].status == "Enabled"
}

# Drata integration: Recommend CloudWatch for monitoring
warn contains msg if {
    some name
    resource := input.resource.aws_cloudtrail[name]
    not resource.cloud_watch_logs_group_arn
    msg := sprintf("[DRATA] CloudTrail '%s' should send logs to CloudWatch Logs for Drata monitoring", [name])
}
```

### Policy Labels Explained

- **`[SOC2-CC6.1]`**: Common Criteria 6.1 - Logical and Physical Access Controls
- **`[SOC2-CC6.6]`**: Common Criteria 6.6 - System Monitoring
- **`[SOC2-CC6.7]`**: Common Criteria 6.7 - Infrastructure and Software
- **`[SOC2-CC7.2]`**: Common Criteria 7.2 - System Monitoring
- **`[SOC2-A1.2]`**: Availability 1.2 - System Availability
- **`[DRATA]`**: Drata-specific integration requirements

## Adding New Policies

To add organization-wide policies:

1. Edit the appropriate `.rego` file in this directory
2. Follow the existing pattern for deny/warn rules
3. Test locally with conftest:
   ```bash
   conftest test your-config-file --policy ./policies
   ```
4. Commit and push to main
5. All repos will automatically use the new policies

## Testing Policies Locally

Install Conftest:
```bash
# macOS
brew install conftest

# Linux
wget https://github.com/open-policy-agent/conftest/releases/download/v0.55.0/conftest_0.55.0_Linux_x86_64.tar.gz
tar xzf conftest_0.55.0_Linux_x86_64.tar.gz
sudo mv conftest /usr/local/bin/
```

Test your Terraform configurations against SOC2 policies:
```bash
# Test a single Terraform file
conftest test main.tf --policy ./policies --namespace terraform

# Test all Terraform files in a directory
conftest test *.tf --policy ./policies --namespace terraform

# Test with detailed output
conftest test main.tf --policy ./policies --namespace terraform --output=table

# Test and fail on warnings (stricter enforcement)
conftest test main.tf --policy ./policies --namespace terraform --fail-on-warn
```

Example output:
```
FAIL - main.tf - [SOC2-CC6.1] S3 bucket 'my-bucket' must have server-side encryption enabled for data at rest
FAIL - main.tf - [SOC2-CC7.2] S3 bucket 'my-bucket' must have access logging enabled for audit trail
WARN - main.tf - [DRATA] CloudTrail 'main-trail' should send logs to CloudWatch Logs for Drata monitoring
```

Test other file types:
```bash
# Test Kubernetes manifests
conftest test deployment.yaml --policy ./policies --namespace kubernetes

# Test Dockerfile
conftest test Dockerfile --policy ./policies --namespace docker
```

## Resources

- [Conftest Documentation](https://www.conftest.dev/)
- [OPA Policy Language](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [Rego Playground](https://play.openpolicyagent.org/)
- [Policy Examples](https://github.com/open-policy-agent/conftest/tree/master/examples)
