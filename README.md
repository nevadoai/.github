# Nevado AI - Organization GitHub Configuration

This repository contains organization-wide GitHub configurations and reusable workflows.

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
    uses: nevadoai/.github/.github/workflows/auto-approve-after-ai-review.yml@main
    secrets: inherit
```

**Required Org Secrets:**
- `TYLER_APPROVE_PAT` - Tyler's PAT for approving Josh's PRs
- `JOSH_APPROVE_PAT` - Josh's PAT for approving Tyler's PRs

See [AI Auto-Approval Setup](https://github.com/nevadoai/command-center/blob/main/docs/AI_AUTO_APPROVAL_SETUP.md) for detailed setup instructions.
