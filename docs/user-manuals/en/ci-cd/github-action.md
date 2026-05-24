---
title: "GitHub Action"
description: "Use the official Leakwatch GitHub Action to scan for secrets in your GitHub workflows."
---

# GitHub Action

Every push to your repository is an opportunity for a secret to slip through. The official **Leakwatch GitHub Action** (`HodeTech/leakwatch-action@v1`) integrates Leakwatch directly into your GitHub workflow — it installs the tool, runs a scan, maps exit codes, and optionally uploads SARIF results to GitHub Code Scanning, all without any external service dependency.

## Quick start

The minimal configuration blocks the workflow when secrets are found:

```yaml
# .github/workflows/leakwatch-minimal.yml
name: Secret scan (minimal)

on: [push, pull_request]

jobs:
  leakwatch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: HodeTech/leakwatch-action@v1
```

With only the defaults, the action scans the filesystem (`scan-type: fs`), produces SARIF output, skips live verification (`no-verify: true`), and fails the job if any finding is reported.

## Full example with SARIF upload

The following workflow enables SARIF upload to GitHub Code Scanning, which surfaces findings as security alerts inside the repository:

```yaml
# .github/workflows/leakwatch.yml
name: Secret scan

on:
  push:
    branches: ["main", "develop"]
  pull_request:

permissions:
  contents: read
  security-events: write   # required for SARIF upload

jobs:
  leakwatch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Scan for secrets
        uses: HodeTech/leakwatch-action@v1
        with:
          scan-type: fs
          path: .
          format: sarif
          no-verify: "true"
          min-severity: low
          sarif-upload: "true"
          fail-on-findings: "true"
```

:::note
SARIF upload requires the job to declare `permissions: security-events: write`. Without it, the upload step fails with a 403 error. The `contents: read` permission is also needed for `actions/checkout@v4`.
:::

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `scan-type` | `fs` | Scan type to run: `fs`, `git`, or `image`. |
| `path` | `.` | Path to scan (for `fs`/`git`) or image reference (for `image`). |
| `format` | `sarif` | Output format: `json`, `sarif`, `csv`, or `table`. |
| `only-verified` | `false` | Report only findings confirmed active by live verification. |
| `no-verify` | `true` | Disable secret verification (no outbound calls to providers). |
| `min-severity` | `low` | Minimum severity to report: `low`, `medium`, `high`, or `critical`. |
| `sarif-upload` | `false` | Upload SARIF results to GitHub Code Scanning after the scan. |
| `fail-on-findings` | `true` | Fail the workflow step when findings are reported (exit code 1). When `false`, a `::warning::` annotation is emitted instead so the scan does not block the pipeline. Hard errors (exit code 2) always fail the step regardless of this setting. |
| `version` | `latest` | Leakwatch version to install. Use a tag such as `v1.5.0` to pin a specific release. |

## Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | `0` if no findings were reported; `1` if findings were reported. Mirrors the Leakwatch exit code. |
| `sarif-file` | Path to the SARIF output file on the runner (set when `format: sarif`). |

## Verification in CI

By default, `no-verify` is `true` — live verification is **off** in CI. This keeps the scan fast and avoids making outbound network calls to provider APIs from CI runners, which may be behind a firewall or have rate-limited credentials.

To enable verification in CI, set `no-verify: "false"`:

```yaml
- uses: HodeTech/leakwatch-action@v1
  with:
    no-verify: "false"
```

:::warn
Enabling verification in CI causes Leakwatch to make authenticated API calls to providers (AWS, GitHub, Stripe, etc.) for each candidate finding. Be aware of provider rate limits and ensure the runner has outbound internet access.
:::

## How SARIF upload works

When `sarif-upload: "true"` and `format: sarif`, the action:

1. Tells Leakwatch to write output to `results.sarif`.
2. After the scan, calls `github/codeql-action/upload-sarif@v3` with `category: leakwatch`.
3. GitHub processes the file and surfaces findings as **Code Scanning alerts** under the repository's **Security** tab.

The upload step runs with `if: always()`, so results are uploaded even when `fail-on-findings: "true"` causes the scan step to set a failure.

## Using action outputs

```yaml
- name: Scan for secrets
  id: scan
  uses: HodeTech/leakwatch-action@v1
  with:
    fail-on-findings: "false"   # let the workflow continue

- name: Print result
  run: echo "Findings reported: ${{ steps.scan.outputs.findings-count }}"
```

## Pinning a specific version

For reproducible builds, pin `version` to a specific tag:

```yaml
- uses: HodeTech/leakwatch-action@v1
  with:
    version: "v1.5.0"
```

This installs exactly `github.com/HodeTech/leakwatch@v1.5.0` via `go install`.

## See also

- [Output Formats](#/output/output-formats) — understanding JSON, SARIF, CSV, and table output.
- [Exit Codes](#/reference/exit-codes) — how exit codes map to scan outcomes.
- [How Verification Works](#/verification/how-verification-works) — when and how Leakwatch calls provider APIs.
- [Pre-commit Hook](#/ci-cd/pre-commit) — catch secrets before they are committed.
- [Other CI Systems](#/ci-cd/other-ci) — GitLab CI, Jenkins, and generic shell integration.
