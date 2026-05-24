---
title: "Filesystem"
description: "Scan a local directory tree for leaked secrets with leakwatch scan fs."
---

# Filesystem

Local source code is where secrets most often appear first. The `leakwatch scan fs` command walks every file in a directory tree, runs the full detection pipeline on each one, and reports any findings before they can be committed — or after the fact on an existing codebase.

## Basic usage

```bash
leakwatch scan fs [path]
```

`path` is optional. When omitted, Leakwatch scans the current working directory (`.`). Only one path argument is accepted.

```bash
# Scan the current directory
leakwatch scan fs

# Scan a specific project folder
leakwatch scan fs ./my-project
```

## What the filesystem source skips automatically

To keep scans fast and noise-free, the filesystem source skips the following without any configuration:

- **Binary files** — detected by the presence of a null byte in the first 8 KB of the file.
- **Known binary extensions** — common compiled, image, audio, video, and archive formats.
- **Lock files** — `package-lock.json`, `yarn.lock`, `Pipfile.lock`, and similar.

## Flags

### Filesystem-specific

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--exclude` | string (repeatable) | — | Glob patterns for paths to exclude. Can be repeated or comma-separated. |

### Common scan flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--format` | `-f` | `json` | Output format: `json`, `sarif`, `csv`, `table`. |
| `--output` | `-o` | stdout | Write results to this file instead of stdout. |
| `--concurrency` | `-c` | CPU count | Number of concurrent workers. |
| `--max-file-size` | — | `10485760` (10 MB) | Skip files larger than this value (bytes). |
| `--show-raw` | — | `false` | Include the raw secret value in output. |
| `--no-verify` | — | `false` | Disable secret verification. |
| `--only-verified` | — | `false` | Report only findings confirmed active by verification. |
| `--min-severity` | — | `low` | Minimum severity to report: `low`, `medium`, `high`, `critical`. |
| `--remediation` | — | `false` | Attach remediation guidance to each finding. |

Root-level flags `--config` and `--log-level` (default `warn`) also apply.

## Examples

Scan the current directory and print a colorized table to the terminal:

```bash
leakwatch scan fs . --format table
```

Exclude test files and vendor directories, then save SARIF output for GitHub Code Scanning:

```bash
leakwatch scan fs . \
  --exclude "**/*_test.go" \
  --exclude "vendor/**" \
  --format sarif \
  --output results.sarif
```

Limit file size to 5 MB and increase worker count for a large monorepo:

```bash
leakwatch scan fs . --max-file-size 5242880 --concurrency 8 --format table
```

Show only high-severity findings and include rotation instructions:

```bash
leakwatch scan fs . --min-severity high --remediation --format table
```

## Excluding paths

The `--exclude` flag accepts glob patterns and can be specified multiple times or as a comma-separated list:

```bash
# Two separate flags
leakwatch scan fs . --exclude "**/*_test.go" --exclude "docs/**"

# Comma-separated
leakwatch scan fs . --exclude "**/*_test.go,docs/**"
```

For permanent exclusion rules shared across your team, add them to `.leakwatch.yaml` under `filter.exclude-paths`. Those rules apply to every source, not just filesystem scans. You can also create a `.leakwatchignore` file in your project root. See [Config File](#/configuration/config-file) and [Ignoring Findings](#/configuration/ignoring-findings) for details.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed, no findings. |
| `1` | Scan completed, findings reported. |
| `2` | Scan failed (configuration error, unreadable path, etc.). |

A scan summary (source type, target, file count, duration, and finding count) is printed to stderr after every run. Scans cancel gracefully on SIGINT/SIGTERM.

:::tip
Run `leakwatch scan fs . --format table` during development to get a quick visual overview. Switch to `--format sarif` in CI pipelines to integrate with GitHub Code Scanning.
:::

## See also

- [Quick Start](#/getting-started/quick-start) — run your first scan in under a minute.
- [Config File](#/configuration/config-file) — configure default format, exclusions, and more.
- [Ignoring Findings](#/configuration/ignoring-findings) — `.leakwatchignore` and inline suppression.
- [How Verification Works](#/verification/how-verification-works) — understand verification statuses.
- [Git History](#/scanning/git-history) — scan committed history, not just the working tree.
- [CLI Reference](#/reference/cli-reference) — full flag reference for all commands.
