---
title: "CLI Reference"
description: "Complete reference for every Leakwatch command, subcommand, and flag."
---

# CLI Reference

This page is the authoritative reference for all Leakwatch commands and flags. For conceptual explanations and worked examples, follow the cross-links to the relevant scanning or configuration pages.

## Global flags

These flags are available on every command and subcommand.

| Flag | Default | Description |
|------|---------|-------------|
| `--config <path>` | auto-discovered `.leakwatch.yaml` | Path to a configuration file. When omitted, Leakwatch searches the current directory and its parents for `.leakwatch.yaml`. |
| `--log-level <level>` | `warn` | Logging verbosity: `debug`, `info`, `warn`, or `error`. Log output goes to stderr and does not affect scan results. |

## `leakwatch version`

Prints the binary version, commit hash, and build timestamp, then exits.

```bash
leakwatch version
```

```text
leakwatch v1.5.0 (commit: a3f9c12, built: 2026-05-10T08:22:00Z)
```

## `leakwatch init`

Generates a `.leakwatch.yaml` configuration file in the current directory with recommended defaults.

```bash
leakwatch init [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--output <path>` | `.leakwatch.yaml` | Write the config file to this path instead of the default. |
| `--force` | `false` | Overwrite an existing config file. Without this flag, `init` exits with an error if the output file already exists. |

```bash
# Generate the default config
leakwatch init

# Overwrite an existing config
leakwatch init --force
```

## `leakwatch scan`

Parent command for all scan subcommands. Has no behavior on its own; run a subcommand.

### Common scan flags

The following flags are available on **all** `scan` subcommands.

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--format` | `-f` | `json` | Output format: `json`, `sarif`, `csv`, or `table`. |
| `--output` | `-o` | stdout | Write results to this file path instead of stdout. |
| `--concurrency` | `-c` | CPU count | Number of concurrent scan workers. |
| `--max-file-size` | — | `10485760` (10 MB) | Skip files or blobs larger than this number of bytes. |
| `--show-raw` | — | `false` | Include the raw (unredacted) secret value in output. Use with caution. |
| `--no-verify` | — | `false` | Disable live secret verification. No outbound API calls are made. |
| `--only-verified` | — | `false` | Report only findings that Leakwatch has confirmed are active via live verification. |
| `--min-severity` | — | `low` | Minimum severity to include in output: `low`, `medium`, `high`, or `critical`. |
| `--remediation` | — | `false` | Attach remediation guidance (rotation/revocation steps) to each finding. |

---

### `scan fs`

Scans a local directory tree.

```bash
leakwatch scan fs [path] [flags]
```

`path` defaults to `.`. Accepts at most one positional argument.

#### Filesystem-specific flags

| Flag | Default | Description |
|------|---------|-------------|
| `--exclude <pattern>` | — | Glob pattern for paths to exclude. Repeatable. |

#### Examples

```bash
# Scan the current directory, print a colorized table
leakwatch scan fs . --format table

# Save SARIF output, exclude test files and vendor
leakwatch scan fs . \
  --exclude "**/*_test.go" \
  --exclude "vendor/**" \
  --format sarif \
  --output results.sarif
```

---

### `scan git`

Scans the full commit history of a local or remote Git repository.

```bash
leakwatch scan git <url_or_path> [flags]
```

Exactly one positional argument is required: a local path or an HTTP/HTTPS/SSH URL.

#### Git-specific flags

| Flag | Default | Description |
|------|---------|-------------|
| `--since <YYYY-MM-DD>` | — | Scan only commits after this date. |
| `--since-commit <hash>` | — | Scan only changes from this commit hash to HEAD. |
| `--branch <name>` | — | Target a specific branch instead of the default branch. |
| `--depth <int>` | `0` (full) | Shallow clone depth for remote repositories. `0` fetches the full history. |

#### Examples

```bash
# Scan full local history
leakwatch scan git . --format table

# Scan only commits added by a pull request
leakwatch scan git . --since-commit a1b2c3d --format json
```

---

### `scan image`

Scans the layers of an OCI/Docker image for secrets. Leakwatch is daemonless and pulls directly from the registry — no Docker socket is required.

```bash
leakwatch scan image <image:tag> [flags]
```

Exactly one positional argument is required.

#### Examples

```bash
# Scan a public image
leakwatch scan image nginx:latest --format table

# Scan a private registry image and save JSON output
leakwatch scan image registry.example.com/my-app:v2.3.0 \
  --format json \
  --output image-results.json
```

---

### `scan s3`

Scans objects in an AWS S3 bucket.

```bash
leakwatch scan s3 <bucket> [flags]
```

Exactly one positional argument is required.

#### S3-specific flags

| Flag | Default | Description |
|------|---------|-------------|
| `--prefix <string>` | — | Limit the scan to objects whose key starts with this prefix. |
| `--region <string>` | — | AWS region of the bucket. Falls back to `AWS_REGION` environment variable or the AWS SDK default. |

#### Examples

```bash
# Scan an entire bucket
leakwatch scan s3 my-data-bucket --region us-east-1 --format table

# Scan only a specific prefix
leakwatch scan s3 my-data-bucket --prefix backups/2026/ --format json
```

---

### `scan gcs`

Scans objects in a Google Cloud Storage bucket.

```bash
leakwatch scan gcs <bucket> [flags]
```

Exactly one positional argument is required.

#### GCS-specific flags

| Flag | Default | Description |
|------|---------|-------------|
| `--prefix <string>` | — | Limit the scan to objects whose name starts with this prefix. |
| `--project <string>` | — | GCP project ID. Required when the bucket's project cannot be inferred from the default credentials. |

#### Examples

```bash
# Scan an entire GCS bucket
leakwatch scan gcs my-gcs-bucket --project my-gcp-project --format table

# Scan a prefix
leakwatch scan gcs my-gcs-bucket --prefix uploads/2026/ --format json
```

---

### `scan slack`

Scans message text in a Slack workspace.

```bash
leakwatch scan slack [flags]
```

No positional arguments.

#### Slack-specific flags

| Flag | Default | Description |
|------|---------|-------------|
| `--token <string>` | — | Slack bot token. Can also be set via `LEAKWATCH_SLACK_TOKEN`. |
| `--channels <list>` | — | Comma-separated list of channel names or IDs to scan. Scans all accessible channels when omitted. |
| `--exclude-channels <list>` | — | Comma-separated list of channel names or IDs to skip. |
| `--since <YYYY-MM-DD>` | — | Scan only messages posted after this date. |
| `--include-dms` | `false` | Include direct messages (requires additional OAuth scopes). |
| `--rate-limit <int>` | `20` | Maximum Slack API requests per second. |

#### Examples

```bash
# Scan all accessible channels
leakwatch scan slack --token xoxb-••••••••••••-••••••••••••-•••••••••••••••••••••••• --format table

# Scan specific channels since a date
leakwatch scan slack \
  --token xoxb-••••••••••••-••••••••••••-••••••••••••••••••••••••• \
  --channels general,engineering \
  --since 2026-01-01 \
  --format json
```

---

### `scan repos`

Scans multiple Git repositories in parallel.

```bash
leakwatch scan repos <url_or_path...> [flags]
```

Requires at least two positional arguments (repository URLs or local paths).

#### Repos-specific flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--parallel` | — | `3` | Number of repositories to scan concurrently. |
| `--concurrency` | `-c` | CPU count | Worker concurrency within each repository scan. |

#### Examples

```bash
# Scan two repositories in parallel
leakwatch scan repos \
  https://github.com/org/repo-a.git \
  https://github.com/org/repo-b.git \
  --format json

# Increase parallelism for a large set of repos
leakwatch scan repos \
  https://github.com/org/repo-a.git \
  https://github.com/org/repo-b.git \
  https://github.com/org/repo-c.git \
  --parallel 3 \
  --format sarif \
  --output multi-repo.sarif
```

---

## See also

- [Exit Codes](#/reference/exit-codes) — how exit codes map to scan outcomes.
- [Environment Variables](#/reference/environment-variables) — configure Leakwatch without flags.
- [Filesystem Scanning](#/scanning/filesystem) — detailed `scan fs` guide.
- [Git History](#/scanning/git-history) — detailed `scan git` guide.
- [Configuration File](#/configuration/config-file) — `.leakwatch.yaml` reference.
