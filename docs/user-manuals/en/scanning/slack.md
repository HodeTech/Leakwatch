---
title: "Slack Workspace"
description: "Scan Slack channel and DM message text for leaked secrets."
---

# Slack Workspace

Developers frequently share credentials in chat — a token pasted into a channel for a quick test, a password sent in a DM, or an API key mentioned in an incident thread. `leakwatch scan slack` reads message text across your Slack workspace and flags any secrets it finds.

:::warn
Leakwatch scans **message text only**. Scanning the contents of uploaded files (attachments, snippets) is not implemented. Only the text body of messages is analysed.
:::

## Basic usage

```bash
leakwatch scan slack
```

This command takes **no positional arguments**. All configuration is provided through flags or environment variables.

## Authentication

A Slack Bot Token is required. Provide it via the `--token` flag or the `LEAKWATCH_SLACK_TOKEN` environment variable. Using an environment variable is recommended so the token never appears in shell history or process listings.

```bash
export LEAKWATCH_SLACK_TOKEN=xoxb-...
leakwatch scan slack
```

### Required bot token scopes

The bot token must be associated with a Slack app that has the following OAuth scopes:

| Scope | Purpose |
|-------|---------|
| `channels:history` | Read messages in public channels the bot has joined. |
| `groups:history` | Read messages in private channels the bot has joined. |
| `im:history` | Read direct messages (required only with `--include-dms`). |
| `mpim:history` | Read group direct messages (required only with `--include-dms`). |

## Flags

### Slack-specific

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--token` | string | — | Slack Bot Token. Prefer `LEAKWATCH_SLACK_TOKEN` env var. |
| `--channels` | string | all channels | Comma-separated list of channel names to scan. |
| `--exclude-channels` | string | — | Comma-separated list of channel names to skip. |
| `--since` | string (YYYY-MM-DD) | — | Scan messages posted on or after this date. |
| `--include-dms` | bool | `false` | Also scan direct messages and group DMs. |
| `--rate-limit` | float | `20` | Maximum Slack API requests per second. |

### Common scan flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--format` | `-f` | `json` | Output format: `json`, `sarif`, `csv`, `table`. |
| `--output` | `-o` | stdout | Write results to this file instead of stdout. |
| `--concurrency` | `-c` | CPU count | Number of concurrent workers. |
| `--max-file-size` | — | `10485760` (10 MB) | Internal chunk size limit (bytes). |
| `--show-raw` | — | `false` | Include the raw secret value in output. |
| `--no-verify` | — | `false` | Disable secret verification. |
| `--only-verified` | — | `false` | Report only findings confirmed active by verification. |
| `--min-severity` | — | `low` | Minimum severity to report: `low`, `medium`, `high`, `critical`. |
| `--remediation` | — | `false` | Attach remediation guidance to each finding. |

Root-level flags `--config` and `--log-level` (default `warn`) also apply.

## Examples

Scan all channels the bot has access to, using an environment variable for the token:

```bash
export LEAKWATCH_SLACK_TOKEN=xoxb-...
leakwatch scan slack
```

Scan specific channels and limit to messages since the start of the year:

```bash
leakwatch scan slack \
  --channels general,engineering,backend \
  --since 2026-01-01
```

Exclude noisy channels and include direct messages:

```bash
leakwatch scan slack \
  --exclude-channels random,social,giphy \
  --include-dms
```

Reduce the API request rate to avoid Slack rate-limit errors on large workspaces:

```bash
leakwatch scan slack --rate-limit 10 --format table
```

Save only verified active findings to a JSON file:

```bash
leakwatch scan slack \
  --only-verified \
  --format json \
  --output slack-findings.json
```

## Finding metadata

Each finding from a Slack scan includes message and channel metadata:

| Field | Description |
|-------|-------------|
| `channel` | The channel name where the finding was detected. |
| `message_ts` | Slack message timestamp (unique message ID). |
| `author` | Slack user ID of the message author. |

## Performance considerations

Slack API requests are subject to rate limits enforced by Slack. The `--rate-limit` flag (default `20` requests/second) controls how aggressively Leakwatch makes requests. Lower this value if you see `429 Too Many Requests` errors, especially on large workspaces.

Use `--channels` to target specific channels rather than scanning the entire workspace on every run. Combine with `--since` to scan only recent messages incrementally.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed, no findings. |
| `1` | Scan completed, findings reported. |
| `2` | Scan failed (missing token, authentication error, etc.). |

A scan summary is printed to stderr after every run. Scans cancel gracefully on SIGINT/SIGTERM.

## See also

- [Quick Start](#/getting-started/quick-start) — run your first scan in under a minute.
- [Config File](#/configuration/config-file) — configure defaults in `.leakwatch.yaml`.
- [Ignoring Findings](#/configuration/ignoring-findings) — suppress known false positives.
- [How Verification Works](#/verification/how-verification-works) — understand verification statuses.
- [Git History](#/scanning/git-history) — scan committed history for secrets.
- [CLI Reference](#/reference/cli-reference) — full flag reference for all commands.
