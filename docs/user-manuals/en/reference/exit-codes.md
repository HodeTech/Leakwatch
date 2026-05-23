---
title: "Exit Codes"
description: "Leakwatch exit code reference and how to use them in scripts and CI pipelines."
---

# Exit Codes

Leakwatch uses a small, well-defined set of exit codes so that CI pipelines and shell scripts can act on scan results without parsing output. Every scan subcommand exits with one of three codes.

## Code reference

| Code | Name | Meaning |
|------|------|---------|
| `0` | Clean | The scan completed successfully and no findings passed the active filters. |
| `1` | Findings | The scan completed and one or more secrets were found (and passed the active filters). |
| `2` | Error | A hard error occurred — for example, an invalid flag, an unreadable path, or an authentication failure. An `Error: ...` message and a usage hint are printed to stderr. |

## How filters affect exit code 1

Exit code `1` is only emitted when at least one finding survives all active output filters. The two most relevant filters are:

- **`--min-severity`** — findings below the threshold are suppressed. If all findings are `low` severity and you run with `--min-severity high`, exit code `0` is returned even though secrets exist.
- **`--only-verified`** — only findings confirmed active by live verification are reported. If no active secrets are found, exit code `0` is returned.

This means exit code `0` means "no findings matched your current filter settings" — not necessarily that the codebase contains no secrets at all.

:::warn
A clean `0` exit under `--only-verified` does not guarantee the codebase is secret-free. Secrets for which verification is unavailable (9 detector types) are always reported as unverified and are suppressed by `--only-verified`. Pair `--only-verified` with a separate unfiltered scan if you need full coverage.
:::

## Using exit codes in shell scripts

```bash
#!/usr/bin/env bash
set +e
leakwatch scan fs . --format json --output leakwatch.json --no-verify
EXIT_CODE=$?
set -e

case "$EXIT_CODE" in
  0)
    echo "No secrets found. Build continues."
    ;;
  1)
    echo "Secrets found — review leakwatch.json and remediate before merging."
    exit 1
    ;;
  *)
    echo "Leakwatch encountered an error (exit $EXIT_CODE)."
    exit "$EXIT_CODE"
    ;;
esac
```

`set +e` before the scan prevents the shell from exiting on non-zero codes, giving you the chance to capture and handle the code yourself.

## Using exit codes in CI pipelines

Most CI systems treat any non-zero exit code as a step failure. Since Leakwatch exits `1` when secrets are found, the pipeline fails automatically without any extra configuration — simply run the scan command.

To allow the pipeline to continue even when secrets are found (for example, to collect the report without blocking the build), explicitly ignore the exit code:

```bash
leakwatch scan fs . --format sarif --output results.sarif --no-verify || true
```

Or, in GitLab CI:

```yaml
allow_failure: true
```

Or, in the GitHub Action, set `fail-on-findings: "false"`.

## Exit code 2 in practice

Exit code `2` indicates a configuration or runtime error that prevented the scan from running at all. Common causes:

- An invalid flag value (for example, `--format invalid`).
- A path that does not exist or is not readable.
- A missing required argument (for example, `scan git` with no URL).
- An authentication error when connecting to a cloud source.

The error message is printed to stderr and includes context to help diagnose the problem:

```text
Error: unknown format "xlsx"; valid values: json, sarif, csv, table
```

## See also

- [Other CI Systems](#/ci-cd/other-ci) — how to wire exit codes into GitLab CI, Jenkins, and others.
- [GitHub Action](#/ci-cd/github-action) — how the official action maps exit codes to step outcomes.
- [CLI Reference](#/reference/cli-reference) — full flag reference.
