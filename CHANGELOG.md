# Changelog

All notable changes to Leakwatch will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [v1.2.0] - 2026-03-24

### Added
- **Slack Workspace Scanning** — scan Slack messages, channels, and files for secrets
- `scan slack` command with Bot Token authentication (`--token` or `LEAKWATCH_SLACK_TOKEN`)
- Channel filtering (`--channels`, `--exclude-channels`), date filtering (`--since`)
- DM scanning opt-in (`--include-dms`), file scanning (`--include-files`)
- Rate-limited Slack API pagination (configurable with `--rate-limit`)
- `SourceMetadata` extended with Slack fields (Channel, ChannelName, MessageUser, MessageTS, ThreadTS)

---

## [v1.1.0] - 2026-03-24

### Added
- **Remediation Guidance** — actionable rotation/revocation instructions for all detectors
- `--remediation` flag on all scan commands to include guidance in output
- Remediation registry with guidance for 10+ detector types (AWS, GitHub, Slack, Stripe, JWT, DB Connection, Private Key, Generic)
- SARIF output includes `help` and `helpUri` properties on rules when remediation is enabled
- CSV output includes `remediation` column
- Table output includes `REMEDIATION` column

---

## [v1.0.0] - 2026-03-24

### Added

#### Scan Sources
- Filesystem scanning with `scan fs` command
- Git repository scanning with `scan git` command (full history + diff-based)
- Container image scanning with `scan image` command (layer-by-layer, daemonless)
- AWS S3 bucket scanning with `scan s3` command
- Google Cloud Storage scanning with `scan gcs` command
- Parallel multi-repo scanning with `scan repos` command

#### Secret Detectors
- AWS Access Key ID detector
- GitHub Personal Access Token detector
- Slack Bot/User Token detector
- Slack Webhook URL detector
- Stripe Live API Key detector
- Stripe Test API Key detector
- JWT detector
- Database Connection String detector (PostgreSQL, MySQL, MongoDB, Redis)
- Private Key detector (RSA, SSH, DSA, EC, PGP)
- Generic API Key detector (with entropy filtering)
- YAML custom rule support for user-defined detectors

#### Detection Engine
- Aho-Corasick keyword pre-filtering for O(n) multi-pattern matching
- Shannon entropy analysis with configurable thresholds
- Hybrid detection pipeline: keyword pre-filter → regex validation → entropy check
- Worker pool with bounded concurrency and graceful shutdown
- Context cancellation propagation throughout the pipeline

#### Secret Verification
- Verifier interface with rate-limited concurrent verification engine
- AWS STS `GetCallerIdentity` verifier
- GitHub API `/user` verifier
- `--only-verified` flag to show only active secrets
- `--no-verify` flag to disable verification

#### Output Formats
- JSON output with `omitempty` and `ShowRaw` security control
- SARIF v2.1.0 output for GitHub Code Scanning integration
- CSV output for spreadsheet analysis
- Human-readable terminal table output
- Severity serialized as string in JSON (`"critical"`, not `3`)

#### Filtering & Ignoring
- `.leakwatchignore` file support with glob patterns (including `**`)
- Inline ignore comments (`# leakwatch:ignore` and `# leakwatch:ignore:<detector-id>`)
- `--min-severity` flag for severity threshold filtering
- File size, binary file, and extension filtering

#### Configuration
- Hierarchical configuration: CLI flags > env vars > project YAML > global YAML > defaults
- `.leakwatch.yaml` configuration file
- `LEAKWATCH_` environment variable prefix
- Git-specific flags: `--since`, `--since-commit`, `--branch`, `--depth`
- Cloud-specific flags: `--prefix`, `--region`, `--project`

#### CI/CD & Distribution
- GitHub Actions (`action/action.yml`) with SARIF upload support
- Pre-commit hook (`.pre-commit-hooks.yaml`)
- Dockerfile (multi-stage, non-root, Alpine-based)
- Homebrew formula (`Formula/leakwatch.rb`)
- GoReleaser configuration for cross-platform builds
- CI pipeline: test (Go 1.23/1.24 matrix), lint, security scan, 80% coverage gate

#### Documentation
- 6 user guides: Getting Started, Configuration, CI/CD Integration, Custom Rules, Container Scanning, Cloud Scanning
- 8 Architecture Decision Records (ADRs)
- Architecture design document with interface definitions
- Competitive analysis and technology decisions
- Code review standards (50+ checklist items, 12 zero-tolerance rules)
- Release and distribution standards
- Development standards (coding, testing, CI/CD)
- Documentation standards (Mermaid diagrams, templates)

### Security
- `ShowRaw` defense-in-depth: raw secret content stripped by default at formatter level
- URL credential sanitization before logging
- Path traversal protection in filesystem and container sources
- Temp directory cleanup for cloned repositories (`Close()` method)
- `secret_scanning.yml` to exclude test fixtures from GitHub Push Protection
