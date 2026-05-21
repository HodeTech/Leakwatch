# Changelog

All notable changes to Leakwatch will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [v1.5.0] - 2026-04-09

### Added
- **ADO.NET (Microsoft SQL Server) connection string** format support in the `dbconn` detector

### Fixed
- **False positive reduction** — improved filtering for lock files (`package-lock.json`, `yarn.lock`, and friends), placeholder patterns, and test fixtures
- **ADO.NET connection string parsing** — handles key/value pairs separated by `;` correctly
- **PagerDuty detector** — context-aware detection to reduce false positives in unrelated string matches

### Changed
- **CI pinned to Go 1.25.8** — latest version currently available in GitHub Actions runners

---

## [v1.4.0] - 2026-04-08

### Added
- **Scan summary** — every scan prints a summary to stderr (date, source type, target, files scanned, duration, findings count, verification stats)
- **`leakwatch init` command** — generates a `.leakwatch.yaml` with recommended defaults
- **Colored table output** — severity-colored terminal output (red=critical/high, yellow=medium, blue=low), auto-disabled when writing to a file
- **Rich help messages** — all commands include `Example` sections with practical usage patterns
- **Better error messages** — friendly error messages with help suggestions

### Changed
- **`scan fs` defaults to current directory** — path argument is now optional (defaults to `.`)
- **`.leakwatchignore` CWD fallback** — also searches the current working directory if `.leakwatchignore` is not found alongside the config file

### Security
- Upgraded to **Go 1.25.8** + **go-git v5.17.1** (security fixes, including the idx file DoS vulnerability)

---

## [v1.3.2] - 2026-03-25

### Fixed
- **GoReleaser binary name** — forced lowercase binary name in release artifacts

---

## [v1.3.1] - 2026-03-25

### Added
- **Code of Conduct, issue templates, GitHub Discussions** enabled for the repository

### Changed
- **Homebrew automation** — CI configured with `HOMEBREW_TAP_TOKEN` so GoReleaser can push to the Homebrew tap automatically on release

---

## [v1.3.0] - 2026-03-25

### Added
- **51 new secret detectors** bringing the total to 60 detector packages (64 detector instances)
  - Sprint 1: OpenAI, Anthropic, GitLab, SendGrid, NPM, Discord, Telegram, Redis, Snowflake, Datadog
  - Sprint 2: Hugging Face, DeepSeek, GCP, Azure (Storage + Entra), Okta, Twilio, Mailgun, Vault, Grafana, PagerDuty, CircleCI, GitHub OAuth
  - Sprint 3: PyPI, RubyGems, Docker Hub, DigitalOcean, Heroku, Vercel, New Relic, Sentry, Shopify, Supabase, Cloudflare, Notion, Linear, Figma, Airtable
  - Sprint 4: Terraform, Databricks, Bitbucket, Coinbase, Infura, RabbitMQ, FTP, LDAP, Auth0, LaunchDarkly, Snyk, SonarCloud, Doppler, MS Teams, Postmark
- **54 verifiers (51 packages)** — verification coverage increased to ~84% (54/64)
  - V-1 (Tier 1 P0): OpenAI, Anthropic, GitLab, SendGrid, DigitalOcean, Cloudflare, Heroku, New Relic, Telegram, Discord, Notion
  - V-2 (Tier 1 P1): Sentry, Vercel, NPM, PyPI, Grafana, PagerDuty, Databricks, Linear, Figma, Airtable, HuggingFace, CircleCI
  - V-3 (Tier 1 P2): DockerHub, Doppler, Snyk, SonarCloud, Postmark, Terraform, LaunchDarkly, Mailgun, Coinbase, Infura
  - V-4 (Tier 2): Okta, Shopify, Stripe (live+test), Twilio, Bitbucket, Auth0, Datadog, RubyGems, DeepSeek, Supabase
  - V-5 (Tier 2+3): GitHub OAuth, Teams Webhook, Azure Storage, Azure Entra, GCP, Snowflake, RabbitMQ
  - Verification types: **Live API verification** (API call to provider) and **Format validation** (structural check without network call, used for JWT, Azure Storage, Azure Entra, GCP Service Account, Snowflake)
  - Per-provider rate limiting for all verifiers (configurable)
- **Remediation guidance** for all detector types (previously planned for the `v1.1.0` slot — shipped together with `v1.3.0`)
- **Slack workspace scanning** — `scan slack` command with channel/date/DM/file filtering (previously planned for the `v1.2.0` slot — shipped together with `v1.3.0`)
- **APISIX key patterns** added to the generic API key detector

> **Note:** The `v1.1.0` (Remediation) and `v1.2.0` (Slack) phases were merged into `main` but never released as standalone git tags. Their features were rolled up into the `v1.3.0` release.

---

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
- Remediation registry with guidance for all built-in detector types (AWS, GitHub, Slack, Stripe, JWT, DB Connection, Private Key, Generic, and more)
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
