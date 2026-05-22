# Leakwatch - Phased Development Roadmap

> **Document Version:** 6.1
> **Date:** 2026-04-09
> **Status:** Approved
> **Last Updated:** 2026-05-21

---

## Current Status

| Phase | Status | Version | Date |
|-------|--------|---------|------|
| Phase 1 — MVP | Completed | `v0.1.0` | 2026-03-24 |
| Phase 2 — Git Integration | Completed | `v0.2.0` | 2026-03-24 |
| Phase 3 — Detection & Verification | Completed | `v0.3.0` | 2026-03-24 |
| Phase 4 — Enterprise Capabilities | Completed | `v0.4.0` | 2026-03-24 |
| Phase 5 — Platform Expansion | Completed (8/8) | `v1.0.0` | 2026-03-24 |
| Phase 6 — Remediation Guidance | Completed | `v1.1.0` | 2026-03-24 |
| Phase 7 — Slack Scanning | Completed | `v1.2.0` | 2026-03-24 |
| Phase 8 — Verifier Expansion | Completed | `v1.3.0` | 2026-03-25 |
| Phase 8.1 — Binary/Homebrew Fix | Completed | `v1.3.1` | 2026-03-25 |
| Phase 8.2 — CLI UX Improvements | Completed | `v1.3.2` | 2026-03-25 |
| Phase 8.3 — Scan Summary + Security | Completed | `v1.4.0` | 2026-04-08 |
| Phase 8.4 — False Positive Reduction | Completed | `v1.5.0` | 2026-04-09 |
| Phase 9 — Confluence/Jira | Planned | `v1.6.0` | — |
| Phase 10 — Secrets Inventory | Planned | `v1.7.0` | — |
| Phase 11 — Honeytokens | Planned | `v1.8.0` | — |

### v1.5.0 Highlights

- **False positive reduction** — improved filtering for lock files (`package-lock.json`, `yarn.lock`, etc.), test fixtures, and placeholder patterns
- **ADO.NET connection string support** — `dbconn` detector updated to recognize Microsoft SQL Server ADO.NET connection strings
- **Go 1.25.8 pin** — CI pinned to Go 1.25.8 (latest version available in GitHub Actions runners at the time of release)
- **PagerDuty context-aware detection** — context-based checks to reduce false positives

### v1.4.0 Highlights

- **Scan summary** — every scan prints a summary to stderr (source, target, duration, file count, findings count, verification stats)
- **`leakwatch init` command** — generates `.leakwatch.yaml` with sensible defaults
- **Colored table output** — ANSI colors by severity in the terminal table formatter (critical=red, high=yellow, medium=cyan, low=white)
- **Rich help messages** — all commands include `Example` sections
- **`.leakwatchignore` CWD fallback** — when no `.leakwatchignore` is found alongside the config file, the current working directory is also checked
- **Go 1.25.8** + go-git v5.17.1 — security patches

### v1.3.2 Highlights

- **CLI UX improvements** — more readable help messages, refined defaults
- **GoReleaser binary name fix** — forced lowercase binary name in release artifacts

### v1.3.1 Highlights

- **Homebrew automation** — CI configured with `HOMEBREW_TAP_TOKEN` for automatic Homebrew tap updates via GoReleaser
- **Community infrastructure** — Code of Conduct, issue templates, GitHub Discussions enabled

### v1.3.0 Highlights

- **54 verifiers implemented (51 packages)** — verification coverage increased from ~5% to ~84% (54/64)
- **Live API verification** for the majority of detectors across cloud, AI/ML, DevTools, CI/CD, communication, payment, monitoring, security, and SaaS categories
- **Format validation** for 5 detectors (JWT, Azure Storage, Azure Entra, GCP Service Account, Snowflake)
- **Per-provider rate limiting** for all verifiers with configurable limits
- **5 implementation sprints** completed: V-1 through V-5

### v1.0.0 Highlights

- **5 scan sources:** Filesystem, Git history, Container image, AWS S3, Google Cloud Storage
- **64 detectors (60 packages):** AWS, GitHub, Slack, Stripe, JWT, and many more across cloud, AI/ML, DevTools, CI/CD, communication, payment, database, infrastructure, identity, monitoring, security, and SaaS categories + YAML custom rules
- **4 output formats:** JSON, SARIF, CSV, Table
- **Aho-Corasick hybrid detection engine** with Shannon entropy analysis
- **Verifier infrastructure:** 54 verifiers (51 packages), including AWS STS and GitHub API verifiers (rate-limited, concurrent)
- **`.leakwatchignore`** and inline ignore (`# leakwatch:ignore`)
- **CI/CD:** Pre-commit hook, GitHub Action, Docker image, Homebrew formula
- **Parallel repo scanning** (`scan repos --parallel`)
- **Filtering:** `--min-severity`, `--only-verified`, `--no-verify`
- **Documentation:** 6 guides, 8 ADRs, 4 standards documents, architecture design
- **2 full code reviews** completed (136 findings identified and resolved)

---

## Roadmap Overview

Leakwatch development is planned in 5 phases, each building on the previous one. Each phase produces a usable deliverable upon completion.

```mermaid
gantt
    title Leakwatch Development Roadmap
    dateFormat YYYY-MM-DD
    axisFormat %b %Y

    section Phase 1 — MVP
        Project skeleton & CLI          :done, f1a, 2026-04-01, 2w
        Detector/Source interfaces      :done, f1b, after f1a, 1w
        Filesystem scanning             :done, f1c, after f1b, 1w
        Worker pool & JSON output       :done, f1d, after f1c, 2w

    section Phase 2 — Git
        go-git integration              :done, f2a, after f1d, 2w
        scan git command                :done, f2b, after f2a, 1w
        Scan limiting (since/depth)     :done, f2c, after f2b, 1w

    section Phase 3 — Detection & Verification
        Aho-Corasick engine             :done, f3a, after f2c, 2w
        Entropy analysis                :done, f3b, after f3a, 1w
        Verifier infrastructure         :done, f3c, after f3b, 2w
        AWS/GitHub verifiers            :done, f3d, after f3c, 2w

    section Phase 4 — Enterprise
        Container image scanning        :done, f4a, after f3d, 2w
        SARIF/CSV output formats        :done, f4b, after f4a, 1w
        Pre-commit & .leakwatchignore   :done, f4c, after f4b, 2w

    section Phase 5 — Expansion
        S3/GCS scanning                 :done, f5a, after f4c, 3w
        GitHub Action & Docker          :done, f5b, after f5a, 2w
        v1.0.0 Release                  :milestone, after f5b, 0d
        Slack/Confluence scanning       :f5c, after f5b, 4w
        SaaS platform & Dashboard       :f5d, after f5c, 8w
```

---

## Phase 1: Minimum Viable Product (MVP) — COMPLETED

**Goal:** Build the core scan engine and CLI structure. A functional first version that can scan the local filesystem.

**Duration:** 4-6 Weeks | **Status:** Completed

### Deliverables

| Task | Priority | Description |
|------|----------|-------------|
| Project skeleton | Critical | Project structure with `cobra-cli`, `go.mod` initialization |
| CLI infrastructure | Critical | `scan fs <path>` command, `--format`, `--output`, `--concurrency` flags |
| Configuration system | Critical | Viper integration, `.leakwatch.yaml` file reading, env var support |
| Detector interface and registry | Critical | `Detector` interface, `Register()`, `All()` mechanism |
| Source interface | Critical | `Source` interface, `Chunk` and `SourceMetadata` types |
| Filesystem source | Critical | `io/fs` based `FilesystemSource` implementation |
| Worker pool | Critical | Goroutine pool, jobs/results channels, context cancellation |
| Basic detectors | High | AWS Access Key ID, RSA/SSH Private Key, Generic API Key |
| JSON output formatter | High | `Formatter` interface, JSON implementation |
| Basic filtering | Medium | File size limit, extension filtering |
| Unit tests | High | >80% test coverage for all components |
| CI pipeline | High | GitHub Actions: test, lint, build |

### Acceptance Criteria

- [x] `leakwatch scan fs /path/to/dir` command works
- [x] AWS Access Key ID, RSA Private Key are detected
- [x] Output is produced in JSON format
- [x] Worker count is configurable with `--concurrency` flag
- [x] Output can be written to file with `--output` flag
- [x] CI pipeline is green (test + lint + build)
- [x] Test coverage >80%

### Exit Criteria

GitHub Release published with `v0.1.0` tag.

---

## Phase 2: Git Integration and History Scanning — COMPLETED

**Goal:** Add the ability to scan Git repositories and their full commit histories.

**Duration:** 3-4 Weeks | **Status:** Completed

### Deliverables

| Task | Priority | Description |
|------|----------|-------------|
| go-git integration | Critical | Add dependency, open local/remote repos |
| `scan git` command | Critical | `scan git <url_or_path>` command |
| Git source (GitSource) | Critical | Navigate commit history, read files from each commit |
| Commit metadata | High | Add commit hash, author, date, branch info to findings |
| Scan limiting | High | `--since`, `--depth`, `--branch` flags |
| Remote repo cloning | High | HTTP(S) and SSH authentication support |
| Diff-based scanning | Medium | Scan only changed files (CI/CD optimization) |
| Performance tests | Medium | Large repo benchmarks |

### Acceptance Criteria

- [x] `leakwatch scan git /path/to/repo` command works
- [x] `leakwatch scan git https://github.com/...` scans remote repo
- [x] Full commit history is scanned
- [x] Date filtering works with `--since 2024-01-01`
- [x] Commit info appears in findings
- [x] 10K-commit repo is scanned in <30 seconds

### Exit Criteria

GitHub Release published with `v0.2.0` tag.

---

## Phase 3: Advanced Detection and Verification — COMPLETED

**Goal:** Improve detection accuracy, reduce false positive rate, add secret verification.

**Duration:** 5-7 Weeks | **Status:** Completed

### Deliverables

| Task | Priority | Description |
|------|----------|-------------|
| Aho-Corasick engine | Critical | Keyword pre-filtering with pattern matching |
| Detector expansion | Critical | New detectors (Slack, Stripe, JWT, DB Connection String, etc.) |
| Shannon entropy module | High | Calculation, thresholds, regex integration |
| Verifier interface | Critical | Verification infrastructure, rate limiting, timeout |
| AWS verifier | Critical | Verification via STS GetCallerIdentity |
| GitHub verifier | High | Verification via GitHub API /user endpoint |
| Verification status output | High | VERIFIED_ACTIVE, UNVERIFIED, INACTIVE display |
| `--only-verified` flag | High | Show only verified findings |
| `--no-verify` flag | High | Disable verification |
| YAML custom rule support | Medium | User-defined regex rules (.leakwatch.yaml) |

### Acceptance Criteria

- [x] 100+ patterns matched in <1ms with Aho-Corasick
- [x] AWS key is verified (verified active/inactive)
- [x] GitHub token is verified
- [x] False positives are filtered with `--only-verified`
- [x] Low-entropy matches are flagged with entropy analysis
- [x] Custom rules can be defined via YAML

### Exit Criteria

GitHub Release published with `v0.3.0` tag. **The key differentiating feature is completed in this phase.**

---

## Phase 4: Enterprise Capabilities — COMPLETED

**Goal:** Container image scanning, advanced output formats, pre-commit integration.

**Duration:** 4-6 Weeks | **Status:** Completed

### Deliverables

| Task | Priority | Description |
|------|----------|-------------|
| Container image source | Critical | Layer-based scanning with go-containerregistry |
| `scan image` command | Critical | `scan image <image:tag>` command |
| Registry authentication | High | Docker Hub, GHCR, ECR, GCR support |
| SARIF output format | High | GitHub Code Scanning integration |
| CSV output format | Medium | Tabular output |
| Table (human-readable) output | Medium | Terminal table for quick review |
| `.leakwatchignore` | High | .gitignore-style exclusions |
| Inline ignore | Medium | `# leakwatch:ignore` comment support |
| Pre-commit hook | High | `.pre-commit-hooks.yaml` file |
| Severity filtering | Medium | `--min-severity high` flag |

### Acceptance Criteria

- [x] `leakwatch scan image nginx:latest` command works
- [x] Deleted secrets in container layers are detected
- [x] SARIF output is accepted by GitHub Code Scanning
- [x] Pre-commit hook works
- [x] Files can be excluded with `.leakwatchignore`

### Exit Criteria

GitHub Release published with `v0.4.0` tag.

---

## Phase 5: Platform Expansion — COMPLETED

**Goal:** New scan sources, distribution channels, verifier implementations, IDE integration.

**Duration:** Continuous | **Status:** Completed

### Deliverables

| Task | Status | Description |
|------|--------|-------------|
| S3 bucket scanning | [x] Completed | `scan s3 <bucket>` with prefix filtering, region support |
| GCS bucket scanning | [x] Completed | `scan gcs <bucket>` with ADC auth, prefix filtering |
| Homebrew formula | [x] Completed | `Formula/leakwatch.rb` |
| Docker image | [x] Completed | Multi-stage Dockerfile, non-root alpine |
| GitHub Action | [x] Completed | `action/action.yml` with SARIF upload |
| AWS & GitHub verifiers | [x] Completed | AWS STS GetCallerIdentity, GitHub /user API |
| Parallel repo scanning | [x] Completed | `scan repos` with `--parallel` flag |
| VS Code extension | [x] Completed | Diagnostics, scan-on-save, status bar, workspace/file scan |

### Acceptance Criteria

- [x] `leakwatch scan s3 my-bucket` scans S3 objects
- [x] `leakwatch scan gcs my-bucket` scans GCS objects
- [x] `leakwatch scan repos url1 url2 --parallel 5` scans multiple repos
- [x] Docker image runs scans without local installation
- [x] GitHub Action uploads SARIF to Code Scanning
- [x] AWS keys are verified via STS
- [x] VS Code extension provides inline diagnostics and scan-on-save

### Exit Criteria

GitHub Release published with `v1.0.0` tag.

---

## Phase 6: Remediation Guidance — COMPLETED

**Goal:** Actionable remediation instructions for every detected secret type.

**Duration:** 2 weeks | **Version:** `v1.1.0` | **Status:** Completed

### Deliverables

| Task | Priority | Description |
|------|----------|-------------|
| Remediation type | Critical | `Remediation` struct in `pkg/finding/finding.go` |
| Remediation registry | Critical | Per-detector remediation data with rotation steps, doc URLs |
| Formatter updates | High | JSON, SARIF, CSV, Table all display remediation |
| CLI flags | High | `--remediation`, `--remediation-format brief\|full` |
| Tests | High | Registry and enrichment tests |

### Acceptance Criteria

- [x] `leakwatch scan fs /path --remediation` includes rotation steps
- [x] SARIF output includes remediation in rule `help` property
- [x] All 10+ detectors have remediation guidance

---

## Phase 7: Slack Workspace Scanning — COMPLETED

**Goal:** Scan Slack messages, channels, and files for leaked secrets.

**Duration:** 3-4 weeks | **Version:** `v1.2.0` | **Status:** Completed

### Deliverables

| Task | Priority | Description |
|------|----------|-------------|
| SlackSource | Critical | `source.Source` implementation with rate-limited pagination |
| Slack client interface | Critical | Testable `slackClient` abstraction |
| `scan slack` command | Critical | Channel/date filtering, DM opt-in |
| SourceMetadata fields | High | Channel, user, timestamp in findings |
| Tests | High | Mocked client tests |
| Guide | Medium | `docs/guides/slack-scanning.md` |

### Acceptance Criteria

- [x] `leakwatch scan slack --token xoxb-...` scans workspace
- [x] Channel filtering works with `--channels`
- [x] Date filtering works with `--since`
- [x] Rate limiting respects Slack API tiers

---

## Phase 8: Verifier Expansion — COMPLETED

**Goal:** Increase verification coverage to ~84% (54/64). Verified secrets are the key differentiator.

**Duration:** 5 sprints | **Version:** `v1.3.0` | **Status:** Completed

**Analysis:** [docs/architecture/05-VERIFIER-ANALYSIS.md](architecture/05-VERIFIER-ANALYSIS.md)

### Deliverables

| Sprint | Verifiers | Coverage | Status |
|--------|-----------|----------|--------|
| V-1 (Tier 1 P0) | OpenAI, Anthropic, GitLab, SendGrid, DigitalOcean, Cloudflare, Heroku, New Relic, Telegram, Discord, Notion | 14/64 (22%) | [x] Completed |
| V-2 (Tier 1 P1) | Sentry, Vercel, NPM, PyPI, Grafana, PagerDuty, Databricks, Linear, Figma, Airtable, HuggingFace, CircleCI | 26/64 (41%) | [x] Completed |
| V-3 (Tier 1 P2) | DockerHub, Doppler, Snyk, SonarCloud, Postmark, Terraform, LaunchDarkly, Mailgun, Coinbase, Infura | 36/64 (56%) | [x] Completed |
| V-4 (Tier 2) | Okta, Shopify, Stripe, Twilio, Bitbucket, Auth0, Datadog, RubyGems, DeepSeek, Supabase | 47/64 (73%) | [x] Completed |
| V-5 (Tier 2+3) | GitHub OAuth, Teams Webhook, Azure Storage, Azure Entra, GCP, Snowflake, RabbitMQ | 54/64 (84%) | [x] Completed |

**Final totals:** 54 verifiers (51 packages) covering 64 detectors (60 packages).

### Acceptance Criteria

- [x] Verification coverage reaches ~84% (54/64)
- [x] All Tier 1 verifiers use simple HTTP GET/POST pattern
- [x] Rate limiting per provider (configurable)
- [x] `--only-verified` returns results for the verified detector types
- [x] Never log raw credentials during verification

---

## Phase 9: Confluence/Jira Scanning — PLANNED


**Goal:** Scan Atlassian Confluence pages and Jira issues for leaked secrets.

**Duration:** 4-5 weeks | **Version:** `v1.6.0` | **Status:** Planned

### Deliverables

| Task | Priority | Description |
|------|----------|-------------|
| Atlassian shared client | Critical | HTTP client with Cloud + Server/DC auth |
| ConfluenceSource | Critical | Space/page pagination, HTML extraction |
| JiraSource | Critical | JQL query, issue/comment scanning |
| `scan confluence` command | Critical | Space filtering, attachment scanning |
| `scan jira` command | Critical | Project filtering, JQL support |
| SourceMetadata fields | High | Space, page, issue key in findings |
| Tests | High | `httptest.NewServer` mocks |
| Guide | Medium | `docs/guides/atlassian-scanning.md` |

### Acceptance Criteria

- [ ] `leakwatch scan confluence --url URL --api-token TOKEN` scans pages
- [ ] `leakwatch scan jira --url URL --jql "project=SEC"` scans issues
- [ ] Both Cloud and Server editions supported
- [ ] HTML content properly extracted from Confluence storage format

---

## Phase 10: Secrets Inventory — PLANNED

**Goal:** Persistent SQLite-based inventory tracking secrets across scans.

**Duration:** 4-5 weeks | **Version:** `v1.7.0` | **Status:** Planned

### Deliverables

| Task | Priority | Description |
|------|----------|-------------|
| SQLite store | Critical | Pure Go `modernc.org/sqlite`, WAL mode |
| Inventory service | Critical | Upsert, dedup, status tracking |
| `inventory list` | Critical | Filter by status, severity, source |
| `inventory stats` | High | Aggregate statistics |
| `inventory show/update` | High | Detail view, status changes |
| `inventory export` | Medium | JSON/CSV export |
| `inventory reverify` | Medium | Re-verify active secrets |
| Scan integration | Critical | `--inventory` flag on all scan commands |
| Tests | High | In-memory SQLite tests |
| Guide | Medium | `docs/guides/secrets-inventory.md` |

### Acceptance Criteria

- [ ] `leakwatch scan fs /path --inventory` persists findings
- [ ] `leakwatch inventory list --status active` shows tracked secrets
- [ ] `leakwatch inventory stats` shows aggregate counts
- [ ] Deduplication across multiple scan runs
- [ ] Only redacted values stored (never raw secrets)

---

## Phase 11: Honeytokens — PLANNED

**Goal:** Generate and deploy decoy credentials that alert on unauthorized use.

**Duration:** 3-4 weeks | **Version:** `v1.8.0` | **Status:** Planned

### Deliverables

| Task | Priority | Description |
|------|----------|-------------|
| Generator framework | Critical | AWS, GitHub, generic key generators |
| Honeytoken store | Critical | SQLite persistence (shares inventory DB) |
| Webhook alerter | Critical | HTTP POST on trigger detection |
| `honeytoken generate` | Critical | Create fake credentials |
| `honeytoken deploy` | High | Inject into .env/yaml/json files |
| `honeytoken list/revoke` | High | Management commands |
| `honeytoken check` | High | Check for triggered tokens |
| Scan integration | Medium | `--detect-honeytokens` flag |
| Tests | High | Generator, store, alerter tests |
| Guide | Medium | `docs/guides/honeytokens.md` |

### Acceptance Criteria

- [ ] `leakwatch honeytoken generate --type aws` produces realistic fake key
- [ ] `leakwatch honeytoken deploy <id> .env` injects into file
- [ ] Webhook fires when honeytoken is detected in unexpected location
- [ ] Value shown once during generation, only hash persisted

---

## Known Gaps & Follow-up Work

These are not new phases — they are **work that the current `v1.5.0` release still owes**: features the documentation promises but the code does not (yet) deliver, code-quality findings that survived the PR #6 cleanup pass, and refactors flagged by SonarCloud that need their own focused review. Tracked here so nothing slips through the cracks.

**Source:** PR #6 (chore/docs-cleanup-and-sonar-alignment) verification pass and SonarCloud scan of `cemililik_Leakwatch` taken 2026-05-21.

### P0 — Functional Bugs (documented features that did not work) — ✅ RESOLVED

All three were fixed in branch `fix/wire-custom-rules-and-inline-ignore` (PR #7). Each was a feature referenced in the public guides whose wiring was missing from the scan pipeline; each is now wired up, tested, and verified end-to-end with the real CLI.

| # | Bug | Resolution |
|---|-----|------------|
| 1 | **YAML `custom-rules:` was never loaded** — `custom.RegisterCustomRules` existed with tests but had no caller, so user-defined detectors were silently ignored. | `Config.CustomRules []custom.RuleDef` added and bound via Viper; `executeScan` now calls `custom.RegisterCustomRules` before `detector.All()`. Registration is **duplicate-safe**: `RegisterCustomRules` pre-checks `detector.Get(id)` and skips colliding IDs with an error instead of panicking (the registry panics on duplicate IDs). Verified: a `custom-rules:` block in `.leakwatch.yaml` now produces findings; a rule colliding with `aws-access-key-id` is skipped with a warning, no panic. |
| 2 | **Inline ignore (`# leakwatch:ignore[:<id>]`) was not applied** — helpers existed but `executeScan` never invoked them; also impossible because no source set a line number. | Engine now computes line numbers (see below) and the worker drops any finding whose source line carries the marker, **before** verification. New exported helper `filter.LineHasInlineIgnore(data, lineNum, detectorID)` is shared by the worker and the existing `FilterFindingsByInlineIgnore` (DRY). Verified: a secret on a `# leakwatch:ignore` line is not reported; a `:<other-detector>` marker does not suppress unrelated detectors. |
| 3 | **`verification.*` YAML config was not bound** — `verification.enabled/timeout/concurrency/rate-limit` were emitted by `leakwatch init` and documented but had no `VerificationConfig` struct. | `VerificationConfig` added with Viper binding + validation (positive timeout/concurrency/rate-limit); `executeScan` builds the `verifier.Config` from it. `--no-verify` still takes precedence. Verified: `verification.enabled: false` leaves findings `unverified` (no network call); an invalid `timeout: 0s` is rejected at load time. |

**Prerequisite delivered as part of the fix — line-number tracking:** no source (`filesystem`, `git`, …) ever set `SourceMetadata.Line`, so every finding reported `line: 0`. `engine.rawToFinding` now derives the 1-based line from the match's byte offset within the chunk (guarded by `Line == 0` so a future line-aware source is respected). This both powers inline ignore and fixes the long-standing `line: 0` gap in JSON/SARIF/CSV/table output.

### P1 — Config Schema Drift — ✅ MOSTLY RESOLVED

Fixed in PR #7 alongside the P0 items (same "documented but no-op" category):

| YAML key | Status |
|---|---|
| `output.severity-threshold` | ✅ Bound. `--min-severity` still takes precedence (verified). |
| `filter.exclude-detectors` | ✅ Bound. Listed detector IDs are removed from the active set before scanning (verified: excluding `aws-access-key-id` yields zero AWS findings). |
| `slack.token`, `slack.channels`, `slack.exclude-channels`, `slack.include-dms`, `slack.include-files`, `slack.rate-limit` | ⏳ **Still flag-only.** The `scan slack` command is fully functional via CLI flags / `LEAKWATCH_SLACK_TOKEN`; reading these from `.leakwatch.yaml` is a nice-to-have, not a correctness gap. Deferred — bind in a future `scan slack` config pass, or trim them from `configuration.md`. |

### P1 — SonarCloud Findings Still Open

PR #6 closed: 8 BLOCKER vulns (`action.yml` script injection), 110 × `godre:S8184` blank-import smell, 13 × `go:S1192` in `remediation/guidance.go`, 2 hotspots (Dockerfile + release.yml). Remaining open findings as of the 2026-05-21 scan:

| Rule | Count | Severity | Where | Plan |
|---|---:|---|---|---|
| `go:S3776` Cognitive complexity > 15 | 11 funcs | Critical | [internal/source/git/git.go:269](../internal/source/git/git.go) (**cog 49**), `s3.go:122` (31), `git.go:164` (29), `cmd/scan_common.go:154` (29), `scan_repos.go:60` (26), `filesystem.go:67` (24), `container.go:116` (22), `sarif_formatter.go:121` (22), `slack.go:196` (19), `gcs.go:174` (16), `table_formatter.go:37` (16) | Extract-method refactor per function. `git.go:269` is the highest priority (49 ≫ 15). |
| `go:S1192` | 1 | Critical | `internal/verifier/infura/infura_verifier.go:93` — `"Infura API key is invalid or revoked"` ×3 | Local `const`. |
| `go:S108` Empty test block | 2 | Major | `gcs_test.go:321`, `s3_test.go:242` | Either remove or add `TODO` + meaningful assertion. |
| `godre:S8196` One-method interface naming | 3 | Minor | `cmd/scan_common.go:34`, `internal/source/gcs/gcs.go:45`, `internal/verifier/aws/aws_verifier.go:22` | Rename to `-er` suffix (project naming convention). |
| `godre:S8205` Nested anonymous struct | 2 | Minor | `terraform_verifier.go:107`, `linear_verifier.go:112` | Promote to named type. |
| `godre:S8209` Consecutive same-type params | 1 | Minor | `internal/filter/inline.go:27` | Group params (`a, b string` rather than `a string, b string`). |
| `typescript:S6551` | 7 | Minor | `vscode/src/scanner.ts` | Replace `?? ""` non-string fallbacks with explicit `String(...)` casts. |
| `typescript:S7772` | 2-3 | Minor | `vscode/src/extension.ts`, `scanner.ts`, `webpack.config.js` | Use `node:` prefix for `path`, `child_process`. |
| `typescript:S7778` | 2 | Minor | `vscode/src/extension.ts` | Combine consecutive `push(a); push(b);` into `push(a, b)`. |
| `docker:S7020` | 1 | Minor | `Dockerfile:11` | Likely already closed by the PR #6 line split; verify on next scan. |

### P1 — SonarCloud Project Hygiene

- **Quality Gate** — was `NONE` at the time of PR #6's first verification scan; the default "Sonar way" gate is now in effect. It Quality-Gate-Failed PR #6 twice on `new_duplicated_lines_density` (11.6%, then 11.0% after the first fix attempt). Root cause: **SonarCloud Automatic Analysis does not read `sonar-project.properties`** — that file is only honored by CI Based Analysis. Fix landed in PR #6: the exclusions in `sonar-project.properties` were also mirrored to the project via the Settings API (`POST /api/settings/set` for `sonar.cpd.exclusions`, `sonar.exclusions`, `sonar.coverage.exclusions`). **Action remaining:** verify the assigned gate is the project owner's preference; revisit the cpd exclusions in any future refactor PR (especially the verifier-httpapi extraction listed under P2).
- **`sonar-project.properties`** — added in PR #6 as a canonical source-of-truth file and as the configuration that CI Based Analysis would use. It is currently a documentation artifact (Automatic Analysis ignores it). **Done.**
- **`.github/workflows/sonar.yml`** — still missing. A dedicated workflow with `SonarSource/sonarqube-scan-action` would (a) enable per-PR coverage upload, (b) make `sonar-project.properties` the live source of truth (no more API mirroring), and (c) tighten the PR feedback loop. **Action:** add as a small chore PR once `SONAR_TOKEN` is configured as a repo secret. The Automatic Analysis must be **disabled** in the SonarCloud UI at the same time, otherwise the two analysis paths will fight each other.

### P2 — Duplication Refactor Opportunities

SonarCloud reports the project at **36.8% duplicated lines**. PR #6 dramatically reduced one source (the remediation registry — was 99.3% density). Remaining major duplication clusters:

| Refactor | Files affected | Estimated dedup |
|---|---|---|
| **`internal/verifier/httpapi` generic HTTP helper** (Bearer/Basic + JSON body + status-code → `VerificationStatus` map) | 14+ verifier packages (anthropic, openai, deepseek, github, huggingface, gitlab, dockerhub, discord, circleci, etc., each at ~95% density and ~100-130 lines) | ~6 000 → ~1 000 duplicate lines |
| **`internal/verifier/testutil/verifierharness`** table-driven HTTP mock | 14+ `_test.go` files mirror the same setup/teardown for table-driven HTTP tests (sendgrid, snyk, rubygems, npm, dockerhub, heroku, sentry, notion, ...) | ~1 500 → ~300 duplicate lines |
| **`internal/detector/credstring`** common `scheme://user:pass@host` detector | 4 connection-string detectors (FTP, Redis, RabbitMQ, LDAP — tests are ~92% byte-identical) and their tests | ~500 → ~150 duplicate lines |

Combined target: **project duplication 36.8% → ~10%**. Each of these is architectural — open a dedicated PR per refactor, not a mega-commit.

### P2 — Coverage Gaps

CLAUDE.md sets the detector-coverage standard at **≥95%**. Packages currently below or at the edge:

| Package | Coverage | Standard | Note |
|---|---:|---|---|
| `detector/generic` | 82.1% | 95% | Entropy paths not all exercised. |
| `detector/heroku` | 93.8% | 95% | One regex branch uncovered. |
| `detector/privatekey` | 92.3% | 95% | DSA / EC / PGP branches less covered than RSA / SSH. |
| `detector/snowflake` | 92.3% | 95% | Format validator edge cases. |
| `detector/stripe` | 92.3% | 95% | Live + test key duplication; testutil refactor (P2 above) helps here. |

Source packages (no formal standard, but visible gaps):

| Package | Coverage |
|---|---:|
| `source/container` | 55.2% |
| `source/git` | 64.2% |
| `source/gcs` | 71.3% |
| `source/s3` | 73.6% |

### P2 — Miscellaneous

- **VS Code extension custom rules path setting** ([vscode-extension.md](guides/vscode-extension.md) `leakwatch.customRulesPath`) is wired through to the CLI via `--custom-rules`, but the CLI side does nothing until P0 #1 is fixed. Will auto-resolve.
- **JWT format-only verifier (optional future):** `internal/verifier/jwt/` does not exist. If we ever want format-only verification for JWTs (decode + `exp` check) we need a new verification status semantic ("verified_well_formed" or similar) to avoid implying the token grants access. Until then, JWT findings are correctly classified as "Not Verifiable".

### P3 — Long-tail Notes

- **Missing `v1.1.0` / `v1.2.0` git tags:** Phase 6 and Phase 7 were released as part of `v1.3.0` without intermediate tags. Backfilling tags retroactively is optional (`git tag v1.1.0 <commit>; git tag v1.2.0 <commit>; git push --tags`) — useful for some package indexers, not blocking. See note under Release Plan.
- **Self-scan noise from test fixtures:** detector and verifier tests embed synthetic keys that match their own regex. `.leakwatchignore` already excludes `**/*_test.go` and `internal/verifier/**` for user-facing scans; running `leakwatch scan fs .` inside this repo with the default ignore will still find a handful in `rules/examples.yaml` and docs — acceptable.

---

## Future: Long Term Vision

| Task | Description |
|------|-------------|
| ML-based detection | Machine learning for unknown secret formats |
| Vault integration | Automatic rotation with HashiCorp Vault / AWS Secrets Manager |
| SaaS platform | Centralized management dashboard |
| API mode | Run Leakwatch as a service |
| Webhook notifications | Slack, Teams, PagerDuty integrations |

---

## Release Plan

| Version | Phase | Description | Date |
|---------|-------|-------------|------|
| `v0.1.0` | Phase 1 | MVP — Filesystem scanning, basic detectors | 2026-03-24 |
| `v0.2.0` | Phase 2 | Git history scanning | 2026-03-24 |
| `v0.3.0` | Phase 3 | Verification, Aho-Corasick, entropy | 2026-03-24 |
| `v0.4.0` | Phase 4 | Container scanning, SARIF, pre-commit | 2026-03-24 |
| `v1.0.0` | Phase 5 | S3/GCS, verifiers, GitHub Action, Docker | 2026-03-24 |
| `v1.1.0` | Phase 6 | Remediation guidance for all detectors (no git tag — see note) | — |
| `v1.2.0` | Phase 7 | Slack workspace scanning (no git tag — see note) | — |
| `v1.3.0` | Phase 8 | Verifier expansion (~84% coverage, 54/64) | 2026-03-25 |
| `v1.3.1` | Phase 8.1 | Binary/Homebrew fix, community infrastructure | 2026-03-25 |
| `v1.3.2` | Phase 8.2 | CLI UX improvements | 2026-03-25 |
| `v1.4.0` | Phase 8.3 | Scan summary, `init` command, colored table, security patches | 2026-04-08 |
| `v1.5.0` | Phase 8.4 | False positive reduction, ADO.NET support | 2026-04-09 |
| `v1.6.0` | Phase 9 | Confluence/Jira scanning | — |
| `v1.7.0` | Phase 10 | Secrets inventory (SQLite) | — |
| `v1.8.0` | Phase 11 | Honeytokens | — |
| `v2.x.x` | Future | ML detection, SaaS platform, Vault | Ongoing |

> **Note on v1.1.0 / v1.2.0:** Phase 6 (Remediation Guidance) and Phase 7 (Slack Scanning) were completed and merged into `main`, but no `v1.1.0` or `v1.2.0` git tags were ever created. The features shipped as part of the `v1.3.0` release. The version slots are preserved here to keep the phase-to-version mapping consistent.

---

## Success Metrics

### Technical

| Metric | Target | Measurement |
|--------|--------|-------------|
| Test coverage | >80% | `go test -cover` |
| False positive rate | <5% (verified mode) | Benchmark test suite |
| Scan speed (10K commits) | <30 seconds | CI benchmark |
| Memory usage | <512MB (medium repo) | pprof |
| Binary size | <30MB | GoReleaser |
| CI pipeline duration | <5 minutes | GitHub Actions |

### Community

| Metric | 6-Month Target | 12-Month Target |
|--------|----------------|-----------------|
| GitHub Stars | 500+ | 2,000+ |
| Contributors | 5+ | 15+ |
| Detector count | 50+ | 200+ |
| Verifier count | 54 (achieved) | 60+ |
| Source count | 5 (fs, git, container, S3, GCS) | 8+ |

---

## Risk Management

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Go regex performance is insufficient | Medium | High | Aho-Corasick pre-filtering; Rust FFI if needed |
| Slow community adoption | High | Medium | Quality documentation, example projects, blog posts |
| Existing tools evolve rapidly | Medium | Medium | Focus on differentiation (MIT + verification combo) |
| Solo developer burnout | High | High | Small phase-based goals, encourage community contributions |
| API verification rate limiting | Medium | Low | Smart rate limiting, caching, `--no-verify` option |
