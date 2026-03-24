# Leakwatch - Phased Development Roadmap

> **Document Version:** 4.0
> **Date:** 2026-03-24
> **Status:** Active
> **Last Updated:** 2026-03-24

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
| Phase 8 — Confluence/Jira | Planned | `v1.3.0` | — |
| Phase 9 — Secrets Inventory | Planned | `v1.4.0` | — |
| Phase 10 — Honeytokens | Planned | `v1.5.0` | — |

### v1.0.0 Highlights

- **5 scan sources:** Filesystem, Git history, Container image, AWS S3, Google Cloud Storage
- **10+ detectors:** AWS, GitHub Token, Slack Token/Webhook, Stripe (live/test), JWT, DB Connection String, Private Key, Generic API Key + YAML custom rules
- **4 output formats:** JSON, SARIF, CSV, Table
- **Aho-Corasick hybrid detection engine** with Shannon entropy analysis
- **Verifier infrastructure:** AWS STS and GitHub API verifiers (rate-limited, concurrent)
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

## Phase 8: Confluence/Jira Scanning — PLANNED

**Goal:** Scan Atlassian Confluence pages and Jira issues for leaked secrets.

**Duration:** 4-5 weeks | **Version:** `v1.3.0` | **Status:** Planned

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

## Phase 9: Secrets Inventory — PLANNED

**Goal:** Persistent SQLite-based inventory tracking secrets across scans.

**Duration:** 4-5 weeks | **Version:** `v1.4.0` | **Status:** Planned

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

## Phase 10: Honeytokens — PLANNED

**Goal:** Generate and deploy decoy credentials that alert on unauthorized use.

**Duration:** 3-4 weeks | **Version:** `v1.5.0` | **Status:** Planned

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
| `v1.1.0` | Phase 6 | Remediation guidance for all detectors | — |
| `v1.2.0` | Phase 7 | Slack workspace scanning | — |
| `v1.3.0` | Phase 8 | Confluence/Jira scanning | — |
| `v1.4.0` | Phase 9 | Secrets inventory (SQLite) | — |
| `v1.5.0` | Phase 10 | Honeytokens | — |
| `v2.x.x` | Future | ML detection, SaaS platform, Vault | Ongoing |

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
| Verifier count | 5+ | 20+ |
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
