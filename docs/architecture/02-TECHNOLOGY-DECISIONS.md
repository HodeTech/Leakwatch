# Leakwatch - Technology Decisions and Rationale

> **Document Version:** 1.1
> **Date:** 2026-05-22
> **Status:** Approved

---

## 1. Executive Summary

This document describes the technology choices of the Leakwatch project, the rationale behind these choices, and the alternatives that were evaluated. Each decision was made based on performance, ecosystem fit, development velocity, and long-term sustainability criteria.

**Key Decision:** Go (Golang) has been selected as the primary development language.

---

## 2. Programming Language Selection: Go (Golang)

### 2.1 Evaluation Criteria

| Criterion | Weight | Description |
|-----------|--------|-------------|
| Regex/Pattern Matching Performance | 25% | The bottleneck of the scanning engine |
| Concurrency Model | 20% | Parallel I/O-bound scanning |
| Ecosystem (Git, Container, CLI) | 20% | Availability of critical libraries |
| Cross-Compilation & Distribution | 15% | Single binary, zero dependencies |
| Development Velocity | 10% | Time to first release |
| Community & Hiring | 10% | Ease of finding contributors |

### 2.2 Language Comparison Matrix

| Criterion | Go | Rust | Python | .NET (C#) | TypeScript |
|-----------|-----|------|--------|-----------|------------|
| **Regex Performance** | Good (RE2) | **Best** | Weak | Good | Moderate |
| **Aho-Corasick Quality** | Adequate | **Best** | Weak | Adequate | Weak |
| **Concurrency Ease** | **Best** | Good (complex) | Weak (GIL) | Good | Weak |
| **Git Library** | **Excellent** (go-git) | Excellent (gitoxide) | Good | Good | Weak |
| **Container Image Library** | **Best** (go-containerregistry) | Developing | Adequate | Weak | Weak |
| **Cross-Compilation** | **Best** | Good | Weak | Adequate | Weak |
| **Single Binary** | **Yes** | **Yes** | No | Yes (AOT) | No |
| **SARIF Support** | Good | Adequate | Good | **Best** | Basic |
| **Development Velocity** | **High** | Moderate | High | Moderate | High |
| **Security Community** | Wide | Growing | **Widest** | Narrow | Wide |
| **Proven References** | **TruffleHog, Gitleaks** | ripgrep | detect-secrets | None | None |

### 2.3 Go Selection Rationale

1. **Proven Architecture:** TruffleHog and Gitleaks have validated Go's suitability for this problem domain. Working architectures can be studied and improved upon.

2. **Best Ecosystem Fit:**
   - `go-git` — Pure Go, no CGO required, full git history access
   - `go-containerregistry` — Industry standard for OCI/Docker image processing
   - `cobra` + `viper` — Gold standard for CLI frameworks
   - The combination of these three libraries does not exist in any other language

3. **Concurrency Simplicity:** Fan-out/fan-in patterns with goroutines + channels are natural and hard to get wrong.

4. **Distribution Excellence:** `GOOS=linux GOARCH=amd64 go build` produces a single static binary for all platforms. Critical for CI/CD integration.

5. **Development Velocity:** Fast compilation, simple language, large developer pool.

### 2.4 Go's Known Weakness and Mitigation Strategy

**Issue:** Go's RE2-based `regexp` package is 2-5x slower than Rust's `regex` crate.

**Mitigation Strategy (Aho-Corasick First Approach):**

Most secret patterns start with fixed prefixes (e.g., `AKIA`, `ghp_`, `sk-live-`). The strategy:

1. **Primary:** Aho-Corasick algorithm for fixed prefix matching (O(n) — depends on text size, independent of pattern count)
2. **Secondary:** Regex validation only when an Aho-Corasick match is found
3. **Tertiary:** Additional filtering with entropy analysis

This approach reduces regex workload by 90%+, effectively eliminating Go's regex disadvantage in practice.

### 2.5 Why Not Rust?

Rust would be the best choice in terms of raw performance. However:

- Container image libraries are not as mature as Go's
- Development velocity is lower (ownership model learning curve)
- No existing reference architecture (TruffleHog/Gitleaks are in Go)
- Higher entry barrier for community contributions

**Future Possibility:** If performance becomes critical, the scanning engine's hot path could be written in Rust and called via CGO (hybrid architecture).

### 2.6 Why Not .NET?

- No `go-containerregistry` equivalent for container image parsing
- The security OSS community is very weak in the .NET ecosystem
- No similar reference project to study
- Binary sizes are larger compared to Go/Rust (15-30MB AOT)

---

## 3. Core Library Selections

### 3.1 CLI Framework: Cobra + Viper

| Library | Version | Purpose |
|---------|---------|---------|
| `github.com/spf13/cobra` | v1.8+ | Command structure, flag management, help text |
| `github.com/spf13/viper` | v1.18+ | Configuration management (YAML, env vars, flags) |

**Rationale:**
- Industry standard used by Kubernetes, GitHub CLI, Hugo
- Nested command support (`scan git`, `scan fs`, `scan image`, `verify aws`)
- POSIX-compliant flag management (`-f`, `--flag`)
- Seamless integration with Viper — config file + environment variable + flag hierarchy
- Rapid project scaffolding with `cobra-cli`
- Automatic help, man page, and markdown documentation generation

**Alternative (Rejected):** `urfave/cli` — sufficient for simpler projects, but inadequate nested command support and Viper integration.

### 3.2 Git Operations: go-git

| Library | Version | Purpose |
|---------|---------|---------|
| `github.com/go-git/go-git/v5` | v5.12+ | Git repo operations, history analysis |

**Rationale:**
- Pure Go implementation — no CGO required, seamless cross-compilation
- No external `git` binary dependency
- Full programmatic control over Git objects
- Used by TruffleHog — proven
- Optimized scanning with `LogOptions` (since, depth)
- In-memory test support with pluggable storage

**Alternative (Rejected):** `git2go` — C dependency (libgit2), CGO complexity, cross-compilation difficulty.

### 3.3 Container Image Operations: go-containerregistry

| Library | Version | Purpose |
|---------|---------|---------|
| `github.com/google/go-containerregistry` | v0.20+ | OCI/Docker image layer analysis |

**Rationale:**
- No Docker daemon required — lightweight, portable
- Supports OCI and Docker manifest formats
- Layer-by-layer analysis — detects deleted files in previous layers
- Used by crane, ko, cosign
- Registry authentication support (Docker Hub, GHCR, ECR, GCR)

### 3.4 Pattern Matching: Aho-Corasick

| Library | Version | Purpose |
|---------|---------|---------|
| `github.com/cloudflare/ahocorasick` | latest | Multi-pattern matching |

**Rationale:**
- O(n) time complexity — depends on text size, independent of pattern count
- Performance remains constant even when thousands of patterns are added
- CPU cache friendly — single-pass scanning
- Proven implementation used by Cloudflare in production

**Alternative:** `github.com/petar-dambovaliev/aho-corasick` — newer, more Go-idiomatic API.

### 3.5 Output Formats

| Library | Purpose |
|---------|---------|
| `encoding/json` (stdlib) | JSON output |
| `encoding/csv` (stdlib) | CSV output |
| `encoding/json` + hand-written structs (stdlib) | SARIF v2.1.0 output (no external library) |

### 3.6 Testing Infrastructure

| Library | Purpose |
|---------|---------|
| `testing` (stdlib) | Unit tests |
| `testing/fstest` (stdlib) | In-memory filesystem tests |
| `github.com/stretchr/testify` | Assertion and mock library |

### 3.7 Cloud Provider SDKs

| Library | Purpose |
|---------|---------|
| `github.com/aws/aws-sdk-go-v2` | AWS S3 source scanning; AWS STS key verification |
| `cloud.google.com/go/storage` | Google Cloud Storage (GCS) source scanning |
| `github.com/slack-go/slack` | Slack workspace source scanning |
| `net/http` (stdlib) | All other API verifications (GitHub, OpenAI, etc.) |

---

## 4. Build and Distribution Tools

### 4.1 GoReleaser

| Tool | Purpose |
|------|---------|
| `goreleaser` | Cross-compilation, archiving, and GitHub Release creation |

**Rationale:**
- Single command builds for Linux/macOS/Windows (amd64, arm64)
- Automatic GitHub Release asset uploading
- Homebrew formula and Scoop manifest generation
- Docker image building and publishing
- Automatic changelog generation

### 4.2 GitHub Actions

| Workflow | Purpose |
|----------|---------|
| `ci.yml` | Test, lint, build on every push/PR |
| `release.yml` | Release publishing via GoReleaser on tag push |

### 4.3 Code Quality Tools

| Tool | Purpose |
|------|---------|
| `golangci-lint` | Static analysis and linting (50+ linters) |
| `gofumpt` | Strict Go code formatting |
| `govulncheck` | Known vulnerability scanning |

---

## 5. Minimum Go Version

**Go 1.25+** (current: 1.25.8 as declared in `go.mod`)

**Rationale:**
- `io/fs` package (Go 1.16+) — filesystem abstraction
- Generics support (Go 1.18+) — type-safe collections
- `log/slog` (Go 1.21+) — structured logging
- Improved GC performance (Go 1.22+)
- `range over func` (Go 1.23+) — iterator support
- Toolchain improvements and security patches (Go 1.25+)

---

## 6. Project Structure

```
leakwatch/
├── cmd/                        # CLI commands (Cobra)
│   ├── root.go                 # Root command
│   ├── scan.go                 # scan parent command
│   ├── scan_git.go             # scan git subcommand
│   ├── scan_fs.go              # scan fs subcommand
│   ├── scan_image.go           # scan image subcommand
│   └── verify.go               # verify command
├── internal/                   # Internal packages (unexported)
│   ├── engine/                 # Scan engine core
│   │   ├── engine.go           # Worker pool and orchestration
│   │   ├── worker.go           # Worker goroutines
│   │   └── pipeline.go         # Scan pipeline
│   ├── detector/               # Secret detectors
│   │   ├── registry.go         # Detector registry
│   │   ├── detector.go         # Detector interface
│   │   ├── aws.go              # AWS detectors
│   │   ├── github.go           # GitHub detectors
│   │   ├── generic.go          # Generic detectors
│   │   └── custom.go           # YAML-based custom rules
│   ├── source/                 # Scan sources
│   │   ├── source.go           # Source interface
│   │   ├── git.go              # Git source
│   │   ├── filesystem.go       # Filesystem source
│   │   └── container.go        # Container image source
│   ├── verifier/               # Secret verification modules
│   │   ├── verifier.go         # Verifier interface
│   │   ├── aws.go              # AWS STS verification
│   │   └── github.go           # GitHub API verification
│   ├── entropy/                # Entropy calculation
│   │   └── shannon.go          # Shannon entropy implementation
│   ├── matcher/                # Pattern matching engine
│   │   ├── ahocorasick.go      # Aho-Corasick implementation
│   │   └── regex.go            # Regex validation
│   ├── output/                 # Output formatters
│   │   ├── formatter.go        # Formatter interface
│   │   ├── json.go             # JSON output
│   │   ├── sarif.go            # SARIF output
│   │   └── csv.go              # CSV output
│   ├── config/                 # Configuration management
│   │   └── config.go           # Viper-based config
│   └── filter/                 # Filtering (.leakwatchignore etc.)
│       └── filter.go           # File/path filtering
├── pkg/                        # Public packages (library usage)
│   └── finding/                # Finding data structure
│       └── finding.go          # Finding model
├── rules/                      # Built-in rule definitions
│   ├── aws.yaml                # AWS secret patterns
│   ├── github.yaml             # GitHub secret patterns
│   ├── gcp.yaml                # GCP secret patterns
│   ├── generic.yaml            # Generic secret patterns
│   └── ...
├── docs/                       # Project documentation
├── .github/                    # GitHub Actions workflows
│   └── workflows/
│       ├── ci.yml
│       └── release.yml
├── .goreleaser.yml             # GoReleaser configuration
├── .golangci.yml               # Linter configuration
├── .pre-commit-hooks.yaml      # Pre-commit hook definition
├── go.mod                      # Go module definition
├── go.sum                      # Dependency checksums
├── main.go                     # Entry point
├── LICENSE                     # MIT License
└── README.md                   # Project description
```

---

## 7. Performance Targets

| Metric | Target | Reference |
|--------|--------|-----------|
| Medium repo scan (10K commits) | < 30 seconds | Gitleaks ~60s, TruffleHog ~120s |
| Filesystem scan (10K files) | < 10 seconds | — |
| Container image scan (500MB) | < 60 seconds | — |
| Memory usage (medium repo) | < 512MB | TruffleHog can exceed 1GB+ |
| Binary size | < 30MB | — |
| Startup time | < 100ms | — |

---

## 8. License Decision: MIT

**Rationale:**
- Zero barrier for enterprise adoption (targeting users avoiding AGPL)
- Same license model as Gitleaks — proven approach
- Commercial tier (SaaS/Enterprise) can be added in the future (open-core model)
- Encourages community contributions
- No restrictions in embedding/integration scenarios
