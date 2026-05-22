# Leakwatch - Development Standards and Infrastructure

> **Document Version:** 1.1
> **Date:** 2026-05-22
> **Status:** Approved

---

## 1. Development Environment Requirements

### 1.1 Required Tools

| Tool | Minimum Version | Purpose |
|------|-----------------|---------|
| Go | 1.25+ | Primary programming language |
| Git | 2.30+ | Version control |
| golangci-lint | 2.11+ | Static analysis and linting |
| goreleaser | 2.0+ | Build and release automation |
| pre-commit | 3.0+ | Git hook management |

### 1.2 Optional Tools

| Tool | Purpose |
|------|---------|
| Docker | Container image testing |
| cobra-cli | CLI scaffold generation |
| govulncheck | Vulnerability scanning |
| gofumpt | Strict code formatting |
| delve (dlv) | Debugging |

### 1.3 IDE Support

- **VS Code:** Go extension (Go Team at Google)
- **GoLand:** JetBrains (first-class Go support)
- **Vim/Neovim:** gopls LSP

---

## 2. Code Standards

### 2.1 Go Coding Rules

Leakwatch follows these style guides:

1. **Effective Go** — The official Go team style guide
2. **Go Code Review Comments** — Common review notes
3. **Uber Go Style Guide** — Additional enterprise standards

### 2.2 Naming Conventions

| Element | Rule | Example |
|---------|------|---------|
| Package | Short, lowercase, single word | `detector`, `engine`, `output` |
| Exported function | PascalCase | `ScanRepository()` |
| Internal function | camelCase | `parseConfig()` |
| Interface | PascalCase, "-er" suffix | `Detector`, `Verifier`, `Formatter` |
| Constant | PascalCase or SCREAMING_SNAKE | `MaxFileSize`, `StatusVerifiedActive` |
| Variable | camelCase | `chunkSize`, `workerCount` |
| File name | snake_case | `aws_access_key.go`, `worker_pool.go` |
| Test file | `_test.go` suffix | `engine_test.go` |

### 2.3 Package Organization Rules

```
internal/   → Packages not accessible from outside (implementation details)
pkg/        → Packages accessible from outside (library usage)
cmd/        → CLI command definitions (thin layer, no business logic)
```

- The `cmd/` package contains only CLI flag definitions and wiring
- Business logic lives under `internal/`
- Types intended for external use live under `pkg/`

### 2.4 Error Handling

```go
// CORRECT: Wrap errors to add context
if err != nil {
    return fmt.Errorf("failed to open git repo %s: %w", path, err)
}

// INCORRECT: Returning bare error
if err != nil {
    return err
}

// CORRECT: Define sentinel errors
var (
    ErrSourceNotFound   = errors.New("source not found")
    ErrInvalidConfig    = errors.New("invalid configuration")
    ErrVerifyTimeout    = errors.New("verification timeout")
)

// CORRECT: Check context cancellation
select {
case <-ctx.Done():
    return ctx.Err()
default:
}
```

### 2.5 Logging Standards

```go
// CORRECT: Structured logging (log/slog)
slog.Info("scan completed",
    "source", "git",
    "findings", len(findings),
    "duration", elapsed,
)

// INCORRECT: fmt.Println or log.Printf
fmt.Println("Scan completed")
log.Printf("Findings: %d", len(findings))

// INCORRECT: Logging secret content
slog.Info("secret found", "raw", secretValue) // NEVER DO THIS
```

---

## 3. Test Standards

### 3.1 Test Pyramid

```mermaid
block-beta
    columns 1
    block:e2e["E2E Tests (few)\nEnd-to-end testing of CLI commands"]:1
    end
    block:integration["Integration Tests (moderate)\nReal git repo, real filesystem"]:1
    end
    block:unit["Unit Tests (many)\nEvery function, every detector, every parser"]:1
    end
```

### 3.2 Test Coverage Targets

| Package | Minimum Coverage |
|---------|-----------------|
| `internal/detector/*` | 95% |
| `internal/engine/*` | 85% |
| `internal/source/*` | 80% |
| `internal/verifier/*` | 75% |
| `internal/entropy/*` | 95% |
| `internal/matcher/*` | 90% |
| `internal/output/*` | 85% |
| **Overall Target** | **70%+ (enforced by CI)** |

> These per-package figures are aspirational targets; CI enforces only the overall 70% floor.

### 3.3 Test Writing Rules

```go
// CORRECT: Table-driven tests
func TestAWSAccessKeyDetector(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected int // expected finding count
    }{
        {
            name:     "valid AWS access key",
            input:    "AKIAIOSFODNN7EXAMPLE",
            expected: 1,
        },
        {
            name:     "test/placeholder key",
            input:    "AKIAIOSFODNN7XXXXXXX",
            expected: 1, // Pattern matches, verification distinguishes
        },
        {
            name:     "no match",
            input:    "this is normal text",
            expected: 0,
        },
    }

    d := &AWSAccessKeyID{}
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            findings := d.Scan(context.Background(), []byte(tt.input))
            assert.Len(t, findings, tt.expected)
        })
    }
}

// CORRECT: In-memory filesystem test with io/fs
func TestFilesystemSource(t *testing.T) {
    fsys := fstest.MapFS{
        "config.yaml": &fstest.MapFile{
            Data: []byte("api_key: AKIAIOSFODNN7EXAMPLE"),
        },
        "main.go": &fstest.MapFile{
            Data: []byte("package main"),
        },
    }
    // Pass fsys to Source, test it
}
```

### 3.4 Test Naming

```
Test<Function>_<Scenario>_<ExpectedResult>

Examples:
- TestScanGit_ValidRepo_ReturnsFindings
- TestShannonEntropy_HighEntropyString_AboveThreshold
- TestAWSVerifier_InvalidKey_ReturnsInactive
- TestEngine_CancelledContext_StopsGracefully
```

### 3.5 Mock and Stub Usage

```go
// Test against interfaces, mocks come naturally
type mockDetector struct {
    id       string
    keywords []string
    findings []RawFinding
}

func (m *mockDetector) ID() string            { return m.id }
func (m *mockDetector) Keywords() []string     { return m.keywords }
func (m *mockDetector) Scan(_ context.Context, _ []byte) []RawFinding {
    return m.findings
}
```

---

## 4. CI/CD Pipeline

### 4.1 CI Workflow (.github/workflows/ci.yml)

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        go-version: ['1.25']
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: ${{ matrix.go-version }}
      - uses: actions/cache@v4
        with:
          path: ~/go/pkg/mod
          key: ${{ runner.os }}-go-${{ hashFiles('**/go.sum') }}
      - run: go test -race -coverprofile=coverage.out ./...
      - run: go build ./...

  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.25'
      - run: go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.11.4
      - run: golangci-lint run ./... --config .golangci.yml

  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.25'
      - run: go install golang.org/x/vuln/cmd/govulncheck@latest
      - run: govulncheck ./...
```

### 4.2 Release Workflow (.github/workflows/release.yml)

```yaml
name: Release

on:
  push:
    tags: ['v*']

permissions:
  contents: write

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-go@v5
        with:
          go-version: '1.25'
      - uses: goreleaser/goreleaser-action@v6
        with:
          version: '~> v2'
          args: release --clean
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### 4.3 GoReleaser Configuration (.goreleaser.yml)

```yaml
version: 2

builds:
  - env:
      - CGO_ENABLED=0
    goos:
      - linux
      - darwin
      - windows
    goarch:
      - amd64
      - arm64
    ldflags:
      - -s -w
      - -X main.version={{.Version}}
      - -X main.commit={{.Commit}}
      - -X main.date={{.Date}}

archives:
  - format: tar.gz
    name_template: >-
      {{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}
    format_overrides:
      - goos: windows
        format: zip

checksum:
  name_template: 'checksums.txt'

changelog:
  sort: asc
  filters:
    exclude:
      - '^docs:'
      - '^test:'
      - '^ci:'
```

---

## 5. Git Workflow

### 5.1 Branching Strategy: GitHub Flow

```mermaid
gitgraph
    commit id: "init"
    branch feature/scan-git
    commit id: "feat: git source"
    commit id: "test: git tests"
    checkout main
    merge feature/scan-git id: "merge scan-git"
    branch feature/container-scan
    commit id: "feat: container source"
    commit id: "feat: layer parsing"
    checkout main
    merge feature/container-scan id: "merge container"
    commit id: "release v0.2.0"
```

- `main` — always stable and deployable
- `feature/<name>` — separate branch for each feature
- `fix/<name>` — for bug fixes
- `docs/<name>` — for documentation updates

### 5.2 Commit Message Format: Conventional Commits

```
<type>[scope]: <description>

[body]

[footer]
```

**Types:**

| Type | Description |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation |
| `test` | Adding/fixing tests |
| `refactor` | Refactoring |
| `perf` | Performance improvement |
| `ci` | CI/CD changes |
| `chore` | Maintenance tasks |

**Examples:**

```
feat(detector): add AWS Secret Access Key detector
fix(engine): fix goroutine leak on worker pool context cancellation
docs(readme): update installation instructions
test(entropy): add Shannon entropy edge case tests
perf(matcher): improve Aho-Corasick automaton build time by 40%
```

### 5.3 Pull Request Rules

- Every PR requires at least 1 approval (review)
- CI pipeline must pass
- Test coverage must not decrease
- Linter warnings must be fixed
- PR description must include:
  - What was done and why
  - Test plan
  - Breaking changes must be noted if applicable

### 5.4 Version Numbering: Semantic Versioning (SemVer)

```
v{MAJOR}.{MINOR}.{PATCH}

MAJOR — Backward-incompatible API changes
MINOR — Backward-compatible new features
PATCH — Backward-compatible bug fixes

Examples:
v0.1.0 — First MVP release
v0.2.0 — Git integration added
v0.3.0 — Verification module added
v1.0.0 — Stable API, production-ready
```

---

## 6. Linter Configuration (.golangci.yml)

The project uses **golangci-lint v2** (`version: "2"` schema). The canonical file is `.golangci.yml` in the repo root. An authoritative excerpt:

```yaml
version: "2"

formatters:
  enable:
    - gofumpt          # Strict go formatting (replaces gofmt)

linters:
  enable:
    - errcheck         # Unchecked error-returning functions
    - govet            # Go vet checks
    - staticcheck      # Advanced static analysis
    - unused           # Unused code
    - gocritic         # Style and performance checks
    - misspell         # English spelling checks
    - prealloc         # Slice pre-allocation opportunities
    - revive           # Additional linting rules
    - unconvert        # Unnecessary type conversions
    - bodyclose        # HTTP response body close check
    - noctx            # HTTP request context check
  settings:
    gocritic:
      enabled-tags:
        - diagnostic
        - performance
    revive:
      rules:
        - name: exported
          disabled: true
        - name: package-comments
          disabled: true
  exclusions:
    rules:
      - path: _test\.go
        linters:
          - errcheck
          - gocritic
      - linters:
          - gocritic
        text: "hugeParam|rangeValCopy|appendAssign"
```

> **Important:** The v2 schema moves formatter configuration under `formatters:` (not `linters:`), and uses `exclusions.rules` instead of `issues.exclude-rules`. Do not mix v1 and v2 syntax — golangci-lint v2 will reject v1 configuration keys.

---

## 7. Documentation Standards

### 7.1 Code Documentation

```go
// Package detector provides detector interfaces and built-in detector
// implementations for secret detection.
package detector

// AWSAccessKeyID is a detector that identifies AWS Access Key IDs.
// It recognizes keys with AKIA, ABIA, ACCA, and ASIA prefixes.
//
// AWS Access Key ID format: (AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}
//
// Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html
type AWSAccessKeyID struct{}
```

### 7.2 Project Documentation

| File | Content |
|------|---------|
| `README.md` | Project introduction, quick start, basic usage |
| `docs/architecture/01-COMPETITIVE-ANALYSIS.md` | Competitive analysis and market positioning |
| `docs/architecture/02-TECHNOLOGY-DECISIONS.md` | Technology decisions and rationale |
| `docs/architecture/03-ARCHITECTURE.md` | Detailed architecture design |
| `docs/standards/04-DEVELOPMENT-STANDARDS.md` | This document — development standards |
| `docs/05-ROADMAP.md` | Phased development roadmap |
| `docs/decisions/ADR-NNNN-*.md` | Architecture Decision Records |
| `CONTRIBUTING.md` | Contributing guide |
| `CHANGELOG.md` | Version change log |
| `LICENSE` | MIT License |

---

## 8. Dependency Management

### 8.1 Rules

- Go modules (`go.mod`) are used
- Dependencies are kept to a minimum — standard library is preferred
- Every dependency addition/update is justified in the PR description
- Regular security scanning with `govulncheck`
- Direct dependencies are explicitly listed in `go.mod`

### 8.2 Direct Dependency List

All entries are verified against `go.mod`. SARIF output is implemented with the standard library (`encoding/json`) — no external SARIF library is used.

| Dependency | Purpose | License |
|------------|---------|---------|
| `github.com/spf13/cobra` | CLI framework | Apache-2.0 |
| `github.com/spf13/viper` | Configuration management | MIT |
| `github.com/go-git/go-git/v5` | Git operations | Apache-2.0 |
| `github.com/google/go-containerregistry` | Container image scanning | Apache-2.0 |
| `github.com/cloudflare/ahocorasick` | Pattern matching | BSD-3 |
| `github.com/aws/aws-sdk-go-v2` | AWS S3 source + AWS STS verification | Apache-2.0 |
| `cloud.google.com/go/storage` | Google Cloud Storage source scanning | Apache-2.0 |
| `github.com/slack-go/slack` | Slack workspace source scanning | BSD-2 |
| `github.com/stretchr/testify` | Test assertions | MIT |
| `golang.org/x/time` | Rate limiting | BSD-3 |

All dependencies have open source licenses compatible with commercial use.

---

## 9. Security Standards

### 9.1 Code Security

- Development with OWASP Top 10 awareness
- User inputs are validated (file paths, URLs, regex patterns)
- Path traversal protection (`filepath.Clean`, `filepath.Rel`)
- Regex ReDoS protection (guaranteed by RE2 engine)
- Secrets are never logged, never written to disk (even temporarily)
- `govulncheck` is mandatory in the CI pipeline

### 9.2 Distribution Security

- Release binaries are verifiable via checksum
- Reproducible builds with GoReleaser
- Minimum permissions in GitHub Actions (principle of least privilege)
- Dependency license compatibility check

---

## 10. Performance Profiling

### 10.1 Profiling Tools

```bash
# CPU profile
go test -cpuprofile=cpu.out -bench=BenchmarkScan ./internal/engine/
go tool pprof cpu.out

# Memory profile
go test -memprofile=mem.out -bench=BenchmarkScan ./internal/engine/
go tool pprof mem.out

# Trace
go test -trace=trace.out -bench=BenchmarkScan ./internal/engine/
go tool trace trace.out
```

### 10.2 Benchmark Tests

```go
func BenchmarkAhoCorasickMatch(b *testing.B) {
    matcher := NewAhoCorasickMatcher(allKeywords)
    data := loadTestCorpus(b)
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        matcher.Match(data)
    }
}

func BenchmarkShannonEntropy(b *testing.B) {
    data := []byte("AKIAIOSFODNN7EXAMPLE")
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        entropy.Calculate(data)
    }
}
```
