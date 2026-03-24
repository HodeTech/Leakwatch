# CLAUDE.md — Leakwatch Development Guide

This file defines the standards and context that Claude Code should reference when working on the Leakwatch project.

## Project Description

Leakwatch is a high-performance, open source (MIT) security tool that detects, verifies, and reports leaked secrets (API keys, passwords, certificates) in codebases, Git histories, and container images.

**Language:** Go (1.22+)
**License:** MIT
**Repo:** https://github.com/cemililik/Leakwatch

## Project Structure

```
leakwatch/
├── cmd/                    # CLI commands (Cobra) — thin layer, no business logic
├── internal/               # Internal packages — all business logic lives here
│   ├── engine/             # Scan engine (worker pool, pipeline)
│   ├── detector/           # Secret detectors (Detector interface)
│   │   ├── aws/            # AWS Access Key detector
│   │   ├── github/         # GitHub Token detector
│   │   ├── slack/          # Slack Token/Webhook detectors
│   │   ├── stripe/         # Stripe API Key detectors (live/test)
│   │   ├── jwt/            # JWT detector
│   │   ├── dbconn/         # Database Connection String detector
│   │   ├── privatekey/     # Private Key detector
│   │   ├── generic/        # Generic API Key detector
│   │   └── custom/         # YAML custom rule support
│   ├── source/             # Scan sources (Source interface)
│   │   ├── filesystem/     # Local filesystem source
│   │   ├── git/            # Git repository source (go-git)
│   │   ├── container/      # Container image source (go-containerregistry)
│   │   ├── s3/             # AWS S3 bucket source
│   │   └── gcs/            # Google Cloud Storage source
│   ├── verifier/           # Secret verification (Verifier interface)
│   │   ├── aws/            # AWS STS verifier
│   │   └── github/         # GitHub API verifier
│   ├── entropy/            # Shannon entropy calculation
│   ├── matcher/            # Aho-Corasick keyword pre-filtering
│   ├── output/             # Output formatters (Formatter interface)
│   │   ├── json/           # JSON formatter
│   │   ├── sarif/          # SARIF v2.1.0 formatter
│   │   ├── csv/            # CSV formatter
│   │   └── table/          # Terminal table formatter
│   ├── config/             # Viper-based configuration
│   └── filter/             # .leakwatchignore, inline ignore
├── pkg/                    # Public packages (finding model)
├── action/                 # GitHub Action definition
├── Formula/                # Homebrew formula
├── Dockerfile              # Multi-stage Docker build
├── docs/                   # Documentation
│   ├── architecture/       # Architecture and technical design documents
│   ├── standards/          # Development and documentation standards
│   ├── decisions/          # ADR (Architecture Decision Records)
│   ├── guides/             # Usage guides (getting started, config, CI/CD, etc.)
│   └── 05-ROADMAP.md       # Roadmap
└── main.go                 # Entry point
```

## Core Architecture Decisions

Architecture decisions are documented in ADR format under `docs/decisions/`. These decisions must be followed during development:

| ADR | Decision | Summary |
|-----|----------|---------|
| [ADR-0001](docs/decisions/ADR-0001-programlama-dili.md) | Go | Proven ecosystem, concurrency, single binary |
| [ADR-0002](docs/decisions/ADR-0002-cli-cercevesi.md) | Cobra + Viper | Nested commands, hierarchical configuration |
| [ADR-0003](docs/decisions/ADR-0003-git-kutuphanesi.md) | go-git | Pure Go, no CGO, no external dependencies |
| [ADR-0004](docs/decisions/ADR-0004-eklenti-mimarisi.md) | Compile-time registration | init() + blank import, type-safe |
| [ADR-0005](docs/decisions/ADR-0005-desen-eslestirme.md) | Aho-Corasick hybrid | AC pre-filter → regex validation → entropy |
| [ADR-0006](docs/decisions/ADR-0006-container-kutuphanesi.md) | go-containerregistry | Daemonless, layer-based analysis |
| [ADR-0007](docs/decisions/ADR-0007-lisans.md) | MIT | Enterprise adoption, open-core compatibility |
| [ADR-0008](docs/decisions/ADR-0008-eszamanlilik-modeli.md) | Worker Pool | Fixed worker count, channel-based |

## Coding Standards

Full standards: [docs/standards/04-DEVELOPMENT-STANDARDS.md](docs/standards/04-DEVELOPMENT-STANDARDS.md)

### Critical Rules

- **Language:** Go 1.22+, `CGO_ENABLED=0`
- **Style:** Effective Go + Uber Go Style Guide
- **Linting:** `golangci-lint` is mandatory, runs in all CI
- **Formatting:** `gofumpt` (strict gofmt)
- **Test coverage:** minimum 80%, detectors 95%
- **Error handling:** Wrap every error with `fmt.Errorf("context: %w", err)` before returning
- **Logging:** `log/slog` structured logging — DO NOT use fmt.Println/log.Printf
- **Secret safety:** NEVER log, write to disk, or cache discovered secrets

### Naming

| Element | Rule | Example |
|---------|------|---------|
| Package | Short, lowercase | `detector`, `engine` |
| Exported | PascalCase | `ScanRepository()` |
| Internal | camelCase | `parseConfig()` |
| Interface | PascalCase, "-er" suffix | `Detector`, `Verifier` |
| File | snake_case | `aws_access_key.go` |
| Test | `_test.go` suffix | `engine_test.go` |

### Package Rules

- `cmd/` → CLI wiring only, no business logic
- `internal/` → All business logic, not externally accessible
- `pkg/` → Public types (Finding model)
- Prefer the standard library, do not add unnecessary dependencies

### Writing Tests

- Prefer **table-driven tests**
- Use `testing/fstest.MapFS` for in-memory filesystem tests
- Test naming: `Test<Function>_<Scenario>_<ExpectedResult>`
- Mocks: test against interfaces, mocks come naturally
- Race detector: `go test -race ./...`

## Commit Standards

**Format:** Conventional Commits

```
<type>(<scope>): <description>

Types: feat, fix, docs, test, refactor, perf, ci, chore
```

**Examples:**
```
feat(detector): add AWS Secret Access Key detector
fix(engine): fix goroutine leak on worker pool context cancellation
test(entropy): add Shannon entropy edge case tests
```

## Core Dependencies

| Package | Purpose |
|---------|---------|
| `spf13/cobra` | CLI framework |
| `spf13/viper` | Configuration management |
| `go-git/go-git/v5` | Git operations |
| `google/go-containerregistry` | Container image analysis |
| `cloudflare/ahocorasick` | Multi-pattern matching |
| `aws/aws-sdk-go-v2` | AWS verification |
| `cloud.google.com/go/storage` | GCS scanning |
| `stretchr/testify` | Test assertions |
| `golang.org/x/time` | Rate limiting |

## Documentation Standards

Full standards: [docs/standards/00-DOCUMENTATION-STANDARDS.md](docs/standards/00-DOCUMENTATION-STANDARDS.md)

- **Language:** All documentation, code comments, error messages, and log messages MUST be in **English**
- All diagrams must be in **Mermaid** format (DO NOT use ASCII art)
- Code blocks must include a language tag: ` ```go `, ` ```yaml `
- Internal links use relative paths
- Architecture decisions are documented in `docs/decisions/ADR-NNNN-*.md` format

## Things to Avoid

- Logging, printing to console, or putting secret content in test fixtures
- Adding libraries that require CGO (breaks cross-compilation)
- Putting business logic under `cmd/`
- Creating ASCII art diagrams (use Mermaid)
- Making architectural decisions that contradict existing ADRs (update the ADR first)
- Manually editing `go.sum` or the `vendor/` directory
- Skipping git hooks with `--no-verify`
