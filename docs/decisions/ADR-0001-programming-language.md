# ADR-0001: Programming Language Selection — Go (Golang)

- **Status:** Accepted
- **Date:** 2026-03-24
- **Decision Makers:** Project team

## Context

Leakwatch is a security tool that performs secret scanning across multiple sources (Git history, file system, container images). The core requirements for the tool are:

- High-performance pattern matching (thousands of regex patterns, gigabytes of data)
- Parallel I/O-bound scanning (concurrency)
- Cross-platform single binary distribution (Linux, macOS, Windows)
- Programmatic interaction with Git, container images, and cloud services
- Adoption potential by the security community

## Decision

**Go (Golang)** has been selected as the primary development language.

### Rationale

1. **Proven domain fit:** TruffleHog (~17K stars) and Gitleaks (~18K stars) are written in Go for the same problem domain. Architectural references can be studied and improved upon.

2. **Unmatched ecosystem synergy:** The trio of `go-git` (pure Go git), `go-containerregistry` (OCI/Docker industry standard), and `cobra`+`viper` (CLI gold standard) is not available in any other language.

3. **Concurrency simplicity:** Fan-out/fan-in patterns with goroutines + channels are natural and hard to get wrong.

4. **Distribution excellence:** A single static binary with no CGO via `GOOS=linux GOARCH=amd64 go build`. Zero dependencies in CI/CD environments.

5. **Development velocity:** Fast compilation, simple language semantics, large developer pool.

### Known weakness and mitigation strategy

Go's RE2-based `regexp` package is 2-5x slower compared to Rust's regex crate. This will be mitigated with an Aho-Corasick-first hybrid strategy (see [ADR-0005](ADR-0005-pattern-matching.md)). By reducing regex workload by 90%+, Go's regex disadvantage is practically eliminated.

## Alternatives Considered

### Rust

- **Pros:** Best regex and Aho-Corasick performance, memory safety
- **Cons:** Container image libraries not mature, slower development velocity, high community contribution barrier, no reference architecture
- **Decision:** Rejected. In the future, the scanning hot path could be accelerated via Rust FFI.

### Python

- **Pros:** Largest developer pool, detect-secrets as reference
- **Cons:** 10-100x slower in CPU-bound scanning (GIL), single binary distribution difficult, memory inefficient
- **Decision:** Rejected. Could only be considered for the plugin/rule layer.

### .NET (C#)

- **Pros:** Good performance (AOT), strong SARIF support
- **Cons:** No `go-containerregistry` equivalent, weak security OSS community, no reference project
- **Decision:** Rejected.

### TypeScript

- **Pros:** Large developer pool
- **Cons:** Slow in CPU-bound scanning, single binary difficult, weak container/git libraries
- **Decision:** Rejected.

## Consequences

### Positive

- Proven reference architectures (TruffleHog, Gitleaks) can be studied
- All critical libraries available in the Go ecosystem
- Cross-platform single binary distribution guaranteed
- Large developer pool, community contribution potential
- Simple CI/CD integration

### Negative

- Regex performance lower compared to Rust (will be mitigated with Aho-Corasick)
- Generics support arrived with Go 1.18+, but still not as mature as Rust/C#
- Go's error handling (`if err != nil`) can be verbose

## Related Decisions

- [ADR-0005: Pattern Matching Strategy](ADR-0005-pattern-matching.md) — Mitigation of Go's regex weakness
