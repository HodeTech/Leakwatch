# ADR-0004: Plugin Architecture — Compile-Time Registration

- **Status:** Accepted
- **Date:** 2026-03-24
- **Decision Makers:** Project team

## Context

Leakwatch needs to allow easy addition of new secret detectors, scan sources, and verifiers. In Go, there are two approaches for plugin architecture: runtime plugins and compile-time registration.

## Decision

**Compile-time registration model** (via `init()` + blank import) has been selected.

### Rationale

- Standard registration pattern using Go's `init()` function and blank import (`import _ "pkg"`)
- Proven idiomatic Go pattern used in the `database/sql` and `image` packages
- Full alignment with the static binary philosophy
- No risk of uncontrolled/malicious plugins (critical for a security tool)
- Compile-time type safety

### Mechanism

1. Each plugin package implements a specific interface (`Detector`, `Source`, `Verifier`)
2. The package's `init()` function registers itself with a central registry
3. The main application includes plugin packages via `import _ "pkg"`
4. Community contributions are made by adding new packages via Pull Requests

## Alternatives Considered

### Runtime plugin (Go plugin package)

- **Pros:** Users can add plugins by dropping .so files
- **Cons:** Go version, compiler flags, and C toolchain must match exactly — extremely fragile. Full support only on Linux. Distribution and maintenance are complex.
- **Decision:** Rejected. Effectively impractical in the Go ecosystem.

### YAML-based rule definition (as a supplement)

- **Pros:** Define simple regex rules without writing code
- **Decision:** Accepted — as a complement to the compile-time model. Simple regex patterns are defined via YAML, while advanced validation logic is implemented via Go interfaces.

## Consequences

### Positive

- Secure: no unvetted code is executed
- Simple: standard Go import mechanism, no additional tooling required
- Type safe: errors caught at compile time
- Two-tier extensibility: YAML (simple) + Go (advanced)

### Negative

- Third-party plugins require a fork or custom build
- Adding new plugins requires recompilation (except YAML rules)

## Related Decisions

- [ADR-0001: Programming Language](ADR-0001-programming-language.md) — Go's static compilation philosophy supports this decision
