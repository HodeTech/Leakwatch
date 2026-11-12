---
title: "Installation"
description: "Install Leakwatch via Homebrew, go install, Docker, or a prebuilt binary."
---

# Installation

Getting Leakwatch onto your machine takes less than a minute. Choose the method that best fits your workflow: Homebrew is the simplest option on macOS and Linux, `go install` is ideal if you already have a Go toolchain, Docker keeps your host system clean, and prebuilt binaries work everywhere without any toolchain at all.

## Homebrew (macOS and Linux)

The official tap supports macOS and Linux on both amd64 and arm64.

```bash
brew install HodeTech/tap/leakwatch
```

The tap is hosted at [github.com/HodeTech/homebrew-tap](https://github.com/HodeTech/homebrew-tap). Homebrew handles upgrades with `brew upgrade leakwatch`.

## Go install

If you have Go 1.27.4 or later installed, you can build and install the latest release directly from source:

```bash
go install github.com/HodeTech/leakwatch@latest
```

The binary is placed in `$(go env GOPATH)/bin`. Make sure that directory is on your `PATH`.

:::note
`go install` always fetches the latest tagged release. To pin a specific version, replace `@latest` with the current release tag, `@v1.8.3`.
:::

## Docker

A minimal, multi-stage Alpine image is published to the GitHub Container Registry. The image runs as a non-root user (`leakwatch`), has CGO disabled, and uses `/scan` as its working directory.

```bash
docker run --rm \
  -v "$(pwd):/scan" \
  ghcr.io/hodetech/leakwatch:latest \
  scan fs /scan
```

Available tags:

| Tag | Description |
|-----|-------------|
| `:latest` | Most recent release |
| `:1.8.3` | Exact current-release pin |
| `:v1.8` | Current minor-version pin (tracks patch releases) |

Mount the directory you want to scan to `/scan` inside the container. Flags and options work identically to the native binary — see [CLI Reference](#/reference/cli-reference) for the full list.

:::tip
For Docker-specific usage patterns, including scanning remote Git repositories and passing credentials securely, see [Using Docker](#/ci-cd/docker-usage).
:::

### Verifying the image signature

Release images are signed keyless with [Sigstore/cosign](https://github.com/sigstore/cosign). From v1.8.3 onwards the signature covers the multi-arch manifest list that `:latest`, the exact-version tag, and the minor-version tag all resolve to, so you can verify the reference you actually pull:

```bash
cosign verify ghcr.io/hodetech/leakwatch:latest \
  --certificate-identity-regexp '^https://github\.com/HodeTech/Leakwatch/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Releases up to and including v1.8.2 signed only the per-architecture images, so for those versions verify `:<version>-amd64` or `:<version>-arm64` instead (for example `:1.8.2-amd64`).

## Prebuilt binary

Every release publishes archives for all supported platforms on the [GitHub Releases](https://github.com/HodeTech/Leakwatch/releases) page. Download the archive for your platform, verify it, extract it, and place the binary on your `PATH`.

**Supported platforms:** Linux, macOS, and Windows on amd64 and arm64.

Archive names follow the pattern `leakwatch_<VERSION>_<OS>_<ARCH>.tar.gz` (`.zip` on Windows), where `<VERSION>` has no leading `v` (for example `1.8.2`), `<OS>` is `linux`, `darwin`, or `windows`, and `<ARCH>` is `amd64` or `arm64`. Release assets always carry the version in their name, so a `latest/download/...` URL needs the current version spelled out too; the commands below pin it explicitly.

The commands below cover Linux and macOS and share shell variables, so run them in the same terminal session. On Windows, download the `.zip` archive (`leakwatch_<VERSION>_windows_<ARCH>.zip`) from the Releases page and verify it against `checksums.txt` and `checksums.txt.bundle` in the same way.

### 1. Download

Set `OS` and `ARCH` to match your platform (the example is Linux amd64):

```bash
LEAKWATCH_VERSION=v1.8.3
OS=linux      # linux or darwin
ARCH=amd64    # amd64 or arm64
ARCHIVE="leakwatch_${LEAKWATCH_VERSION#v}_${OS}_${ARCH}.tar.gz"
BASE_URL="https://github.com/HodeTech/Leakwatch/releases/download/${LEAKWATCH_VERSION}"
curl -LO "${BASE_URL}/${ARCHIVE}"
```

### 2. Verify (recommended)

Every release also publishes a Software Bill of Materials (SBOM) for each archive (`<archive>.sbom.json`), a `checksums.txt` file, and a [Sigstore/cosign](https://github.com/sigstore/cosign) keyless signature bundle (`checksums.txt.bundle`) over that checksums file. In supply-chain-sensitive environments, verify the signature on `checksums.txt` first, then check your archive against it, **before** you extract or run anything. Each command runs only if the previous one succeeded, so a failed signature check stops the sequence:

```bash
curl -LO "${BASE_URL}/checksums.txt" && \
curl -LO "${BASE_URL}/checksums.txt.bundle" && \
cosign verify-blob \
  --bundle checksums.txt.bundle \
  --certificate-identity-regexp '^https://github\.com/HodeTech/Leakwatch/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt && \
grep " ${ARCHIVE}\$" checksums.txt | sha256sum --check
```

On macOS, replace `sha256sum --check` with `shasum -a 256 --check`. A missing or mismatching checksum entry makes the last command exit non-zero.

### 3. Install

Run these commands only if step 2 completed without an error for `${ARCHIVE}` (or you deliberately skipped it).

```bash
tar -xzf "${ARCHIVE}"
sudo mv leakwatch /usr/local/bin/leakwatch
```

## Verifying your installation

After any installation method, confirm the binary is reachable and check the version:

```bash
leakwatch version
```

Expected output:

```text
leakwatch 1.8.3 (commit: 1a2b3c4, built: 2026-11-12T12:00:00Z)
```

If the command is not found, check that the install directory is on your `PATH`.

## Next steps

- [Quick Start](#/getting-started/quick-start) — run your first scan in under a minute.
- [How It Works](#/getting-started/how-it-works) — the architecture behind a Leakwatch scan.
- [Configuration File](#/configuration/config-file) — customize scan behavior with `.leakwatch.yaml`.

## See also

- [Quick Start](#/getting-started/quick-start)
- [Using Docker](#/ci-cd/docker-usage)
- [CLI Reference](#/reference/cli-reference)
- [Configuration File](#/configuration/config-file)
