# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Sequoia PGP is a complete implementation of OpenPGP (RFC 9580 and RFC 4880) written in Rust. This is a **post-quantum cryptography (PQC) branch** implementing ML-DSA, ML-KEM, and SLH-DSA algorithms. The project is structured as a Cargo workspace with multiple crates.

## Repository Structure

**Core Crates:**
- `openpgp/` - Low-level OpenPGP implementation (main library)
- `sequoia-sq/` - Command-line interface for OpenPGP operations
- `net/` - Network services for OpenPGP
- `ipc/` - IPC services for Sequoia and GnuPG
- `autocrypt/` - Autocrypt support
- `buffered-reader/` - Buffered reading utilities

**Key Directories:**
- `openpgp/src/crypto/` - Cryptographic implementations
- `openpgp/src/crypto/backend/` - Multiple crypto backend implementations (nettle, openssl, botan, cng, rust, fuzzing)
- `openpgp/src/packet/` - OpenPGP packet types
- `openpgp/src/cert/` - Certificate handling
- `openpgp/src/parse/` - Parsing logic
- `openpgp/src/serialize/` - Serialization logic

## Building and Testing

### Prerequisites for PQC Support

This branch requires OpenSSL 3.x for post-quantum cryptography support:

```bash
# macOS (Homebrew)
brew install openssl@3

# Set environment variables for OpenSSL (required for build)
export OPENSSL_DIR=/opt/homebrew/opt/openssl@3
export OPENSSL_LIB_DIR=/opt/homebrew/opt/openssl@3/lib
export OPENSSL_INCLUDE_DIR=/opt/homebrew/opt/openssl@3/include
export PKG_CONFIG_PATH=/opt/homebrew/opt/openssl@3/lib/pkgconfig
export BINDGEN_EXTRA_CLANG_ARGS="-I/opt/homebrew/opt/openssl@3/include"
export RUSTFLAGS="-L/opt/homebrew/opt/openssl@3/lib"

# Linux (Debian/Ubuntu)
apt install libssl-dev pkg-config clang

# Verify OpenSSL version (should be 3.x)
openssl version
```

### Basic Build Commands

```bash
# Build with OpenSSL backend (REQUIRED for PQC algorithms)
cargo build --all --no-default-features --features crypto-openssl,compression

# Build with release optimizations
cargo build --release --all --no-default-features --features crypto-openssl,compression

# Build specific package (e.g., sq CLI tool)
cargo build -p sequoia-sq --no-default-features --features crypto-openssl,compression

# Build with default Nettle backend (no PQC support)
cargo build --all
```

**Important**: The default `crypto-nettle` backend does NOT support PQC algorithms. You must use `crypto-openssl` to work with ML-DSA, ML-KEM, and SLH-DSA.

### Testing

```bash
# Run all tests with OpenSSL backend (for PQC)
cargo test --all --no-default-features --features crypto-openssl,compression

# Run tests for specific package
cargo test -p sequoia-openpgp --no-default-features --features crypto-openssl,compression

# Run specific test by name
cargo test <test_name> --no-default-features --features crypto-openssl,compression

# Run with verbose output
cargo test -- --nocapture

# Run PQC-specific certificate tests
cargo test -p sequoia-openpgp cert --no-default-features --features crypto-openssl,compression
```

### Code Quality

```bash
# Run clippy linter
cargo clippy --all

# Check code without building
cargo check --all

# Build documentation
cargo doc --document-private-items --no-deps

# Format code
cargo fmt
```

## Cryptographic Backend System

Sequoia supports **multiple cryptographic backends** selected at compile time via Cargo features. **Exactly one backend must be selected** in leaf crates.

**Available backends:**
- `crypto-nettle` (default) - Nettle cryptographic library
- `crypto-openssl` - OpenSSL backend (uses `ossl` crate from kryoptic)
- `crypto-botan` - Botan v3 backend
- `crypto-botan2` - Botan v2 backend
- `crypto-cng` - Windows CNG backend
- `crypto-rust` - RustCrypto crates (experimental)
- `crypto-fuzzing` - Fuzzing backend

**Important backend rules:**
- Leaf crates (binaries, cdylibs) select the backend
- Library crates must use `default-features = false` and NOT select a backend
- The OpenSSL backend is currently used for PQC algorithms (ML-DSA, ML-KEM, SLH-DSA)

**Experimental crypto features:**
- `allow-experimental-crypto` - Required for experimental backends
- `allow-variable-time-crypto` - Required for non-constant-time backends

## Post-Quantum Cryptography (PQC)

This branch (`justus/pqc-ossl`) implements post-quantum algorithms following draft-ietf-openpgp-pqc-11:

### Implemented Algorithms

**Digital Signatures:**
- **ML-DSA-65+Ed25519** - Composite signature (ML-DSA-65 + Ed25519)
- **ML-DSA-87+Ed448** - Composite signature (ML-DSA-87 + Ed448)
- **SLH-DSA-128s** - Stateless hash-based signature (128-bit security, small)
- **SLH-DSA-128f** - Stateless hash-based signature (128-bit security, fast)
- **SLH-DSA-256s** - Stateless hash-based signature (256-bit security, small)

**Key Encapsulation (KEMs):**
- **ML-KEM-768+X25519** - Composite KEM (ML-KEM-768 + X25519)
- **ML-KEM-1024+X448** - Composite KEM (ML-KEM-1024 + X448)

### PQC Code Locations

- **Algorithm definitions**: `openpgp/src/crypto/types/public_key_algorithm.rs`
- **MPI structures**: `openpgp/src/crypto/mpi.rs` (PublicKey, SecretKeyMaterial, Signature enums)
- **OpenSSL backend**: `openpgp/src/crypto/backend/openssl/`
- **Test vectors**: `openpgp/tests/data/pqc/` (from draft-ietf-openpgp-pqc-11)
- **Certificate tests**: `openpgp/src/cert.rs` (uses PQC test vectors)

### Important Notes

- PQC algorithms ONLY work with the `crypto-openssl` backend
- The OpenSSL backend uses the `ossl` crate from https://github.com/teythoon/kryoptic (branch: justus/workwork)
- All PQC algorithms require OpenSSL 3.x with PQC support
- SLHDSA256s was fixed from an initial typo (SLHDSA256f) - see `slhdsa-fix.patch`

For detailed PQC implementation status, see `PQC-STATUS.md`.

## Development Guidelines

### Modifying Crypto Backend Code

Backend implementations live in `openpgp/src/crypto/backend/<backend-name>/`. Each backend implements the same interface defined in `openpgp/src/crypto/backend/interface/`.

When modifying crypto code:
1. Ensure changes work across applicable backends
2. Test with different backend features enabled
3. Check that PQC algorithms compile and pass tests

### Working with Packets

OpenPGP packets are versioned enums. Each packet version has its own struct. Key packet types:
- `Signature` - Digital signatures (use `SignatureBuilder` for creation)
- `Key` - Public/private key material
- `UserID` - Identity information
- `PKESK` - Public-Key Encrypted Session Key
- `SKESK` - Symmetric-Key Encrypted Session Key

Packets are typically instantiated via parsing or message creation, not manually constructed.

### Working with Certificates

Certificates (in `cert.rs`) are collections of keys + identities + certifications. The primary key serves as:
1. UUID/fingerprint for the certificate
2. Certifier for binding signatures (self-signatures)
3. Third-party certification creator

Use `CertBuilder` for creating new certificates.

### Compression Features

Compression is optional:
- `compression` - All compression algorithms
- `compression-deflate` - DEFLATE and zlib only
- `compression-bzip2` - bzip2 only

## CI/CD

CI configuration is in `.gitlab-ci.yml` and uses a common CI component from `sequoia-pgp/common-ci`.

Special CI jobs:
- `fuzzing` - Tests crypto-fuzzing backend
- `doc` - Builds documentation

## MSRV (Minimum Supported Rust Version)

**MSRV: 1.79** (tracks Debian testing's Rust version)

## Clippy Configuration

Custom thresholds in `clippy.toml`:
- `enum-variant-size-threshold = 512`
- `too-many-arguments-threshold = 10`
- `type-complexity-threshold = 500`

## Important Notes

- The workspace uses `resolver = "2"`
- Crypto packages are compiled with `opt-level = 2` even in dev profile for performance
- Line endings must be preserved (set `core.autocrlf = false` on Windows)
- CI automatically excludes leak tests with `--skip leak_tests`
- The `ossl` dependency uses a custom fork from kryoptic (branch: justus/workwork)

## Documentation

- API docs: https://docs.sequoia-pgp.org/
- sq user docs: https://book.sequoia-pgp.org
- Manual pages: https://sequoia-pgp.gitlab.io/sequoia-sq/man/
