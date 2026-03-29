# Contributing to rDHCP

Thank you for your interest in contributing to rDHCP. This document covers the process for contributing to this project.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone git@github.com:YOUR_USERNAME/rDHCP.git`
3. Create a branch: `git checkout -b feature/your-feature`
4. Make your changes
5. Submit a pull request

## Development Setup

```bash
# Install Rust (stable)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build
cargo build

# Run tests
cargo test

# Run with example config (requires root for port 67)
sudo cargo run -- example-config.toml
```

## Code Guidelines

### Rust

- Use `cargo fmt` before committing
- Run `cargo clippy` and fix all warnings
- Run `cargo test` and ensure all tests pass
- Run `cargo check` with zero errors and no new warnings
- Use Rust 2024 edition features where appropriate
- No `unsafe` code without justification and review

### Performance

This is a core network service. Every allocation on the hot path matters.

- **No heap allocations in the packet receive/respond loop** unless unavoidable
- Use `Arc<str>` instead of `String` for shared data
- Use stack-allocated buffers for packet serialization
- Profile before and after your change if it touches the hot path
- Run `bench/run.sh` to verify no performance regression

### Correctness

- Reference the relevant RFC section in comments for protocol logic
- Add unit tests for any new packet parsing or serialization code
- Verify byte offsets against the RFC spec — never guess
- Test with `perfdhcp` for end-to-end validation

## Pull Request Process

1. Update `CHANGELOG.md` with your changes
2. Bump the version in `Cargo.toml` (patch for fixes, minor for features)
3. Ensure `cargo test` passes
4. Ensure `cargo check` produces no errors
5. Describe what your PR does and why in the PR description
6. Link any related issues

## What We're Looking For

- Bug fixes with test cases
- Performance improvements with benchmark results
- RFC compliance improvements (cite the section)
- New DHCP options support
- Documentation improvements
- Test coverage improvements

## What We're Not Looking For

- External database backends (the zero-dependency design is intentional)
- Paid/proprietary crate dependencies
- Features that add complexity without clear benefit
- Breaking changes to the config format without migration path

## Reporting Issues

- Use GitHub Issues
- Include your OS, Rust version, and rDHCP version
- Include the relevant config section (redact secrets)
- Include server logs at `debug` level if reporting a bug
- For performance issues, include `perfdhcp` output

## Code of Conduct

Be respectful. Be constructive. Focus on the code, not the person.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
