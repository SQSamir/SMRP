# Contributing to SMRP

Thank you for your interest! This is a research project — contributions that
improve correctness, security, and clarity are most welcome.

## Ground Rules

- Be respectful. This project follows the [Contributor Covenant](https://www.contributor-covenant.org/).
- Open an issue before starting significant work so we can align on scope.
- All code must compile on stable Rust with `cargo clippy -- -D warnings`.

## Getting Started

```sh
git clone https://github.com/SQSamir/smrp
cd smrp
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

## What to Contribute

Good first issues:

- Expand the test suite (more replay-window edge cases, handshake fuzzing)
- Add a `smrp-core` integration test that runs a full client-server round-trip
- Improve error messages and tracing spans
- Document public API with `///` doc-comments
- Fill out `docs/SPEC.md` with formal state-machine diagrams

Out of scope (for now):

- Retransmission / reliability layer (out of design charter)
- TLS or DTLS compatibility
- Certificate authorities or X.509

## Pull Request Checklist

- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace -- -D warnings` passes
- [ ] New public items have doc-comments
- [ ] Commit messages are imperative, present-tense ("Add replay test for wraparound")
- [ ] One logical change per PR

## Security Issues

**Do not open a public issue for security vulnerabilities.**
Email samir.gasimov@live.com with subject `[SMRP SECURITY]` and allow up to 7
days for a response before public disclosure.

## License

By contributing you agree that your contributions will be licensed under the
MIT License.
