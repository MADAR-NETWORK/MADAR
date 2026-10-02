# Contributing to MADAR Network

Thank you for your interest in MADAR. Bug reports, documentation fixes, tests and code are all welcome.

By participating you agree to follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## Before you start

- **Security issues:** do not open a public issue. Follow [SECURITY.md](SECURITY.md).
- **Bugs:** search existing issues first, then open one with the bug report template.
- **New features or protocol changes:** open an issue to discuss the idea before writing code. Anything that changes the runtime (consensus rules, admission, governance, storage layout) affects every node on the network and needs a design discussion first.

## Development setup

Follow [GETTING_STARTED.md](GETTING_STARTED.md) to install the pinned toolchain and system packages, then:

```bash
bash scripts/verify-build-env.sh     # your toolchain matches the pinned one
cargo build --locked --workspace
cargo test --locked --workspace
```

Optional: install the local git hooks (including the secret scanner):

```bash
bash scripts/install-hooks.sh
```

## Pull request checklist

Every pull request must pass the same checks that CI runs (see [`.github/workflows/ci.yml`](.github/workflows/ci.yml)):

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets
cargo test --locked --workspace
bash scripts/check-no-secrets.sh --all
cargo deny check bans licenses sources
bash scripts/check-advisories.sh
```

In addition:

- **Keep pull requests focused.** One logical change per pull request.
- **Add tests** for new behavior and for every bug fix.
- **Do not change `Cargo.lock`** unless the pull request is about dependencies. Dependency changes need a short justification; new advisories must be documented in [`docs/security/dependency-exceptions.md`](docs/security/dependency-exceptions.md) or the check fails.
- **Runtime changes:** if you change anything that alters runtime behavior or storage, bump `spec_version` in [`consensus/src/lib.rs`](consensus/src/lib.rs) and explain the migration (if any) in the pull request. Runtime upgrades only reach the live network after 2-of-3 committee approval.
- **Never commit secrets:** no private keys, seed phrases, passwords, tokens or `.env` files. The secret scanner blocks common patterns, but you are responsible for what you push.
- **Update the docs** ([`README.md`](README.md), [`docs/`](docs/)) and add a line to [`CHANGELOG.md`](CHANGELOG.md) under *Unreleased* when the change is user-visible.

## Coding style

- Rust 2021 edition, formatted with `rustfmt` defaults.
- Prefer clear code over clever code. Comment *why*, not *what*.
- Runtime (`no_std`) code must never panic on user input: return errors and charge correct weights.
- Every dispatchable call needs an accurate weight. Expensive paths (such as Argon2id verification) must be weighted for the worst case.
- Keep dependencies minimal. Prefer what the Polkadot SDK already provides.

## Commit messages

Write a short summary line in the imperative mood (e.g. "Fix renewal grace period off-by-one"), followed by an optional body that explains why the change is needed.

## Licensing of contributions

MADAR Network is licensed under the [Apache License 2.0](LICENSE). Unless you explicitly state otherwise, any contribution you intentionally submit for inclusion is licensed under Apache-2.0, as described in section 5 of the license, without any additional terms or conditions.
