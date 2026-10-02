# Roadmap

This roadmap describes direction, not promises or dates. Priorities may change as the testnet teaches us more. Discussion is welcome in GitHub issues.

## Now — public testnet

- [x] BABE + GRANDPA consensus with a fixed, approved voter set
- [x] Argon2id admission puzzle, fair lottery and membership renewal
- [x] One vote per approved operator; no transaction fees; no sudo
- [x] 2-of-3 committee governance for runtime upgrades, signed offline
- [x] Madar Stamp: on-chain proof-of-existence timestamps
- [x] Full node for Linux and a desktop node app for Windows
- [x] Signed-update verification with key rotation and revocation
- [ ] More independent voting operators in different locations
- [ ] Benchmarked weights for every call (replacing the conservative placeholders)
- [ ] Re-calibrating the Argon2id cost on ARM64 hardware

## Next — hardening

- [ ] Independent external security audit of the runtime and node
- [ ] Bug bounty program
- [ ] Reproducible builds verified across operating systems
- [ ] Resolving or replacing the upstream-blocked dependency advisories listed in [`docs/security/dependency-exceptions.md`](docs/security/dependency-exceptions.md)
- [ ] Prebuilt, signed Linux packages and a macOS build of the desktop app
- [ ] More developer documentation and examples (RPC, runtime API, stamp verification)

## Later — mainnet candidate

- [ ] Mainnet candidate gates: no open Critical/High findings, a completed audit, and a live bug bounty
- [ ] A fresh mainnet genesis with real operators only (no development accounts)
- [ ] Public, documented process for approving new operators

Have an idea? Open an issue with the feature request template.
