# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.2](https://github.com/SecurityRonin/usb-forensic/compare/usb-forensic-v0.3.1...usb-forensic-v0.3.2) - 2026-08-09

### Fixed

- *(gitignore)* unanchor the target rule so nested cargo projects are ignored

## [0.3.1](https://github.com/SecurityRonin/usb-forensic/compare/usb-forensic-v0.3.0...usb-forensic-v0.3.1) - 2026-08-06

### Fixed

- *(supply-chain)* allow the bzip2-1.0.6 licence the 7z decode path needs
- *(deps)* widen disk-forensic 0.9 -> 0.11, clearing the vulnerable lru

## [0.3.0](https://github.com/SecurityRonin/usb-forensic/compare/usb-forensic-v0.2.0...usb-forensic-v0.3.0) - 2026-08-04

### Added

- *(shellbag)* GREEN — emit drive-letter + browsed-folder Claims

### Fixed

- *(deps)* take peripheral-core from the registry, not the sibling repo
- *(deps)* tighten mbr/gpt-partition floors to field-bearing versions (0.6.2/0.6.1)

### Other

- Merge pull request #23 from SecurityRonin/fix/docs-actions-pages-deploy

## [0.2.0](https://github.com/SecurityRonin/usb-forensic/compare/usb-forensic-v0.1.0...usb-forensic-v0.2.0) - 2026-07-25

### Added

- *(usb4n6)* wire DriverFrameworks source into the pipeline + docs
- *(driver-framework)* GREEN — DriverFrameworks-UserMode source

### Documentation

- correct stale parity markers after 0.1.0

### Fixed

- *(vet)* declare own crates first-party so version bumps don't break supply-chain audit

Pre-code design seed. The repository holds the validated product thesis, the
competitive landscape, and the build roadmap; it is scaffolded to the SecurityRonin
fleet standard (CI, panic-free lints, supply-chain gates, MkDocs site) but carries no
correlation logic yet. `publish = false` until the first Phase 1 feature lands under
TDD.

### Added
- Product thesis and competitive landscape (`README.md`,
  `docs/competitive-landscape.md`), corrected after an adversarial pressure-test
  (Fable 5 deep analysis + Codex critique) that rejected the "better than USB
  Detective cross-platform" framing in favour of the pipeline/reproducibility wedge.
- Fleet-standard scaffolding: workspace panic-free lints, CI (fmt / clippy / test
  matrix / 100% coverage / MSRV 1.81 / cargo-deny / docs), MkDocs docs site,
  `SECURITY.md`, `CONTRIBUTING.md`, Apache-2.0 `LICENSE`.
