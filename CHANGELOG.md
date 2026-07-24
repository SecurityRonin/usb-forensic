# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/SecurityRonin/usb-forensic/compare/usb-forensic-v0.1.0...usb-forensic-v0.2.0) - 2026-07-24

### Added

- *(usb4n6)* wire DriverFrameworks source into the pipeline + docs
- *(driver-framework)* GREEN — DriverFrameworks-UserMode source

### Documentation

- correct stale parity markers after 0.1.0

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
