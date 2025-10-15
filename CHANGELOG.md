# Changelog

All notable changes to this project will be documented in this file.

## [0.1.6] - 2025-10-15

### What's New

- Randomize the ICMP identifier with a UUID so concurrent client instances no longer collide on PID-derived IDs.
- Add interval controls across the ping, multi-ping, and mtr demos, defaulting to 200 ms for faster feedback while still honoring longer pauses.
- Rework multi-ping into a continuous monitor with start/stop controls that keep stats and tables responsive without manual reruns.
- Tighten Textual styling so action buttons share sizing and form inputs gain consistent padding.

## [0.1.4] - 2025-10-14

### Highlights

- Added a `--bootstrap-cap` flag so `uvx icmpx` can grant `CAP_NET_RAW` to the active interpreter automatically.
- Standardized the raw socket permission error message to English to match the CLI guidance.
- Extended official support to Python 3.11–3.14 while preferring Python 3.14 when present.
- Updated packaging metadata to use an SPDX license expression and satisfy modern setuptools warnings.
- The bootstrap flow now re-verifies `CAP_NET_RAW`, auto-launches the demo on success, and regular runs preflight permission checks.
- CLI feedback now uses Rich panels and colors to highlight errors, warnings, and next steps.

## [0.1.3] - 2025-10-14

### Added

- Console script entry point so `uvx icmpx` launches the Textual demo without cloning the repo.

### Changed

- Moved the Textual TUI into the `icmpx` package and export a `run()` helper for reuse.
- Ship the `style.tcss` stylesheet with the package to keep the UI styled after installation.

### Documentation

- Updated both READMEs with the new `uvx icmpx` usage instructions and refreshed references to the packaged demo.

## [0.1.2] - 2025-09-08

- Previous public release.
