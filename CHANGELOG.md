# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Single-file output: `lock` now writes one `.pbx` containing a `PBX1` header line (the file's wrapped key as base64 JSON) followed by the standard age payload. The `.key` sidecar is gone. `unlock` still reads v0.2.0 two-file output via the sidecar. Stock age decrypts the payload with `tail -n +2 file.pbx | age -d -i key.txt`.

## [0.2.0] - 2026-11-21

### Added

- The secret screen and interactive prompts now state the secret rules for the chosen mode, with the security reason for each rule, before any input is required.

### Changed

- Unified key map shown in every footer: arrows or Tab navigate, Backspace flips the settings switch, A applies, Esc goes back, Q quits. The home settings toggle no longer uses a form widget.
- Encryption moved from one global keystore to per-file keys. Every `lock` creates a fresh age identity for the file, wraps it under a key derived from your secret, and stores it as `<file>.pbx.key` next to the `.pbx`. `unlock` and `export-key` work per file. Settings (`settings.json`) hold the key type and the gate-encrypt toggle; when the key type is unset, the encrypt flow asks before encrypting. The Settings screen is a stable option list: Tab/Backspace move down, arrows flip the current option, A applies, and states persist between sessions.

### Removed

- The `pillarbox init` command. Setup now happens only through bare `pillarbox`, which starts onboarding when no keystore exists.
- Folder encryption. `lock` accepts single files only and rejects folders with exit code 2; `.tar.pbx` archives are no longer produced or decrypted.

## [0.1.0] - 2026-11-21

### Added

- Encrypt and decrypt single files (`.pbx`) and folders (`.tar.pbx`) with filippo.io/age streaming encryption.
- First-run onboarding and a keyboard-driven home menu, file picker and key map (Bubble Tea).
- Four unlock modes: password, PIN, password+2FA and PIN+2FA.
- Argon2id key derivation with HKDF, XChaCha20-Poly1305 key wrapping, a 32-byte device secret for PIN modes and RFC 6238 TOTP with replay protection.
- Recovery key (age identity) shown once at init and via `pillarbox export-key`; output decrypts with the stock `age` binary.
- CLI commands: init, lock, unlock, status, export-key, config, version, completion, with `--no-tui`, `--secret-stdin`, `--totp` and `--quiet` flags and exit codes 0-5.
- Archive extraction rejects `..`, absolute paths and symlinks resolving outside the target.
- `scripts/e2e.sh` end-to-end test running in CI on Ubuntu and macOS.
- GoReleaser release publishing binaries for darwin and linux on amd64 and arm64.
