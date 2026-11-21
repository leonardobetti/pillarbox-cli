# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Shared install-wide TOTP seed (`totp.seed`): one QR for all 2FA files on this machine.
- TUI asks before overwriting an existing file on decrypt.
- TUI encrypt requires acknowledging the recovery key, then keep or remove the original.
- Help FAQ: Settings vs per-file mode, shared 2FA, PIN device secret, recovery keys.
- Status shows shared 2FA and device secret presence.

### Changed

- Settings and Status label the key type as the default for new files.
- 2FA chooser and secret screens state that one authenticator entry covers the install.
- Architecture docs match the per-file PBX1 model and shared TOTP.

## [0.3.8] - 2026-11-21

### Changed

- Keyboard shortcuts in footers/help render the key glyphs in bold (same dim colour).
- Focused picker (and Settings) rows are bold as well as prefixed with `>`.

### Removed

- `prd.md` and `AGENTS.md` from the repository.

## [0.3.7] - 2026-11-21

### Fixed

- Help tab teatest no longer requires the wrapped phrase "open source" as one substring.

## [0.3.6] - 2026-11-21

### Added

- Help tab intro: what Pillarbox does (Argon2id + age), free/open source, credits to Leonardo Betti and Nasser Khalil with LLM assistance.

## [0.3.5] - 2026-11-21

### Changed

- Clearer success copy after encrypt and decrypt (path plus what credentials that file needs; original-file keep/remove note).
- Installer curl-pipe ends with a short welcome: Pillarbox is installed — run `pillarbox`. Enjoy.

## [0.3.4] - 2026-11-21

### Added

- Decrypt secret screen names the selected `.pbx` and states what that file needs (passphrase, PIN, and/or 2FA code).

## [0.3.3] - 2026-11-21

### Fixed

- Settings no longer traps Tab: ↑/↓ move options, backspace toggles, Tab/←/→ leave for the next top-level section (Help).

## [0.3.2] - 2026-11-21

### Changed

- Home TUI requires at least 80×40 terminal cells (~800×800px at a typical monospace font). Smaller windows show a resize hint instead of a broken layout.

## [0.3.1] - 2026-11-21

### Fixed

- Home TUI rendering: `fit()` no longer slices ANSI sequences (garbled tab labels like `4;38;2;…mpt`). Active tab underline is a row of `─` characters; content box no longer uses a fixed lipgloss Height that broke the border.

## [0.3.0] - 2026-11-21

### Changed

- Single-file output: `lock` now writes one `.pbx` containing a `PBX1` header line (the file's wrapped key as base64 JSON) followed by the standard age payload. The `.key` sidecar is gone. `unlock` still reads v0.2.0 two-file output via the sidecar. Stock age decrypts the payload with `tail -n +2 file.pbx | age -d -i key.txt`.
- Home TUI layout: horizontal tabs (Encrypt, Decrypt, Status, Settings, Help), magenta bordered content box, and a keybinding footer. Bare `pillarbox` on a TTY opens the home menu directly.
- Settings rename: `gate-encrypt` is now `auth-encrypt` (`Require authentication to encrypt`, default false). When enabled, Encrypt asks for the secret before the file picker and reuses it. The key-type chooser persists the choice to `settings.json`.
- TUI decrypt overwrites an existing original next to the `.pbx` (`UnlockOptions{Force: true}`). CLI still requires `--force`.
- PIN secret rules show only `PIN: 6 to 12 digits, numbers only.` The 2FA QR screen lays out the code entry beside the QR so it fits 80×24.

### Removed

- First-run onboarding flow (`RunOnboarding` / `onboarding.go`). Key type is set in Settings or asked on first Encrypt.

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
