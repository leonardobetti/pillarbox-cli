Pillarbox CLI: PRD and build plan
Version 0.1. Hackathon draft. Repository: pillarbox-cli. Licence: MIT.
Part 1 is the PRD. Save it as docs/PRD.md in the repository and point Mistral Vibe at it with @docs/PRD.md. Part 2 is the build plan, with the pstack commands to paste into Vibe.
Part 1: PRD
1. Problem
Cryptomator encrypts files with a key hierarchy, authenticated encryption and a passphrase unlock, but it needs a graphical interface. People who work in a terminal have no tool with the same approach that installs in one command, runs from a shell and works from the keyboard. age, gpg and openssl expose primitives and leave onboarding, secret handling and 2FA to the user.
2. Goal
Ship a single pillarbox binary for macOS and Linux today. It encrypts and decrypts files and folders, guides a new user through setup on the first command, offers four unlock modes with optional TOTP 2FA, and works with the keyboard alone.
Demo criteria:
1.  On a clean machine, install the binary and finish onboarding in under 90 seconds.
2.  pillarbox lock ./project followed by pillarbox unlock ./project.tar.pbx restores the folder, and the checksums match.
3.  A wrong secret, a wrong 2FA code and a modified .pbx file each fail with a one-line message and a non-zero exit code.
4.  Every interactive screen works without a mouse.
5.  A tagged v0.1.0 release publishes binaries for four targets.
3. Users
• Power users who work in the terminal, use the keyboard and script their tools.
• Web developers who protect .env files, database exports, client folders and backups.
4. Scope
In scope for v0.1:
• Encrypt and decrypt single files and folders.
• First-run onboarding.
• Unlock modes: password, PIN, password + 2FA, PIN + 2FA.
• Keyboard-driven file picker and menus.
• Non-interactive use for scripts.
• Recovery key.
• macOS (arm64, amd64) and Linux (amd64, arm64).
Out of scope for v0.1:
• Landing page (repository pillarbox-landing, later).
• Mounting a vault as a drive (needs FUSE), encrypted file names inside a vault, sync.
• Windows and any graphical interface.
• Hardware keys, multiple users, key rotation.
• Secure deletion of originals.
5. Technical decisions
Area
Decision
Reason
Language
Go, latest stable
One static binary, cross-compiles to all four targets, the standard library covers tar and streaming I/O, and the Charm libraries are written in Go.
CLI
Cobra
Subcommands, flags, shell completion.
Interface
Bubble Tea, Bubbles, Huh, Lip Gloss
Compiled into the binary. Gum is a separate program that shell scripts call. This tool needs typed code for crypto, keystore and TOTP, so Gum would add a runtime dependency and still need Go behind it.
File encryption
filippo.io/age library
Streaming format with chunked ChaCha20-Poly1305, small API, no file format to design today. Output decrypts with the stock age tool given the recovery key. BSD-3-Clause, compatible with MIT.
Key derivation
Argon2id (golang.org/x/crypto/argon2)
Memory-hard, standardised in RFC 9106.
Key wrapping
XChaCha20-Poly1305 (golang.org/x/crypto/chacha20poly1305)
24-byte random nonces are safe to generate.
2FA
TOTP, RFC 6238 (github.com/pquerna/otp)
Works with common authenticator apps.
Folders
archive/tar streamed into age
File names and structure sit inside the encrypted stream.
Secret input
golang.org/x/term
No echo. Secrets never pass as arguments.
Release
GoReleaser and GitHub Actions
Four targets from one tag. A Homebrew tap is a stretch goal.
Rejected: a shell script around openssl (no authenticated streaming, and TOTP plus state handling are hard in shell). Rust with ratatui (slower to ship in one day, valid later).
The project is called Pillarbox. The binary is pillarbox.
6. Security model
6.1 What is protected
File contents. For folders, also file names and structure. Not hidden: file size, the fact that the file is Pillarbox output, and the modification time of the .pbx file. For a single file the default output name <name>.pbx shows the original name, and -o sets another name.
6.2 Unlock modes
Mode
Secret
Device secret in the key
TOTP check
Notes
password
Passphrase, 12 characters or more
No
No
Strength set by passphrase length and Argon2id cost.
pin
PIN, 6 to 12 digits
Yes
No
The PIN alone cannot decrypt.
password+2fa
Passphrase
No
Yes

pin+2fa
PIN
Yes
Yes

6.3 PIN limit
A 6-digit PIN has 1,000,000 values. At 0.5 seconds per Argon2id guess that is about six days on one core, and an attacker can use many cores. The PIN modes therefore mix a 32-byte device secret into the key. The device secret is a file in the user config folder with mode 0600. Files locked in PIN mode decrypt only on a machine that has the device secret, or with the recovery key. If an attacker copies the whole config folder, the PIN is the only protection left. Storing the device secret in the macOS Keychain or the Linux Secret Service is the next step. Onboarding states this in two sentences.
6.4 2FA limit
A TOTP code is derived from a secret and expires every 30 seconds, so it cannot feed the key derivation. In v0.1 the program checks the code after the secret unwraps the TOTP seed. The seed is stored encrypted under the key-encryption key, so an attacker cannot read it without the PIN or passphrase. An attacker who has the keystore file and the secret, and who replaces the binary, can skip the check. The 2FA modes raise the cost of a stolen secret for anyone using the stock binary. They do not add key strength. Onboarding and the README call this mode a step-up check. A later version can add a keyfile or a FIDO2 hmac-secret that feeds the key derivation, which gives a second factor with cryptographic effect.
6.5 Non-goals
• Malware on the host, side channels, multi-user machines.
• Secure deletion. SSDs and APFS copy-on-write make it unreliable, so the original stays unless the user passes --remove-original.
• Guaranteed zeroing of secrets in memory. Go gives no such guarantee. The code clears buffers where it can.
6.6 Recovery key
At init the program shows the age identity (AGE-SECRET-KEY-1...) once. The user types saved to continue. pillarbox export-key shows it again after authentication. With it, age -d -i key.txt file.pbx decrypts any Pillarbox output without Pillarbox.
7. Cryptography specification
7.1 Init
1.  Generate an age X25519 identity. The public key is the recipient.
2.  Read the secret twice. For PIN modes, write 32 random bytes to <config>/pillarbox/device.key with mode 0600.
3.  Derive: ikm = Argon2id(secret, salt, t=3, m=64 MiB, p=4, 32 bytes), then KEK = HKDF-SHA256(ikm, salt = device secret or empty, info = pillarbox/kek/v1, 32 bytes). The salt is 16 random bytes.
4.  Wrap the identity with XChaCha20-Poly1305 under the KEK. Associated data: keystore version, mode and recipient.
5.  For 2FA modes, generate a 20-byte TOTP seed, show it as an otpauth:// URI and a QR code, ask for one valid code, then wrap the seed under the KEK the same way.
6.  Write <config>/pillarbox/keystore.json through a temp file, fsync and rename, mode 0600.
<config> is os.UserConfigDir().
7.2 Keystore fields
version, mode, Argon2id parameters and salt, recipient, wrapped identity (nonce and ciphertext), wrapped TOTP seed (optional), last_totp_step (optional), policy.gate_encrypt, created_at. Argon2id parameters live in the file so a later version can raise them.
7.3 Lock
1.  Read the recipient from the keystore. If policy.gate_encrypt is true, authenticate first (secret, then TOTP if enabled).
2.  File: stream through age.Encrypt to <name>.pbx. Folder: stream archive/tar through age.Encrypt to <dir>.tar.pbx. Tar stores regular files, directories and symlinks (as symlinks), with relative paths.
3.  Write to a temp file in the target directory with mode 0600, fsync, then rename. A failure leaves no partial output.
7.4 Unlock
1.  Read the secret, derive the KEK, unwrap the identity. A failed unwrap is an authentication failure. Do not say which factor failed.
2.  If the mode has 2FA, unwrap the seed and verify the code (current step and one step either side). Reject a step equal to last_totp_step, then store the new step.
3.  Stream through age.Decrypt. For folders, extract with checks: reject .., absolute paths, and symlinks that resolve outside the target. Refuse to overwrite existing paths without --force.
4.  Any integrity failure removes the partial output and exits with code 4.
8. User flows
8.1 First run
Any command without a keystore, on a terminal, starts onboarding. Without a terminal it exits with code 5 and prints run pillarbox init.
Screens:
1.  Welcome. What Pillarbox does, and the three commands to know: pillarbox (menu), lock, unlock.
2.  Unlock mode. Four options, one line each, with the PIN and 2FA limits from 6.3 and 6.4.
3.  Secret. Enter twice. Show length rules. No echo.
4.  2FA setup (only for 2FA modes). QR code, URI, and a prompt for one code. Also ask whether encryption should require 2FA too (default no).
5.  Recovery key and summary. Offer to lock a first file.
Esc quits at any screen and writes nothing. The keystore is written once, at the end.
8.2 Home menu
pillarbox with a keystore and a terminal opens a menu: Lock, Unlock, Status, Settings, Help. Lock and Unlock open a file picker.
8.3 Scripts
--no-tui disables all interactive screens. The secret comes from --secret-stdin, the code from --totp. A command that needs input and has no terminal, no flag and no stdin exits with code 2.
8.4 Key map
Key
Action
Up, Down or k, j
Move
Left, Right or h, l
Parent folder, enter folder (picker)
Enter
Select or confirm
Esc
Back, or cancel onboarding
Tab, Shift+Tab
Next, previous field
/
Filter a list
?
Show or hide key help
q
Quit from the menu
Ctrl+C
Abort at any time
Every screen shows its keys in a footer.
9. CLI reference
pillarbox                         onboarding or home menu
pillarbox init [--mode MODE] [--force]
pillarbox lock <path> [-o OUT] [--remove-original] [--force]    alias: encrypt
pillarbox unlock <file.pbx> [-o OUT] [--force]                  alias: decrypt
pillarbox status                  mode, 2FA state, keystore path, version
pillarbox export-key              prints the recovery key after authentication
pillarbox config set gate-encrypt true|false
pillarbox version
pillarbox completion bash|zsh|fish
Global flags: --no-tui, --secret-stdin, --totp CODE, --quiet. No command accepts a secret as an argument.
Exit codes: 0 success, 1 other error, 2 usage error, 3 authentication failed, 4 integrity failure, 5 keystore missing or invalid.
Messages are one line: the cause, then the next step.
10. Functional requirements
ID
Requirement
Acceptance
FR-01
Onboarding starts on first run (section 8.1).
With no keystore, any command starts it on a terminal. Esc leaves no keystore. Completion leaves one with mode 0600.
FR-02
Four unlock modes.
A test locks and unlocks a file in each mode.
FR-03
Lock a file.
Output <name>.pbx exists. The input is unchanged.
FR-04
Lock a folder.
Output <dir>.tar.pbx contains no plaintext names (check with strings).
FR-05
Unlock a file or folder.
Checksums of all files match the originals. Existing paths are not overwritten without --force.
FR-06
Integrity.
One flipped byte, a truncated file and an appended byte each give exit code 4 and no output file.
FR-07
Authentication.
A wrong secret and a wrong TOTP code both give exit code 3 with the same message.
FR-08
TOTP.
Accepts the current step and one either side. Rejects the same step twice.
FR-09
Encrypt gate.
With gate-encrypt true, lock asks for the secret (and TOTP). With false, it does not.
FR-10
Keyboard use.
Every screen is reachable and completable with the keys in 8.4.
FR-11
Scripts.
--no-tui --secret-stdin works in a pipe. No secret appears in ps output, shell history or logs.
FR-12
Recovery.
export-key output decrypts a .pbx file with stock age.
FR-13
Status.
Prints no secret, seed or key.
FR-14
Privacy.
No network calls and no telemetry.
FR-15
Streaming.
Locking a 1 GiB file keeps peak memory under 200 MiB.
11. Non-functional requirements
• One static binary (CGO_ENABLED=0), no runtime dependency.
• pillarbox version starts in under 150 ms.
• Key derivation takes 0.3 to 1.5 seconds on a laptop from 2018 or later.
• Terminals: Ghostty, Alacritty, iTerm2, Terminal.app, GNOME Terminal. Layout fits 80 by 24. NO_COLOR is honoured. Colour never carries meaning alone.
• Dependencies are open source with licences compatible with MIT. go-licenses or a manual check runs before the release.
12. Repository layout
pillarbox-cli/
  cmd/pillarbox/main.go
  internal/cli/        Cobra commands, exit codes
  internal/tui/        Bubble Tea models: onboarding, home, picker
  internal/keystore/   schema, load, save, wrap, unwrap
  internal/auth/       KDF, modes, TOTP, device secret
  internal/vault/      lock and unlock pipelines (age, tar)
  internal/archive/    tar writer and reader with path checks
  testdata/
  scripts/e2e.sh
  docs/PRD.md  docs/ARCHITECTURE.md
  .goreleaser.yaml
  .github/workflows/ci.yml  release.yml
  LICENSE  README.md  CHANGELOG.md  AGENTS.md
13. Test plan
• Unit: round trip per mode, wrong secret, wrong TOTP, reused TOTP step, tampered keystore, tampered .pbx, truncated .pbx, empty file.
• Archive: entries with .., absolute paths, symlinks pointing outside the target, long names, empty folders.
• Interface: teatest scripts for onboarding in each mode, and for Esc before the last screen.
• End to end: scripts/e2e.sh builds the binary, runs every mode, compares checksums and checks exit codes. It runs in CI on Ubuntu and macOS.
• Streaming: the 1 GiB test runs behind a build tag, outside CI.
14. Documentation and release
• README order: the problem, install, a 60-second quick start, the four modes, the limits in section 6, how to decrypt with stock age.
• CHANGELOG.md in Keep a Changelog format. Tag v0.1.0. GoReleaser publishes archives and a checksum file.
• Install paths for v0.1: download from GitHub Releases, or go install. Homebrew tap and an install script are stretch goals.
15. Open questions
1.  Does --remove-original stay in v0.1, given the deletion limits in 6.5? Default: keep it, off by default.
2.  Should gate-encrypt default to on? Default: off.
3.  Pin the age version and check its current licence text before release.
4.  Display name Pillarbox or pillar-box? This document uses pillarbox for the binary and the repositories.
