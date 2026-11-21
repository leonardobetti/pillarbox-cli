# Pillarbox

Pillarbox encrypts and decrypts files from the terminal. It needs no mouse, no account and no network. One static binary runs on macOS and Linux.

## The problem

Cryptomator encrypts files with a key hierarchy, authenticated encryption and a passphrase unlock, but it needs a graphical interface. Tools like `age`, `gpg` and `openssl` expose low-level building blocks and leave secret handling and 2FA (two-factor authentication) to you. Pillarbox gives terminal users the same approach as a keyboard-driven command. Open the home menu, pick a file, then run `lock` and `unlock`.

## Install

Pipe the install script:

```sh
curl -fsSL https://raw.githubusercontent.com/leonardobetti/pillarbox-cli/main/scripts/install.sh | sh
```

Or download a binary for your platform from [GitHub Releases](https://github.com/leonardobetti/pillarbox-cli/releases), or install with Go:

```sh
go install github.com/leonardobetti/pillarbox-cli/cmd/pillarbox@latest
```

The install script verifies the archive against `checksums.txt` from the release before installing.

## Quick start

Run this on a clean machine. It takes under a minute.

1. Run `pillarbox` on a terminal. The home menu opens straight away (Encrypt, Decrypt, Status, Settings, Help). Choose a key type in Settings, or the first Encrypt asks and saves it.
2. Encrypt a file: `pillarbox lock .env` creates a single `.env.pbx`. The file carries its own key in a `PBX1` header line followed by a standard age payload; you type the secret each time. Save the recovery key when shown — Pillarbox prints it once.
3. Decrypt it back: `pillarbox unlock .env.pbx` reads the embedded key and asks for the secret. In the TUI, decrypt overwrites an existing original next to the `.pbx`.

For scripts, skip the screens and pipe the secret:

```sh
printf '%s\n' "$MY_SECRET" | pillarbox --no-tui --secret-stdin lock .env
```

## Unlock modes

Settings (or the first Encrypt) picks one of four key types. Every encrypted file gets its own key, embedded in the `.pbx` itself. The secret screen states the rules for the chosen mode before you type anything:

| Mode | Secret | Device secret in the key | TOTP check |
| --- | --- | --- | --- |
| `password` | Passphrase, 12 characters or more | No | No |
| `pin` | PIN, 6 to 12 digits | Yes | No |
| `password+2fa` | Passphrase | No | Yes |
| `pin+2fa` | PIN | Yes | Yes |

### PIN limit

A 6-digit PIN has 1,000,000 values. At 0.5 seconds per Argon2id guess that is about six days on one core, and an attacker can use many cores. PIN modes therefore mix a 32-byte device secret into the key. The device secret is a file in your config folder with mode `0600`. Files locked in PIN mode decrypt only on a machine that has the device secret, or with the recovery key. If an attacker copies your whole config folder, the PIN is the only protection left.

### 2FA limit

A TOTP (time-based one-time password, RFC 6238) code expires every 30 seconds, so it cannot feed the key derivation. In v0.1 Pillarbox checks the code after your secret unwraps the TOTP seed. An attacker who has your keystore and your secret, and who replaces the binary, can skip the check. The 2FA modes raise the cost of a stolen secret for anyone using the stock binary. They do not add key strength.

## Decrypt with stock age

The recovery key is an `age` secret key. With it, the stock `age` tool decrypts any Pillarbox output without Pillarbox.

1. Run `pillarbox export-key` and authenticate. Save the output to a file with mode `0600`:

   ```sh
   pillarbox export-key > key.txt && chmod 600 key.txt
   ```

2. Decrypt. The `.pbx` is a `PBX1` header line plus a standard age payload, so strip the first line:

   ```sh
   tail -n +2 file.pbx | age -d -i key.txt > file
   ```

## Keys

Every screen shows its keys in the footer. Tab or ←/→ switch the top tabs, ↑/↓ move inside the box, Enter selects, Backspace goes to the parent directory or cycles settings, Q quits, Ctrl+C aborts (or copies the 2FA URI). In Settings: ←/→ toggles the option, A applies.

## Commands

| Command | What it does |
| --- | --- |
| `pillarbox` | Open the home menu on a TTY; print help (or exit 5 if no settings) without a TTY |
| `pillarbox lock <path> [-o OUT] [--remove-original] [--force]` | Encrypt a file |
| `pillarbox unlock <file.pbx> [-o OUT] [--force]` | Decrypt a `.pbx` file |
| `pillarbox status` | Show key type, auth-encrypt, settings path and version |
| `pillarbox export-key <file.pbx>` | Print the recovery key of one file after authentication |
| `pillarbox config set auth-encrypt true\|false` | Require the secret before the encrypt file picker (default false) |
| `pillarbox config set key-type MODE` | Set the key type used for new files |
| `pillarbox version` | Print the version |

Global flags: `--no-tui`, `--secret-stdin`, `--totp CODE`, `--quiet`. No command accepts a secret as an argument.

Exit codes: 0 success, 1 other error, 2 usage error, 3 authentication failed, 4 integrity failure, 5 keystore missing or invalid.

## License

MIT, see [LICENSE](LICENSE).
