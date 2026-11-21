# Pillarbox

Pillarbox encrypts and decrypts files from the terminal. It needs no mouse, no account and no network. One static binary runs on macOS and Linux.

## The problem

Cryptomator encrypts files with a key hierarchy, authenticated encryption and a passphrase unlock, but it needs a graphical interface. Tools like `age`, `gpg` and `openssl` expose low-level building blocks and leave onboarding, secret handling and 2FA (two-factor authentication) to you. Pillarbox gives terminal users the same approach as a keyboard-driven command. Set up once, then run `lock` and `unlock`.

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

1. Run `pillarbox`. Pillarbox guides you through five screens: what it does, the unlock mode, your secret, 2FA setup if you chose a 2FA mode, and your recovery key. Save the recovery key. Pillarbox shows it once.
2. Encrypt a file: `pillarbox lock .env` creates `.env.pbx`.
3. Decrypt it back: `pillarbox unlock .env.pbx`.

For scripts, skip the screens and pipe the secret:

```sh
printf '%s\n' "$MY_SECRET" | pillarbox --no-tui --secret-stdin lock .env
```

## Unlock modes

The onboarding menu picks one of four unlock modes. The secret screen states the rules for the chosen mode, and why they exist, before you type anything:

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

2. Decrypt:

   ```sh
   age -d -i key.txt file.pbx > file
   ```

## Commands

| Command | What it does |
| --- | --- |
| `pillarbox` | Onboarding when there is no keystore, home menu otherwise |
| `pillarbox lock <path> [-o OUT] [--remove-original] [--force]` | Encrypt a file |
| `pillarbox unlock <file.pbx> [-o OUT] [--force]` | Decrypt a `.pbx` file |
| `pillarbox status` | Show mode, 2FA state, keystore path and version |
| `pillarbox export-key` | Print the recovery key after authentication |
| `pillarbox config set gate-encrypt true\|false` | Require authentication before `lock` |
| `pillarbox version` | Print the version |

Global flags: `--no-tui`, `--secret-stdin`, `--totp CODE`, `--quiet`. No command accepts a secret as an argument.

Exit codes: 0 success, 1 other error, 2 usage error, 3 authentication failed, 4 integrity failure, 5 keystore missing or invalid.

## License

MIT, see [LICENSE](LICENSE).
