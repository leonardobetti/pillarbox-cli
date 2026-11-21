# Pillarbox

Pillarbox encrypts and decrypts files in the terminal. It needs no mouse, no account, and no network. One static binary runs on macOS and Linux.

## Why it exists

Cryptomator encrypts files with a passphrase, but it needs a GUI. Tools such as `age`, `gpg`, and `openssl` expose cryptography and leave secret handling and TOTP to you. Pillarbox is a keyboard-driven terminal command that does both. Open the home menu, pick a file, then lock or unlock it.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/leonardobetti/pillarbox-cli/main/scripts/install.sh | sh
```

Download a binary from [GitHub Releases](https://github.com/leonardobetti/pillarbox-cli/releases), or install with Go:

```sh
go install github.com/leonardobetti/pillarbox-cli/cmd/pillarbox@latest
```

The install script checks the archive against `checksums.txt` from the release.

## Quick start

1. Run `pillarbox` in a terminal. The home menu opens with Encrypt, Decrypt, Status, Settings, and Help. Set a key type in Settings, or Encrypt asks on first use and saves it.
2. Encrypt a file with `pillarbox lock .env`. That writes `.env.pbx`: a `PBX1` header line plus a standard age payload. You type the secret each time. Save the recovery key when Pillarbox prints it. It shows that key once.
3. Decrypt with `pillarbox unlock .env.pbx`. It reads the embedded key and asks for the secret. In the TUI, decrypt overwrites an existing original next to the `.pbx`.

For scripts, pipe the secret:

```sh
printf '%s\n' "$MY_SECRET" | pillarbox --no-tui --secret-stdin lock .env
```

## Unlock modes

Settings, or the first Encrypt, picks one of four key types. Each encrypted file carries its own key inside the `.pbx`. The secret screen lists the rules for that mode before you type.

| Mode | Secret | Device secret in the key | TOTP check |
| --- | --- | --- | --- |
| `password` | Passphrase, 12 characters or more | No | No |
| `pin` | PIN, 6 to 12 digits | Yes | No |
| `password+2fa` | Passphrase | No | Yes |
| `pin+2fa` | PIN | Yes | Yes |

### PIN limit

A 6-digit PIN has 1,000,000 values. At 0.5 seconds per Argon2id guess, a single core needs about six days. An attacker can use many cores. PIN modes mix a 32-byte device secret into the key. That secret lives in your config folder with mode `0600`. Files locked in PIN mode decrypt only on a machine that has the device secret, or with the recovery key. If someone copies the whole config folder, the PIN is the only protection left.

### 2FA limit

A TOTP code, RFC 6238, expires every 30 seconds, so it cannot feed key derivation. Pillarbox checks the code after your secret unwraps the TOTP seed. An attacker who has the file key material and your secret, and who replaces the binary, can skip that check. The 2FA modes raise the cost of a stolen secret when people use the stock binary. They do not add key strength.

## Decrypt with stock age

The recovery key is an `age` secret key. With it, stock `age` decrypts Pillarbox output without Pillarbox.

1. Run `pillarbox export-key` and authenticate. Save the output with mode `0600`:

   ```sh
   pillarbox export-key > key.txt && chmod 600 key.txt
   ```

2. Strip the `PBX1` header line, then decrypt the age payload:

   ```sh
   tail -n +2 file.pbx | age -d -i key.txt > file
   ```

## Keys

Every screen shows shortcuts in the footer. Tab or left and right arrows switch the top tabs. Up and down move inside the box. Enter selects. Backspace goes to the parent directory or toggles the focused Settings option. Q quits. Ctrl+C aborts, or copies the 2FA URI on the QR screen. In Settings, A applies.

## Commands

| Command | What it does |
| --- | --- |
| `pillarbox` | Open the home menu on a TTY. Without a TTY, print help, or exit 5 if settings are missing. |
| `pillarbox lock <path> [-o OUT] [--remove-original] [--force]` | Encrypt a file |
| `pillarbox unlock <file.pbx> [-o OUT] [--force]` | Decrypt a `.pbx` file |
| `pillarbox status` | Show key type, auth-encrypt, settings path, and version |
| `pillarbox export-key <file.pbx>` | Print the recovery key of one file after authentication |
| `pillarbox config set auth-encrypt true\|false` | Require the secret before the encrypt file picker. Default is false. |
| `pillarbox config set key-type MODE` | Set the key type used for new files |
| `pillarbox version` | Print the version |

Global flags: `--no-tui`, `--secret-stdin`, `--totp CODE`, `--quiet`. No command accepts a secret as an argument.

Exit codes: 0 success, 1 other error, 2 usage error, 3 authentication failed, 4 integrity failure, 5 keystore missing or invalid.

## License

MIT. See [LICENSE](LICENSE).
