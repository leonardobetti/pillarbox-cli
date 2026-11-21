# Architecture

Interface design for the Pillarbox core. Callers in `internal/cli` and
`internal/tui` depend on the interfaces in `internal/auth`, `internal/keystore`,
and `internal/vault`.

## Model

- Settings (`settings.json`) hold the default key type for new encrypts and the
  auth-encrypt toggle. Changing Settings does not rewrite existing `.pbx` files.
- Every `lock` creates a fresh age identity, wraps it under a KEK derived from
  the secret (and the device secret for PIN modes), and embeds the keystore in
  a `PBX1` header on the `.pbx`.
- PIN modes use one machine-local `device.key`.
- 2FA modes use one install-wide `totp.seed`. The QR is shown once. Every 2FA
  file wraps that same seed under its own KEK. Decrypt still asks for a TOTP
  code after the secret unwraps the seed from that file.

## How callers use the core

### CLI (`--no-tui`)

`lock <path>`

1. Load default mode from Settings (exit 5 if unset).
2. Read the secret. For PIN modes, `DevStore.LoadOrCreate()`.
3. For 2FA modes, load `totp.seed` or generate, verify one code, and save it.
4. Build a per-file keystore with `Initializer.Initialize`.
5. `Vault.Lock` writes the `.pbx` with the key in the PBX1 header.
6. Print the recovery key once (unless `--quiet`).

`unlock <file.pbx>`

1. `Vault.ReadKey` loads the embedded keystore.
2. `Authenticator.Authenticate` with secret and optional TOTP code.
3. Persist `LastTOTPStep` via `Vault.SaveKey` when needed.
4. `Vault.Unlock` (CLI requires `--force` to overwrite).

`status` prints default key type, auth-encrypt, whether shared 2FA and the
device secret exist, the settings path, and the version. It never prints
secrets.

`export-key` authenticates and prints the recovery key for one file.

### TUI

Same core calls. Extra UX:

- First-time key type chooser saves the Settings default and says so.
- Shared 2FA QR only when `totp.seed` is missing.
- After encrypt: acknowledge the recovery key, then keep or remove the original.
- Before decrypt overwrite: confirm when the destination already exists.

## Dependency graph

```
cli, tui → auth, keystore, vault
auth     → keystore
vault    → keystore, filippo.io/age
keystore → stdlib only
```

## Config paths

| Path | Role |
| --- | --- |
| `<config>/pillarbox/settings.json` | Default key type, auth-encrypt |
| `<config>/pillarbox/device.key` | 32-byte PIN device secret |
| `<config>/pillarbox/totp.seed` | 20-byte shared TOTP seed |

## Errors to exit codes

| Condition | Exit |
| --- | --- |
| success | 0 |
| other failure | 1 |
| usage error | 2 |
| wrong secret or TOTP | 3 |
| integrity failure | 4 |
| settings or file key missing or invalid | 5 |
