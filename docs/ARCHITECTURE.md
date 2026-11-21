# ARCHITECTURE

Interface design for the Pillarbox core. This document plus the three
interface files are the whole change: no implementation. Sources: PRD
sections 5 to 9 in `prd.md`.

Goal: one person builds the core implementations (internal/keystore,
internal/auth, internal/vault) while another builds internal/cli and
internal/tui against fakes. cli and tui therefore depend only on the
interfaces declared here, never on concrete core types.

## How callers use the core

### CLI, scripts path (`--no-tui`, PRD 8.3 and 9)

`init --mode M [--force]`

1. `store` = keystore `Store` at `os.UserConfigDir()/pillarbox/keystore.json`
2. if `store.Exists()` and not `--force` → exit 1
3. `secret` = `prompter.ReadSecretTwice()` (or `--secret-stdin`)
4. if mode is `pin` or `pin+2fa` → `deviceSecret` = `deviceStore.LoadOrCreate()` (PRD 6.3)
5. `kek` = `kdf.DeriveKEK(secret, salt, deviceSecret, keystore.DefaultArgon2Params)` (PRD 7.1 step 3)
6. `identity` = `age.GenerateX25519Identity()` (library call, PRD 7.1 step 1)
7. build `ks *keystore.Keystore`; `ks.WrappedIdentity` = `wrapper.Wrap(kek, ks, identitySecretBytes)` (PRD 7.1 step 4)
8. if 2FA mode → `seed, uri` = `totp.GenerateSeed()`; show URI and QR; `code` = `prompter.ReadTOTP()`; `totp.Verify(seed, code, 0)`; `ks.WrappedTOTPSeed` = `wrapper.Wrap(kek, ks, seed)` (PRD 7.1 step 5)
9. `store.Save(ks)` once, at the end; show the recovery key once (PRD 6.6)

`lock <path> [-o OUT] [--remove-original] [--force]`

1. `ks` = `store.Load()`; `ErrNotFound`/`ErrInvalid` → exit 5 (on a TTY, section 8.1 starts onboarding instead)
2. if `ks.Policy.GateEncrypt` → `authenticator.Authenticate(ks, secret, code)`; `ErrAuth` → exit 3 (PRD 7.3 step 1)
3. `vault.Lock(path, ks.Recipient, LockOptions{...})`

`unlock <file.pbx> [-o OUT] [--force]`

1. `ks` = `store.Load()` → exit 5 if missing
2. `secret` = `--secret-stdin` or `prompter.ReadSecret()`; `code` = `--totp` or `prompter.ReadTOTP()`
3. `identityBytes, newStep, err` = `authenticator.Authenticate(ks, secret, code)`; `ErrAuth` → exit 3
4. if 2FA mode → `ks.LastTOTPStep = &newStep`; `store.Save(ks)` (PRD 7.4 step 2)
5. `identity` = `age.ParseIdentities(string(identityBytes))`
6. `vault.Unlock(src, identity, UnlockOptions{...})`; `ErrIntegrity` → exit 4

`status` prints mode, 2FA state, keystore path and version from `store.Load()` and never prints secret material (FR-13). `export-key` authenticates and prints the recovery key (PRD 6.6).

### TUI path (PRD 8.1, 8.2)

Same calls, different `SecretPrompter`: Huh forms instead of `x/term`. The
onboarding screens map one-to-one onto the `init` sequence above, and Esc
writes nothing, so `store.Save` still happens once at the end. The home menu
items call the lock/unlock flows above. Interface tests run under teatest with
a fake `SecretPrompter` and a fake `Vault`.

## Dependency graph

```
cli, tui → auth, keystore, vault
auth     → keystore
vault    → filippo.io/age
keystore → stdlib only
```

No cycles. keystore stays schema-only: it stores the recipient as a string
and never imports age; vault owns all age types and parses the recipient.

## Shapes considered

- **Shape A, capability interfaces (chosen).** Each capability is a small
  interface: `keystore.Store`, `keystore.Wrapper`, `auth.KDF`, `auth.TOTP`,
  `auth.DeviceSecretStore`, `auth.SecretPrompter`, `auth.Authenticator`,
  `vault.Vault`. Callers compose exactly what a flow needs. Every piece of
  state has one owner (Store owns keystore.json, DeviceSecretStore owns
  device.key, Vault owns output files) and a fake is a single-method struct.
- **Shape B, one facade per package** (`keystore.Service`, `auth.Service`,
  `vault.Service`). Fewer types, but every fake must stub the whole facade,
  state ownership blurs (auth would need the Store inside), and callers must
  know more of the core to wire one flow. Rejected.

## Interfaces

### internal/keystore/keystore.go

| Name | Kind | Contract |
| --- | --- | --- |
| `Mode` | string type | `password`, `pin`, `password+2fa`, `pin+2fa`; persisted values, stable (PRD 6.2) |
| `Argon2Params`, `DefaultArgon2Params` | struct, var | t=3, m=64 MiB, p=4 (PRD 7.1 step 3) |
| `WrappedKey` | struct | nonce + ciphertext (PRD 7.2) |
| `Policy` | struct | `GateEncrypt` (PRD 7.2) |
| `Keystore` | struct | the keystore.json schema (PRD 7.2) |
| `ErrNotFound`, `ErrInvalid` | sentinels | map to exit 5 |
| `Store` | interface | `Path/Exists/Load/Save`; only writer; atomic temp+fsync+rename, mode 0600 (PRD 7.1 step 6) |
| `Wrapper` | interface | `Wrap/Unwrap` under a KEK, XChaCha20-Poly1305, AAD = version+mode+recipient (PRD 7.1 step 4) |

### internal/auth/auth.go

| Name | Kind | Contract |
| --- | --- | --- |
| `ErrAuth` | sentinel | the only auth error; identical for wrong secret and wrong code (PRD 7.4 step 1, FR-07) |
| `SecretPrompter` | interface | `ReadSecret/ReadSecretTwice/ReadTOTP`; no-echo, never in argv/logs/errors |
| `KDF` | interface | `DeriveKEK`: Argon2id then HKDF-SHA256, info `pillarbox/kek/v1` (PRD 7.1 step 3) |
| `DeviceSecretStore` | interface | `LoadOrCreate`: 32 bytes, mode 0600 (PRD 6.3) |
| `TOTP` | interface | `GenerateSeed` + `Verify(seed, code, lastStep)`: current step ±1, reject replay (PRD 7.4 step 2, FR-08) |
| `Authenticator` | interface | `Authenticate(ks, secret, code)` → identity bytes + TOTP step; the one unlock call for cli and tui |

### internal/vault/vault.go

| Name | Kind | Contract |
| --- | --- | --- |
| `ErrIntegrity` | sentinel | tampered .pbx or unsafe archive entry; partial output removed; maps to exit 4 |
| `LockOptions`, `UnlockOptions` | structs | the lock/unlock flags (PRD 9) |
| `Vault` | interface | `Lock(src, recipient, opts)` and `Unlock(src, identity, opts)`: age streaming, tar for folders, temp+fsync+rename mode 0600, no partial output (PRD 7.3, 7.4) |

## Errors to exit codes (PRD 9)

| Condition | Error | Exit |
| --- | --- | --- |
| success | — | 0 |
| any other failure | — | 1 |
| usage error | cobra | 2 |
| wrong secret or wrong TOTP | `auth.ErrAuth` | 3 |
| tampered .pbx, unsafe archive entry | `vault.ErrIntegrity` | 4 |
| keystore missing or invalid | `keystore.ErrNotFound`, `keystore.ErrInvalid` | 5 |

## Invariants every implementation must keep

- Secrets never appear in argv, logs or errors (AGENTS.md). Prompts return
  `[]byte`; error values carry no secret material; `ErrAuth` has a fixed
  message.
- `keystore.Store` is the only writer of keystore.json; saves are atomic
  (temp file, fsync, rename) with mode 0600 (PRD 7.1 step 6).
- device.key is 32 random bytes, mode 0600 (PRD 6.3).
- Vault writes outputs as temp file in the target directory, mode 0600,
  fsync, rename; any failure leaves no partial output (PRD 7.3 step 3,
  7.4 step 4).
- A failed unwrap never says which factor failed (PRD 7.4 step 1).
- TOTP accepts the current step and one either side, rejects a reused step
  (PRD 7.4 step 2).
- Extraction rejects `..`, absolute paths and symlinks resolving outside the
  target (PRD 7.4 step 3).
- No network calls, no telemetry (FR-14).

## Fakes for parallel work

cli and tui tests define their own fakes implementing the interfaces above:
`fakeStore`, `fakeWrapper`, `fakeKDF`, `fakeTOTP`, `fakeDeviceSecret`,
`fakePrompter`, `fakeAuthenticator`, `fakeVault`. No core implementation is
needed to build or test cli and tui.

## Not in this change

Implementations of the interfaces above, the internal/archive interface
(vault's tar path checks, PRD section 12), the TUI models, and copying
`prd.md` to `docs/PRD.md`.
