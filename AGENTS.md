# AGENTS.md

Working conventions for this repository, taken from section 5 of `prd.md`. Apply them in every change, whether written by a human or an agent.

## Stack (PRD section 5)

| Area | Decision |
| --- | --- |
| Language | Go, latest stable. One static binary, built with `CGO_ENABLED=0`. |
| CLI | Cobra. Commands and exit codes live in `internal/cli`. |
| Interface | Bubble Tea, Bubbles, Huh, Lip Gloss. Compiled into the binary, not Gum. |
| File encryption | `filippo.io/age` streaming format. |
| Key derivation | Argon2id (`golang.org/x/crypto/argon2`). |
| Key wrapping | XChaCha20-Poly1305 (`golang.org/x/crypto/chacha20poly1305`). |
| 2FA | TOTP, RFC 6238 (`github.com/pquerna/otp`). |
| Folders | `archive/tar` streamed into age. |
| Secret input | `golang.org/x/term`, no echo. |
| Release | GoReleaser and GitHub Actions. |

## Secrets never appear in argv, logs or errors

- No command accepts a secret as an argument (PRD section 9). Secrets arrive only through `--secret-stdin` or a no-echo prompt.
- Error messages, logs and panic output must never contain a passphrase, PIN, TOTP code, TOTP seed, device secret or key.
- FR-11: no secret appears in `ps` output, shell history or logs.
- Treat any secret as unprintable at every boundary, including test fixtures and wrapped errors.
