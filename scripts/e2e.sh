#!/usr/bin/env bash
# scripts/e2e.sh, PRD section 13. Builds the pillarbox binary, creates a
# keystore in each of the four modes, locks and unlocks a file, compares
# checksums, and checks exit codes for a wrong secret (3), a tampered file
# (4) and a folder path (2). Exits 0 on success. Portable across Linux and
# macOS (bash 3.2, no GNU-only tools).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

BIN="$WORK/pillarbox"
TOTPCODE="$WORK/totpcode"
MKKS="$WORK/mkkeystore"

# Fixed RFC 6238 test seed (base32 of "12345678901234567890"). Only used with
# the PILLARBOX_E2E_TOTP_SEED test hook so the script can compute a valid code.
TOTP_SEED="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

PASS="correct horse battery staple"
PIN="123456"
WRONG_PASS="wrong horse battery staple"
WRONG_PIN="000000"

say() { printf 'e2e: %s\n' "$*"; }
fail() { printf 'e2e: FAIL: %s\n' "$*" >&2; exit 1; }

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# Run the binary with an isolated config dir so each mode gets a fresh
# keystore. Both HOME and XDG_CONFIG_HOME are set because os.UserConfigDir
# uses XDG_CONFIG_HOME on Linux when it is absolute and $HOME on darwin.
pb_env() {
  local run="$1"; shift
  ( HOME="$run/home" XDG_CONFIG_HOME="$run/home/.config" "$@" )
}

pb() {
  local run="$1"; shift
  pb_env "$run" "$BIN" "$@"
}

# pb_stdin <run> <secret> <args...>: like pb but feeds the secret on stdin.
pb_stdin() {
  local run="$1" secret="$2"; shift 2
  ( printf '%s\n' "$secret" | pb_env "$run" "$BIN" --no-tui --secret-stdin "$@" )
}

say "building pillarbox, totpcode and mkkeystore"
( cd "$ROOT" && CGO_ENABLED=0 go build -o "$BIN" ./cmd/pillarbox )
( cd "$ROOT" && CGO_ENABLED=0 go build -o "$TOTPCODE" ./scripts/totpcode )
( cd "$ROOT" && CGO_ENABLED=0 go build -o "$MKKS" ./scripts/mkkeystore )

# Shared fixture.
FIX="$WORK/fixtures"
mkdir -p "$FIX"
printf 'pillarbox e2e file fixture\nline two\n' > "$FIX/file.txt"
FILE_SUM="$(sha256 "$FIX/file.txt")"

# mode_secret <mode>: the valid secret for a mode.
mode_secret() {
  case "$1" in
    pin|pin+2fa) printf '%s' "$PIN" ;;
    *) printf '%s' "$PASS" ;;
  esac
}

# mode_wrong <mode>: a wrong secret for a mode.
mode_wrong() {
  case "$1" in
    pin|pin+2fa) printf '%s' "$WRONG_PIN" ;;
    *) printf '%s' "$WRONG_PASS" ;;
  esac
}

# mode_has2fa <mode>: prints "yes" for 2FA modes.
mode_has2fa() {
  case "$1" in
    *+2fa) printf 'yes' ;;
    *) printf 'no' ;;
  esac
}

# run_mode <mode>: full happy path plus negative checks for one mode.
run_mode() {
  MODE="$1"
  local run="$WORK/run-$MODE"
  mkdir -p "$run/home" "$run/data"
  local secret wrong extra
  secret="$(mode_secret "$MODE")"
  wrong="$(mode_wrong "$MODE")"
  extra=""
  if [ "$(mode_has2fa "$MODE")" = yes ]; then
    extra="--totp $("$TOTPCODE" "$TOTP_SEED" 0)"
  fi

  # The CLI has no init command anymore; the mkkeystore helper seeds the
  # keystore non-interactively for the e2e run.
  say "mode $MODE: create keystore"
  if [ "$(mode_has2fa "$MODE")" = yes ]; then
    ( printf '%s\n' "$secret" | pb_env "$run" env PILLARBOX_E2E_TOTP_SEED="$TOTP_SEED" \
      "$MKKS" --mode "$MODE" ) >/dev/null
  else
    ( printf '%s\n' "$secret" | pb_env "$run" "$MKKS" --mode "$MODE" ) >/dev/null
  fi

  say "mode $MODE: lock and unlock a file"
  cp "$FIX/file.txt" "$run/data/file.txt"
  if [ "$(mode_has2fa "$MODE")" = yes ]; then
    pb_stdin "$run" "$secret" $extra lock "$run/data/file.txt" >/dev/null
    pb_stdin "$run" "$secret" --totp "$("$TOTPCODE" "$TOTP_SEED" 0)" unlock "$run/data/file.txt.pbx" -o "$run/data/file.out" >/dev/null
  else
    pb_stdin "$run" "$secret" lock "$run/data/file.txt" >/dev/null
    pb_stdin "$run" "$secret" unlock "$run/data/file.txt.pbx" -o "$run/data/file.out" >/dev/null
  fi
  [ "$(sha256 "$run/data/file.out")" = "$FILE_SUM" ] || fail "mode $MODE: file checksum mismatch"

  say "mode $MODE: locking a folder exits 2"
  mkdir -p "$run/data/adir"
  rc=0
  pb_stdin "$run" "$secret" lock "$run/data/adir" >/dev/null 2>&1 || rc=$?
  [ "$rc" -eq 2 ] || fail "mode $MODE: folder lock gave exit $rc, want 2"
  [ ! -e "$run/data/adir.tar.pbx" ] || fail "mode $MODE: folder lock produced output"

  say "mode $MODE: wrong secret exits 3"
  local rc=0
  if [ "$(mode_has2fa "$MODE")" = yes ]; then
    # Offset -1 stays within the accepted +/-1 window and differs from the
    # persisted step of the previous successful unlock.
    pb_stdin "$run" "$wrong" --totp "$("$TOTPCODE" "$TOTP_SEED" -1)" unlock "$run/data/file.txt.pbx" -o "$run/data/should-not-exist" >/dev/null 2>&1 || rc=$?
  else
    pb_stdin "$run" "$wrong" unlock "$run/data/file.txt.pbx" -o "$run/data/should-not-exist" >/dev/null 2>&1 || rc=$?
  fi
  [ "$rc" -eq 3 ] || fail "mode $MODE: wrong secret gave exit $rc, want 3"
  [ ! -e "$run/data/should-not-exist" ] || fail "mode $MODE: partial output after wrong secret"

  say "mode $MODE: tampered file exits 4"
  cp "$run/data/file.txt.pbx" "$run/data/tampered.pbx"
  local f="$run/data/tampered.pbx" off=100 byte new
  byte="$(od -An -tu1 -j "$off" -N 1 "$f" | tr -d ' ')"
  new=$(( (byte + 1) % 256 ))
  printf "$(printf '\\%03o' "$new")" | dd of="$f" bs=1 seek="$off" conv=notrunc 2>/dev/null
  rc=0
  if [ "$(mode_has2fa "$MODE")" = yes ]; then
    # The failed wrong-secret attempt persisted no step, so offset -1 is
    # still acceptable here and auth succeeds, exposing the integrity error.
    pb_stdin "$run" "$secret" --totp "$("$TOTPCODE" "$TOTP_SEED" -1)" unlock "$f" -o "$run/data/should-not-exist-2" >/dev/null 2>&1 || rc=$?
  else
    pb_stdin "$run" "$secret" unlock "$f" -o "$run/data/should-not-exist-2" >/dev/null 2>&1 || rc=$?
  fi
  [ "$rc" -eq 4 ] || fail "mode $MODE: tampered file gave exit $rc, want 4"
  [ ! -e "$run/data/should-not-exist-2" ] || fail "mode $MODE: partial output after tampered file"
}

for m in password pin password+2fa pin+2fa; do
  run_mode "$m"
done

say "all modes passed"
exit 0
