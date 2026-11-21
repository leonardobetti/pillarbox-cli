package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"

	"github.com/leonardobetti/pillarbox-cli/internal/keystore"
)

// fastParams keep tests quick; Argon2id parameters live in the keystore so
// tests may lower them, PRD 7.2.
var fastParams = keystore.Argon2Params{Time: 1, Memory: 1024, Threads: 1}

var allModes = []keystore.Mode{
	keystore.ModePassword,
	keystore.ModePIN,
	keystore.ModePassword2FA,
	keystore.ModePIN2FA,
}

type fixture struct {
	ks           *keystore.Keystore
	secret       []byte
	seed         []byte
	identity     []byte
	store        keystore.Store
	auth         Authenticator
	devStore     DeviceSecretStore
	keystorePath string
}

func newFixture(t *testing.T, mode keystore.Mode) *fixture {
	t.Helper()
	dir := t.TempDir()

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	identity := []byte(id.String())
	recipient := id.Recipient().String()

	secret := []byte("correct horse battery staple")
	if mode == keystore.ModePIN || mode == keystore.ModePIN2FA {
		secret = []byte("123456")
	}

	devStore := NewDeviceSecretStore(filepath.Join(dir, "device.key"))
	var deviceSecret []byte
	if mode.HasDeviceSecret() {
		var err error
		deviceSecret, _, err = devStore.LoadOrCreate()
		if err != nil {
			t.Fatalf("LoadOrCreate: %v", err)
		}
	}

	var seed []byte
	if mode.Has2FA() {
		seed = make([]byte, 20)
		if _, err := rand.Read(seed); err != nil {
			t.Fatal(err)
		}
	}

	ks, err := NewInitializer(NewKDF(), keystore.NewWrapper()).Initialize(mode, recipient, identity, secret, deviceSecret, seed, fastParams)
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	keystorePath := filepath.Join(dir, "keystore.json")
	store := keystore.NewStore(keystorePath)
	if err := store.Save(ks); err != nil {
		t.Fatalf("Save: %v", err)
	}

	return &fixture{
		ks:           ks,
		secret:       secret,
		seed:         seed,
		identity:     identity,
		store:        store,
		auth:         NewAuthenticator(NewKDF(), keystore.NewWrapper(), devStore, NewTOTP()),
		devStore:     devStore,
		keystorePath: keystorePath,
	}
}

func codeForStep(t *testing.T, seed []byte, step int64) string {
	t.Helper()
	sec := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed)
	code, err := totp.GenerateCode(sec, time.Unix(step*30, 0))
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	return code
}

func curStep() int64 { return time.Now().Unix() / 30 }

// wrongCode returns a 6-digit code outside the accepted window that differs
// from every code in the window.
func wrongCode(t *testing.T, seed []byte) string {
	t.Helper()
	cur := curStep()
	inWindow := map[string]bool{}
	for _, s := range []int64{cur - 1, cur, cur + 1} {
		inWindow[codeForStep(t, seed, s)] = true
	}
	for _, c := range []string{"000000", "111111", "999999", "424242"} {
		if !inWindow[c] {
			return c
		}
	}
	t.Fatal("could not find a code outside the window")
	return ""
}

func TestAuthenticateAllModesRightSecret(t *testing.T) {
	for _, mode := range allModes {
		t.Run(string(mode), func(t *testing.T) {
			f := newFixture(t, mode)
			code := ""
			if mode.Has2FA() {
				code = codeForStep(t, f.seed, curStep())
			}
			got, _, err := f.auth.Authenticate(f.ks, f.secret, code)
			if err != nil {
				t.Fatalf("Authenticate with right secret: %v", err)
			}
			if string(got) != string(f.identity) {
				t.Fatal("unwrapped identity differs from the original")
			}
		})
	}
}

func TestAuthenticateAllModesWrongSecret(t *testing.T) {
	for _, mode := range allModes {
		t.Run(string(mode), func(t *testing.T) {
			f := newFixture(t, mode)
			code := ""
			if mode.Has2FA() {
				code = codeForStep(t, f.seed, curStep())
			}
			_, _, err := f.auth.Authenticate(f.ks, []byte("wrong secret"), code)
			if !errors.Is(err, ErrAuth) {
				t.Fatalf("wrong secret: err = %v, want ErrAuth", err)
			}
			if err != nil && err.Error() != ErrAuth.Error() {
				t.Fatal("error message differs from the fixed ErrAuth message")
			}
		})
	}
}

func TestAuthenticateWrongTOTPCode(t *testing.T) {
	for _, mode := range []keystore.Mode{keystore.ModePassword2FA, keystore.ModePIN2FA} {
		t.Run(string(mode), func(t *testing.T) {
			f := newFixture(t, mode)
			_, _, err := f.auth.Authenticate(f.ks, f.secret, wrongCode(t, f.seed))
			if !errors.Is(err, ErrAuth) {
				t.Fatalf("wrong TOTP: err = %v, want ErrAuth", err)
			}
		})
	}
}

func TestAuthenticateReusedTOTPStep(t *testing.T) {
	for _, mode := range []keystore.Mode{keystore.ModePassword2FA, keystore.ModePIN2FA} {
		t.Run(string(mode), func(t *testing.T) {
			f := newFixture(t, mode)
			code := codeForStep(t, f.seed, curStep())

			_, newStep, err := f.auth.Authenticate(f.ks, f.secret, code)
			if err != nil {
				t.Fatalf("first use: %v", err)
			}
			// Persist the step as PRD 7.4 step 2 says, then replay the code.
			f.ks.LastTOTPStep = &newStep
			_, _, err = f.auth.Authenticate(f.ks, f.secret, code)
			if !errors.Is(err, ErrAuth) {
				t.Fatalf("reused TOTP step: err = %v, want ErrAuth", err)
			}
			// A neighboring step is still accepted, FR-08.
			prev := codeForStep(t, f.seed, newStep-1)
			if _, _, err := f.auth.Authenticate(f.ks, f.secret, prev); err != nil {
				t.Fatalf("previous step rejected: %v", err)
			}
		})
	}
}

func TestAuthenticateTamperedKeystore(t *testing.T) {
	for _, mode := range allModes {
		t.Run(string(mode), func(t *testing.T) {
			f := newFixture(t, mode)
			code := ""
			if mode.Has2FA() {
				code = codeForStep(t, f.seed, curStep())
			}

			// Flip one byte of the wrapped identity, persist, reload.
			bad := *f.ks
			ct := append([]byte{}, f.ks.WrappedIdentity.Ciphertext...)
			ct[0] ^= 0x01
			bad.WrappedIdentity.Ciphertext = ct
			if err := f.store.Save(&bad); err != nil {
				t.Fatalf("Save tampered: %v", err)
			}
			loaded, err := f.store.Load()
			if err != nil {
				t.Fatalf("Load tampered: %v", err)
			}
			_, _, err = f.auth.Authenticate(loaded, f.secret, code)
			if !errors.Is(err, ErrAuth) {
				t.Fatalf("tampered keystore: err = %v, want ErrAuth", err)
			}
		})
	}
}

func TestLoadCorruptedKeystoreFile(t *testing.T) {
	f := newFixture(t, keystore.ModePassword)
	if err := os.WriteFile(f.keystorePath, []byte("{corrupted"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := f.store.Load()
	if !errors.Is(err, keystore.ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
}

func TestKeystoreFileContainsNoSecrets(t *testing.T) {
	f := newFixture(t, keystore.ModePIN2FA)
	data, err := os.ReadFile(f.keystorePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range [][]byte{f.identity, f.secret, f.seed} {
		if bytes.Contains(data, leak) {
			t.Fatal("keystore.json contains secret material")
		}
	}
}

func TestPINModeWithoutDeviceSecretFails(t *testing.T) {
	f := newFixture(t, keystore.ModePIN)
	// Point the authenticator at a device store whose file was removed.
	if err := os.Remove(filepath.Join(filepath.Dir(f.keystorePath), "device.key")); err != nil {
		t.Fatal(err)
	}
	_, _, err := f.auth.Authenticate(f.ks, f.secret, "")
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("PIN mode without device secret: err = %v, want ErrAuth", err)
	}
}

func TestTOTPVerifyWindow(t *testing.T) {
	seed := make([]byte, 20)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	cur := curStep()
	tr := NewTOTP()

	for _, step := range []int64{cur - 1, cur, cur + 1} {
		ok, newStep, err := tr.Verify(seed, codeForStep(t, seed, step), -1)
		if err != nil || !ok || newStep != step {
			t.Fatalf("step %d: ok=%v newStep=%d err=%v", step, ok, newStep, err)
		}
	}
	ok, _, err := tr.Verify(seed, codeForStep(t, seed, cur+2), -1)
	if err != nil || ok {
		t.Fatalf("step cur+2 accepted: ok=%v err=%v", ok, err)
	}
	// Replay: lastStep == cur rejects the code for cur.
	ok, _, err = tr.Verify(seed, codeForStep(t, seed, cur), cur)
	if err != nil || ok {
		t.Fatalf("replayed step accepted: ok=%v err=%v", ok, err)
	}
}

func TestGenerateSeed(t *testing.T) {
	seed, uri, err := NewTOTP().GenerateSeed()
	if err != nil {
		t.Fatal(err)
	}
	if len(seed) != 20 {
		t.Fatalf("seed len = %d, want 20", len(seed))
	}
	if !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Fatalf("uri = %q, want otpauth:// prefix", uri)
	}
}

func TestDeviceSecretStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pillarbox", "device.key")
	d := NewDeviceSecretStore(path)

	if _, err := d.Load(); err == nil {
		t.Fatal("Load before create succeeded")
	}
	s1, created, err := d.LoadOrCreate()
	if err != nil || !created || len(s1) != 32 {
		t.Fatalf("LoadOrCreate: created=%v len=%d err=%v", created, len(s1), err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("device.key mode = %o, want 600", info.Mode().Perm())
	}
	s2, created, err := d.LoadOrCreate()
	if err != nil || created || !bytes.Equal(s1, s2) {
		t.Fatalf("second LoadOrCreate: created=%v equal=%v err=%v", created, bytes.Equal(s1, s2), err)
	}
}

func TestDeriveKEKMatchesReference(t *testing.T) {
	secret := []byte("secret")
	salt := bytes.Repeat([]byte{0x03}, 16)
	dev := bytes.Repeat([]byte{0x04}, 32)
	p := fastParams

	got, err := NewKDF().DeriveKEK(secret, salt, dev, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 32 {
		t.Fatalf("kek len = %d, want 32", len(got))
	}

	// Reference computation straight from the PRD formula, 7.1 step 3.
	ikm := argon2.IDKey(secret, salt, p.Time, p.Memory, p.Threads, 32)
	r := hkdf.New(sha256.New, ikm, dev, []byte("pillarbox/kek/v1"))
	want := make([]byte, 32)
	if _, err := io.ReadFull(r, want); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("DeriveKEK does not match the reference Argon2id+HKDF computation")
	}

	other, err := NewKDF().DeriveKEK([]byte("other"), salt, dev, p)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got, other) {
		t.Fatal("different secrets produced the same KEK")
	}
}

func TestDeriveKEKDefaultParams(t *testing.T) {
	start := time.Now()
	kek, err := NewKDF().DeriveKEK([]byte("secret"), bytes.Repeat([]byte{0x03}, 16), nil, keystore.DefaultArgon2Params)
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	t.Logf("default Argon2id params took %s", elapsed)
	if len(kek) != 32 {
		t.Fatalf("kek len = %d", len(kek))
	}
	if elapsed > 5*time.Second {
		t.Fatalf("derivation took %s, PRD NFR budget is 0.3-1.5s on a 2018 laptop", elapsed)
	}
}
