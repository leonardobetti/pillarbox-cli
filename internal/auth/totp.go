package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"time"

	"github.com/pquerna/otp/totp"
)

// totpPeriod is the RFC 6238 step in seconds, PRD 6.4.
const totpPeriod = 30

type totpImpl struct{}

// NewTOTP returns the RFC 6238 TOTP implementation.
func NewTOTP() TOTP { return totpImpl{} }

func b32(seed []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed)
}

// otpauthURI builds the otpauth:// URI for a seed. It stays compact on
// purpose: the default algorithm, digits and period are implied, and a short
// URI keeps the terminal QR code small enough for an 80x24 screen. The label
// is install-wide because every 2FA file shares this seed.
func otpauthURI(seed []byte) string {
	return "otpauth://totp/Pillarbox:install?secret=" + b32(seed)
}

// OTPAuthURI returns the otpauth:// URI for an existing seed.
func OTPAuthURI(seed []byte) string { return otpauthURI(seed) }

// GenerateSeed returns 20 random bytes and their otpauth:// URI, PRD 7.1
// step 5.
func (totpImpl) GenerateSeed() (seed []byte, uri string, err error) {
	seed = make([]byte, 20)
	if _, err := rand.Read(seed); err != nil {
		return nil, "", err
	}
	return seed, otpauthURI(seed), nil
}

// GenerateSeedFromBase32 builds a seed and its otpauth URI from a base32
// string. It exists for scripts/e2e.sh, which must know the seed to compute a
// valid code; production uses GenerateSeed.
func GenerateSeedFromBase32(s string) (seed []byte, uri string, err error) {
	seed, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err != nil {
		return nil, "", err
	}
	if len(seed) != 20 {
		return nil, "", errors.New("seed must decode to 20 bytes")
	}
	return seed, otpauthURI(seed), nil
}

// Verify accepts the current step and one step either side, rejects a step
// equal to lastStep, PRD 7.4 step 2 and FR-08. Returns the step to persist.
func (totpImpl) Verify(seed []byte, code string, lastStep int64) (ok bool, newStep int64, err error) {
	sec := b32(seed)
	cur := time.Now().Unix() / totpPeriod
	for _, step := range []int64{cur - 1, cur, cur + 1} {
		if step < 0 || step == lastStep {
			continue
		}
		want, err := totp.GenerateCode(sec, time.Unix(step*totpPeriod, 0))
		if err != nil {
			return false, 0, err
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return true, step, nil
		}
	}
	return false, 0, nil
}
