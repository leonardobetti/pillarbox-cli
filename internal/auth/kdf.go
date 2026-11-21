package auth

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"

	"github.com/leonardobetti/pillarbox-cli/internal/keystore"
)

// kekInfo is the HKDF info string of PRD 7.1 step 3.
const kekInfo = "pillarbox/kek/v1"

type argon2KDF struct{}

// NewKDF returns the Argon2id + HKDF-SHA256 KDF.
func NewKDF() KDF { return argon2KDF{} }

// DeriveKEK computes ikm = Argon2id(secret, salt, params) and then
// kek = HKDF-SHA256(ikm, salt = deviceSecret or empty, info = pillarbox/kek/v1),
// 32 bytes, PRD 7.1 step 3.
func (argon2KDF) DeriveKEK(secret, salt, deviceSecret []byte, p keystore.Argon2Params) ([]byte, error) {
	ikm := argon2.IDKey(secret, salt, p.Time, p.Memory, p.Threads, 32)
	defer clear(ikm)
	r := hkdf.New(sha256.New, ikm, deviceSecret, []byte(kekInfo))
	kek := make([]byte, 32)
	if _, err := io.ReadFull(r, kek); err != nil {
		clear(kek)
		return nil, err
	}
	return kek, nil
}

// clear zeroes a sensitive buffer where Go allows it, PRD 6.5.
func clear(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
