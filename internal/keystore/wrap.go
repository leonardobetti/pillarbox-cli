package keystore

import (
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

type xWrapper struct{}

// NewWrapper returns the XChaCha20-Poly1305 Wrapper of PRD 7.1 steps 4-5.
func NewWrapper() Wrapper { return xWrapper{} }

// aad binds a wrapped value to the keystore version, mode and recipient, PRD
// 7.1 step 4, so a wrapped value cannot be replayed across keystores.
func aad(ks *Keystore) []byte {
	return []byte(fmt.Sprintf("pillarbox/keystore/v%d/%s/%s", ks.Version, ks.Mode, ks.Recipient))
}

func (xWrapper) Wrap(kek []byte, ks *Keystore, plaintext []byte) (WrappedKey, error) {
	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return WrappedKey{}, err
	}
	nonce := make([]byte, aead.NonceSize()) // 24 bytes, PRD 7.1 step 4
	if _, err := rand.Read(nonce); err != nil {
		return WrappedKey{}, err
	}
	ct := aead.Seal(nil, nonce, plaintext, aad(ks))
	return WrappedKey{Nonce: nonce, Ciphertext: ct}, nil
}

// Unwrap returns a generic error on any failure. Callers must treat it as an
// authentication failure and must not report which factor failed, PRD 7.4
// step 1.
func (xWrapper) Unwrap(kek []byte, ks *Keystore, w WrappedKey) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return nil, err
	}
	if len(w.Nonce) != aead.NonceSize() {
		return nil, errors.New("bad nonce length")
	}
	pt, err := aead.Open(nil, w.Nonce, w.Ciphertext, aad(ks))
	if err != nil {
		return nil, errors.New("unwrap failed")
	}
	return pt, nil
}
