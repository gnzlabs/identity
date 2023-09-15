package cipher

import (
	"crypto"
	"io"

	"github.com/gnzlabs/identity/errors"
)

// Implement crypto.Signer for identity/cipher.Aead
func (key *Aead) Public() crypto.PublicKey {
	return key.hsm.Public()
}

// Implement crypto.Signer for identity/cipher.Aead
func (key *Aead) Sign(rand io.Reader, ciphertext []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if opts != nil {
		err = errors.ErrUnsupportedSigScheme
	} else if ciphertext == nil || len(ciphertext) <= key.Overhead() {
		err = errors.ErrInvalidContentLength
	} else {
		signature, err = key.hsm.Sign(rand, ciphertext[len(ciphertext)-key.Overhead():], opts)
	}
	return
}

func (key *Aead) VerifyAuthentication(ciphertext, signature []byte) (verified bool) {
	if ciphertext != nil && len(ciphertext) > key.Overhead() {
		verified = key.hsm.VerifyAuthentication(ciphertext[len(ciphertext)-key.Overhead():], signature)
	}
	return
}
