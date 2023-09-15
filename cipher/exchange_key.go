package cipher

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"

	"github.com/aead/ecdh"
	"github.com/gnzlabs/identity/errors"
)

func getEphemeralKeyExchange(pubkey crypto.PublicKey, alg x509.PublicKeyAlgorithm) (kex ecdh.KeyExchange, err error) {
	switch alg {
	case x509.ECDSA:
		if key, ok := pubkey.([]byte); !ok {
			err = errors.ErrInvalidPublicKey
		} else if len(key) == 32 {
			kex = ecdh.Generic(elliptic.P256())
		} else if len(key) == 48 {
			kex = ecdh.Generic(elliptic.P384())
		} else {
			err = errors.ErrUnsupportedAlgorithm
		}
	case x509.Ed25519:
		kex = ecdh.X25519()
	default:
		err = errors.ErrUnsupportedAlgorithm
	}
	return
}

func exchangeKey(pubkey crypto.PublicKey, alg x509.PublicKeyAlgorithm) (symmetric []byte, ephemeral crypto.PublicKey, err error) {
	if kex, e := getEphemeralKeyExchange(pubkey, alg); e != nil {
		err = e
	} else if private, public, e := kex.GenerateKey(rand.Reader); e != nil {
		err = e
	} else if err = kex.Check(pubkey); err == nil {
		symmetric = kex.ComputeSecret(private, pubkey)
		ephemeral = public
	}
	return
}
