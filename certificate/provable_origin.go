package certificate

import (
	"crypto/x509"

	"github.com/gnzlabs/identity/certificate/extensions"
	"github.com/gnzlabs/identity/errors"
)

type ProvableOrigin interface {
	Certificate() *x509.Certificate
	ProofOfOrigin() (*x509.Certificate, error)
}

func GetProofOfOrigin(certificate Extensible) (proofOfOrigin *x509.Certificate, err error) {
	if extProofOfOrigin, e := findExtensionByOID(certificate, extensions.OIDProofOfOrigin); e != nil {
		err = e
	} else if extProofOfOrigin.Value == nil {
		err = errors.ErrCertNotFound
	} else {
		proofOfOrigin, err = x509.ParseCertificate(extProofOfOrigin.Value)
	}
	return
}
