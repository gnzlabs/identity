package certificate

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"github.com/gnzlabs/identity/errors"
)

type Extensible interface {
	Certificate() *x509.Certificate
	Extensions() *map[string]pkix.Extension
}

func parseExtensions(extended Extensible) (extensions *map[string]pkix.Extension, err error) {
	var unhandledExtensions []pkix.Extension
	if extended.Certificate() == nil {
		err = errors.ErrInvalidCert
	} else {
		if extended.Certificate().Extensions != nil {
			unhandledExtensions = append(unhandledExtensions, extended.Certificate().Extensions...)
		}
		if extended.Certificate().ExtraExtensions != nil {
			unhandledExtensions = append(unhandledExtensions, extended.Certificate().ExtraExtensions...)
		}
		extensionMap := make(map[string]pkix.Extension, len(unhandledExtensions))
		for _, extension := range unhandledExtensions {
			oid := extension.Id.String()
			if _, keyExists := extensionMap[oid]; keyExists {
				err = fmt.Errorf(errors.ErrDuplicateExtension.Error(), oid)
				break
			} else {
				extensionMap[oid] = extension
			}
		}
		if err == nil {
			extensions = &extensionMap
		}
	}
	return
}

func findExtensionByOID(cert Extensible, oid asn1.ObjectIdentifier) (extension *pkix.Extension, err error) {
	if cert.Extensions() == nil {
		err = errors.ErrInvalidCert
	} else if value, exists := (*cert.Extensions())[oid.String()]; !exists {
		err = fmt.Errorf(errors.ErrNoSuchExtension.Error(), oid.String())
	} else {
		extension = &value
	}
	return
}
