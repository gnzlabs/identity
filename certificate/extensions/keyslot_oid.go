package extensions

import (
	"encoding/asn1"

	"github.com/gnzlabs/keyring"
	"github.com/gnzlabs/keyring/errors"
)

func GetSlotExtensionOID(certificateSlot keyring.KeySlot) (oid asn1.ObjectIdentifier, err error) {
	switch certificateSlot {
	case keyring.SigningKeySlot:
		oid = OIDAuthenticate
	case keyring.AuthenticationKeySlot:
		oid = OIDVerifyAuthentication
	case keyring.EncryptionKeySlot:
		oid = OIDEncrypt
	default:
		err = errors.ErrorInvalidKeySlot
	}
	return
}
