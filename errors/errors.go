package errors

const (
	ErrDuplicateExtension CertificateError = "duplicate extension (asn.1 OID: %s)"
	ErrNoSuchExtension    CertificateError = "no such extension (asn.1 OID: %s)"
	ErrInvalidCertificate CertificateError = "invalid certificate"
)

const (
	ErrKeyExchangeFailed CryptoError = "key exchange failed"
)
