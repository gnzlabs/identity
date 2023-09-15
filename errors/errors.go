package errors

const (
	ErrCertNotFound           CertificateError = "certificate not found"
	ErrDuplicateExtension     CertificateError = "duplicate extension (asn.1 OID: %s)"
	ErrNoSuchExtension        CertificateError = "no such extension (asn.1 OID: %s)"
	ErrInvalidAttestationCert CertificateError = "invalid attestation certificate"
	ErrInvalidCert            CertificateError = "invalid certificate"
	ErrInvalidCertTemplate    CertificateError = "invalid certificate template"
	ErrInvalidCSR             CertificateError = "invalid certificate signing requirest"
)

const (
	ErrKeyExchangeFailed    CryptoError = "key exchange failed"
	ErrInvalidContentLength CryptoError = "invalid content length"
	ErrInvalidPublicKey     CryptoError = "invalid public key"
	ErrUnsupportedAlgorithm CryptoError = "unsupported algorithm"
	ErrUnsupportedSigScheme CryptoError = "unsupported signature scheme"
)
