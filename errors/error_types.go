package errors

type CertificateError string

func (e CertificateError) Error() string {
	return string(e)
}

type CryptoError string

func (e CryptoError) Error() string {
	return string(e)
}
