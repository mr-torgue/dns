package dns

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"

	"github.com/mr-torgue/go-openssl"
)

// toOpenSSLPrivateKey converts a crypto.PrivateKey into an openssl.PrivateKey.
// Keys that are already openssl keys pass through unchanged; standard
// library keys (*rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey) are
// marshalled to DER and reloaded into OpenSSL so that the internal
// OpenSSL primitives can be used regardless of where the key came from.
func toOpenSSLPrivateKey(p crypto.PrivateKey) (openssl.PrivateKey, error) {
	if k, ok := p.(openssl.PrivateKey); ok {
		return k, nil
	}
	var der []byte
	var err error
	switch k := p.(type) {
	case *rsa.PrivateKey:
		der = x509.MarshalPKCS1PrivateKey(k)
	case *ecdsa.PrivateKey:
		der, err = x509.MarshalECPrivateKey(k)
	default:
		der, err = x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return nil, err
		}
	}
	if err != nil {
		return nil, err
	}
	return openssl.LoadPrivateKeyFromDER(der)
}

// toOpenSSLPublicKey converts a crypto.PublicKey into an openssl.PublicKey,
// for keys that are not already openssl keys.
func toOpenSSLPublicKey(p crypto.PublicKey) (openssl.PublicKey, error) {
	if k, ok := p.(openssl.PublicKey); ok {
		return k, nil
	}
	der, err := x509.MarshalPKIXPublicKey(p)
	if err != nil {
		return nil, err
	}
	return openssl.LoadPublicKeyFromDER(der)
}
