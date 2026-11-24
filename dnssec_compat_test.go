package dns

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/mr-torgue/go-openssl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestToOpenSSLPrivateKey Passthrough: an already-openssl key must come
// back as the identical object, without any marshalling round trip.
func TestToOpenSSLPrivateKeyPassthrough(t *testing.T) {
	native, err := openssl.GenerateRSAKey(2048)
	require.Nil(t, err, "err should be nil")

	converted, err := toOpenSSLPrivateKey(native)
	require.Nil(t, err, "err should be nil")

	// the exact same object must be returned
	assert.Equal(t, native, converted, "openssl key should pass through unchanged")
}

// TestToOpenSSLPrivateKeyRSA converts a std-lib RSA key and proves the
// conversion preserved the key material by cross-verification in both
// directions (RSA is deterministic so signatures can be compared bytewise).
func TestToOpenSSLPrivateKeyRSA(t *testing.T) {
	std, err := rsa.GenerateKey(rand.Reader, 2048)
	require.Nil(t, err, "err should be nil")

	converted, err := toOpenSSLPrivateKey(std)
	require.Nil(t, err, "err should be nil")

	hashed := sha256.Sum256([]byte("miek.nl"))

	// sign with the converted (openssl) key, verify with the original
	// std-lib public key
	sig, err := converted.Sign(rand.Reader, hashed[:], crypto.SHA256)
	require.Nil(t, err, "err should be nil")
	assert.Nil(t, rsa.VerifyPKCS1v15(&std.PublicKey, crypto.SHA256, hashed[:], sig),
		"openssl-signed signature should verify with std crypto")

	// sign with the std-lib key, verify with the converted key's derived
	// public key: RSA PKCS1v15 is deterministic so the bytes must match
	stdSig, err := rsa.SignPKCS1v15(rand.Reader, std, crypto.SHA256, hashed[:])
	require.Nil(t, err, "err should be nil")
	assert.Equal(t, stdSig, sig, "same key material must produce the same deterministic RSA signature")
}

// TestToOpenSSLPrivateKeyECDSA converts a std-lib ECDSA key; the signature
// is randomized so both directions are checked via verification.
func TestToOpenSSLPrivateKeyECDSA(t *testing.T) {
	std, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.Nil(t, err, "err should be nil")

	converted, err := toOpenSSLPrivateKey(std)
	require.Nil(t, err, "err should be nil")

	hashed := sha256.Sum256([]byte("miek.nl"))

	// openssl signs -> std verifies
	sig, err := converted.Sign(rand.Reader, hashed[:], crypto.SHA256)
	require.Nil(t, err, "err should be nil")
	assert.True(t, ecdsa.VerifyASN1(&std.PublicKey, hashed[:], sig),
		"openssl-signed signature should verify with std crypto")

	// std signs -> openssl verifies
	stdSig, err := ecdsa.SignASN1(rand.Reader, std, hashed[:])
	require.Nil(t, err, "err should be nil")
	pub := converted.Public().(openssl.PublicKey)
	assert.Nil(t, pub.Verify(hashed[:], stdSig, crypto.SHA256),
		"std-signed signature should verify through OpenSSL")
}

// TestToOpenSSLPrivateKeyED25519 converts a std-lib Ed25519 key; Ed25519
// signs the raw message.
func TestToOpenSSLPrivateKeyED25519(t *testing.T) {
	stdPub, stdPriv, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err, "err should be nil")

	converted, err := toOpenSSLPrivateKey(stdPriv)
	require.Nil(t, err, "err should be nil")

	msg := []byte("miek.nl")

	sig, err := converted.Sign(rand.Reader, msg, nil)
	require.Nil(t, err, "err should be nil")
	assert.True(t, ed25519.Verify(stdPub, msg, sig),
		"openssl-signed signature should verify with std crypto")

	stdSig := ed25519.Sign(stdPriv, msg)
	pub := converted.Public().(openssl.PublicKey)
	assert.Nil(t, pub.Verify(msg, stdSig, nil),
		"std-signed signature should verify through OpenSSL")
}

// TestToOpenSSLPrivateKeyUnsupported checks that keys x509 cannot
// marshal produce a conversion error instead of a panic.
func TestToOpenSSLPrivateKeyUnsupported(t *testing.T) {
	type bogusKey struct{ rsa.PrivateKey }

	_, err := toOpenSSLPrivateKey(bogusKey{})
	assert.NotNil(t, err, "unsupported key type should not convert")

	_, err = toOpenSSLPrivateKey(nil)
	assert.NotNil(t, err, "nil key should not convert")
}

// TestToOpenSSLPublicKey converts std public keys of each family and checks
// that derived OpenSSL public keys verify signatures made by the matching
// private keys.
func TestToOpenSSLPublicKey(t *testing.T) {
	hashed := sha256.Sum256([]byte("miek.nl"))

	t.Run("RSA", func(t *testing.T) {
		std, err := rsa.GenerateKey(rand.Reader, 2048)
		require.Nil(t, err, "err should be nil")
		sig, err := rsa.SignPKCS1v15(rand.Reader, std, crypto.SHA256, hashed[:])
		require.Nil(t, err, "err should be nil")

		pub, err := toOpenSSLPublicKey(&std.PublicKey)
		require.Nil(t, err, "err should be nil")
		assert.Nil(t, pub.Verify(hashed[:], sig, crypto.SHA256),
			"std signature should verify through the converted OpenSSL public key")
	})

	t.Run("ECDSA", func(t *testing.T) {
		std, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.Nil(t, err, "err should be nil")
		sig, err := ecdsa.SignASN1(rand.Reader, std, hashed[:])
		require.Nil(t, err, "err should be nil")

		pub, err := toOpenSSLPublicKey(&std.PublicKey)
		require.Nil(t, err, "err should be nil")
		assert.Nil(t, pub.Verify(hashed[:], sig, crypto.SHA256),
			"std signature should verify through the converted OpenSSL public key")
	})

	t.Run("ED25519", func(t *testing.T) {
		stdPub, stdPriv, err := ed25519.GenerateKey(rand.Reader)
		require.Nil(t, err, "err should be nil")
		msg := []byte("miek.nl")
		sig := ed25519.Sign(stdPriv, msg)

		pub, err := toOpenSSLPublicKey(stdPub)
		require.Nil(t, err, "err should be nil")
		assert.Nil(t, pub.Verify(msg, sig, nil),
			"std signature should verify through the converted OpenSSL public key")
	})

	t.Run("Passthrough", func(t *testing.T) {
		native, err := openssl.GenerateRSAKey(2048)
		require.Nil(t, err, "err should be nil")
		pub, err := toOpenSSLPublicKey(native.Public().(openssl.PublicKey))
		require.Nil(t, err, "err should be nil")
		assert.Equal(t, native.Public().(openssl.PublicKey), pub,
			"openssl public key should pass through unchanged")
	})

	t.Run("Unsupported", func(t *testing.T) {
		_, err := toOpenSSLPublicKey(nil)
		assert.NotNil(t, err, "nil public key should not convert")
	})
}

// TestPrivateKeyStringCrossImplementation proves the BIND private-key file
// output is identical whether the caller hands over a std-lib key or the
// same key as an OpenSSL key.
func TestPrivateKeyStringCrossImplementation(t *testing.T) {
	std, err := rsa.GenerateKey(rand.Reader, 2048)
	require.Nil(t, err, "err should be nil")
	converted, err := toOpenSSLPrivateKey(std)
	require.Nil(t, err, "err should be nil")

	key := new(DNSKEY)
	key.Algorithm = RSASHA256

	assert.Equal(t,
		key.PrivateKeyString(std),
		key.PrivateKeyString(converted),
		"PrivateKeyString must not depend on the key implementation")
}

// TestToOpenSSLPrivateKeySignRRSIG runs the full RRSIG flow with a pure
// std-lib key through the crypto.Signer interface (the drop-in use case).
func TestToOpenSSLPrivateKeySignRRSIG(t *testing.T) {
	std, err := rsa.GenerateKey(rand.Reader, 2048)
	require.Nil(t, err, "err should be nil")

	// build a DNSKEY from the std-lib public key, using the compat layer
	// to convert it and the existing internal helpers to fill the rdata
	opub, err := toOpenSSLPublicKey(&std.PublicKey)
	require.Nil(t, err, "err should be nil")
	E, N, err := openssl.GetParamsRSA(opub)
	require.Nil(t, err, "err should be nil")
	key := new(DNSKEY)
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = RSASHA256
	require.True(t, key.setPublicKeyRSA(E, N), "filling the DNSKEY rdata failed")

	soa := new(SOA)
	soa.Hdr = RR_Header{"miek.nl.", TypeSOA, ClassINET, 14400, 0}
	soa.Ns = "open.nlnetlabs.nl."
	soa.Mbox = "miekg.atoom.net."
	soa.Serial = 1293945905
	soa.Refresh = 14400
	soa.Retry = 3600
	soa.Expire = 604800
	soa.Minttl = 86400

	sig := new(RRSIG)
	sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.TypeCovered = TypeSOA
	sig.Labels = uint8(CountLabel(soa.Hdr.Name))
	sig.OrigTtl = soa.Hdr.Ttl
	sig.Expiration = 1296534305
	sig.Inception = 1293942305
	sig.KeyTag = key.KeyTag()
	sig.SignerName = key.Hdr.Name
	sig.Algorithm = RSASHA256

	require.Nil(t, sig.Sign(std, []RR{soa}), "signing with a std-lib key should work")
	assert.Nil(t, sig.Verify(key, []RR{soa}), "the resulting RRSIG should verify")
}
