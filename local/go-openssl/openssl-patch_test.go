package openssl

import (
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetParamsRSA tests if it can retrieve (E, N) for an RSA cipher.
func TestGetParamsRSA(t *testing.T) {
	// test-case 1
	bitlen := 2048
	expectedValue := big.NewInt(3)
	priv, err := GenerateRSAKey(bitlen)
	e, N, err := GetParamsRSA(priv)
	require.Nil(t, err, "error should be nil")
	require.NotNil(t, e, "e should not be nil")
	require.NotNil(t, N, "N should not be nil")
	assert.Equal(t, expectedValue, e, "e should match")
	// should hold with a very large probability
	assert.LessOrEqual(t, N.BitLen(), bitlen, "N.BitLen() should be <= bitlen")
	assert.Greater(t, N.BitLen(), bitlen-64, "N.BitLen() should be > bitlen-64")

	// test-case 2
	bitlen = 4096
	expectedValue = big.NewInt(132589)
	priv, err = GenerateRSAKeyWithExponent(bitlen, 132589)
	e, N, err = GetParamsRSA(priv)
	require.Nil(t, err, "error should be nil")
	require.NotNil(t, e, "e should not be nil")
	require.NotNil(t, N, "N should not be nil")
	assert.Equal(t, expectedValue, e, "e should match")
	// should hold with a very large probability
	assert.LessOrEqual(t, N.BitLen(), bitlen, "N.BitLen() should be <= bitlen")
	assert.Greater(t, N.BitLen(), bitlen-64, "N.BitLen() should be > bitlen-64")

	// test-case 3
	priv, err = GenerateED25519Key()
	e, N, err = GetParamsRSA(priv)
	assert.NotNil(t, err, "error should not be nil")
	assert.Nil(t, e, "e should be nil")
	assert.Nil(t, N, "N should be nil")

	// test-case 4: load RSA key
	expectedValueE := big.NewInt(65537)
	expectedValueN := new(big.Int)
	expectedValueN.SetString(`A4B1CA9DB93C02C092A09F4C25763C27A733579E6102C48AE618A2338C94CD234C993374129DDA31502925BBC5DC777FC97823E58DF9ADFC7C095FDCCF29B6E92899704A5805E7FBF9EB52224B55B4334EB6B8D06A6ECE4915168E311D9DFAAEEB1B13F76F9327D7EDBDB82B25FE19603654B767F1780251E3164E7DE739E62C6853262DA5868C6A09F73393F4C351CFBFD970A4534FDDC21799FD4C5228C49C56AD7736743C71C0A6FA08D90E885ED0CED366F83C30D1BE3AA06AB2F9236ADC0B63F183788716494E803C54CCD789646A823632CFE94164C727C56DCB4C84EE098A3005C2B14F8483AD74FCFA6C1599A6C5EA539401C666E00874FEA16DB9FD`, 16)
	bytes, err := os.ReadFile("testdata/keys/RSA2048-public_key.der")
	require.Nil(t, err, "error should be nil")
	require.NotNil(t, bytes, "bytes should not be nil")
	pub, err := LoadPublicKeyFromDER(bytes)
	require.Nil(t, err, "error should be nil")
	require.NotNil(t, pub, "pub should not be nil")
	e, N, err = GetParamsRSA(pub)
	require.Nil(t, err, "error should be nil")
	require.NotNil(t, e, "e should not be nil")
	require.NotNil(t, N, "N should not be nil")
	assert.Equal(t, expectedValueE, e, "e should be equal to expected value")
	assert.Equal(t, expectedValueN, N, "N should be equal to expected value")

}

// TestGetECDSAKeys tests if it can retrieve public and private keys parameters
// from a given ECDSA key.
func TestGetECDSAKeys(t *testing.T) {
	// test-case 1
	priv, err := GenerateECKey(Prime256v1)
	X, Y, err := GetECDSAPublicKey(priv)
	require.Nil(t, err, "error should be nil")
	require.NotNil(t, X, "X should not be nil")
	require.NotNil(t, Y, "Y should not be nil")
	// should hold with a very large probability
	assert.LessOrEqual(t, X.BitLen(), 256, "N.BitLen() should be <= 256")
	assert.Greater(t, X.BitLen(), 128, "N.BitLen() should be > 128")
	assert.LessOrEqual(t, Y.BitLen(), 256, "N.BitLen() should be <= 256")
	assert.Greater(t, Y.BitLen(), 128, "N.BitLen() should be > 128")

	// test-case 2
	priv, err = GenerateECKey(Secp384r1)
	X, Y, err = GetECDSAPublicKey(priv)
	require.Nil(t, err, "error should be nil")
	require.NotNil(t, X, "X should not be nil")
	require.NotNil(t, Y, "Y should not be nil")
	// should hold with a very large probability
	assert.LessOrEqual(t, X.BitLen(), 384, "N.BitLen() should be <= 384")
	assert.Greater(t, X.BitLen(), 256, "N.BitLen() should be > 256")
	assert.LessOrEqual(t, Y.BitLen(), 384, "N.BitLen() should be <= 384")
	assert.Greater(t, Y.BitLen(), 256, "N.BitLen() should be > 256")

	// test-case 3
	priv, err = GenerateECKey(Secp521r1)
	X, Y, err = GetECDSAPublicKey(priv)
	require.Nil(t, err, "error should be nil")
	require.NotNil(t, X, "X should not be nil")
	require.NotNil(t, Y, "Y should not be nil")
	// should hold with a very large probability
	assert.LessOrEqual(t, X.BitLen(), 521, "N.BitLen() should be <= 521")
	assert.Greater(t, X.BitLen(), 384, "N.BitLen() should be > 384")
	assert.LessOrEqual(t, Y.BitLen(), 521, "N.BitLen() should be <= 521")
	assert.Greater(t, Y.BitLen(), 384, "N.BitLen() should be > 384")

	// test-case 4: negative
	priv, err = GenerateED25519Key()
	X, Y, err = GetECDSAPublicKey(priv)
	assert.NotNil(t, err, "error should not be nil")
	assert.Nil(t, X, "X should be nil")
	assert.Nil(t, Y, "Y should be nil")

	// test-case 5: load EC key
	bytes, err := os.ReadFile("testdata/keys/ECDSA-public_key.der")
	require.Nil(t, err, "error should be nil")
	require.NotNil(t, bytes, "bytes should not be nil")
	pub, err := LoadPublicKeyFromDER(bytes)
	require.Nil(t, err, "error should be nil")
	require.NotNil(t, pub, "pub should not be nil")
	X, Y, err = GetECDSAPublicKey(pub)
	require.Nil(t, err, "error should be nil")
	expectedBytesX := []byte{0x8c, 0x26, 0x1c, 0x82, 0xea, 0x21, 0x64, 0xe5, 0xcb, 0x60, 0xdb, 0xc9, 0x02, 0xf7, 0xbe, 0x5b, 0x8a, 0xbe, 0xff, 0x34, 0x41, 0x98, 0xcf, 0x0d, 0x34, 0x07, 0x6a, 0x4e, 0x9a, 0xbe, 0x63, 0x9b}
	expectedBytesY := []byte{0xbe, 0x0b, 0x6d, 0x30, 0x8f, 0x7b, 0x91, 0xcc, 0x1e, 0x39, 0xd1, 0x7f, 0xe6, 0x1a, 0xc3, 0x69, 0x56, 0x39, 0x5a, 0xc7, 0x1f, 0xa2, 0x9f, 0x14, 0xd4, 0x47, 0x3e, 0xdd, 0x99, 0xf8, 0x42, 0xb8}
	expectedX := new(big.Int).SetBytes(expectedBytesX)
	expectedY := new(big.Int).SetBytes(expectedBytesY)
	assert.Equal(t, expectedX, X, "X should match expected value")
	assert.Equal(t, expectedY, Y, "Y should match expected value")

	// test-case 6: load private key
	bytes, err = os.ReadFile("testdata/keys/ECDSA-private_key.der")
	require.Nil(t, err, "error should be nil")
	require.NotNil(t, bytes, "bytes should not be nil")
	priv, err = LoadPrivateKeyFromDER(bytes)
	require.Nil(t, err, "error should be nil")
	require.NotNil(t, priv, "priv should not be nil")
	X, Y, err = GetECDSAPublicKey(priv)
	require.Nil(t, err, "error should be nil")
	expectedX = new(big.Int).SetBytes(expectedBytesX)
	expectedY = new(big.Int).SetBytes(expectedBytesY)
	assert.Equal(t, expectedX, X, "X should match expected value")
	assert.Equal(t, expectedY, Y, "Y should match expected value")
	privkey, err := GetECDSAPrivateKey(priv)
	require.Nil(t, err, "error should be nil")
	require.NotNil(t, privkey, "privkey should not be nil")
	expectedBytesPrivkey := []byte{0xa3, 0x2e, 0x3e, 0x14, 0xf3, 0xc1, 0x73, 0xe6, 0xf9, 0xc3, 0x70, 0xde, 0xe5, 0x70, 0x4c, 0xa9, 0x9a, 0x11, 0xd6, 0x5a, 0x1e, 0x8d, 0xef, 0x7a, 0x5f, 0x91, 0x6a, 0x8e, 0xf2, 0xe9, 0xd0, 0x8d}
	expectedPrivkey := new(big.Int).SetBytes(expectedBytesPrivkey)
	assert.Equal(t, expectedPrivkey, privkey, "privkey should match expected value")

}

// TestGetRawKey tests if the raw key is returned.
func TestGetRawKey(t *testing.T) {
	// test-case 1
	priv, err := GenerateED25519Key()
	bytes, err := GetRawPublicKey(priv)
	assert.Nil(t, err, "error should be nil")
	assert.Greater(t, len(bytes), 0, "bytes should be larger than 0")

	// test-case 2: ECDSA
	// According to docs not supported:
	// This function only works for algorithms that support raw public keys. Currently this is: EVP_PKEY_X25519, EVP_PKEY_ED25519, EVP_PKEY_X448 or EVP_PKEY_ED448.
	priv, err = GenerateECKey(Prime256v1)
	bytes, err = GetRawPublicKey(priv)
	assert.NotNil(t, err, "error should not be nil")
	assert.Nil(t, bytes, "bytes should be nil")

	// test-case 3: load RSA key (not supported)
	bytes, err = os.ReadFile("testdata/keys/RSA2048-public_key.der")
	require.Nil(t, err, "error should be nil")
	require.NotNil(t, bytes, "bytes should not be nil")
	pub, err := LoadPublicKeyFromDER(bytes)
	require.Nil(t, err, "error should be nil")
	require.NotNil(t, pub, "pub should not be nil")
	bytes, err = GetRawPublicKey(pub)
	require.NotNil(t, err, "error should not be nil")
	require.Nil(t, bytes, "bytes should be nil")

	// test-case 4: load EC key (not supported)
	bytes, err = os.ReadFile("testdata/keys/ECDSA-public_key.der")
	require.Nil(t, err, "error should be nil")
	require.NotNil(t, bytes, "bytes should not be nil")
	pub, err = LoadPublicKeyFromDER(bytes)
	require.Nil(t, err, "error should be nil")
	require.NotNil(t, pub, "pub should not be nil")
	bytes, err = GetRawPublicKey(pub)
	require.NotNil(t, err, "error should not be nil")
	require.Nil(t, bytes, "bytes should be nil")

	// test-case 5: load EDDSA
	bytes, err = os.ReadFile("testdata/keys/ED25519-public_key.der")
	require.Nil(t, err, "error should be nil")
	require.NotNil(t, bytes, "bytes should not be nil")
	pub, err = LoadPublicKeyFromDER(bytes)
	require.Nil(t, err, "error should be nil")
	require.NotNil(t, pub, "pub should not be nil")
	bytes, err = GetRawPublicKey(pub)
	require.Nil(t, err, "error should be nil")
	require.NotNil(t, bytes, "bytes should not be nil")
	rawkeybytes := []byte{0x77, 0xe7, 0x2a, 0x2a, 0xb9, 0x60, 0x6d, 0xf0, 0xec, 0x6e, 0x71, 0x57, 0x9e, 0xda, 0x58, 0xe6, 0xdf, 0x08, 0x1a, 0xc3, 0xab, 0xf8, 0x08, 0xe4, 0x58, 0xb4, 0x04, 0x26, 0x6b, 0x1d, 0x04, 0x26}
	assert.Equal(t, len(rawkeybytes), len(bytes), "raw key length did not match")
	assert.Equal(t, rawkeybytes, bytes, "raw key did not match")

	// test-case 6: load FALCON512
	bytes, err = os.ReadFile("testdata/keys/FALCON512-public_key.der")
	require.Nil(t, err, "error should be nil")
	require.NotNil(t, bytes, "bytes should not be nil")
	pub, err = LoadPublicKeyFromDER(bytes)
	require.Nil(t, err, "error should be nil")
	require.NotNil(t, pub, "pub should not be nil")
	bytes, err = GetRawPublicKey(pub)
	require.Nil(t, err, "error should be nil")
	require.NotNil(t, bytes, "bytes should not be nil")
	rawkeybytes = []byte{0x09, 0x91, 0x60, 0x2c, 0x03, 0x07, 0xe2, 0xf4, 0x03, 0x70, 0x7a, 0x84, 0xac, 0xc1, 0x83, 0x56, 0x10, 0x96, 0x2a, 0x03, 0x63, 0x67, 0xac, 0xba, 0xc0, 0x8a, 0x29, 0x48, 0x2e, 0x0b, 0x68, 0x52, 0x7a, 0x7e, 0xc8, 0x46, 0x6f, 0x3c, 0x7b, 0xd9, 0xf4, 0x01, 0xaa, 0x8e, 0x8c, 0xcc, 0xd3, 0xbc, 0x69, 0x0f, 0x4c, 0x3e, 0x1c, 0x8b, 0x70, 0x46, 0x69, 0x75, 0xe4, 0x9d, 0xe4, 0xf9, 0x1b, 0xd1, 0x7e, 0xfa, 0xb5, 0xb3, 0xf2, 0x0b, 0x62, 0x95, 0xa2, 0xde, 0xb7, 0x24, 0xde, 0xf7, 0x8d, 0x80, 0x2a, 0xb5, 0x71, 0x51, 0xd3, 0x7c, 0x71, 0x57, 0xda, 0xe0, 0x27, 0x35, 0x53, 0x1a, 0x1d, 0x06, 0x47, 0xe5, 0x2d, 0x17, 0x45, 0x7a, 0x55, 0xa4, 0x45, 0x2c, 0x2e, 0xaa, 0x58, 0x91, 0xfa, 0xe7, 0xdd, 0x63, 0x96, 0x15, 0x94, 0x50, 0xd1, 0x4a, 0x3e, 0xfe, 0x10, 0x16, 0x5a, 0x85, 0x70, 0x21, 0x74, 0xeb, 0xa6, 0x85, 0xee, 0xb5, 0x89, 0xb6, 0x98, 0xc5, 0x38, 0x95, 0x0a, 0x78, 0x3c, 0xbf, 0xa6, 0xb3, 0xa6, 0xaf, 0xbe, 0x1d, 0xb5, 0xc0, 0xf4, 0x87, 0x9c, 0xb0, 0xa4, 0xa8, 0x34, 0x6f, 0xaa, 0xf8, 0x6c, 0xc1, 0xde, 0xd0, 0x10, 0x1d, 0x1a, 0x1a, 0x96, 0x8d, 0x91, 0xb5, 0xd4, 0xcc, 0x92, 0x96, 0xe7, 0x10, 0x27, 0x48, 0x2e, 0x33, 0x81, 0xa7, 0x9b, 0x99, 0x8c, 0x28, 0x00, 0xb8, 0x01, 0xc2, 0xba, 0x44, 0x3b, 0x52, 0x39, 0x38, 0xa5, 0xcd, 0xad, 0x8a, 0x2c, 0xd4, 0x34, 0x34, 0x00, 0xde, 0xe8, 0xaf, 0x0a, 0x69, 0xfb, 0xd3, 0x1a, 0x9c, 0x8b, 0x24, 0xbb, 0x06, 0x42, 0xcb, 0x7e, 0x46, 0x2e, 0x4d, 0xbb, 0x4b, 0xab, 0xa3, 0xa1, 0xe1, 0x6c, 0x97, 0x23, 0x6b, 0x6b, 0x77, 0x12, 0x97, 0xa6, 0x0c, 0x6d, 0xc9, 0x38, 0x42, 0x6f, 0x57, 0x17, 0xe3, 0x90, 0x26, 0x7d, 0x3f, 0x4b, 0x5f, 0x24, 0x89, 0x68, 0x60, 0x31, 0x72, 0x1f, 0xd3, 0xec, 0x7b, 0x7d, 0x3e, 0x49, 0x21, 0xd7, 0x93, 0x93, 0x3a, 0x6f, 0xb6, 0x03, 0x9f, 0x62, 0x27, 0x79, 0x6e, 0xc2, 0xd7, 0x9e, 0xc4, 0x5b, 0x6c, 0xaa, 0xb4, 0xab, 0xe9, 0x61, 0xa5, 0xa6, 0xee, 0xf4, 0xb4, 0x54, 0x73, 0x1f, 0x9e, 0x32, 0xb8, 0x76, 0x9d, 0x06, 0x7f, 0xde, 0xf4, 0xc4, 0x70, 0x85, 0x1a, 0x68, 0x64, 0xff, 0x24, 0x03, 0x16, 0x52, 0x6d, 0xde, 0x53, 0x81, 0xbf, 0x16, 0xc9, 0x5f, 0xc9, 0xba, 0x83, 0x3e, 0x0e, 0xee, 0xab, 0x30, 0xcf, 0x26, 0x43, 0x85, 0x74, 0xa0, 0x62, 0x79, 0x20, 0xb1, 0x13, 0x51, 0x62, 0xc9, 0x11, 0xf1, 0x08, 0xdc, 0x0c, 0x3b, 0xd6, 0x57, 0xa5, 0x7d, 0x87, 0x21, 0x9f, 0xe6, 0x9a, 0x2b, 0x58, 0x55, 0x7b, 0x55, 0x6a, 0x2a, 0x56, 0x29, 0x2f, 0x6d, 0x64, 0x14, 0x11, 0x42, 0x3d, 0x98, 0x3e, 0x37, 0x0e, 0xb9, 0x13, 0xed, 0x5c, 0x92, 0xa8, 0x3d, 0xe7, 0xe7, 0xb7, 0xe3, 0x05, 0xab, 0xcd, 0x5f, 0x9a, 0xb8, 0x25, 0x37, 0x9c, 0x0c, 0x5a, 0x6b, 0x57, 0x87, 0x35, 0x11, 0x89, 0x9d, 0x78, 0x18, 0xca, 0xca, 0x89, 0xa8, 0xe9, 0xb7, 0xde, 0x4a, 0x5b, 0x6b, 0xa0, 0x31, 0x7a, 0xca, 0x05, 0xeb, 0x9e, 0xde, 0xc0, 0xa4, 0xff, 0x07, 0x7a, 0x9e, 0x12, 0x6b, 0xf1, 0xc4, 0x86, 0xea, 0x8b, 0x15, 0x7b, 0xb2, 0x28, 0x05, 0xa7, 0x6e, 0x46, 0x03, 0xf5, 0xb2, 0x14, 0x18, 0x66, 0xa1, 0xf2, 0xb9, 0xad, 0xef, 0xe5, 0x9f, 0x5e, 0x2b, 0x60, 0xf7, 0x63, 0xf4, 0x4c, 0xdc, 0xac, 0xd3, 0x3a, 0x8f, 0x0c, 0x72, 0xfc, 0x5f, 0xc9, 0xd1, 0x41, 0xfb, 0x7d, 0xf2, 0x76, 0x9b, 0x35, 0xd8, 0x89, 0x92, 0x2c, 0x90, 0xe7, 0xa7, 0x25, 0x1d, 0x4f, 0xc6, 0xea, 0xb0, 0x75, 0x59, 0xfe, 0xa6, 0xc6, 0xe1, 0xf4, 0x93, 0xd4, 0x7b, 0x1f, 0x59, 0xf8, 0x49, 0x82, 0x00, 0x95, 0xae, 0x7e, 0x9e, 0x36, 0x75, 0x1f, 0x44, 0x36, 0xad, 0xa8, 0x80, 0x88, 0xa0, 0xa4, 0x1e, 0xbe, 0xf9, 0x19, 0xb7, 0xe2, 0x3d, 0xb6, 0x41, 0x36, 0x35, 0xd6, 0xd0, 0x7f, 0x8b, 0xb9, 0x5c, 0x04, 0x40, 0x81, 0x5b, 0xb1, 0x61, 0x14, 0x35, 0xd1, 0x87, 0x5f, 0x1d, 0x2a, 0x0a, 0xf0, 0xc7, 0x08, 0xc1, 0x7f, 0xd9, 0x8f, 0xb9, 0x7b, 0x6b, 0xd6, 0x7a, 0x72, 0x13, 0x82, 0x7a, 0x1d, 0x27, 0x27, 0x11, 0x92, 0x13, 0x0f, 0xcb, 0xfe, 0x38, 0xd2, 0x4f, 0xd9, 0xa2, 0x8f, 0x3f, 0xb4, 0xa0, 0xc0, 0x43, 0x3b, 0xc4, 0xef, 0xb2, 0xf5, 0x1a, 0x86, 0x18, 0xa3, 0x0c, 0x20, 0x8c, 0x34, 0x53, 0xed, 0xa4, 0x9e, 0x1f, 0x9c, 0xb8, 0x47, 0xef, 0x4c, 0xa9, 0x01, 0xfd, 0x71, 0x20, 0x74, 0x46, 0xb3, 0x3a, 0xe0, 0x23, 0xa8, 0x21, 0x05, 0x3b, 0x47, 0x45, 0x47, 0xfa, 0xfd, 0x17, 0x33, 0x12, 0x2c, 0x18, 0xd4, 0xf5, 0x96, 0xff, 0xb0, 0x6d, 0x54, 0xb7, 0x7f, 0xcf, 0xdf, 0x8a, 0x38, 0xb1, 0xf8, 0x98, 0x8f, 0x26, 0x80, 0x14, 0xdf, 0x70, 0xbe, 0x1d, 0xbe, 0xb8, 0xa6, 0x0f, 0x6b, 0x8e, 0x09, 0xe3, 0x13, 0x78, 0x73, 0x30, 0xd7, 0x24, 0xf4, 0x72, 0x81, 0x0c, 0x2b, 0xe0, 0xad, 0x68, 0x46, 0x29, 0x4f, 0xe2, 0x4e, 0x61, 0xb4, 0x55, 0x44, 0xa0, 0xda, 0x82, 0x17, 0xbd, 0x1f, 0x14, 0xcd, 0x66, 0xef, 0x2c, 0xf8, 0x25, 0xa0, 0x12, 0x02, 0x89, 0xa0, 0xec, 0x9f, 0x46, 0x3c, 0xb6, 0x74, 0x4c, 0x45, 0x12, 0xde, 0x20, 0x55, 0x67, 0xa6, 0xe1, 0x59, 0x95, 0x16, 0xd9, 0xa1, 0x97, 0x76, 0x3f, 0xb8, 0x36, 0x0a, 0x6e, 0x9e, 0xd0, 0x8f, 0x5d, 0xb3, 0xa8, 0x21, 0x45, 0x3c, 0xb7, 0x2c, 0x35, 0x71, 0x84, 0x08, 0x87, 0x81, 0x71, 0x8b, 0x75, 0xe5, 0xa5, 0x60, 0x08, 0xb6, 0x37, 0xe6, 0xbd, 0x89, 0x9d, 0xb5, 0xbd, 0x81, 0xe8, 0x10, 0x1b, 0x0b, 0x9d, 0xc1, 0x2c, 0x55, 0x1b, 0x08, 0xbc, 0x6c, 0x62, 0x1c, 0xf9, 0xa6, 0xd6, 0x39, 0x68, 0x88, 0xee, 0xd1, 0xda, 0x6d, 0xe8, 0x5d, 0x89, 0xa4, 0x64, 0x67, 0x02, 0xbe, 0x2e, 0x8d, 0xf0, 0xc6, 0xeb, 0xdc, 0xdc, 0xb6, 0xda, 0x1b, 0x62, 0x27, 0xd5, 0x89, 0x0d, 0xa0, 0x7b, 0xb1, 0x7f, 0x00, 0x06, 0x26, 0x10, 0x65, 0x54, 0x69, 0x0d, 0x1a, 0xa5, 0x99, 0x3f, 0xba, 0xcc, 0xa3, 0x8e, 0x72, 0x22, 0x3e, 0xe4, 0xa1, 0xcb, 0xf0, 0x33, 0x32, 0x1d, 0x90, 0xd6, 0xca, 0x3e, 0x44, 0xd1, 0x55, 0xda, 0xa3, 0xca, 0xf7, 0x47, 0x58, 0x14, 0x86, 0x38, 0xcd, 0x2a, 0x1a, 0x06, 0x23, 0xf4, 0xaa, 0xac, 0xba, 0x1a, 0x2d, 0x28, 0x19, 0xed, 0x54, 0xcb}
	assert.Equal(t, len(rawkeybytes), len(bytes), "raw key length did not match")
	assert.Equal(t, rawkeybytes, bytes, "raw key did not match")

	// test-case 7: load P256_FALCON512
	bytes, err = os.ReadFile("testdata/keys/P256_FALCON512-public_key.der")
	require.Nil(t, err, "error should be nil")
	require.NotNil(t, bytes, "bytes should not be nil")
	pub, err = LoadPublicKeyFromDER(bytes)
	require.Nil(t, err, "error should be nil")
	require.NotNil(t, pub, "pub should not be nil")
	bytes, err = GetRawPublicKey(pub)
	require.Nil(t, err, "error should be nil")
	require.NotNil(t, bytes, "bytes should not be nil")
	rawkeybytes = []byte{0x00, 0x00, 0x00, 0x41, 0x04, 0xf1, 0xdd, 0xd8, 0xa7, 0xc9, 0x3c, 0x2e, 0x6f, 0x44, 0x83, 0x9a, 0xe3, 0x39, 0x82, 0xbb, 0x50, 0x91, 0x39, 0x83, 0x29, 0x3c, 0x6d, 0x17, 0x02, 0xe5, 0x38, 0xf1, 0xde, 0x00, 0x28, 0x34, 0x24, 0x8f, 0xc3, 0x4c, 0x2c, 0x7c, 0x30, 0x03, 0x59, 0x9c, 0x0b, 0x9d, 0xc3, 0x18, 0x90, 0xe3, 0x87, 0x70, 0x6f, 0x0a, 0x68, 0xdd, 0xd0, 0x54, 0x48, 0x27, 0x2e, 0x32, 0xea, 0x8e, 0xca, 0x44, 0x41, 0x09, 0x7d, 0x84, 0x7f, 0xab, 0x02, 0x89, 0xdd, 0x4c, 0x22, 0x63, 0xa0, 0x48, 0x5e, 0xe3, 0x39, 0xf1, 0x5e, 0x64, 0x0e, 0x18, 0x92, 0x49, 0x59, 0x63, 0x45, 0xb2, 0xab, 0xe0, 0x52, 0x46, 0xfb, 0xa3, 0xc7, 0x4a, 0xab, 0x74, 0x55, 0x6a, 0x52, 0x63, 0xe1, 0x6d, 0x0a, 0x0c, 0xd0, 0x67, 0x81, 0xec, 0x32, 0x40, 0x9a, 0x79, 0x33, 0x39, 0x28, 0x3a, 0x62, 0x20, 0xf4, 0x43, 0x29, 0xa0, 0xe2, 0x6e, 0x88, 0xab, 0xa3, 0x89, 0xc1, 0x74, 0x7b, 0xba, 0xc4, 0xa8, 0x96, 0x2b, 0xae, 0x55, 0x09, 0x92, 0x12, 0x27, 0xe3, 0x2f, 0x1e, 0x80, 0xd4, 0xa2, 0x10, 0xeb, 0x79, 0x54, 0x66, 0xfe, 0xcb, 0x8d, 0x2b, 0xd3, 0xb2, 0xf6, 0x45, 0x55, 0x57, 0x5c, 0xc9, 0x64, 0x80, 0xe8, 0x6b, 0xcc, 0x6c, 0xe3, 0x2f, 0x5a, 0x50, 0x81, 0x93, 0x16, 0x3c, 0x2e, 0x32, 0x63, 0x5b, 0x97, 0x42, 0x7a, 0x7a, 0x81, 0x25, 0x11, 0xe9, 0xdb, 0xe6, 0xac, 0x9e, 0x0e, 0x96, 0x07, 0x62, 0x9b, 0x58, 0xd0, 0x31, 0xe5, 0xc6, 0x40, 0xf2, 0x93, 0xac, 0xfe, 0x01, 0x1c, 0x20, 0xa5, 0x21, 0x58, 0x66, 0xf8, 0x7c, 0x95, 0x96, 0x84, 0xcc, 0x2f, 0x62, 0x76, 0xc3, 0xde, 0x79, 0xb6, 0xc5, 0x1a, 0x83, 0x28, 0x40, 0xa3, 0x3d, 0x1a, 0x75, 0x14, 0x41, 0x10, 0x4a, 0x60, 0xdd, 0x33, 0xc7, 0xa3, 0x4c, 0x08, 0x5d, 0x64, 0x99, 0xb2, 0xe0, 0xb5, 0x17, 0x0e, 0x7f, 0x40, 0x19, 0xe0, 0x8f, 0x0b, 0xad, 0xf8, 0xb4, 0xf6, 0xcf, 0x33, 0x87, 0xd5, 0x77, 0x58, 0xb4, 0x87, 0xf8, 0x95, 0xd1, 0x65, 0x56, 0xa8, 0x5a, 0x66, 0x0c, 0x2e, 0xa9, 0x73, 0x55, 0xd8, 0x6b, 0x97, 0x64, 0x24, 0x27, 0x12, 0xc9, 0x25, 0x80, 0xed, 0x91, 0xfb, 0x39, 0x50, 0xd0, 0x6a, 0x74, 0xac, 0x38, 0xb9, 0xa8, 0x30, 0x62, 0x54, 0x39, 0x7a, 0x4c, 0xee, 0xcf, 0x57, 0x0d, 0x28, 0xe0, 0xba, 0xcd, 0x2e, 0x3a, 0xe9, 0x2a, 0x52, 0x54, 0x08, 0x36, 0x5e, 0x58, 0x4e, 0x05, 0x38, 0x1b, 0x2c, 0x20, 0xd6, 0xe9, 0xe8, 0x95, 0x22, 0xee, 0x3f, 0xec, 0xab, 0xe6, 0x58, 0xaf, 0x27, 0x23, 0x2d, 0x81, 0x65, 0xe2, 0x4e, 0x67, 0xbe, 0x8a, 0x83, 0xf7, 0x68, 0x6b, 0xde, 0x4b, 0x9e, 0xeb, 0x19, 0x69, 0x1d, 0x22, 0x16, 0xda, 0x26, 0x7b, 0x54, 0xca, 0xc5, 0x94, 0xf9, 0xcf, 0xd5, 0x90, 0x45, 0xaf, 0x41, 0x09, 0x24, 0x81, 0xa2, 0x5b, 0x2e, 0xbf, 0x55, 0x2b, 0x19, 0xd8, 0xce, 0x3a, 0x47, 0xf2, 0x9c, 0xe8, 0xf2, 0x04, 0xae, 0xb8, 0x98, 0xc4, 0x16, 0x47, 0xea, 0x0d, 0x8d, 0xc1, 0x28, 0xe4, 0x0a, 0xc1, 0xe4, 0x92, 0x8d, 0xb8, 0x7a, 0x40, 0x48, 0x38, 0x5a, 0x6a, 0xe8, 0xa2, 0x69, 0xc0, 0x97, 0x5b, 0xb6, 0x2b, 0xf4, 0x56, 0x64, 0xca, 0xab, 0x16, 0xb1, 0x92, 0x49, 0xe4, 0xc6, 0x7b, 0x38, 0x4b, 0xc9, 0xfe, 0x4f, 0x3f, 0x5a, 0xfa, 0xdc, 0xd3, 0xaa, 0x01, 0xc0, 0x25, 0xa5, 0x3c, 0xeb, 0x58, 0xa1, 0xa1, 0xb8, 0x34, 0x22, 0x48, 0xda, 0xa1, 0x08, 0x2e, 0x60, 0x74, 0xd1, 0x51, 0x2e, 0xd9, 0x66, 0x0e, 0x1d, 0x7a, 0x93, 0x4f, 0xe8, 0xa6, 0x89, 0x8e, 0xe8, 0x8c, 0x12, 0x9f, 0x77, 0xc8, 0x96, 0x53, 0xf2, 0x19, 0xe7, 0x4f, 0xdd, 0x7b, 0x09, 0x93, 0x23, 0x4a, 0xae, 0xf6, 0xe9, 0xd4, 0x56, 0x5e, 0x2a, 0x65, 0xe8, 0xfe, 0xc9, 0xa0, 0x63, 0xaf, 0xa6, 0x5e, 0x1f, 0x45, 0x10, 0xa4, 0x06, 0xb4, 0x55, 0x9c, 0x4b, 0xc7, 0xda, 0xd0, 0x51, 0x78, 0x28, 0x0a, 0x3c, 0xcf, 0x8b, 0x05, 0x7d, 0x9f, 0xa4, 0x11, 0xc9, 0x18, 0xb7, 0x56, 0x23, 0x06, 0x39, 0x23, 0x03, 0x72, 0x16, 0xd7, 0x10, 0x03, 0x1a, 0x5b, 0xb4, 0x2d, 0x0e, 0x60, 0x2f, 0xed, 0xd2, 0x52, 0x2a, 0x9d, 0xa5, 0xf4, 0x64, 0x9e, 0x62, 0xa5, 0x37, 0x6b, 0x4e, 0xa9, 0xd2, 0x52, 0x25, 0x0d, 0x75, 0x84, 0x04, 0xff, 0x00, 0x0a, 0xe7, 0x9a, 0xa6, 0xae, 0xfa, 0x2e, 0xba, 0x70, 0xf2, 0x59, 0x99, 0x7a, 0x0d, 0xe5, 0x74, 0x38, 0x44, 0xed, 0x9c, 0xa0, 0xe2, 0xe6, 0x42, 0x8a, 0x55, 0x31, 0x26, 0x28, 0xc8, 0x83, 0x8f, 0x1b, 0xb9, 0x33, 0xf4, 0xc6, 0xe2, 0x72, 0x03, 0x99, 0x32, 0x01, 0xa9, 0xaa, 0xb6, 0xaa, 0x27, 0x05, 0xc4, 0xba, 0x56, 0x38, 0x04, 0x41, 0x95, 0xc6, 0xc6, 0x03, 0xd9, 0xe5, 0xf3, 0x6e, 0x95, 0x53, 0xb9, 0x2d, 0x52, 0xb6, 0x16, 0x41, 0x86, 0xa9, 0x29, 0x5c, 0xf5, 0x56, 0x1d, 0x48, 0x83, 0x01, 0xc5, 0xcb, 0x4c, 0x51, 0xbd, 0xcb, 0x0e, 0x84, 0x92, 0xb8, 0x1c, 0x90, 0x47, 0x84, 0x47, 0x01, 0x20, 0x70, 0x3f, 0x96, 0xad, 0xcd, 0x4e, 0x2a, 0x0d, 0x79, 0xd5, 0xe1, 0x43, 0xc6, 0x26, 0x32, 0xfd, 0xb9, 0xe3, 0xea, 0x2f, 0x61, 0x78, 0x29, 0x31, 0xc3, 0x99, 0x3e, 0x69, 0xc2, 0x5f, 0xda, 0x1e, 0x95, 0xde, 0x31, 0x59, 0xec, 0x02, 0xfb, 0x89, 0xcc, 0x44, 0x70, 0x9b, 0x83, 0x82, 0x61, 0x9f, 0x00, 0x40, 0x55, 0xda, 0xb9, 0xd1, 0x48, 0x72, 0x62, 0x35, 0x07, 0x94, 0x12, 0xd9, 0x51, 0x70, 0x0d, 0xbb, 0x97, 0x65, 0xa1, 0x68, 0xc2, 0xc5, 0x97, 0x08, 0x28, 0xfc, 0xbd, 0x44, 0x83, 0x98, 0x1d, 0xac, 0xd4, 0xa9, 0xe4, 0xd0, 0x84, 0x41, 0x59, 0x4b, 0x0f, 0x82, 0xb3, 0x93, 0x7b, 0x19, 0x4a, 0x28, 0x7d, 0x49, 0xf7, 0x7e, 0x01, 0x4a, 0x7a, 0xdd, 0x7d, 0x50, 0xcc, 0x9c, 0x68, 0x82, 0xa6, 0x6a, 0xe6, 0x6b, 0x9c, 0xc6, 0x20, 0x3d, 0x1c, 0x01, 0x44, 0x10, 0x4b, 0x6e, 0x25, 0x1a, 0xb1, 0xfb, 0x90, 0x55, 0x6c, 0x00, 0xea, 0xb8, 0x1e, 0x55, 0x6c, 0x78, 0x74, 0x05, 0x99, 0x0e, 0xc8, 0xb5, 0x21, 0x04, 0x52, 0xba, 0x31, 0x1c, 0xc0, 0x32, 0x0c, 0x29, 0xb7, 0x17, 0xdd, 0xac, 0x68, 0xc5, 0xac, 0xb5, 0x14, 0xab, 0x8b, 0x19, 0x08, 0x56, 0xb0, 0x90, 0x83, 0xe8, 0x18, 0x22, 0x7a, 0x27, 0xf0, 0x91, 0xdd, 0x3e, 0x9d, 0x47, 0x60, 0x30, 0x16, 0x93, 0x34, 0x59, 0x48, 0x5b, 0xc9, 0x9a, 0xc8, 0x38, 0x8d, 0x2c, 0x13, 0x71, 0x18, 0x67, 0x3e, 0x90, 0x5b, 0xe7, 0xbf, 0x65, 0xee, 0x75, 0xd9, 0xc4, 0x3a, 0x11, 0x40, 0xd7, 0x39, 0x60, 0x53, 0x85, 0x29, 0xe8, 0x58, 0x46, 0x3d, 0xc8, 0x03, 0x8a, 0x1c, 0x0c, 0x2d, 0xac, 0x0d, 0xd5, 0xf9, 0x8c, 0x7d, 0x8e, 0x06, 0x0e, 0xc8, 0x26, 0xc7, 0xcc, 0x91, 0x8c, 0xf0, 0x41, 0xb7, 0xcd, 0x82, 0xb5, 0x81, 0x63, 0x22, 0x7f, 0x62, 0x36}
	assert.Equal(t, len(rawkeybytes), len(bytes), "raw key length did not match")
	assert.Equal(t, rawkeybytes, bytes, "raw key did not match")

	// test-case 8: load RSA3072_FALCON512

	// test-case 9: load FALCON1024

	// test-case 10: load Dilithium
}

// TestBuildRSAKey tests if the RSA key is built.
// Tests both creating public and private keys.
func TestBuildRSAKey(t *testing.T) {
	// simple test for public key
	e := big.NewInt(137)
	N := big.NewInt(9973)
	pub, _ := BuildRSAPublicKey(e, N)
	eNew, NNew, _ := GetParamsRSA(pub)
	assert.Equal(t, e, eNew, "e and eNew should be the same")
	assert.Equal(t, N, NNew, "N and NNew should be the same")

	// generate key, get components (e, N), reconstruct and test if it uses the same (e, N)
	n := 10
	bitlen := 3072
	for i := 0; i < n; i++ {
		priv, err := GenerateRSAKey(bitlen)
		e, N, err := GetParamsRSA(priv)
		require.Nil(t, err, "error should be nil")
		require.NotNil(t, e, "e should not be nil")
		require.NotNil(t, N, "N should not be nil")
		pub, err := BuildRSAPublicKey(e, N)
		eNew, NNew, err := GetParamsRSA(pub)
		assert.Equal(t, e, eNew, "e and eNew should be the same")
		assert.Equal(t, N, NNew, "N and NNew should be the same")
	}

	// same as before but with different e value
	for i := 0; i < n; i++ {
		priv, err := GenerateRSAKeyWithExponent(bitlen, 131)
		e, N, err := GetParamsRSA(priv)
		require.Nil(t, err, "error should be nil")
		require.NotNil(t, e, "e should not be nil")
		require.NotNil(t, N, "N should not be nil")
		pub, err := BuildRSAPublicKey(e, N)
		eNew, NNew, err := GetParamsRSA(pub)
		assert.Equal(t, e, eNew, "e and eNew should be the same")
		assert.Equal(t, N, NNew, "N and NNew should be the same")
	}
	// using private keys this time
	bitlen = 2048
	for i := 0; i < n; i++ {
		priv, err := GenerateRSAKey(bitlen)
		e, N, d, p, q, err := GetParamsRSAPrivate(priv)
		require.Nil(t, err, "error should be nil")
		require.NotNil(t, e, "e should not be nil")
		require.NotNil(t, N, "N should not be nil")
		require.NotNil(t, d, "d should not be nil")
		require.NotNil(t, p, "p should not be nil")
		require.NotNil(t, q, "q should not be nil")
		privNew, err := BuildRSAPrivateKey(e, N, d, p, q)
		eNew, NNew, dNew, pNew, qNew, err := GetParamsRSAPrivate(privNew)
		assert.Equal(t, e, eNew, "e and eNew should be the same")
		assert.Equal(t, N, NNew, "N and NNew should be the same")
		assert.Equal(t, d, dNew, "d and dNew should be the same")
		assert.Equal(t, p, pNew, "p and pNew should be the same")
		assert.Equal(t, q, qNew, "q and qNew should be the same")
	}

	// should be relative prime
	//e = big.NewInt(130)
	//N = big.NewInt(1000)
	//pub, err := BuildRSAKey(e, N)
	//assert.NotNil(t, err, "e and N should be relative primes")
	//assert.Nil(t, pub, "pub should be nil")

}

// TestBuildECDSAKey tests if the ECDSA key is built.
func TestBuildECDSAKey(t *testing.T) {
	n := 10
	for i := 0; i < n; i++ {
		priv, err := GenerateECKey(Prime256v1)
		X, Y, err := GetECDSAPublicKey(priv)
		require.NotNil(t, X, "X should not be nil")
		require.NotNil(t, Y, "Y should not be nil")
		require.Nil(t, err, "error should be nil")
		//XBytes := X.Bytes()
		//YBytes := Y.Bytes()
		//concatenated := append(XBytes, YBytes...)
		//assert.Equal(t, 64, len(concatenated), "concatenated bytes should be 64 bytes long")
		pub, err := BuildECDSAPublicKeyFromParams(X, Y, 32, "prime256v1")
		require.Nil(t, err, "error should be nil")
		XNew, YNew, err := GetECDSAPublicKey(pub)
		require.Nil(t, err, "error should be nil")
		assert.Equal(t, X, XNew, "X and XNew should be the same")
		assert.Equal(t, Y, YNew, "Y and YNew should be the same")
	}

	// same as before but with different curve
	for i := 0; i < n; i++ {
		priv, err := GenerateECKey(Secp384r1)
		X, Y, err := GetECDSAPublicKey(priv)
		require.NotNil(t, X, "X should not be nil")
		require.NotNil(t, Y, "Y should not be nil")
		require.Nil(t, err, "error should be nil")
		//XBytes := X.Bytes()
		//YBytes := Y.Bytes()
		//concatenated := append(XBytes, YBytes...)
		//assert.Equal(t, 96, len(concatenated), "concatenated bytes should be 96 bytes long")
		pub, err := BuildECDSAPublicKeyFromParams(X, Y, 48, "secp384r1")
		require.Nil(t, err, "error should be nil")
		XNew, YNew, err := GetECDSAPublicKey(pub)
		require.Nil(t, err, "error should be nil")
		assert.Equal(t, X, XNew, "X and XNew should be the same")
		assert.Equal(t, Y, YNew, "Y and YNew should be the same")
	}

	// same but now we test for the private key
	for i := 0; i < n; i++ {
		priv, err := GenerateECKey(Secp384r1)
		X, Y, err := GetECDSAPublicKey(priv)
		require.NotNil(t, X, "X should not be nil")
		require.NotNil(t, Y, "Y should not be nil")
		require.Nil(t, err, "error should be nil")
		pub, err := BuildECDSAPublicKeyFromParams(X, Y, 48, "secp384r1")
		require.Nil(t, err, "error should be nil")
		XNew, YNew, err := GetECDSAPublicKey(pub)
		require.Nil(t, err, "error should be nil")
		assert.Equal(t, X, XNew, "X and XNew should be the same")
		assert.Equal(t, Y, YNew, "Y and YNew should be the same")
		D, err := GetECDSAPrivateKey(priv)
		require.Nil(t, err, "error should be nil")
		require.NotNil(t, D, "D should not be nil")
		newPriv, err := BuildECDSAPrivateKey(D, "secp384r1")
		require.Nil(t, err, "error should be nil")
		DNew, err := GetECDSAPrivateKey(newPriv)
		require.Nil(t, err, "error should be nil")
		require.NotNil(t, DNew, "DNew should not be nil")
		assert.Equal(t, D, DNew, "D and DNew should be the same")
	}

}

// TestGenerateBuildRawKey tests if the raw key is generated,
// and rebuilt using the raw buffer.
// Note: should not work for all ciphers.
// Supported: ED25519, ED448, X25519, X448, ML-DSA-44, ML-DSA-65, ML-DSA-87, ML-KEM-512, ML-KEM-768, and ML-KEM-1024.
func TestGenerateBuildRawKey(t *testing.T) {
	// test with wrong string
	priv, err := GenerateKey("ED25119")
	require.NotNil(t, err, "err should not be nil")
	require.Nil(t, priv, "priv should be nil")

	n := 10
	// test for ED25519
	for i := 0; i < n; i++ {
		priv, err := GenerateKey("ED25519")
		require.Nil(t, err, "err should not be nil")
		require.NotNil(t, priv, "priv should not be nil")
		bytes, err := GetRawPublicKey(priv)
		require.NotNil(t, bytes, "bytes should not be nil")
		require.Greater(t, len(bytes), 0, "len(bytes) should be greater than 0")
		pub, err := BuildRawPublicKey(bytes, "ED25519")
		require.Nil(t, err, "error should be nil")
		bytesNew, err := GetRawPublicKey(pub)
		require.Nil(t, err, "error should be nil")
		assert.Equal(t, bytes, bytesNew, "bytes and bytesNew should be the same")
	}

	// test for rsa3072_falconpadded512
	for i := 0; i < n; i++ {
		priv, err := GenerateKey("rsa3072_falconpadded512")
		require.Nil(t, err, "err should not be nil")
		require.NotNil(t, priv, "priv should not be nil")
		bytes, err := GetRawPublicKey(priv)
		require.NotNil(t, bytes, "bytes should not be nil")
		require.Greater(t, len(bytes), 0, "len(bytes) should be greater than 0")
		pub, err := BuildRawPublicKey(bytes, "rsa3072_falconpadded512")
		require.Nil(t, err, "error should be nil")
		bytesNew, err := GetRawPublicKey(pub)
		// bytesNew[0] ^= 0x01 // to test if it fails
		require.Nil(t, err, "error should be nil")
		assert.Equal(t, bytes, bytesNew, "bytes and bytesNew should be the same")
	}

}

// TestKeySignatureSize verifies if the signatures and keys have the expected sizes
func TestKeySignatureSize(t *testing.T) {
	var keyResults []struct {
		Algorithm string
		PrivKey   PrivateKey
		Err       error
		PubSize   int
		PrivSize  int
		SigSize   int
	}
	// RSA3072-FALCON512 hybrid key generation
	// pub size: 1299
	// priv size:
	// sig size : 666 + 384 + 4 (index) = 1054
	priv, err := GenerateKey("rsa3072_falconpadded512")
	keyResults = append(keyResults, struct {
		Algorithm string
		PrivKey   PrivateKey
		Err       error
		PubSize   int
		PrivSize  int
		SigSize   int
	}{"RSA3072_FALCON512", priv, err, 1299, 3055, 1054})
	// P256-FALCON512 hybrid key generation
	// pub size:
	// priv size:
	// sig size : 666 + 64 + 4 (index) = 734
	priv, err = GenerateKey("p256_falconpadded512")
	keyResults = append(keyResults, struct {
		Algorithm string
		PrivKey   PrivateKey
		Err       error
		PubSize   int
		PrivSize  int
		SigSize   int
	}{"P256_FALCON512", priv, err, 966, 1406, 742})
	// FALCON512
	priv, err = GenerateKey("falconpadded512")
	keyResults = append(keyResults, struct {
		Algorithm string
		PrivKey   PrivateKey
		Err       error
		PubSize   int
		PrivSize  int
		SigSize   int
	}{"FALCON512", priv, err, 897, 1281, 666})
	// FALCON1024
	priv, err = GenerateKey("falconpadded1024")
	keyResults = append(keyResults, struct {
		Algorithm string
		PrivKey   PrivateKey
		Err       error
		PubSize   int
		PrivSize  int
		SigSize   int
	}{"FALCON1024", priv, err, 1793, 2305, 1280})
	// FALCON1024
	priv, err = GenerateKey("p521_falconpadded1024")
	keyResults = append(keyResults, struct {
		Algorithm string
		PrivKey   PrivateKey
		Err       error
		PubSize   int
		PrivSize  int
		SigSize   int
	}{"P521_FALCON1024", priv, err, 1930, 2532, 1422})

	digest, _ := GetDigestByName("sha256", true)
	n := 10
	for i := 0; i < n; i++ {
		data := make([]byte, 10+rand.Intn(91))
		rand.Read(data)
		for _, keyResult := range keyResults {
			// Process each key with each digest
			require.Nil(t, keyResult.Err, fmt.Sprintf("Err should be nil for %s", keyResult.Algorithm))
			require.NotNil(t, keyResult.PrivKey, fmt.Sprintf("PrivKey should not be nil for %s", keyResult.Algorithm))
			signature, err := keyResult.PrivKey.SignPKCS1v15(digest, data)
			require.Nil(t, err, fmt.Sprintf("Signature err should be nil for %s", keyResult.Algorithm))
			require.NotNil(t, signature, fmt.Sprintf("signature should not be nil for %s", keyResult.Algorithm))
			assert.Equal(t, keyResult.SigSize, len(signature), fmt.Sprintf("Signature lengths should match for %s", keyResult.Algorithm))
			privbytes, err := GetRawPrivateKey(keyResult.PrivKey)
			require.Nil(t, err, fmt.Sprintf("Priv err should be nil for %s", keyResult.Algorithm))
			assert.Equal(t, keyResult.PrivSize, len(privbytes), fmt.Sprintf("Private key lengths should match for %s", keyResult.Algorithm))
			pubbytes, err := GetRawPublicKey(keyResult.PrivKey)
			require.Nil(t, err, fmt.Sprintf("Pub err should be nil for %s", keyResult.Algorithm))
			assert.Equal(t, keyResult.PubSize, len(pubbytes), fmt.Sprintf("Public key lengths should match for %s", keyResult.Algorithm))

		}
	}
}

// TestGenerateSignVerify generates, signs, and verifies data
// with different ciphers.
func TestGenerateSignVerify(t *testing.T) {

	digests := []*Digest{
		func() *Digest { d, _ := GetDigestByName("md5", true); return d }(),
		func() *Digest { d, _ := GetDigestByName("sha1", true); return d }(),
		func() *Digest { d, _ := GetDigestByName("sha256", true); return d }(),
	}

	var keyResults []struct {
		Algorithm string
		PrivKey   PrivateKey
		Err       error
	}

	// RSA key generation
	for _, bitlen := range []int{2048, 3072, 4096} {
		priv, err := GenerateRSAKey(bitlen)
		keyResults = append(keyResults, struct {
			Algorithm string
			PrivKey   PrivateKey
			Err       error
		}{fmt.Sprintf("RSA%d", bitlen), priv, err})
	}

	// ECDSA key generation
	for _, curve := range []EllipticCurve{Prime256v1, Secp384r1, Secp521r1} {
		priv, err := GenerateECKey(curve)
		keyResults = append(keyResults, struct {
			Algorithm string
			PrivKey   PrivateKey
			Err       error
		}{fmt.Sprintf("ECDSA_%d", curve), priv, err})
	}

	/*
		// ED25519 key generation
		priv, err := GenerateKey("ED25519")
		keyResults = append(keyResults, struct {
			Algorithm string
			PrivKey   PrivateKey
			Err       error
		}{"ED25519", priv, err})
	*/
	// RSA3072-FALCON512 hybrid key generation
	priv, err := GenerateKey("rsa3072_falconpadded512")
	keyResults = append(keyResults, struct {
		Algorithm string
		PrivKey   PrivateKey
		Err       error
	}{"RSA3072_FALCON512", priv, err})
	// P256-FALCON512 hybrid key generation
	priv, err = GenerateKey("p256_falconpadded512")
	keyResults = append(keyResults, struct {
		Algorithm string
		PrivKey   PrivateKey
		Err       error
	}{"P256_FALCON512", priv, err})
	// FALCON512
	priv, err = GenerateKey("falconpadded512")
	keyResults = append(keyResults, struct {
		Algorithm string
		PrivKey   PrivateKey
		Err       error
	}{"FALCON512", priv, err})
	// FALCON1024
	priv, err = GenerateKey("falconpadded1024")
	keyResults = append(keyResults, struct {
		Algorithm string
		PrivKey   PrivateKey
		Err       error
	}{"FALCON1024", priv, err})
	// FALCON1024
	priv, err = GenerateKey("p521_falconpadded1024")
	keyResults = append(keyResults, struct {
		Algorithm string
		PrivKey   PrivateKey
		Err       error
	}{"P521_FALCON1024", priv, err})

	n := 3
	for i := 0; i < n; i++ {
		data := make([]byte, 10+rand.Intn(91))
		rand.Read(data)
		for _, keyResult := range keyResults {
			for _, digest := range digests {
				// Process each key with each digest
				require.Nil(t, keyResult.Err, fmt.Sprintf("Err should be nil for %s", keyResult.Algorithm))
				require.NotNil(t, keyResult.PrivKey, fmt.Sprintf("PrivKey should not be nil for %s", keyResult.Algorithm))
				signature, err := keyResult.PrivKey.SignPKCS1v15(digest, data)
				require.Nil(t, err, fmt.Sprintf("Signature err should be nil for %s", keyResult.Algorithm))
				require.NotNil(t, signature, fmt.Sprintf("signature should not be nil for %s", keyResult.Algorithm))
				err = keyResult.PrivKey.VerifyPKCS1v15(digest, data, signature)
				require.Nil(t, err, fmt.Sprintf("Verification err should be nil for %s", keyResult.Algorithm))
			}
		}
	}

	// test if running it twice with the same key delivers a different result
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A}
	n = 2
	for _, keyResult := range keyResults {
		for _, digest := range digests {
			for i := 0; i < n; i++ {
				// Process each key with each digest
				require.Nil(t, keyResult.Err, fmt.Sprintf("Err should be nil for %s", keyResult.Algorithm))
				require.NotNil(t, keyResult.PrivKey, fmt.Sprintf("PrivKey should not be nil for %s", keyResult.Algorithm))
				signature, err := keyResult.PrivKey.SignPKCS1v15(digest, data)
				require.Nil(t, err, fmt.Sprintf("Signature err should be nil for %s", keyResult.Algorithm))
				require.NotNil(t, signature, fmt.Sprintf("signature should not be nil for %s", keyResult.Algorithm))
				err = keyResult.PrivKey.VerifyPKCS1v15(digest, data, signature)
				require.Nil(t, err, fmt.Sprintf("Verification err should be nil for %s", keyResult.Algorithm))
				assert.Nil(t, ensureErrorQueueIsClear(), "there should be no openssl errors")
			}
		}
	}

	// test with ciphers that don't require a digest
	var keyResultsWithoutDigest []struct {
		Algorithm string
		PrivKey   PrivateKey
		Err       error
	}
	// ED25519 key generation
	priv, err = GenerateKey("ED25519")
	keyResultsWithoutDigest = append(keyResultsWithoutDigest, struct {
		Algorithm string
		PrivKey   PrivateKey
		Err       error
	}{"ED25519", priv, err})

	for i := 0; i < n; i++ {
		data := make([]byte, 10+rand.Intn(91))
		rand.Read(data)
		for _, keyResult := range keyResultsWithoutDigest {
			require.Nil(t, keyResult.Err, fmt.Sprintf("Err should be nil for %s", keyResult.Algorithm))
			require.NotNil(t, keyResult.PrivKey, fmt.Sprintf("PrivKey should not be nil for %s", keyResult.Algorithm))
			signature, err := keyResult.PrivKey.SignPKCS1v15(nil, data)
			require.Nil(t, err, fmt.Sprintf("Signature err should be nil for %s", keyResult.Algorithm))
			require.NotNil(t, signature, fmt.Sprintf("signature should not be nil for %s", keyResult.Algorithm))
			err = keyResult.PrivKey.VerifyPKCS1v15(nil, data, signature)
			require.Nil(t, err, fmt.Sprintf("Verification err should be nil for %s", keyResult.Algorithm))
			assert.Nil(t, ensureErrorQueueIsClear(), "there should be no openssl errors")
		}
	}

	digest, _ := GetDigestByName("sha256", true)
	digest2, _ := GetDigestByName("sha1", true)
	data = make([]byte, 10+rand.Intn(91))
	rand.Read(data)
	// test mismatching digests
	priv, err = GenerateKey("rsa3072_falconpadded512")
	require.Nil(t, err, "Err should be nil for rsa3072_falconpadded512")
	require.NotNil(t, priv, "PrivKey should not be nil for rsa3072_falconpadded512")
	signature, err := priv.SignPKCS1v15(digest, data)
	require.Nil(t, err, "Signature err should be nil for rsa3072_falconpadded512")
	require.NotNil(t, signature, "signature should not be nil for rsa3072_falconpadded512")
	err = priv.VerifyPKCS1v15(digest2, data, signature)
	require.NotNil(t, err, "Verification should fail becuase digests are mismatched")

	// test running without digest
	signature, err = priv.SignPKCS1v15(nil, data)
	require.NotNil(t, err, "Signature err should not be nil because no digest is provided")

}

// Benchmarks

// Generate benchmarks
func BenchmarkGenerateRSA(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateRSAKey(2048)
	}
}
func BenchmarkGenerateECDSA(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateECKey(Prime256v1)
	}
}
func BenchmarkGenerateRawKeyED25519(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateKey("ED25519")
	}
}
func BenchmarkGenerateED25519(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateED25519Key()
	}
}
func BenchmarkGenerateRawKeyFALCON512(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateKey("falconpadded512")
	}
}
func BenchmarkGenerateRawKeyP256FALCON512(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateKey("p256_falconpadded512")
	}
}
func BenchmarkGenerateRawKeyRSA3072FALCON512(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateKey("rsa3072_falconpadded512")
	}
}
func BenchmarkGenerateRawKeyFALCON1024(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateKey("falconpadded1024")
	}
}

func BenchmarkGenerateRawKeyP521FALCON1024(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateKey("p521_falconpadded1024")
	}
}

// Sign benchmarks
func BenchmarkSignRSA(b *testing.B) {
	priv, _ := GenerateRSAKey(2048)
	require.NotNil(b, priv, "priv should not be nil")
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A}
	digest, _ := GetDigestByName("sha256", true)
	for i := 0; i < b.N; i++ {
		priv.SignPKCS1v15(digest, data)
	}
}
func BenchmarkSignECDSA(b *testing.B) {
	priv, _ := GenerateECKey(Prime256v1)
	require.NotNil(b, priv, "priv should not be nil")
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A}
	digest, _ := GetDigestByName("sha256", true)
	for i := 0; i < b.N; i++ {
		priv.SignPKCS1v15(digest, data)
	}
}
func BenchmarkSignED25519(b *testing.B) {
	priv, _ := GenerateED25519Key()
	require.NotNil(b, priv, "priv should not be nil")
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A}
	for i := 0; i < b.N; i++ {
		priv.SignPKCS1v15(nil, data)
	}
}
func BenchmarkSignFALCON512(b *testing.B) {
	priv, _ := GenerateKey("falconpadded512")
	require.NotNil(b, priv, "priv should not be nil")
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A}
	digest, _ := GetDigestByName("sha256", true)
	for i := 0; i < b.N; i++ {
		priv.SignPKCS1v15(digest, data)
	}
}
func BenchmarkSignP256_FALCON512(b *testing.B) {
	priv, _ := GenerateKey("p256_falconpadded512")
	require.NotNil(b, priv, "priv should not be nil")
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A}
	digest, _ := GetDigestByName("sha256", true)
	for i := 0; i < b.N; i++ {
		priv.SignPKCS1v15(digest, data)
	}
}
func BenchmarkSignRSA3072FALCON512(b *testing.B) {
	priv, _ := GenerateKey("rsa3072_falconpadded512")
	require.NotNil(b, priv, "priv should not be nil")
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A}
	digest, _ := GetDigestByName("sha256", true)
	for i := 0; i < b.N; i++ {
		priv.SignPKCS1v15(digest, data)
	}
}
func BenchmarkSignFALCON1024(b *testing.B) {
	priv, _ := GenerateKey("falconpadded1024")
	require.NotNil(b, priv, "priv should not be nil")
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A}
	digest, _ := GetDigestByName("sha256", true)
	for i := 0; i < b.N; i++ {
		priv.SignPKCS1v15(digest, data)
	}
}
func BenchmarkSignP521FALCON1024(b *testing.B) {
	priv, _ := GenerateKey("p521_falconpadded1024")
	require.NotNil(b, priv, "priv should not be nil")
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A}
	digest, _ := GetDigestByName("sha256", true)
	for i := 0; i < b.N; i++ {
		priv.SignPKCS1v15(digest, data)
	}
}

// Verify benchmarks
func BenchmarkVerifyRSA(b *testing.B) {
	priv, _ := GenerateRSAKey(2048)
	require.NotNil(b, priv, "priv should not be nil")
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A}
	digest, _ := GetDigestByName("sha256", true)
	signature, _ := priv.SignPKCS1v15(digest, data)
	require.NotNil(b, signature, "signature should not be nil")
	for i := 0; i < b.N; i++ {
		priv.VerifyPKCS1v15(digest, data, signature)
	}
}
func BenchmarkVerifyECDSA(b *testing.B) {
	priv, _ := GenerateECKey(Prime256v1)
	require.NotNil(b, priv, "priv should not be nil")
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A}
	digest, _ := GetDigestByName("sha256", true)
	signature, _ := priv.SignPKCS1v15(digest, data)
	require.NotNil(b, signature, "signature should not be nil")
	for i := 0; i < b.N; i++ {
		priv.VerifyPKCS1v15(digest, data, signature)
	}
}
func BenchmarkVerifyED25519(b *testing.B) {
	priv, _ := GenerateED25519Key()
	require.NotNil(b, priv, "priv should not be nil")
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A}
	signature, _ := priv.SignPKCS1v15(nil, data)
	require.NotNil(b, signature, "signature should not be nil")
	for i := 0; i < b.N; i++ {
		priv.VerifyPKCS1v15(nil, data, signature)
	}
}
func BenchmarkVerifyFALCON512(b *testing.B) {
	priv, _ := GenerateKey("falconpadded512")
	require.NotNil(b, priv, "priv should not be nil")
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A}
	digest, _ := GetDigestByName("sha256", true)
	signature, _ := priv.SignPKCS1v15(digest, data)
	require.NotNil(b, signature, "signature should not be nil")
	for i := 0; i < b.N; i++ {
		priv.VerifyPKCS1v15(digest, data, signature)
	}
}
func BenchmarkVerifyP256FALCON512(b *testing.B) {
	priv, _ := GenerateKey("p256_falconpadded512")
	require.NotNil(b, priv, "priv should not be nil")
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A}
	digest, _ := GetDigestByName("sha256", true)
	signature, _ := priv.SignPKCS1v15(digest, data)
	require.NotNil(b, signature, "signature should not be nil")
	for i := 0; i < b.N; i++ {
		priv.VerifyPKCS1v15(digest, data, signature)
	}
}
func BenchmarkVerifyRSA3072FALCON512(b *testing.B) {
	priv, _ := GenerateKey("rsa3072_falconpadded512")
	require.NotNil(b, priv, "priv should not be nil")
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A}
	digest, _ := GetDigestByName("sha256", true)
	signature, _ := priv.SignPKCS1v15(digest, data)
	require.NotNil(b, signature, "signature should not be nil")
	for i := 0; i < b.N; i++ {
		priv.VerifyPKCS1v15(digest, data, signature)
	}
}
func BenchmarkVerifyFALCON1024(b *testing.B) {
	priv, _ := GenerateKey("falconpadded1024")
	require.NotNil(b, priv, "priv should not be nil")
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A}
	digest, _ := GetDigestByName("sha256", true)
	signature, _ := priv.SignPKCS1v15(digest, data)
	require.NotNil(b, signature, "signature should not be nil")
	for i := 0; i < b.N; i++ {
		priv.VerifyPKCS1v15(digest, data, signature)
	}
}
func BenchmarkVerifyP521FALCON1024(b *testing.B) {
	priv, _ := GenerateKey("p521_falconpadded1024")
	require.NotNil(b, priv, "priv should not be nil")
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A}
	digest, _ := GetDigestByName("sha256", true)
	signature, _ := priv.SignPKCS1v15(digest, data)
	require.NotNil(b, signature, "signature should not be nil")
	for i := 0; i < b.N; i++ {
		priv.VerifyPKCS1v15(digest, data, signature)
	}
}

// Sign and verify benchmarks
func BenchmarkSignVerifyRSA(b *testing.B) {
	priv, _ := GenerateRSAKey(2048)
	require.NotNil(b, priv, "priv should not be nil")
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A}
	digest, _ := GetDigestByName("sha256", true)
	for i := 0; i < b.N; i++ {
		signature, _ := priv.SignPKCS1v15(digest, data)
		require.NotNil(b, signature, "signature should not be nil")
		priv.VerifyPKCS1v15(digest, data, signature)
	}
}
func BenchmarkSignVerifyECDSA(b *testing.B) {
	priv, _ := GenerateECKey(Prime256v1)
	require.NotNil(b, priv, "priv should not be nil")
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A}
	digest, _ := GetDigestByName("sha256", true)
	for i := 0; i < b.N; i++ {
		signature, _ := priv.SignPKCS1v15(digest, data)
		require.NotNil(b, signature, "signature should not be nil")
		priv.VerifyPKCS1v15(digest, data, signature)
	}
}
func BenchmarkSignVerifyED25519(b *testing.B) {
	priv, _ := GenerateED25519Key()
	require.NotNil(b, priv, "priv should not be nil")
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A}
	for i := 0; i < b.N; i++ {
		signature, _ := priv.SignPKCS1v15(nil, data)
		require.NotNil(b, signature, "signature should not be nil")
		priv.VerifyPKCS1v15(nil, data, signature)
	}
}
func BenchmarkSignVerifyFALCON512(b *testing.B) {
	priv, _ := GenerateKey("falconpadded512")
	require.NotNil(b, priv, "priv should not be nil")
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A}
	digest, _ := GetDigestByName("sha256", true)
	for i := 0; i < b.N; i++ {
		signature, _ := priv.SignPKCS1v15(digest, data)
		require.NotNil(b, signature, "signature should not be nil")
		priv.VerifyPKCS1v15(digest, data, signature)
	}
}
func BenchmarkSignVerifyP256FALCON512(b *testing.B) {
	priv, _ := GenerateKey("p256_falconpadded512")
	require.NotNil(b, priv, "priv should not be nil")
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A}
	digest, _ := GetDigestByName("sha256", true)
	for i := 0; i < b.N; i++ {
		signature, _ := priv.SignPKCS1v15(digest, data)
		require.NotNil(b, signature, "signature should not be nil")
		priv.VerifyPKCS1v15(digest, data, signature)
	}
}
func BenchmarkSignVerifyRSA3072FALCON512(b *testing.B) {
	priv, _ := GenerateKey("rsa3072_falconpadded512")
	require.NotNil(b, priv, "priv should not be nil")
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A}
	digest, _ := GetDigestByName("sha256", true)
	for i := 0; i < b.N; i++ {
		signature, _ := priv.SignPKCS1v15(digest, data)
		require.NotNil(b, signature, "signature should not be nil")
		priv.VerifyPKCS1v15(digest, data, signature)
	}
}
func BenchmarkSignVerifyFALCON1024(b *testing.B) {
	priv, _ := GenerateKey("falconpadded1024")
	require.NotNil(b, priv, "priv should not be nil")
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A}
	digest, _ := GetDigestByName("sha256", true)
	for i := 0; i < b.N; i++ {
		signature, _ := priv.SignPKCS1v15(digest, data)
		require.NotNil(b, signature, "signature should not be nil")
		priv.VerifyPKCS1v15(digest, data, signature)
	}
}
func BenchmarkSignVerifyP521FALCON1024(b *testing.B) {
	priv, _ := GenerateKey("p521_falconpadded1024")
	require.NotNil(b, priv, "priv should not be nil")
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A}
	digest, _ := GetDigestByName("sha256", true)
	for i := 0; i < b.N; i++ {
		signature, _ := priv.SignPKCS1v15(digest, data)
		require.NotNil(b, signature, "signature should not be nil")
		priv.VerifyPKCS1v15(digest, data, signature)
	}
}
