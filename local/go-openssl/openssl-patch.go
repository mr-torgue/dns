package openssl

// #include <openssl/bn.h>
// #include <openssl/rsa.h>
// #include <openssl/evp.h>
// #include <openssl/opensslv.h>
// #include <openssl/core_dispatch.h>
// #include <openssl/core_names.h>
// #include <openssl/param_build.h>
// #include <openssl/core.h>
import "C"
import (
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"unsafe"
)

// GetParamsRSA returns the public key for RSA: (e, N).
// Based on: https://github.com/mr-torgue/OQS-bind/blob/main/lib/dns/opensslrsa_link.c#L52.
// Note: only works on OpenSSL version 3.x.
func GetParamsRSA(key PublicKey) (*big.Int, *big.Int, error) {
	if key == nil {
		return nil, nil, errors.New("key should not be nil")
	}
	var e *C.BIGNUM
	var N *C.BIGNUM
	paramNameE := C.CString(C.OSSL_PKEY_PARAM_RSA_E)
	paramNameN := C.CString(C.OSSL_PKEY_PARAM_RSA_N)
	defer C.BN_free(e)
	defer C.BN_free(N)
	defer C.free(unsafe.Pointer(paramNameE))
	defer C.free(unsafe.Pointer(paramNameN))

	if C.EVP_PKEY_get_bn_param(key.evpPKey(), paramNameE, &e) != 1 {
		return nil, nil, errors.New("failed to get RSA public exponent")
	}
	if C.EVP_PKEY_get_bn_param(key.evpPKey(), paramNameN, &N) != 1 {
		return nil, nil, errors.New("failed to get RSA modulus")
	}

	// convert to bigint
	eBytes := make([]byte, (C.BN_num_bits(e)+7)/8) // round up
	C.BN_bn2bin(e, (*C.uchar)(&eBytes[0]))
	eInt := new(big.Int).SetBytes(eBytes)
	if eInt == nil {
		return nil, nil, errors.New("failed to convert e to big.Int")
	}

	NBytes := make([]byte, (C.BN_num_bits(N)+7)/8) // round up
	C.BN_bn2bin(N, (*C.uchar)(&NBytes[0]))
	NInt := new(big.Int).SetBytes(NBytes)
	if NInt == nil {
		return nil, nil, errors.New("failed to convert N to big.Int")
	}

	// REMOVED: used hex before
	//eHex := C.GoString(C.BN_bn2hex(e))
	//eInt, ok := new(big.Int).SetString(eHex, 16)
	//if !ok {
	//	return nil, nil, errors.New("failed to convert e to big.Int")
	//}

	//NHex := C.GoString(C.BN_bn2hex(N))
	//NInt, ok := new(big.Int).SetString(NHex, 16)
	//if !ok {
	//	return nil, nil, errors.New("failed to convert N to big.Int")
	//}

	return eInt, NInt, nil
}

// BuildRSAKey builds an RSA public key based on the parameters E and N.
// Based on: https://github.com/mr-torgue/OQS-bind/blob/main/lib/dns/opensslrsa_link.c#L533.
func BuildRSAKey(E *big.Int, N *big.Int) (PublicKey, error) {
	var pkey *C.EVP_PKEY
	var bld *C.OSSL_PARAM_BLD = C.OSSL_PARAM_BLD_new()
	paramNameE := C.CString(C.OSSL_PKEY_PARAM_RSA_E)
	paramNameN := C.CString(C.OSSL_PKEY_PARAM_RSA_N)
	defer C.free(unsafe.Pointer(paramNameE))
	defer C.free(unsafe.Pointer(paramNameN))

	// convert big.Int to bytes and then to BIGNUM
	eBytes := E.Bytes()
	eBN := C.BN_bin2bn((*C.uchar)(&eBytes[0]), C.int(len(eBytes)), nil)
	defer C.BN_free(eBN)

	nBytes := N.Bytes()
	nBN := C.BN_bin2bn((*C.uchar)(&nBytes[0]), C.int(len(nBytes)), nil)
	defer C.BN_free(nBN)

	// set the parameters
	if C.OSSL_PARAM_BLD_push_BN(bld, paramNameN, nBN) != 1 {
		return nil, errors.New("failed to set RSA modulus")
	}
	if C.OSSL_PARAM_BLD_push_BN(bld, paramNameE, eBN) != 1 {
		return nil, errors.New("failed to set RSA public exponent")
	}

	// build the ctx
	params := C.OSSL_PARAM_BLD_to_param(bld)
	if params == nil {
		return nil, errors.New("failed to build parameters")
	}
	defer C.OSSL_PARAM_free(params)
	RSAName := C.CString("RSA")
	defer C.free(unsafe.Pointer(RSAName))
	ctx := C.EVP_PKEY_CTX_new_from_name(nil, RSAName, nil)
	if ctx == nil {
		return nil, errors.New("failed to create key context")
	}
	defer C.EVP_PKEY_CTX_free(ctx)

	// create the key and return
	if C.EVP_PKEY_fromdata_init(ctx) != 1 {
		return nil, errors.New("failed to initialize key from data")
	}
	if C.EVP_PKEY_fromdata(ctx, &pkey, C.EVP_PKEY_PUBLIC_KEY, params) != 1 {
		return nil, errors.New("failed to create key from data")
	}
	return pKeyFromKey(pkey), nil
}

// GetParamsECDSA returns the X and Y params of ECDSA.
// Based on: https://github.com/mr-torgue/OQS-bind/blob/main/lib/dns/opensslecdsa_link.c#L255
func GetParamsECDSA(key PublicKey) (*big.Int, *big.Int, error) {
	if key == nil {
		return nil, nil, errors.New("key should not be nil")
	}
	var X *C.BIGNUM
	var Y *C.BIGNUM
	paramNameX := C.CString(C.OSSL_PKEY_PARAM_EC_PUB_X)
	paramNameY := C.CString(C.OSSL_PKEY_PARAM_EC_PUB_Y)
	defer C.BN_free(X)
	defer C.BN_free(Y)
	defer C.free(unsafe.Pointer(paramNameX))
	defer C.free(unsafe.Pointer(paramNameY))

	if C.EVP_PKEY_get_bn_param(key.evpPKey(), paramNameX, &X) != 1 {
		return nil, nil, errors.New("failed to get ECDSA X")

	}
	if C.EVP_PKEY_get_bn_param(key.evpPKey(), paramNameY, &Y) != 1 {
		return nil, nil, errors.New("failed to get ECDSA Y")
	}

	// conver to bigint
	XHex := C.GoString(C.BN_bn2hex(X))
	XInt, ok := new(big.Int).SetString(XHex, 16)
	if !ok {
		return nil, nil, errors.New("failed to convert X to big.Int")
	}

	YHex := C.GoString(C.BN_bn2hex(Y))
	YInt, ok := new(big.Int).SetString(YHex, 16)
	if !ok {
		return nil, nil, errors.New("failed to convert Y to big.Int")
	}

	return XInt, YInt, nil
}

// BuildECDSAKey returns the public key for ECDSA given its key (X, Y)
// Based on: https://github.com/mr-torgue/OQS-bind/blob/main/lib/dns/opensslecdsa_link.c#L394.
// TODO(mr-torgue): do not use the groupname since it is error prone
func BuildECDSAKey(key []byte, groupname string) (PublicKey, error) {
	var pkey *C.EVP_PKEY
	var bld *C.OSSL_PARAM_BLD = C.OSSL_PARAM_BLD_new()
	if bld == nil {
		return nil, errors.New("failed to create parameter builder")
	}
	defer C.OSSL_PARAM_BLD_free(bld)
	paramGroupName := C.CString(C.OSSL_PKEY_PARAM_GROUP_NAME)
	paramNameKey := C.CString(C.OSSL_PKEY_PARAM_PUB_KEY)
	groupnameCString := C.CString(groupname)
	defer C.free(unsafe.Pointer(paramGroupName))
	defer C.free(unsafe.Pointer(paramNameKey))
	defer C.free(unsafe.Pointer(groupnameCString))
	// Add POINT_CONVERSION_UNCOMPRESSED prefix (0x04)
	newKey := make([]byte, 1+len(key))
	newKey[0] = 0x04
	copy(newKey[1:], key)

	// set the groupname: "prime256v1", "secp384r1", "secp521r1"
	if C.OSSL_PARAM_BLD_push_utf8_string(bld, paramGroupName, groupnameCString, 10) != 1 {
		return nil, errors.New(fmt.Sprintf("failed to set groupname: %s", C.GoString(groupnameCString)))

	}

	// set public key
	if C.OSSL_PARAM_BLD_push_octet_string(bld, paramNameKey, unsafe.Pointer(&newKey[0]), C.size_t(len(newKey))) != 1 {
		return nil, errors.New("failed to set public key parameter")
	}

	// build the ctx
	params := C.OSSL_PARAM_BLD_to_param(bld)
	if params == nil {
		return nil, errors.New("failed to build parameters")
	}
	defer C.OSSL_PARAM_free(params)
	ECName := C.CString("EC")
	defer C.free(unsafe.Pointer(ECName))
	ctx := C.EVP_PKEY_CTX_new_from_name(nil, ECName, nil)
	if ctx == nil {
		return nil, errors.New("failed to create key context")
	}
	defer C.EVP_PKEY_CTX_free(ctx)

	// create the key and return
	if C.EVP_PKEY_fromdata_init(ctx) != 1 {
		return nil, errors.New("failed to initialize key from data")
	}
	if C.EVP_PKEY_fromdata(ctx, &pkey, C.EVP_PKEY_PUBLIC_KEY, params) != 1 || pkey == nil {
		return nil, errors.New("failed to create key from data")
	}

	return pKeyFromKey(pkey), nil
}

// GetRawKey returns the raw public key.
// Note that this only works for certain ciphers: https://docs.openssl.org/3.6/man3/EVP_PKEY_new/#description
func GetRawKey(key PublicKey) ([]byte, error) {
	if key == nil {
		return nil, errors.New("key should not be nil")
	}
	var len C.size_t

	// First call: Get the required length for the raw key
	if C.EVP_PKEY_get_raw_public_key(key.evpPKey(), nil, &len) != 1 {
		return nil, errors.New("failed to get raw key length")
	}

	// Allocate a buffer of the correct size
	buf := C.malloc(C.size_t(len))
	defer C.free(unsafe.Pointer(buf))

	// Second call: Fill the buffer with the raw key
	if C.EVP_PKEY_get_raw_public_key(
		key.evpPKey(),
		(*C.uchar)(buf), // buf is already a *C.void, so cast directly to *C.uchar
		&len,
	) != 1 {
		return nil, errors.New("failed to get raw key")
	}

	// Convert the C buffer to a Go byte slice
	if buf != nil && len > 0 {
		rawKey := C.GoBytes(unsafe.Pointer(buf), C.int(len))
		return rawKey, nil
	}

	return nil, errors.New("invalid buffer or length")
}

// BuildRawKey builds a key from a raw buffer.
func BuildRawKey(bytes []byte, algName string) (PublicKey, error) {
	if bytes == nil {
		return nil, errors.New("bytes for BuildRawKey should not be nil")
	}
	if len(bytes) == 0 {
		return nil, errors.New("bytes slice cannot be empty")
	}
	var pkey *C.EVP_PKEY
	algNameC := C.CString(algName)
	defer C.free(unsafe.Pointer(algNameC))
	pkey = C.EVP_PKEY_new_raw_public_key_ex(nil, algNameC, nil, (*C.uchar)(&bytes[0]), C.size_t(len(bytes)))
	if pkey == nil {
		return nil, fmt.Errorf("failed to create key from raw public key for algorithm %s", algName)
	}

	return pKeyFromKey(pkey), nil
}

// newPKeyContextFromName is similar to newPKeyContextFromKeyType but using the algorithm name instead.
func newPKeyContextFromName(name string) (*pkeyCtx, error) {
	if err := ensureErrorQueueIsClear(); err != nil {
		return nil, fmt.Errorf("failed creating new pKeyContext from type: %w", err)
	}
	nameC := C.CString(name)
	defer C.free(unsafe.Pointer(nameC))
	ctx := C.EVP_PKEY_CTX_new_from_name(nil, nameC, nil)
	if ctx == nil {
		return nil, errors.New("failed to create pKeyCtx")
	}
	keyCtx := &pkeyCtx{ctx: ctx}
	runtime.SetFinalizer(keyCtx, func(c *pkeyCtx) {
		if c.ctx != nil {
			C.EVP_PKEY_CTX_free(c.ctx)
			c.ctx = nil
		}
	})
	return keyCtx, nil
}

func NewPKeyGenerationContextFromName(name string) (PrivateKeyGenerationContext, error) {
	ctx, err := newPKeyContextFromName(name)
	if err != nil {
		return nil, err
	}
	if err := ensureErrorQueueIsClear(); err != nil {
		return nil, fmt.Errorf("failed initialise keygen: %w", err)
	}
	if int(C.EVP_PKEY_keygen_init(ctx.evpCtx())) != 1 {
		return nil, fmt.Errorf("failed initialise keygen: %w", errorFromErrorQueue())
	}
	return &pkeyGenCtx{*ctx}, nil
}

// GenerateKey creates a key based on the provided name string.
// Inspired on key.go.
// Examples: ED25519, rsa3072_falconpadded512
// Info:
//   - https://docs.openssl.org/3.2/man7/OSSL_PROVIDER-default/#key-derivation-function-kdf
//   - https://github.com/open-quantum-safe/oqs-provider/blob/5fd81fb47a277d827d9a1a6ee27a12af5c1b1a6e/ALGORITHMS.md
func GenerateKey(name string) (PrivateKey, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	keyCtx, err := NewPKeyGenerationContextFromName(name)
	if err != nil {
		return nil, err
	}
	key, err := keyCtx.Generate()
	if err != nil {
		return nil, err
	}
	return key, nil
}
