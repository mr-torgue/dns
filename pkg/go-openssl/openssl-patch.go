package openssl

// #include <openssl/bn.h>
// #include <openssl/rsa.h>
// #include <openssl/ecdsa.h>
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

// GetParamsRSAPrivate returns both public and private key parameters.
// Based on: https://github.com/mr-torgue/OQS-bind/blob/main/lib/dns/opensslrsa_link.c#L52.
// TODO (mr-torgue): add support for exponent1, exponent2, and coefficient
// TODO (mr-torgue): might be nicer to use a struct to reduce the number of return values
func GetParamsRSAPrivate(key PrivateKey) (*big.Int, *big.Int, *big.Int, *big.Int, *big.Int, error) {
	E, N, err := GetParamsRSA(key)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("could not get the RSA public key parameters: %w", err)
	}
	var D *C.BIGNUM
	var P *C.BIGNUM
	var Q *C.BIGNUM
	paramNameD := C.CString(C.OSSL_PKEY_PARAM_RSA_D)
	paramNameP := C.CString(C.OSSL_PKEY_PARAM_RSA_FACTOR1)
	paramNameQ := C.CString(C.OSSL_PKEY_PARAM_RSA_FACTOR2)
	defer C.BN_free(D)
	defer C.BN_free(P)
	defer C.BN_free(Q)
	defer C.free(unsafe.Pointer(paramNameD))
	defer C.free(unsafe.Pointer(paramNameP))
	defer C.free(unsafe.Pointer(paramNameQ))

	if C.EVP_PKEY_get_bn_param(key.evpPKey(), paramNameD, &D) != 1 {
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to get RSA private exponent: %w", errorFromErrorQueue())
	}
	if C.EVP_PKEY_get_bn_param(key.evpPKey(), paramNameP, &P) != 1 {
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to get RSA prime 1: %w", errorFromErrorQueue())
	}
	if C.EVP_PKEY_get_bn_param(key.evpPKey(), paramNameQ, &Q) != 1 {
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to get RSA prime 2: %w", errorFromErrorQueue())
	}

	// convert to bigint
	DBytes := make([]byte, (C.BN_num_bits(D)+7)/8) // round up
	C.BN_bn2bin(D, (*C.uchar)(&DBytes[0]))
	DInt := new(big.Int).SetBytes(DBytes)
	if DInt == nil {
		return nil, nil, nil, nil, nil, errors.New("failed to convert D to big.Int")
	}

	PBytes := make([]byte, (C.BN_num_bits(P)+7)/8) // round up
	C.BN_bn2bin(P, (*C.uchar)(&PBytes[0]))
	PInt := new(big.Int).SetBytes(PBytes)
	if PInt == nil {
		return nil, nil, nil, nil, nil, errors.New("failed to convert P to big.Int")
	}

	QBytes := make([]byte, (C.BN_num_bits(Q)+7)/8) // round up
	C.BN_bn2bin(Q, (*C.uchar)(&QBytes[0]))
	QInt := new(big.Int).SetBytes(QBytes)
	if QInt == nil {
		return nil, nil, nil, nil, nil, errors.New("failed to convert Q to big.Int")
	}

	return E, N, DInt, PInt, QInt, nil
}

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
		return nil, nil, fmt.Errorf("failed to get RSA public exponent: %w", errorFromErrorQueue())
	}
	if C.EVP_PKEY_get_bn_param(key.evpPKey(), paramNameN, &N) != 1 {
		return nil, nil, fmt.Errorf("failed to get RSA modulus: %w", errorFromErrorQueue())
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

	return eInt, NInt, nil
}

// BuildRSAPrivateKey creates an RSA private key based on the provided parameters.
func BuildRSAPrivateKey(E *big.Int, N *big.Int, D *big.Int, P *big.Int, Q *big.Int) (PrivateKey, error) {
	if E == nil || N == nil || D == nil || P == nil || Q == nil {
		return nil, errors.New("RSA private key parameters cannot be nil")
	}
	return buildRSAKey(true, E, N, D, P, Q)
}

// BuildRSAPublicKey creates an RSA private key based on the provided parameters.
func BuildRSAPublicKey(E *big.Int, N *big.Int) (PublicKey, error) {
	if E == nil || N == nil {
		return nil, errors.New("RSA public key parameters cannot be nil")
	}
	return buildRSAKey(false, E, N, nil, nil, nil)
}

// buildRSAKey builds an RSA key based on the provided components.
// If private = true, a private key is returned if E, N, D, P, and Q are provided.
// If private = false, a public key is returned if E and N are provided.
// Based on: https://github.com/mr-torgue/OQS-bind/blob/main/lib/dns/opensslrsa_link.c#L533.
// Note: parameters are not checked here, but in the exported functions.
func buildRSAKey(private bool, E *big.Int, N *big.Int, D *big.Int, P *big.Int, Q *big.Int) (PrivateKey, error) {

	var pkey *C.EVP_PKEY
	var bld *C.OSSL_PARAM_BLD = C.OSSL_PARAM_BLD_new()
	paramNameE := C.CString(C.OSSL_PKEY_PARAM_RSA_E)
	paramNameN := C.CString(C.OSSL_PKEY_PARAM_RSA_N)
	paramNameD := C.CString(C.OSSL_PKEY_PARAM_RSA_D)
	paramNameP := C.CString(C.OSSL_PKEY_PARAM_RSA_FACTOR1)
	paramNameQ := C.CString(C.OSSL_PKEY_PARAM_RSA_FACTOR2)
	defer C.free(unsafe.Pointer(paramNameE))
	defer C.free(unsafe.Pointer(paramNameN))
	defer C.free(unsafe.Pointer(paramNameD))
	defer C.free(unsafe.Pointer(paramNameP))
	defer C.free(unsafe.Pointer(paramNameQ))

	// convert big.Int to bytes and then to BIGNUM
	if E != nil {
		eBytes := E.Bytes()
		eBN := C.BN_bin2bn((*C.uchar)(&eBytes[0]), C.int(len(eBytes)), nil)
		defer C.BN_free(eBN)
		if C.OSSL_PARAM_BLD_push_BN(bld, paramNameE, eBN) != 1 {
			return nil, fmt.Errorf("failed to set RSA public exponent: %w", errorFromErrorQueue())
		}
	}
	if N != nil {
		nBytes := N.Bytes()
		nBN := C.BN_bin2bn((*C.uchar)(&nBytes[0]), C.int(len(nBytes)), nil)
		defer C.BN_free(nBN)
		if C.OSSL_PARAM_BLD_push_BN(bld, paramNameN, nBN) != 1 {
			return nil, fmt.Errorf("failed to set RSA modulus: %w", errorFromErrorQueue())
		}
	}
	if D != nil {
		dBytes := D.Bytes()
		dBN := C.BN_bin2bn((*C.uchar)(&dBytes[0]), C.int(len(dBytes)), nil)
		defer C.BN_free(dBN)
		if C.OSSL_PARAM_BLD_push_BN(bld, paramNameD, dBN) != 1 {
			return nil, fmt.Errorf("failed to set RSA private exponent: %w", errorFromErrorQueue())
		}
	}
	if P != nil {
		pBytes := P.Bytes()
		pBN := C.BN_bin2bn((*C.uchar)(&pBytes[0]), C.int(len(pBytes)), nil)
		defer C.BN_free(pBN)
		if C.OSSL_PARAM_BLD_push_BN(bld, paramNameP, pBN) != 1 {
			return nil, fmt.Errorf("failed to set RSA prime 1: %w", errorFromErrorQueue())
		}
	}
	if Q != nil {
		qBytes := Q.Bytes()
		qBN := C.BN_bin2bn((*C.uchar)(&qBytes[0]), C.int(len(qBytes)), nil)
		defer C.BN_free(qBN)
		if C.OSSL_PARAM_BLD_push_BN(bld, paramNameQ, qBN) != 1 {
			return nil, fmt.Errorf("failed to set RSA prime 2: %w", errorFromErrorQueue())
		}
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
		return nil, fmt.Errorf("failed to create key context: %w", errorFromErrorQueue())
	}
	defer C.EVP_PKEY_CTX_free(ctx)

	// create the key and return
	if C.EVP_PKEY_fromdata_init(ctx) != 1 {
		return nil, fmt.Errorf("failed to initialize key from data: %w", errorFromErrorQueue())
	}
	var status int
	// check if private or not
	if private {
		status = int(C.EVP_PKEY_fromdata(ctx, &pkey, C.EVP_PKEY_KEYPAIR, params))
	} else {
		status = int(C.EVP_PKEY_fromdata(ctx, &pkey, C.EVP_PKEY_PUBLIC_KEY, params))
	}
	if status != 1 {
		return nil, fmt.Errorf("failed to create key from data: %w", errorFromErrorQueue())
	}
	return pKeyFromKey(pkey), nil
}

// GetECDSAPrivateKey returns the private key of an ECDSA cipher in big int format.
// Based on: https://github.com/mr-torgue/OQS-bind/blob/b9bb22a50dd905c47301c633c61234c4db9c36b7/lib/dns/opensslecdsa_link.c#L484
func GetECDSAPrivateKey(key PrivateKey) (*big.Int, error) {
	if key == nil {
		return nil, errors.New("key should not be nil")
	}
	pkey := key.evpPKey()
	var priv *C.BIGNUM

	paramName := C.CString(C.OSSL_PKEY_PARAM_PRIV_KEY)
	defer C.free(unsafe.Pointer(paramName))
	defer C.BN_free(priv)

	if C.EVP_PKEY_get_bn_param(pkey, paramName, &priv) != 1 {
		return nil, fmt.Errorf("failed to get private key parameter: %w", errorFromErrorQueue())
	}

	buf := make([]byte, (C.BN_num_bits(priv)+7)/8) // round up
	C.BN_bn2bin(priv, (*C.uchar)(&buf[0]))
	D := new(big.Int).SetBytes(buf)
	if D == nil {
		return nil, errors.New("failed to convert private key to big.Int")
	}
	return D, nil
}

// GetECDSAPublicKey returns the X and Y params of ECDSA.
// Based on: https://github.com/mr-torgue/OQS-bind/blob/main/lib/dns/opensslecdsa_link.c#L255
func GetECDSAPublicKey(key PublicKey) (*big.Int, *big.Int, error) {
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
		return nil, nil, fmt.Errorf("failed to get ECDSA X: %w", errorFromErrorQueue())

	}
	if C.EVP_PKEY_get_bn_param(key.evpPKey(), paramNameY, &Y) != 1 {
		return nil, nil, fmt.Errorf("failed to get ECDSA Y: %w", errorFromErrorQueue())
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

func BuildECDSAPrivateKey(D *big.Int, groupname string) (PrivateKey, error) {
	if D == nil {
		return nil, errors.New("private key parameter cannot be nil")
	}
	dBytes := D.Bytes()
	return buildECDSAKey(true, dBytes, groupname)
}

// BuildECDSAPublicKeyFromParams returns the public key for ECDSA given its key (X, Y) and curve name.
func BuildECDSAPublicKeyFromParams(X *big.Int, Y *big.Int, pointSize int, groupname string) (PublicKey, error) {
	if X == nil || Y == nil {
		return nil, errors.New("public key parameters cannot be nil")
	}
	// make sure xBytes and yBytes are always pointSize long
	xBytes := make([]byte, pointSize)
	yBytes := make([]byte, pointSize)
	copy(xBytes[pointSize-len(X.Bytes()):], X.Bytes())
	copy(yBytes[pointSize-len(Y.Bytes()):], Y.Bytes())
	key := make([]byte, len(xBytes)+len(yBytes))
	copy(key, xBytes)
	copy(key[len(xBytes):], yBytes)
	return buildECDSAKey(false, key, groupname)
}

func BuildECDSAPublicKey(key []byte, groupname string) (PublicKey, error) {
	if key == nil {
		return nil, errors.New("key cannot be nil")
	}
	if len(key) == 0 {
		return nil, errors.New("key cannot be empty")
	}
	return buildECDSAKey(false, key, groupname)
}

// buildECDSAKey returns a ECDSA key.
// If private = true, a private key is returned.
// If private = false, a public key is returned.
// Based on: https://github.com/mr-torgue/OQS-bind/blob/main/lib/dns/opensslecdsa_link.c#L394.
// TODO(mr-torgue): do not use the groupname since it is error prone
func buildECDSAKey(private bool, key []byte, groupname string) (PrivateKey, error) {
	var pkey *C.EVP_PKEY
	var bld *C.OSSL_PARAM_BLD = C.OSSL_PARAM_BLD_new()
	if bld == nil {
		return nil, fmt.Errorf("failed to create parameter builder: %w", errorFromErrorQueue())
	}
	defer C.OSSL_PARAM_BLD_free(bld)
	paramGroupName := C.CString(C.OSSL_PKEY_PARAM_GROUP_NAME)
	paramNameKey := C.CString(C.OSSL_PKEY_PARAM_PUB_KEY)
	groupnameCString := C.CString(groupname)
	defer C.free(unsafe.Pointer(paramGroupName))
	defer C.free(unsafe.Pointer(paramNameKey))
	defer C.free(unsafe.Pointer(groupnameCString))

	// set the groupname: "prime256v1", "secp384r1", "secp521r1"
	if C.OSSL_PARAM_BLD_push_utf8_string(bld, paramGroupName, groupnameCString, 10) != 1 {
		return nil, fmt.Errorf("failed to set groupname: %s (%w)", C.GoString(groupnameCString), errorFromErrorQueue())
	}
	if private {
		groupNid := C.OBJ_txt2nid(groupnameCString)
		if groupNid == C.NID_undef {
			return nil, fmt.Errorf("invalid curve name: %w", errorFromErrorQueue())
		}
		group := C.EC_GROUP_new_by_curve_name(groupNid)
		if group == nil {
			return nil, fmt.Errorf("failed to create EC group: %w", errorFromErrorQueue())
		}
		defer C.EC_GROUP_free(group)

		priv := C.BN_bin2bn((*C.uchar)(&key[0]), C.int(len(key)), nil)
		if priv == nil {
			return nil, fmt.Errorf("failed to convert private key to BN: %w", errorFromErrorQueue())
		}
		defer C.BN_free(priv)

		if C.OSSL_PARAM_BLD_push_BN(bld, C.CString(C.OSSL_PKEY_PARAM_PRIV_KEY), priv) != 1 {
			return nil, fmt.Errorf("failed to set private key parameter: %w", errorFromErrorQueue())
		}

		pubkey := C.EC_POINT_new(group)
		if pubkey == nil {
			return nil, fmt.Errorf("failed to create EC point: %w", errorFromErrorQueue())
		}
		defer C.EC_POINT_free(pubkey)

		if C.EC_POINT_mul(group, pubkey, priv, nil, nil, nil) != 1 {
			return nil, fmt.Errorf("failed to generate public key: %w", errorFromErrorQueue())
		}

		buf := make([]byte, C.EC_POINT_point2oct(group, pubkey, C.POINT_CONVERSION_UNCOMPRESSED, nil, 0, nil))
		if len(buf) == 0 {
			return nil, fmt.Errorf("failed to convert public key to octet string: %w", errorFromErrorQueue())
		}

		keyLen := C.EC_POINT_point2oct(group, pubkey, C.POINT_CONVERSION_UNCOMPRESSED, (*C.uchar)(&buf[0]), C.size_t(len(buf)), nil)
		if keyLen == 0 {
			return nil, fmt.Errorf("failed to convert public key to octet string: %w", errorFromErrorQueue())
		}
	} else {
		// Add POINT_CONVERSION_UNCOMPRESSED prefix (0x04)
		newKey := make([]byte, 1+len(key))
		newKey[0] = 0x04
		copy(newKey[1:], key)
		// set public key
		if C.OSSL_PARAM_BLD_push_octet_string(bld, paramNameKey, unsafe.Pointer(&newKey[0]), C.size_t(len(newKey))) != 1 {
			return nil, fmt.Errorf("failed to set public key parameter: %w", errorFromErrorQueue())
		}
	}

	// build the ctx
	params := C.OSSL_PARAM_BLD_to_param(bld)
	if params == nil {
		return nil, fmt.Errorf("failed to build parameters: %w", errorFromErrorQueue())
	}
	defer C.OSSL_PARAM_free(params)
	ECName := C.CString("EC")
	defer C.free(unsafe.Pointer(ECName))
	ctx := C.EVP_PKEY_CTX_new_from_name(nil, ECName, nil)
	if ctx == nil {
		return nil, fmt.Errorf("failed to create key context: %w", errorFromErrorQueue())
	}
	defer C.EVP_PKEY_CTX_free(ctx)

	// create the key and return
	if C.EVP_PKEY_fromdata_init(ctx) != 1 {
		return nil, fmt.Errorf("failed to initialize key from data: %w", errorFromErrorQueue())
	}
	var status int
	// check if private or not
	if private {
		status = int(C.EVP_PKEY_fromdata(ctx, &pkey, C.EVP_PKEY_KEYPAIR, params))
	} else {
		status = int(C.EVP_PKEY_fromdata(ctx, &pkey, C.EVP_PKEY_PUBLIC_KEY, params))
	}
	if status != 1 {
		return nil, fmt.Errorf("failed to create key from data: %w", errorFromErrorQueue())
	}

	return pKeyFromKey(pkey), nil
}

// RAW PRIVATE/PUBLIC KEY FUNCTIONS
// convert public/private keys to buffers and import raw buffers.

// GetRawPrivateKey returns the raw private key.
// Based on https://github.com/mr-torgue/OQS-bind/blob/b9bb22a50dd905c47301c633c61234c4db9c36b7/lib/dns/openssleddsa_link.c#L89.
// Note that this only works for certain ciphers: https://docs.openssl.org/3.6/man3/EVP_PKEY_new/#description
func GetRawPrivateKey(key PrivateKey) ([]byte, error) {
	if key == nil {
		return nil, errors.New("key should not be nil")
	}
	var len C.size_t

	// get the required length for the raw key
	if C.EVP_PKEY_get_raw_private_key(key.evpPKey(), nil, &len) != 1 {
		return nil, fmt.Errorf("failed to get raw key length: %w", errorFromErrorQueue())
	}

	// allocate a buffer of the correct size
	buf := C.malloc(C.size_t(len))
	defer C.free(unsafe.Pointer(buf))

	// fill the buffer with the raw key
	if C.EVP_PKEY_get_raw_private_key(key.evpPKey(), (*C.uchar)(buf), &len) != 1 {
		return nil, fmt.Errorf("failed to get raw key: %w", errorFromErrorQueue())
	}

	// Convert the C buffer to a Go byte slice
	if buf != nil && len > 0 {
		rawKey := C.GoBytes(unsafe.Pointer(buf), C.int(len))
		return rawKey, nil
	}

	return nil, errors.New("invalid buffer or length")
}

// GetRawPublicKey returns the raw public key.
// Based on https://github.com/mr-torgue/OQS-bind/blob/b9bb22a50dd905c47301c633c61234c4db9c36b7/lib/dns/openssleddsa_link.c#L89.
// Note that this only works for certain ciphers: https://docs.openssl.org/3.6/man3/EVP_PKEY_new/#description
func GetRawPublicKey(key PublicKey) ([]byte, error) {
	if key == nil {
		return nil, errors.New("key should not be nil")
	}
	var len C.size_t

	// get the required length for the raw key
	if C.EVP_PKEY_get_raw_public_key(key.evpPKey(), nil, &len) != 1 {
		return nil, fmt.Errorf("failed to get raw key length: %w", errorFromErrorQueue())
	}

	// allocate a buffer of the correct size
	buf := C.malloc(C.size_t(len))
	defer C.free(unsafe.Pointer(buf))

	// fill the buffer with the raw key
	if C.EVP_PKEY_get_raw_public_key(key.evpPKey(), (*C.uchar)(buf), &len) != 1 {
		return nil, fmt.Errorf("failed to get raw key: %w", errorFromErrorQueue())
	}

	// Convert the C buffer to a Go byte slice
	if buf != nil && len > 0 {
		rawKey := C.GoBytes(unsafe.Pointer(buf), C.int(len))
		return rawKey, nil
	}

	return nil, errors.New("invalid buffer or length")
}

// BuildRawPrivateKey builds a key from a raw buffer.
func BuildRawPrivateKey(bytes []byte, algName string) (PrivateKey, error) {
	if bytes == nil {
		return nil, errors.New("bytes for BuildRawPrivateKey should not be nil")
	}
	if len(bytes) == 0 {
		return nil, errors.New("bytes slice cannot be empty")
	}
	var pkey *C.EVP_PKEY
	algNameC := C.CString(algName)
	defer C.free(unsafe.Pointer(algNameC))
	pkey = C.EVP_PKEY_new_raw_private_key_ex(nil, algNameC, nil, (*C.uchar)(&bytes[0]), C.size_t(len(bytes)))
	if pkey == nil {
		return nil, fmt.Errorf("failed to create key from raw private key for algorithm %s (%w)", algName, errorFromErrorQueue())
	}

	return pKeyFromKey(pkey), nil
}

// BuildRawPublicKey builds a key from a raw buffer.
func BuildRawPublicKey(bytes []byte, algName string) (PublicKey, error) {
	if bytes == nil {
		return nil, errors.New("bytes for BuildRawPublicKey should not be nil")
	}
	if len(bytes) == 0 {
		return nil, errors.New("bytes slice cannot be empty")
	}
	var pkey *C.EVP_PKEY
	algNameC := C.CString(algName)
	defer C.free(unsafe.Pointer(algNameC))
	pkey = C.EVP_PKEY_new_raw_public_key_ex(nil, algNameC, nil, (*C.uchar)(&bytes[0]), C.size_t(len(bytes)))
	if pkey == nil {
		return nil, fmt.Errorf("failed to create key from raw public key for algorithm %s (%w)", algName, errorFromErrorQueue())
	}

	return pKeyFromKey(pkey), nil
}

// GENERIC KEY GENERATION

// newPKeyContextFromName is similar to newPKeyContextFromKeyType but using the algorithm name instead.
// TODO(mr-torgue): use AddCleanup instead of SetFinalizer and explicitly free the context
func newPKeyContextFromName(name string) (*pkeyCtx, error) {
	if err := ensureErrorQueueIsClear(); err != nil {
		return nil, fmt.Errorf("failed creating new pKeyContext from type: %w", err)
	}
	nameC := C.CString(name)
	defer C.free(unsafe.Pointer(nameC))
	ctx := C.EVP_PKEY_CTX_new_from_name(nil, nameC, nil)
	if ctx == nil {
		return nil, fmt.Errorf("failed to create pKeyCtx: %w", errorFromErrorQueue())
	}
	keyCtx := &pkeyCtx{ctx: ctx}
	runtime.SetFinalizer(keyCtx, func(c *pkeyCtx) {
		if c.ctx != nil {
			C.EVP_PKEY_CTX_free(c.ctx)
			c.ctx = nil
		}
	})
	/*
		runtime.AddCleanup(keyCtx, func(cPtr *C.EVP_PKEY_CTX) {
			if cPtr != nil {
				C.EVP_PKEY_CTX_free(cPtr)
			}
		}, keyCtx.ctx)*/
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
