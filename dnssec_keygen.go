package dns

import (
	"math/big"

	"github.com/pexip/go-openssl"
)

// Generate generates a DNSKEY of the given bit size.
// The public part is put inside the DNSKEY record.
// The Algorithm in the key must be set as this will define
// what kind of DNSKEY will be generated.
// The ECDSA algorithms imply a fixed keysize, in that case
// bits should be set to the size of the algorithm.
// TODO(mr-torgue): add support for PQC
func (k *DNSKEY) Generate(bits int) (openssl.PrivateKey, error) {
	switch k.Algorithm {
	case RSASHA1, RSASHA256, RSASHA1NSEC3SHA1:
		if bits < 512 || bits > 4096 {
			return nil, ErrKeySize
		}
	case RSASHA512:
		if bits < 1024 || bits > 4096 {
			return nil, ErrKeySize
		}
	case ECDSAP256SHA256:
		if bits != 256 {
			return nil, ErrKeySize
		}
	case ECDSAP384SHA384:
		if bits != 384 {
			return nil, ErrKeySize
		}
	case ED25519:
		if bits != 256 {
			return nil, ErrKeySize
		}
	case FALCON512:
		if bits != 666 {
			return nil, ErrKeySize
		}
	default:
		return nil, ErrAlg
	}
	switch k.Algorithm {
	case RSASHA1, RSASHA256, RSASHA512, RSASHA1NSEC3SHA1:
		// TODO(mr-torgue): replace with EVP_PKEY_keygen (https://docs.openssl.org/3.0/man3/EVP_PKEY_keygen/#synopsis)
		//priv, err := rsa.GenerateKey(rand.Reader, bits)
		priv, err := openssl.GenerateRSAKey(bits)
		if err != nil {
			return nil, err
		}
		E, N, err := openssl.GetParamsRSA(priv)
		if err != nil {
			return nil, err
		}
		k.setPublicKeyRSA(E, N)
		return priv, nil
	case ECDSAP256SHA256, ECDSAP384SHA384:
		var c openssl.EllipticCurve
		//var c elliptic.Curve
		switch k.Algorithm {
		case ECDSAP256SHA256:
			c = openssl.Prime256v1
		case ECDSAP384SHA384:
			c = openssl.Secp384r1
		}
		//priv, err := ecdsa.GenerateKey(c, rand.Reader)
		priv, err := openssl.GenerateECKey(c)
		if err != nil {
			return nil, err
		}
		X, Y, err := openssl.GetParamsECDSA(priv)
		if err != nil {
			return nil, err
		}
		k.setPublicKeyECDSA(X, Y)
		return priv, nil
	case ED25519:
		//pub, priv, err := ed25519.GenerateKey(rand.Reader)
		priv, err := openssl.GenerateED25519Key()
		if err != nil {
			return nil, err
		}
		k.setPublicKeyGeneric(priv)
		return priv, nil
	default:
		return nil, ErrAlg
	}
}

// Set the public key (the value E and N)
func (k *DNSKEY) setPublicKeyRSA(_E *big.Int, _N *big.Int) bool {
	if _E == nil || _N == nil {
		return false
	}
	buf := exponentToBuf(_E)
	buf = append(buf, _N.Bytes()...)
	k.PublicKey = toBase64(buf)
	return true
}

// Set the public key for Elliptic Curves
func (k *DNSKEY) setPublicKeyECDSA(_X, _Y *big.Int) bool {
	if _X == nil || _Y == nil {
		return false
	}
	var intlen int
	switch k.Algorithm {
	case ECDSAP256SHA256:
		intlen = 32
	case ECDSAP384SHA384:
		intlen = 48
	}
	k.PublicKey = toBase64(curveToBuf(_X, _Y, intlen))
	return true
}

/*
// Set the public key for Ed25519
func (k *DNSKEY) setPublicKeyED25519(_K ed25519.PublicKey) bool {
	if _K == nil {
		return false
	}
	k.PublicKey = toBase64(_K)
	return true
}*/

// setPublicKeyGeneric encodes the raw public key using base64
func (k *DNSKEY) setPublicKeyGeneric(_K openssl.PublicKey) bool {
	if _K == nil {
		return false
	}
	bytes, err := openssl.GetRawKey(_K)
	if err != nil {
		return false
	}
	k.PublicKey = toBase64(bytes)
	return true
}

// Set the public key (the values E and N) for RSA
// RFC 3110: Section 2. RSA Public KEY Resource Records
func exponentToBuf(_E *big.Int) []byte {
	var buf []byte
	i := _E.Bytes()
	if len(i) < 256 {
		buf = make([]byte, 1, 1+len(i))
		buf[0] = uint8(len(i))
	} else {
		buf = make([]byte, 3, 3+len(i))
		buf[0] = 0
		buf[1] = uint8(len(i) >> 8)
		buf[2] = uint8(len(i))
	}
	buf = append(buf, i...)
	return buf
}

// Set the public key for X and Y for Curve. The two
// values are just concatenated.
func curveToBuf(_X, _Y *big.Int, intlen int) []byte {
	buf := intToBytes(_X, intlen)
	buf = append(buf, intToBytes(_Y, intlen)...)
	return buf
}
