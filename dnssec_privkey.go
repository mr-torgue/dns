package dns

import (
	"math/big"
	"strconv"

	"github.com/mr-torgue/dns/pkg/go-openssl"
)

const format = "Private-key-format: v1.3\n"

var bigIntOne = big.NewInt(1)

// PrivateKeyString converts a PrivateKey to a string. This string has the same
// format as the private-key-file of BIND9 (Private-key-format: v1.3).
// It needs some info from the key (the algorithm), so its a method of the DNSKEY.
// It supports *rsa.PrivateKey, *ecdsa.PrivateKey and ed25519.PrivateKey.
func (r *DNSKEY) PrivateKeyString(p openssl.PrivateKey) string {
	algorithm := strconv.Itoa(int(r.Algorithm))
	algorithm += " (" + AlgorithmToString[r.Algorithm] + ")"

	switch r.Algorithm {
	case RSASHA1, RSASHA1NSEC3SHA1, RSASHA256, RSASHA512:
		E, N, D, P, Q, err := openssl.GetParamsRSAPrivate(p)
		if err != nil {
			return ""
		}
		publicExponent := toBase64(E.Bytes())
		modulus := toBase64(N.Bytes())
		privateExponent := toBase64(D.Bytes())
		prime1 := toBase64(P.Bytes())
		prime2 := toBase64(Q.Bytes())
		// Calculate Exponent1/2 and Coefficient as per: http://en.wikipedia.org/wiki/RSA#Using_the_Chinese_remainder_algorithm
		// and from: http://code.google.com/p/go/issues/detail?id=987
		p1 := new(big.Int).Sub(P, bigIntOne)
		q1 := new(big.Int).Sub(Q, bigIntOne)
		exp1 := new(big.Int).Mod(D, p1)
		exp2 := new(big.Int).Mod(D, q1)
		coeff := new(big.Int).ModInverse(Q, P)

		exponent1 := toBase64(exp1.Bytes())
		exponent2 := toBase64(exp2.Bytes())
		coefficient := toBase64(coeff.Bytes())

		return format +
			"Algorithm: " + algorithm + "\n" +
			"Modulus: " + modulus + "\n" +
			"PublicExponent: " + publicExponent + "\n" +
			"PrivateExponent: " + privateExponent + "\n" +
			"Prime1: " + prime1 + "\n" +
			"Prime2: " + prime2 + "\n" +
			"Exponent1: " + exponent1 + "\n" +
			"Exponent2: " + exponent2 + "\n" +
			"Coefficient: " + coefficient + "\n"

	case ECDSAP256SHA256, ECDSAP384SHA384:
		D, err := openssl.GetECDSAPrivateKey(p)
		if err != nil {
			return ""
		}
		var intlen int
		switch r.Algorithm {
		case ECDSAP256SHA256:
			intlen = 32
		case ECDSAP384SHA384:
			intlen = 48
		}
		private := toBase64(intToBytes(D, intlen))
		return format +
			"Algorithm: " + algorithm + "\n" +
			"PrivateKey: " + private + "\n"

	case ED25519, FALCON512, P256_FALCON512, RSA3072_FALCON512, FALCON1024, P521_FALCON1024:
		raw, err := openssl.GetRawPrivateKey(p)
		if err != nil {
			return ""
		}
		private := toBase64(raw)
		return format +
			"Algorithm: " + algorithm + "\n" +
			"PrivateKey: " + private + "\n"

	default:
		return ""
	}
}
