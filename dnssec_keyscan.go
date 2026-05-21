package dns

// TODO(mr-torgue): add support for PQC. Might need to create new functions for new algorithms.
import (
	"bufio"
	"io"
	"math/big"
	"strconv"
	"strings"

	"github.com/pexip/go-openssl"
)

// NewPrivateKey returns a PrivateKey by parsing the string s.
// s should be in the same form of the BIND private key files.
func (k *DNSKEY) NewPrivateKey(s string) (openssl.PrivateKey, error) {
	if s == "" || s[len(s)-1] != '\n' { // We need a closing newline
		return k.ReadPrivateKey(strings.NewReader(s+"\n"), "")
	}
	return k.ReadPrivateKey(strings.NewReader(s), "")
}

// ReadPrivateKey reads a private key from the io.Reader q. The string file is
// only used in error reporting.
// The public key must be known, because some cryptographic algorithms embed
// the public inside the privatekey.
func (k *DNSKEY) ReadPrivateKey(q io.Reader, file string) (openssl.PrivateKey, error) {
	m, err := parseKey(q, file)
	if m == nil {
		return nil, err
	}
	if _, ok := m["private-key-format"]; !ok {
		return nil, ErrPrivKey
	}
	if m["private-key-format"] != "v1.2" && m["private-key-format"] != "v1.3" {
		return nil, ErrPrivKey
	}
	// TODO(mg): check if the pubkey matches the private key
	algoStr, _, _ := strings.Cut(m["algorithm"], " ")
	algo, err := strconv.ParseUint(algoStr, 10, 8)
	if err != nil {
		return nil, ErrPrivKey
	}
	switch uint8(algo) {
	case RSASHA1, RSASHA1NSEC3SHA1, RSASHA256, RSASHA512:
		priv, err := readPrivateKeyRSA(m)
		if err != nil {
			return nil, err
		}
		pub := k.publicKeyRSA()
		if pub == nil {
			return nil, ErrKey
		}
		return priv, nil
	case ECDSAP256SHA256, ECDSAP384SHA384:
		priv, err := readPrivateKeyECDSA(m)
		if err != nil {
			return nil, err
		}
		pub := k.publicKeyECDSA()
		if pub == nil {
			return nil, ErrKey
		}
		return priv, nil
	case ED25519, FALCON512, P256_FALCON512, RSA3072_FALCON512, FALCON1024, P521_FALCON1024:
		return readPrivateKeyED25519(m)
	default:
		return nil, ErrAlg
	}
}

// Read a private key (file) string and create a public key. Return the private key.
func readPrivateKeyRSA(m map[string]string) (openssl.PrivateKey, error) {
	var E, N, D, P, Q *big.Int
	for k, v := range m {
		switch k {
		case "modulus", "publicexponent", "privateexponent", "prime1", "prime2":
			v1, err := fromBase64([]byte(v))
			if err != nil {
				return nil, err
			}
			switch k {
			case "publicexponent":
				E = new(big.Int).SetBytes(v1)
			case "modulus":
				N = new(big.Int).SetBytes(v1)
			case "privateexponent":
				D = new(big.Int).SetBytes(v1)
			case "prime1":
				P = new(big.Int).SetBytes(v1)
			case "prime2":
				Q = new(big.Int).SetBytes(v1)
			}
		case "exponent1", "exponent2", "coefficient":
			// not used in Go (yet)
		case "created", "publish", "activate":
			// not used in Go (yet)
		}
	}
	return openssl.BuildRSAPrivateKey(E, N, D, P, Q)
}

// readPrivateKeyECDSA parses a bind9 private key file. Example:
// Private-key-format: v1.3
// Algorithm: 13 (ECDSAP256SHA256)
// PrivateKey: 17LMblUjtpdu2Bt5iCtyoJOtCofUGag6MaFKXQm8W+0=
// Created: 20260513224606
// Publish: 20260513224606
// Activate: 20260513224606
func readPrivateKeyECDSA(m map[string]string) (openssl.PrivateKey, error) {
	var D *big.Int
	var groupname string // curve
	// TODO: validate that the required flags are present
	for k, v := range m {
		switch k {
		// make this a parameter
		case "algorithm":
			algoStr, _, _ := strings.Cut(v, " ")
			algo, err := strconv.ParseUint(algoStr, 10, 8)
			if err != nil {
				return nil, err
			}
			groupname = AlgorithmToCurve[uint8(algo)]
		case "privatekey":
			v1, err := fromBase64([]byte(v))
			if err != nil {
				return nil, err
			}
			D = new(big.Int).SetBytes(v1)
		case "created", "publish", "activate":
			/* not used in Go (yet) */
		}
	}
	return openssl.BuildECDSAPrivateKey(D, groupname)
}

func readPrivateKeyED25519(m map[string]string) (openssl.PrivateKey, error) {
	var bytes []byte
	var algName string
	var err error
	// TODO: validate that the required flags are present
	for k, v := range m {
		switch k {
		// make this a parameter
		case "algorithm":
			algoStr, _, _ := strings.Cut(v, " ")
			algo, err := strconv.ParseUint(algoStr, 10, 8)
			if err != nil {
				return nil, err
			}
			algName = AlgorithmToString[uint8(algo)]
		case "privatekey":
			bytes, err = fromBase64([]byte(v))
			if err != nil {
				return nil, err
			}
		case "created", "publish", "activate":
			/* not used in Go (yet) */
		}
	}
	return openssl.BuildRawPrivateKey(bytes, algName)
}

// parseKey reads a private key from r. It returns a map[string]string,
// with the key-value pairs, or an error when the file is not correct.
func parseKey(r io.Reader, file string) (map[string]string, error) {
	m := make(map[string]string)
	var k string

	c := newKLexer(r)

	for l, ok := c.Next(); ok; l, ok = c.Next() {
		// It should alternate
		switch l.value {
		case zKey:
			k = l.token
		case zValue:
			if k == "" {
				return nil, &ParseError{file: file, err: "no private key seen", lex: l}
			}

			m[strings.ToLower(k)] = l.token
			k = ""
		}
	}

	// Surface any read errors from r.
	if err := c.Err(); err != nil {
		return nil, &ParseError{file: file, err: err.Error()}
	}

	return m, nil
}

type klexer struct {
	br io.ByteReader

	readErr error

	line   int
	column int

	key bool

	eol bool // end-of-line
}

func newKLexer(r io.Reader) *klexer {
	br, ok := r.(io.ByteReader)
	if !ok {
		br = bufio.NewReaderSize(r, 1024)
	}

	return &klexer{
		br: br,

		line: 1,

		key: true,
	}
}

func (kl *klexer) Err() error {
	if kl.readErr == io.EOF {
		return nil
	}

	return kl.readErr
}

// readByte returns the next byte from the input
func (kl *klexer) readByte() (byte, bool) {
	if kl.readErr != nil {
		return 0, false
	}

	c, err := kl.br.ReadByte()
	if err != nil {
		kl.readErr = err
		return 0, false
	}

	// delay the newline handling until the next token is delivered,
	// fixes off-by-one errors when reporting a parse error.
	if kl.eol {
		kl.line++
		kl.column = 0
		kl.eol = false
	}

	if c == '\n' {
		kl.eol = true
	} else {
		kl.column++
	}

	return c, true
}

func (kl *klexer) Next() (lex, bool) {
	var (
		l lex

		str strings.Builder

		commt bool
	)

	for x, ok := kl.readByte(); ok; x, ok = kl.readByte() {
		l.line, l.column = kl.line, kl.column

		switch x {
		case ':':
			if commt || !kl.key {
				break
			}

			kl.key = false

			// Next token is a space, eat it
			kl.readByte()

			l.value = zKey
			l.token = str.String()
			return l, true
		case ';':
			commt = true
		case '\n':
			if commt {
				// Reset a comment
				commt = false
			}

			if kl.key && str.Len() == 0 {
				// ignore empty lines
				break
			}

			kl.key = true

			l.value = zValue
			l.token = str.String()
			return l, true
		default:
			if commt {
				break
			}

			str.WriteByte(x)
		}
	}

	if kl.readErr != nil && kl.readErr != io.EOF {
		// Don't return any tokens after a read error occurs.
		return lex{value: zEOF}, false
	}

	if str.Len() > 0 {
		// Send remainder
		l.value = zValue
		l.token = str.String()
		return l, true
	}

	return lex{value: zEOF}, false
}
