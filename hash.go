package dns

import (
	"bytes"
)

// identityHash will not hash, it only buffers the data written into it and returns it as-is.
type identityHash struct {
	b *bytes.Buffer
}

// Implement the hash.Hash interface.

func (i identityHash) Write(b []byte) (int, error) { return i.b.Write(b) }
func (i identityHash) Size() int                   { return i.b.Len() }
func (i identityHash) BlockSize() int              { return 1024 }
func (i identityHash) Reset()                      { i.b.Reset() }
func (i identityHash) Sum(b []byte) []byte         { return append(b, i.b.Bytes()...) }

/*
func hashFromAlgorithm(alg uint8) (*openssl.Digest, error) {
	hashnumber, ok := AlgorithmToHash[alg]
	if !ok {
		return nil, ErrAlg
	}
	if hashnumber == 0 {
		return identityHash{b: &bytes.Buffer{}}, hashnumber, nil
	}
	return hashnumber.New(), hashnumber, nil
}
*/
