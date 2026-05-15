package dns

import (
	"encoding/asn1"
	"encoding/binary"
	"math/big"
	"time"

	"github.com/pexip/go-openssl"
)

// Sign signs a dns.Msg. It fills the signature with the appropriate data.
// The SIG record should have the SignerName, KeyTag, Algorithm, Inception
// and Expiration set.
func (rr *SIG) Sign(k openssl.PrivateKey, m *Msg) ([]byte, error) {
	if k == nil {
		return nil, ErrPrivKey
	}
	if rr.KeyTag == 0 || rr.SignerName == "" || rr.Algorithm == 0 {
		return nil, ErrKey
	}

	rr.Hdr = RR_Header{Name: ".", Rrtype: TypeSIG, Class: ClassANY, Ttl: 0}
	rr.OrigTtl, rr.TypeCovered, rr.Labels = 0, 0, 0

	buf := make([]byte, m.Len()+Len(rr))
	mbuf, err := m.PackBuffer(buf)
	if err != nil {
		return nil, err
	}
	if &buf[0] != &mbuf[0] {
		return nil, ErrBuf
	}
	off, err := PackRR(rr, buf, len(mbuf), nil, false)
	if err != nil {
		return nil, err
	}
	buf = buf[:off:cap(buf)]

	//h, cryptohash, err := hashFromAlgorithm(rr.Algorithm)
	h, _ := openssl.GetDigestByName(AlgorithmToHash[rr.Algorithm], false) // can be nil, some signature schemes don't use a digest

	signdata := append(buf[len(mbuf)+1+2+2+4+2:], buf[:len(mbuf)]...)

	signature, err := sign(k, h, signdata, rr.Algorithm)
	if err != nil {
		return nil, err
	}

	rr.Signature = toBase64(signature)

	buf = append(buf, signature...)
	if len(buf) > int(^uint16(0)) {
		return nil, ErrBuf
	}
	// Adjust sig data length
	rdoff := len(mbuf) + 1 + 2 + 2 + 4
	rdlen := binary.BigEndian.Uint16(buf[rdoff:])
	rdlen += uint16(len(signature))
	binary.BigEndian.PutUint16(buf[rdoff:], rdlen)
	// Adjust additional count
	adc := binary.BigEndian.Uint16(buf[10:])
	adc++
	binary.BigEndian.PutUint16(buf[10:], adc)
	return buf, nil
}

// Verify validates the message buf using the key k.
// It's assumed that buf is a valid message from which rr was unpacked.
func (rr *SIG) Verify(k *KEY, buf []byte) error {
	if k == nil {
		return ErrKey
	}
	if rr.KeyTag == 0 || rr.SignerName == "" || rr.Algorithm == 0 {
		return ErrKey
	}

	h, err := openssl.GetDigestByName(AlgorithmToHash[rr.Algorithm], false) // can be nil, some signature schemes don't use a digest

	buflen := len(buf)
	qdc := binary.BigEndian.Uint16(buf[4:])
	anc := binary.BigEndian.Uint16(buf[6:])
	auc := binary.BigEndian.Uint16(buf[8:])
	adc := binary.BigEndian.Uint16(buf[10:])
	offset := headerSize
	for i := uint16(0); i < qdc && offset < buflen; i++ {
		_, offset, err = UnpackDomainName(buf, offset)
		if err != nil {
			return err
		}
		// Skip past Type and Class
		offset += 2 + 2
	}
	for i := uint16(1); i < anc+auc+adc && offset < buflen; i++ {
		_, offset, err = UnpackDomainName(buf, offset)
		if err != nil {
			return err
		}
		// Skip past Type, Class and TTL
		offset += 2 + 2 + 4
		if offset+1 >= buflen {
			continue
		}
		rdlen := binary.BigEndian.Uint16(buf[offset:])
		offset += 2
		offset += int(rdlen)
	}
	if offset >= buflen {
		return &Error{err: "overflowing unpacking signed message"}
	}

	// offset should be just prior to SIG
	bodyend := offset
	// owner name SHOULD be root
	_, offset, err = UnpackDomainName(buf, offset)
	if err != nil {
		return err
	}
	// Skip Type, Class, TTL, RDLen
	offset += 2 + 2 + 4 + 2
	sigstart := offset
	// Skip Type Covered, Algorithm, Labels, Original TTL
	offset += 2 + 1 + 1 + 4
	if offset+4+4 >= buflen {
		return &Error{err: "overflow unpacking signed message"}
	}
	expire := binary.BigEndian.Uint32(buf[offset:])
	offset += 4
	incept := binary.BigEndian.Uint32(buf[offset:])
	offset += 4
	now := uint32(time.Now().Unix())
	if now < incept || now > expire {
		return ErrTime
	}
	// Skip key tag
	offset += 2
	var signername string
	signername, offset, err = UnpackDomainName(buf, offset)
	if err != nil {
		return err
	}
	// If key has come from the DNS name compression might
	// have mangled the case of the name
	if !equal(signername, k.Header().Name) {
		return &Error{err: "signer name doesn't match key name"}
	}
	sigend := offset
	combined := make([]byte, 0, len(buf[sigstart:sigend])+10+2+len(buf[12:bodyend]))
	combined = append(combined, buf[sigstart:sigend]...)
	combined = append(combined, buf[:10]...)
	combined = append(combined, byte((adc-1)<<8), byte(adc-1))
	combined = append(combined, buf[12:bodyend]...)

	sig := buf[sigend:]
	switch k.Algorithm {
	case RSASHA1, RSASHA256, RSASHA512:
		pk := k.publicKeyRSA()
		if pk != nil {
			return pk.VerifyPKCS1v15(h, combined, sig)
			//return rsa.VerifyPKCS1v15(pk, cryptohash, hashed, sig)
		}
	case ECDSAP256SHA256, ECDSAP384SHA384:
		pk := k.publicKeyECDSA()
		// Split sigbuf into the r and s coordinates and convert to DER signature
		r := new(big.Int).SetBytes(sig[:len(sig)/2])
		s := new(big.Int).SetBytes(sig[len(sig)/2:])
		asn1Bytes, err := asn1.Marshal(struct {
			R, S *big.Int
		}{r, s})
		if err != nil {
			return err
		}
		if pk != nil {
			return pk.VerifyPKCS1v15(h, combined, asn1Bytes)
		}
	case ED25519:
		pk := k.publicKeyGeneric()
		if pk != nil {
			return pk.VerifyPKCS1v15(h, combined, sig)
		}
	}
	return ErrKeyAlg
}
