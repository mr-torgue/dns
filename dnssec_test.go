package dns

import (
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pexip/go-openssl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getSoa() *SOA {
	soa := new(SOA)
	soa.Hdr = RR_Header{"miek.nl.", TypeSOA, ClassINET, 14400, 0}
	soa.Ns = "open.nlnetlabs.nl."
	soa.Mbox = "miekg.atoom.net."
	soa.Serial = 1293945905
	soa.Refresh = 14400
	soa.Retry = 3600
	soa.Expire = 604800
	soa.Minttl = 86400
	return soa
}

func TestSecure(t *testing.T) {
	soa := getSoa()

	sig := new(RRSIG)
	sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.TypeCovered = TypeSOA
	sig.Algorithm = RSASHA256
	sig.Labels = 2
	sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
	sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.OrigTtl = 14400
	sig.KeyTag = 12051
	sig.SignerName = "miek.nl."
	sig.Signature = "oMCbslaAVIp/8kVtLSms3tDABpcPRUgHLrOR48OOplkYo+8TeEGWwkSwaz/MRo2fB4FxW0qj/hTlIjUGuACSd+b1wKdH5GvzRJc2pFmxtCbm55ygAh4EUL0F6U5cKtGJGSXxxg6UFCQ0doJCmiGFa78LolaUOXImJrk6AFrGa0M="

	key := new(DNSKEY)
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = RSASHA256
	key.PublicKey = "AwEAAcNEU67LJI5GEgF9QLNqLO1SMq1EdoQ6E9f85ha0k0ewQGCblyW2836GiVsm6k8Kr5ECIoMJ6fZWf3CQSQ9ycWfTyOHfmI3eQ/1Covhb2y4bAmL/07PhrL7ozWBW3wBfM335Ft9xjtXHPy7ztCbV9qZ4TVDTW/Iyg0PiwgoXVesz"

	// It should validate. Period is checked separately, so this will keep on working
	if sig.Verify(key, []RR{soa}) != nil {
		t.Error("failure to validate")
	}
}

func TestSignature(t *testing.T) {
	sig := new(RRSIG)
	sig.Hdr.Name = "miek.nl."
	sig.Hdr.Class = ClassINET
	sig.Hdr.Ttl = 3600
	sig.TypeCovered = TypeDNSKEY
	sig.Algorithm = RSASHA1
	sig.Labels = 2
	sig.OrigTtl = 4000
	sig.Expiration = 1000 //Thu Jan  1 02:06:40 CET 1970
	sig.Inception = 800   //Thu Jan  1 01:13:20 CET 1970
	sig.KeyTag = 34641
	sig.SignerName = "miek.nl."
	sig.Signature = "AwEAAaHIwpx3w4VHKi6i1LHnTaWeHCL154Jug0Rtc9ji5qwPXpBo6A5sRv7cSsPQKPIwxLpyCrbJ4mr2L0EPOdvP6z6YfljK2ZmTbogU9aSU2fiq/4wjxbdkLyoDVgtO+JsxNN4bjr4WcWhsmk1Hg93FV9ZpkWb0Tbad8DFqNDzr//kZ"

	// Should not be valid
	if sig.ValidityPeriod(time.Now()) {
		t.Error("should not be valid")
	}

	sig.Inception = 315565800   //Tue Jan  1 10:10:00 CET 1980
	sig.Expiration = 4102477800 //Fri Jan  1 10:10:00 CET 2100
	if !sig.ValidityPeriod(time.Now()) {
		t.Error("should be valid")
	}
}

func TestSignVerify2(t *testing.T) {

	// import and verify the keys for RSA
	pubkey, err := ReadRR(strings.NewReader(`
example.com. IN DNSKEY 256 3 8 AwEAAaifTuraCcWF1sG/dwRmJ1Rw4n2fIZQ9Ouf7aZ6nalFkrG+5y+AO tb6/xJSQhlrvp7SNaAiV9S9opGhLG9gE8gRWYaDCvsD6hEcAy9AFNAvc +n/lv8wHkR01y1sxfqjszGMPSbJrrVxg/Qqe4/5Iq79GVG8Bvb7rXeVA Felpe5Kp
`), "Kexample.com.+008+30813.key")
	require.Nil(t, err, "err should be nil")

	privStr := `Private-key-format: v1.3
Algorithm: 8 (RSASHA256)
Modulus: qJ9O6toJxYXWwb93BGYnVHDifZ8hlD065/tpnqdqUWSsb7nL4A61vr/ElJCGWu+ntI1oCJX1L2ikaEsb2ATyBFZhoMK+wPqERwDL0AU0C9z6f+W/zAeRHTXLWzF+qOzMYw9JsmutXGD9Cp7j/kirv0ZUbwG9vutd5UAV6Wl7kqk=
PublicExponent: AQAB
PrivateExponent: gBXzJmZVgdr2lNnRmF/YhEXzZaUZJreUJV9OjZtyIT2t1nh1q07BM5ILyyY1SKI+6+F2Iv917Xs5V5emIOMwymsEGM6jTZJCBp1afLT2phOtborlU3UCh74QxZoIGneMyn9ixe8ORbspGEXOtupMfQKF47ezdWHvmKXQ4akftrk=
Prime1: 0Tp1ePgGfqTgf5DJLlCpEWwPktjXlujyL4P56SLQ+0p1bC1qD5oZBEFlfqfRPrwnZ8oa6Rj7vDDRXG8vEAmY3w==
Prime2: zlEUqwTWaNPDhiwCsot/INH9DLVzu9wXpRL6/uqNrabm65TLLGdo37yvzASH/iRrdEMv4ApCCmcaDYs6nJPddw==
Exponent1: G9XqMQjWXFz1HSOXEFlc1NuKit/cdtBRAC9PvUuLgBMc4iJ8nMzEjUNiDGKpPO5tU6qYv/A59YSNJf4IxdpxAw==
Exponent2: qjBuGSjzaSOOPWaejwPNSZiO4mXn40aJ5qzCiXeYiW+NOzXRZ36iHzW52lS+jaEjVpN5sZkkoworjpKUNccvvw==
Coefficient: ONc1U/hQ0usCbCPc9DqZTD/kSFtDEOJkbzjRf78UcftFw3SVf7rqFeRBOAfvbadgdZPREOYfXW3su0hwRPUYrQ==
`
	privkey, err := pubkey.(*DNSKEY).ReadPrivateKey(strings.NewReader(privStr),
		"Kexample.com.+008+30813.private")
	require.Nil(t, err, "err should be nil")

	if pubkey.(*DNSKEY).PublicKey != "AwEAAaifTuraCcWF1sG/dwRmJ1Rw4n2fIZQ9Ouf7aZ6nalFkrG+5y+AOtb6/xJSQhlrvp7SNaAiV9S9opGhLG9gE8gRWYaDCvsD6hEcAy9AFNAvc+n/lv8wHkR01y1sxfqjszGMPSbJrrVxg/Qqe4/5Iq79GVG8Bvb7rXeVAFelpe5Kp" {
		t.Error("pubkey is not what we've read")
	}
	if pubkey.(*DNSKEY).PrivateKeyString(privkey) != privStr {
		t.Error("privkey is not what we've read")
		t.Errorf("%v", pubkey.(*DNSKEY).PrivateKeyString(privkey))
	}

	cname := new(CNAME)
	cname.Hdr = RR_Header{"www.example.com.", TypeCNAME, ClassINET, 86400, 0}
	cname.Target = "example.com."
	expectedCNAMESignature := "MjFzO8IWZ7cCVMi5w16Hv2U1ShzDMSLmTsjxBO8ABONmznwwg38cqbovYT+oFgm28XXJ8+EjXLhODEVMc5M23jq5YqZd2TcxkiKpytCJstEyQFLDxCIxa8DbMyd/V5sZ66FKsZ56AMWBJdTM5fNm8Xn0mDVSBjL/MkTWlTUAw5I="

	sig := new(RRSIG)
	sig.Hdr = RR_Header{"example.com.", TypeCNAME, ClassINET, 86400, 0}
	sig.TypeCovered = TypeCNAME
	sig.Expiration = 1779235200            // date -u '+%s' -d"2026-05-20 00:00:00"
	sig.Inception = 1778803200             // date -u '+%s' -d"2026-05-15 00:00:00"
	sig.KeyTag = pubkey.(*DNSKEY).KeyTag() // Get the keyfrom the Key
	sig.SignerName = pubkey.(*DNSKEY).Hdr.Name
	sig.Algorithm = RSASHA256
	err = sig.Sign(privkey, []RR{cname})
	require.Nil(t, err, "err should be nil")
	assert.Equal(t, expectedCNAMESignature, sig.Signature, "signatures should be equal")

	ns1 := new(NS)
	ns1.Hdr = RR_Header{"example.com.", TypeNS, ClassINET, 86400, 0}
	ns1.Ns = "ns1.example.com."
	ns2 := new(NS)
	ns2.Hdr = RR_Header{"example.com.", TypeNS, ClassINET, 86400, 0}
	ns2.Ns = "ns2.example.com."
	expectedNSSignature := "KYYNkHvDs96bml/m5eeTPUGswIfHOAwMHeznUL3CRwXPN/jYo0yMJBA0Zd7gyIWG/ERXwkZz8R7xeSRl7T89X5+iomVzN5HTCYuaxjoA5A1sbGy/gP4CqC1DUiaR1IiQF6ogLP5RWEQZ+4JlYjto3cpCEQJBoSnVZVAcsp6no50="

	sig = new(RRSIG)
	sig.Hdr = RR_Header{"example.com.", TypeNS, ClassINET, 86400, 0}
	sig.TypeCovered = TypeNS
	sig.Expiration = 1779235200            // date -u '+%s' -d"2026-05-20 00:00:00"
	sig.Inception = 1778803200             // date -u '+%s' -d"2026-05-15 00:00:00"
	sig.KeyTag = pubkey.(*DNSKEY).KeyTag() // Get the keyfrom the Key
	sig.SignerName = pubkey.(*DNSKEY).Hdr.Name
	sig.Algorithm = RSASHA256
	err = sig.Sign(privkey, []RR{ns2, ns1})
	require.Nil(t, err, "err should be nil")
	assert.Equal(t, expectedNSSignature, sig.Signature, "signatures should be equal")

	err = sig.Verify(pubkey.(*DNSKEY), []RR{ns2, ns1})
	require.Nil(t, err, "err should be nil")

	// import and verify the keys for ECDSA (signature changes)
	pubkey, err = ReadRR(strings.NewReader(`
example.com. IN DNSKEY 256 3 13 NCzoLSlxCjrZDZ5zKTq6LgllKqWV/pCCq1o7HZ5/T3Z8zhpTcZemiZQEJLR9roNKh0pO88ML+XcR9L4GbxRB1w==
`), "Kexample.com.+013+23186.key")
	require.Nil(t, err, "err should be nil")

	privStr = `Private-key-format: v1.3
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: vg6oG9cg9A0spN/6YrtMvASSdZHIxazupgtCNCP0Mmg=
`
	privkey, err = pubkey.(*DNSKEY).ReadPrivateKey(strings.NewReader(privStr),
		"Kexample.com.+013+23186.private")
	require.Nil(t, err, "err should be nil")

	assert.Equal(t, "NCzoLSlxCjrZDZ5zKTq6LgllKqWV/pCCq1o7HZ5/T3Z8zhpTcZemiZQEJLR9roNKh0pO88ML+XcR9L4GbxRB1w==", pubkey.(*DNSKEY).PublicKey, "public keys should be equal")
	assert.Equal(t, privStr, pubkey.(*DNSKEY).PrivateKeyString(privkey), "private keys should be equal")

	cname = new(CNAME)
	cname.Hdr = RR_Header{"www.example.com.", TypeCNAME, ClassINET, 86400, 0}
	cname.Target = "example.com."

	sig = new(RRSIG)
	sig.Hdr = RR_Header{"example.com.", TypeCNAME, ClassINET, 86400, 0}
	sig.TypeCovered = TypeCNAME
	sig.Expiration = 1779235200            // date -u '+%s' -d"2026-05-20 00:00:00"
	sig.Inception = 1778803200             // date -u '+%s' -d"2026-05-15 00:00:00"
	sig.KeyTag = pubkey.(*DNSKEY).KeyTag() // Get the keyfrom the Key
	sig.SignerName = pubkey.(*DNSKEY).Hdr.Name
	sig.Algorithm = ECDSAP256SHA256
	err = sig.Sign(privkey, []RR{cname})
	assert.Nil(t, err, "err should be nil")
	err = sig.Verify(pubkey.(*DNSKEY), []RR{cname})
	assert.Nil(t, err, "err should be nil")

	// one of the valid signatures (signatures include randomness so they change)
	sig.Signature = "oLxEpiV2MPvjpIPwYXzwD6cWnDWMRFepC4LFRXkecqdgXYzP/vaGczQZ9958t9WmU9im2z4HugXAcyjk2zwZvQ=="
	err = sig.Verify(pubkey.(*DNSKEY), []RR{cname})
	assert.Nil(t, err, "err should be nil")

	// test PQC: FALCON512
	pubkey, err = ReadRR(strings.NewReader(`
example.local. IN DNSKEY 256 3 17 CZoqCsqVQrZh2o7BKpVUI9IbuGPYx49mi3WwlIVxGRmKekmodBaFaWzF Lzcp0gDxmkmyxh6kel5tr80YwepN5hSQKfMmYjO95NmzaloctIZR8IUL iLgdUFSxrzVn1VABum0IXuyFVnaW2D4kfXLrj8+3ouKlEGwosqqaNyBM +w194Rv+AZJyWdlUN1tbipCTsRZlHhqdaygkohOZkcgoCQ4VRGT0i3iu OD5ugwfmjfJYFktkr9hyLNKTVAVe+mE1qfT+mOgJYLWa+8/VJ3SWwRsn t6WYvINvSlpcNQDwdaF9UJUqOvtVy7nx0kJAA8p9BVG7oxedFKVEEE4s woih5MfNKn83ROYC34rSQshFtFPg74NCxUi9wUxata1ieVMJmD31I0na ii7oZ9i40MFNYdhbrkQ+ne3rsI9kRnKOGfegmoAHuZtX59bZfbKOtvNK 75BONJS/2gVFMUwCoeDeCTgeCyopVXysjUoXhsFVVTglVdbsIwIEV/dk po+lXHQ9E4qWggWh5owOt4X2pt1RWpGQp/UsSGEE5mbX+q8RDT49Ax7O 7hNckXdhjLEOnHnZryB8Mi0vN6VjAlbNe1eqA/UBDiXKue9emB6/8+Ap zYDw44DWAd9fNkQ1lgNaaEIf1Z/kimqhhbFYHEYcrMMj65R5f2IEcxKe ZAiGHwVRHaNtZv3l6oiALsm9Y/GCiLM6C7Jh5zSFTaJhAgKfiPHPNt0C CFj+x9oIngcEdOqrV2IlZd2NCv7ayg/108IWXBdBdVORi8WLU0TWidmB Y1RYuXVRk9ybBK4jg1jFtdlvShjDQlkVKXB/Wc5swZk3qA5GcW6499dZ EUXaOVSC56xfzXojXazJRWSUV1IPBn8qAun+rZAYXBLYyiCLNUE5qRNE X2a0cLsfX1S0JavBzRv+k/rCqAsWSR1dqYORmLohtQ8zOOK8mWyn9LsX kpX6q5t2L5YLOSP1rmmkqPXOZ1fvMTKWypht5rKLMTDp4i51qKmF4cYe LqJ5NeU6TsNsvciaZIhzUnYEJwTMCBYNdJNTruQushvzWAC9fdWpw+zV +CD2WsZgDlBtSH8FXGUxGJJ2WQ6D0ynNPgjcL54z6JRxX0oduqp5d/Ga qlzKnsU37i9tjaJlYs6dnH5daUNdLUw2v6ckyZcFQc6niVU3JHgsgWqZ 5LVE5wNvowOY6VAavmvK
`), "Kexample.local.+017+61149.key")
	require.Nil(t, err, "err should be nil")

	privStr = `Private-key-format: v1.3
Algorithm: 17 (falconpadded512)
PrivateKey: WRAQQwBOhvw/hOvgOQBuQwxADAeghQwguyRghAxQghRiffPhfvhQgfgwwugAQeAQxfw/e/wew9/fugTOwwfugvewBgtwARCwhBfyg/xO/vfw+AcwPwAgQeA/ffPhQBxhROw/uQAxQgxRPQw+xQgQgu+gQwQvv/edevAxPfRAA/vwvwwPwOxAuvwQwvAfgv+BPgAAhQPgwBewQfPiRfxexP/hO/vgAhQBOe/QQBwRPxPQfw/gBxAAP+PxR+PwgQBgPwChhQiO/vBAgAABOggBPfgRv/hQPw/hg/xAfhe/gAhxePwfxBhwfRgQuOwfuh/QvPvfhRgexP/hPQ+fRf+fvwvwvAARPPPuwwxAv/hCePQfgQAvwwP/wQ+/vOxgwQhAvhRuQgBAQ/PP+ve//Ou/SfBQwPPw/wAiPPxeghQyN/OQfg/QPfPg/xQf+gyAxPf/+QCQBfvgAg+TfwRgRwPRAfRwwvgggfwBfvvPfPwAfhBvdvgee/AAOwhAQggAPBRAwgvQPeQvvQ/iPeAOhgwwARAwBPuyA/9xAOAAhgPABvgPgPexORQQQPPBQfAQOOyeRBfw+uhewwRBPQRggRAwO+hOvwPhAu9gifxPxAvOxOeh+gO+xfwB/xf/fAhffgBQBPfOwhAvRAvv/vAewheSgf/PgSPNg+uwhRAQ9xuwvPAgPOQQw+e//vdxROPxfQRPwuu///Qwf/vvgfxgf9RQOwgO+xP/AQfhwgfewhvgwvxAgvvQvgSPgQ/QgwOgvw+/QuAgewQRwgPQwvBPfAPfOvQAR/hO/ARPfQgAgAQ/+uv+/+xQAg/hw/xg/fQwQBAAgxBf/feAwPe/w/CPfwAguhP/ux/hf+xBO/wfxvQ/fwggxgPfwg/gCA/gPgegxfgAvyPftRB/gQQggQvO/AA+hBQfwRQOACPwfQhQPQQAfPv/hvABgARu/e/gQQf/gPvhfRfAtSv/wgAxABQBQR/ABf/w+wwvuvxPfhAxf/Nxw/PAPwve/+iegfufg//QeO///e7p3OAN1BcMA/3r+drqJzbbC/rMI/T9+ycRDBf+EdPgGwcILgDkBucA8Bkc7gBN5woKD+zTEivz9/Tv7uDi9fUWD+oVBuAOEOwf3Br6EvUoFAAhACgzAQwA1gARB9EbBcvHGALLAuwE6wAC/vnd2uoD/ffW/R0a4v4L9/vp7+vd8P1DCRj+EB77DRM6ACoDAT7x+Q291B8XHOri9vPvJw3x3R0F4Q/uCt4K9f758wzfAyEdCd8C3/cY8iXqMiH0HvjlCxgEBv8SDe4G+9Ed9+z47Onm5MgQFPL5FP7v7/ACEtsOHtz69PjWGyXoAxj83w717vIWDARGCA4C2CIpuwz1/OIU6ga89AoX5PHq6vrv9PESCg0C+9DU+Cn/BPbcCw4VG8cFB+HqGQ8I7w0VEfkZ/+f+7fL0CBMEF/L66QYPDf4qFff1+fzcC/URJP0OCeoM+cUdDhPs7dnWKQsN9u/sFxiq7D76E/YjFsriBP/4/zDhKx0OuNPx6wb8GNf91PMrANsTARACA+gA7Ok+Ix/t+PTIFAQXIdr7Dgby/NzTGUMS6/4I5vsT9hHsHQcD4wb51xgH4ev63RUR1eDQGQ0uLggR+CnvQ+QqLQvwPwEMAhMNGv///xYfChX3Dw73Bwn1BwIC9Pbc7/Xb1/8Q1fXy5e3sCvopCAjh7OgVzvr+
`
	privkey, err = pubkey.(*DNSKEY).ReadPrivateKey(strings.NewReader(privStr),
		"Kexample.local.+017+61149.private")
	require.Nil(t, err, "err should be nil")

	assert.Equal(t, "CZoqCsqVQrZh2o7BKpVUI9IbuGPYx49mi3WwlIVxGRmKekmodBaFaWzFLzcp0gDxmkmyxh6kel5tr80YwepN5hSQKfMmYjO95NmzaloctIZR8IULiLgdUFSxrzVn1VABum0IXuyFVnaW2D4kfXLrj8+3ouKlEGwosqqaNyBM+w194Rv+AZJyWdlUN1tbipCTsRZlHhqdaygkohOZkcgoCQ4VRGT0i3iuOD5ugwfmjfJYFktkr9hyLNKTVAVe+mE1qfT+mOgJYLWa+8/VJ3SWwRsnt6WYvINvSlpcNQDwdaF9UJUqOvtVy7nx0kJAA8p9BVG7oxedFKVEEE4swoih5MfNKn83ROYC34rSQshFtFPg74NCxUi9wUxata1ieVMJmD31I0naii7oZ9i40MFNYdhbrkQ+ne3rsI9kRnKOGfegmoAHuZtX59bZfbKOtvNK75BONJS/2gVFMUwCoeDeCTgeCyopVXysjUoXhsFVVTglVdbsIwIEV/dkpo+lXHQ9E4qWggWh5owOt4X2pt1RWpGQp/UsSGEE5mbX+q8RDT49Ax7O7hNckXdhjLEOnHnZryB8Mi0vN6VjAlbNe1eqA/UBDiXKue9emB6/8+ApzYDw44DWAd9fNkQ1lgNaaEIf1Z/kimqhhbFYHEYcrMMj65R5f2IEcxKeZAiGHwVRHaNtZv3l6oiALsm9Y/GCiLM6C7Jh5zSFTaJhAgKfiPHPNt0CCFj+x9oIngcEdOqrV2IlZd2NCv7ayg/108IWXBdBdVORi8WLU0TWidmBY1RYuXVRk9ybBK4jg1jFtdlvShjDQlkVKXB/Wc5swZk3qA5GcW6499dZEUXaOVSC56xfzXojXazJRWSUV1IPBn8qAun+rZAYXBLYyiCLNUE5qRNEX2a0cLsfX1S0JavBzRv+k/rCqAsWSR1dqYORmLohtQ8zOOK8mWyn9LsXkpX6q5t2L5YLOSP1rmmkqPXOZ1fvMTKWypht5rKLMTDp4i51qKmF4cYeLqJ5NeU6TsNsvciaZIhzUnYEJwTMCBYNdJNTruQushvzWAC9fdWpw+zV+CD2WsZgDlBtSH8FXGUxGJJ2WQ6D0ynNPgjcL54z6JRxX0oduqp5d/GaqlzKnsU37i9tjaJlYs6dnH5daUNdLUw2v6ckyZcFQc6niVU3JHgsgWqZ5LVE5wNvowOY6VAavmvK", pubkey.(*DNSKEY).PublicKey, "public keys should be equal")
	assert.Equal(t, privStr, pubkey.(*DNSKEY).PrivateKeyString(privkey), "private keys should be equal")

	cname = new(CNAME)
	cname.Hdr = RR_Header{"www.example.local.", TypeCNAME, ClassINET, 86400, 0}
	cname.Target = "example.local."

	sig = new(RRSIG)
	sig.Hdr = RR_Header{"example.local.", TypeCNAME, ClassINET, 86400, 0}
	sig.TypeCovered = TypeCNAME
	sig.Expiration = 1779235200            // date -u '+%s' -d"2026-05-20 00:00:00"
	sig.Inception = 1778803200             // date -u '+%s' -d"2026-05-15 00:00:00"
	sig.KeyTag = pubkey.(*DNSKEY).KeyTag() // Get the keyfrom the Key
	sig.SignerName = pubkey.(*DNSKEY).Hdr.Name
	sig.Algorithm = FALCON512
	err = sig.Sign(privkey, []RR{cname})
	assert.Nil(t, err, "err should be nil")
	err = sig.Verify(pubkey.(*DNSKEY), []RR{cname})
	assert.Nil(t, err, "err should be nil")

	// test PQC: P256_FALCON512
	pubkey, err = ReadRR(strings.NewReader(`
example.local. IN DNSKEY 256 3 18 AAAAQQQIIWQCq2t8Mnx2gKvlHbK+V60rzTW+2p35YDnelO6R4VrelYkq HBRpaAqdOroXPY95tITzNuGPEOV9wBVo1t/sCaoirOf8qSBA/ch6cuDO VyytZa1ZYAAFXSiJZNsRsLlXT1jWbapUltTo4EoEFLQ2oK8/jSJ3g8MF LqJRdbarf49IbPSvRLWrzWTZ4xn1QyG2JwvLaaSQ59jhG1WTCbUa8Av1 QnHIAi8bqrdsvkrHDDl4RqhFZcTkLDEt8kBSTj/4YSnsy9O4zUOQww18 owXi2UJofkXN2BnVTs9SFMTEPFs4OP1+gTegEkEA3llBblELjA83LCoV jlxa6L+M9I1JMofnxEKcmgGjqiGHYjGRtp2ESGRZ+zABCvm6TfIWOWY+ khrwQUuaKpSeuKMKzIdUWbeEP+r1B8gFeMhuUSbgKyHVTLyEfHawQC0U ED0Gu4dkXz+UrmNaHsIBtbbH2RVetDCnQYpURzeiNzsAy8xQ3IBRud5D EqjgaZKFcSSo4fGeZ4gW/iTZGJ+HQvyUg2jq2WboIAJtlygTya14yFyO E01l+R6ga7uZ17G1bV9+Op64N2cUFFLX8wQCp6nItaRyav6WXigIj2DD a77eVC+AyaAQPHGo7wwvqJKEm8fTTY2U20rj/KcVRYW00ku+HOfppt9T TvqO08SuF3cEMtpq3PaAub6XbU36OzYglHmjuqx6ttBAiiAzVPQxsS9J IB60VF/s7pcx24feZS0btl/pviJFKuHy4dxJzmDds+bvksQ7QQCAL8PA LFXSSKOU6IPd+vOdZIivdFKXl6kpkMoZA+jhIh/RBSlFLEuZVLSCDdCX HsEiKnuIw5oY4UJxXRl/sovQAICyQoDgxSNT3ZlQoRDHoYIv2Emq7M5j er6exFBAEbrtJcBk7mFK7Qnbh1d4FVmtpqQR0Ark5zJeiLMEdU/jdsk2 OincZfyfEolZA3QQbeRgnAzH2p4pGfBecF0MoGJMspN50PeLbiP0Gi80 g3i1oT0XUCfVzHH0Jd9BGVYF1VgzRC2E2Hdhlp706XuYkGeOWt/lrGMe qyy2d9LP8TCWVxGPxCqBYoI6qC8etBK9QWitYIc4YQPcXsNKDvF5w2bw IWw0qx4b11QOBSrsxwwghGwXd2Mtd1ZNUr0DjkdMp9mdgkMaqIJgkM7t B/IoamKpcgL1ojtuq/GKSslg/JmjoHLIIPsIjSbFkAU/bEgGLKWhzK6k b1Cf5ZvMe3aw+dFx7YsMzHQnWKlqIxYQJ+7myYf41JoMhMESSJUFiJR3
`), "Kexample.local.+018+36951.key")
	require.Nil(t, err, "err should be nil")

	privStr = `Private-key-format: v1.3
Algorithm: 18 (p256_falconpadded512)
PrivateKey: AAAAeTB3AgEBBCDz6MwxQtej7sKBdQZD5wFyWf7YZZi91Lpk/JAkVL8Qq6AKBggqhkjOPQMBB6FEA0IABAghZAKra3wyfHaAq+Udsr5XrSvNNb7anflgOd6U7pHhWt6ViSocFGloCp06uhc9j3m0hPM24Y8Q5X3AFWjW3+xZCF9D++A/G/KCK+99D8697/B99FAI6/D/D/HE99E+9E8GEBA/94B97+9/DD9CHICE8CDCD++CG/CAJFB/BEE678/FFHFDH+97B7DFED8+DCF888A8B+BGBCFC8BAAAD96B7GDD/5EA//8BAE9+D+8A8BA++C9+AC7HG7F+ECA/A/+A5BC+EBB//8EBAAD/E29+98K97G+/+A+ABCHA8/AB89+B+7/AAB6+AE+G8+9DCA9C4C5A+C/BDB/9+BHA2++HCCACEAAB98C7D5FBEBF+CB+CAB5BB9D/BBCDC899AEF96C+BHB+3B9B83AJ915+BCD+16CCF+69C//7E4++675B68AF7AJEA9//B5FB9+9C96EB8DBA9I+797GA/D4NB8BA8+DCC9DHAF17ACACD15A6/B+9A+5//71D8+55GA9/CJ3E7/E88EBE7C937GA/FGD9/CDDB8999CGE6GF0E8AC+BA+8y8IB+D+B+CAA/+88GA7DDG/+87B+FHGACDJ+AC5+IJ69//9BB99/IBBB68BB8G94E9AGAA9A9E9CBDEACHGE6C+A++B8CA/B9FC/EC67C996/BA+68/B7FFA9EEE6C799FBFEF/GEF5/K+D8A+IC8/D45DGC8/F+D7CB88C9CGG8zJ939CBDBEF8DABA6A+8BCB4IA6F69GB/+D95+89+B/FB9CA99B/79/6E+8C6AECAACBHF8D/B8E+CA68CDAAA6FFAB+/8C/419EGA4D/BCD/F++9++HBGCCEA+AG85EF8/A+++D9/7CC8C+/6GC+CED6FB8CBA/G8/+A8BBB8G/CD9DAC9AB9CHGDA87+G+C++E6BECG8H86CB7D9B+BB9CA6+//GB+EBDDC+9B+7+ECEB/AEHK8+8KBA5A+C78+8AB85+A/+9B99+ECEA79/C8AB09+86C+FC+AG7LIG89G87A88CCDB997A9C+/B7A+A2F9DC8EA+DG5CHD+/5B9F+7+E97+JFBG9B9C/++E9+BFJEF85A78R4bCvgjMwIZ+v4HEvYRB+0MEufx6h4IAv4EB/D9ARz6BPfH2tEnCwkNAwb9BhMBLdYKCf/1xf8cKwv18AwHFP73DfT6CAP7KP8d9OZAFiIP5RckGCAL9QDg1vIpIwESAhnrGfsGSyQHy/IXFyb61vwM8x/69/Uw5yEZ5uUfHB7i7g3xEPUG8AUACCQC+iIB8uc9+iQb6hnzHQPz8e8RGN39C/8nAzED1wX+Kib21A0mKek17CX69xULFeHuACEbFy7UAv4TIeYG4AQR1MYA9Rnt/gvZKw/7+PTvDv32Aen+6O30C/IM+hPk/SvwLfLVER0ODBYO+vQQ4ff9MwX8Pe8l9vMWEuD49uZPJiM/Ff0DIhII+wEk2QL1MNvt5w4q8PDa8Rv7E9H7/wMb9Q7X5wYQ/g0IKgJEAwbs+Agd/eHV/Pz7+OkKCOH04CQPEuH7+xjhue4e/w/tzvHsBhXxGCDsIuve8PnN+unpDP4iBiIl7vYI5Bv3wgcV/NsP6RH7y+kKCk3k5eH/GtIC7Q3Y1P3r1/MlCfzLExXt+AQCGg8FHhjGGijiDOn4+f4X0gIX+eoG/c0exhP++A/X/Qz4IO0A8yQEBdrD+QrkxvAJ9/bnIvcNEOjg9gMEC+DqHQXa9uYA/Erp7gocCOID5PEM8w8j3OYO6lLeGxHwC/Hfxv4=
`
	privkey, err = pubkey.(*DNSKEY).ReadPrivateKey(strings.NewReader(privStr),
		"Kexample.local.+018+36951.private")
	require.Nil(t, err, "err should be nil")

	assert.Equal(t, "AAAAQQQIIWQCq2t8Mnx2gKvlHbK+V60rzTW+2p35YDnelO6R4VrelYkqHBRpaAqdOroXPY95tITzNuGPEOV9wBVo1t/sCaoirOf8qSBA/ch6cuDOVyytZa1ZYAAFXSiJZNsRsLlXT1jWbapUltTo4EoEFLQ2oK8/jSJ3g8MFLqJRdbarf49IbPSvRLWrzWTZ4xn1QyG2JwvLaaSQ59jhG1WTCbUa8Av1QnHIAi8bqrdsvkrHDDl4RqhFZcTkLDEt8kBSTj/4YSnsy9O4zUOQww18owXi2UJofkXN2BnVTs9SFMTEPFs4OP1+gTegEkEA3llBblELjA83LCoVjlxa6L+M9I1JMofnxEKcmgGjqiGHYjGRtp2ESGRZ+zABCvm6TfIWOWY+khrwQUuaKpSeuKMKzIdUWbeEP+r1B8gFeMhuUSbgKyHVTLyEfHawQC0UED0Gu4dkXz+UrmNaHsIBtbbH2RVetDCnQYpURzeiNzsAy8xQ3IBRud5DEqjgaZKFcSSo4fGeZ4gW/iTZGJ+HQvyUg2jq2WboIAJtlygTya14yFyOE01l+R6ga7uZ17G1bV9+Op64N2cUFFLX8wQCp6nItaRyav6WXigIj2DDa77eVC+AyaAQPHGo7wwvqJKEm8fTTY2U20rj/KcVRYW00ku+HOfppt9TTvqO08SuF3cEMtpq3PaAub6XbU36OzYglHmjuqx6ttBAiiAzVPQxsS9JIB60VF/s7pcx24feZS0btl/pviJFKuHy4dxJzmDds+bvksQ7QQCAL8PALFXSSKOU6IPd+vOdZIivdFKXl6kpkMoZA+jhIh/RBSlFLEuZVLSCDdCXHsEiKnuIw5oY4UJxXRl/sovQAICyQoDgxSNT3ZlQoRDHoYIv2Emq7M5jer6exFBAEbrtJcBk7mFK7Qnbh1d4FVmtpqQR0Ark5zJeiLMEdU/jdsk2OincZfyfEolZA3QQbeRgnAzH2p4pGfBecF0MoGJMspN50PeLbiP0Gi80g3i1oT0XUCfVzHH0Jd9BGVYF1VgzRC2E2Hdhlp706XuYkGeOWt/lrGMeqyy2d9LP8TCWVxGPxCqBYoI6qC8etBK9QWitYIc4YQPcXsNKDvF5w2bwIWw0qx4b11QOBSrsxwwghGwXd2Mtd1ZNUr0DjkdMp9mdgkMaqIJgkM7tB/IoamKpcgL1ojtuq/GKSslg/JmjoHLIIPsIjSbFkAU/bEgGLKWhzK6kb1Cf5ZvMe3aw+dFx7YsMzHQnWKlqIxYQJ+7myYf41JoMhMESSJUFiJR3", pubkey.(*DNSKEY).PublicKey, "public keys should be equal")
	assert.Equal(t, privStr, pubkey.(*DNSKEY).PrivateKeyString(privkey), "private keys should be equal")

	cname = new(CNAME)
	cname.Hdr = RR_Header{"www.example.local.", TypeCNAME, ClassINET, 86400, 0}
	cname.Target = "example.local."

	sig = new(RRSIG)
	sig.Hdr = RR_Header{"example.local.", TypeCNAME, ClassINET, 86400, 0}
	sig.TypeCovered = TypeCNAME
	sig.Expiration = 1779235200            // date -u '+%s' -d"2026-05-20 00:00:00"
	sig.Inception = 1778803200             // date -u '+%s' -d"2026-05-15 00:00:00"
	sig.KeyTag = pubkey.(*DNSKEY).KeyTag() // Get the keyfrom the Key
	sig.SignerName = pubkey.(*DNSKEY).Hdr.Name
	sig.Algorithm = P256_FALCON512
	err = sig.Sign(privkey, []RR{cname})
	assert.Nil(t, err, "err should be nil")
	err = sig.Verify(pubkey.(*DNSKEY), []RR{cname})
	assert.Nil(t, err, "err should be nil")
}

func TestSignVerify(t *testing.T) {
	// The record we want to sign
	soa := new(SOA)
	soa.Hdr = RR_Header{"miek.nl.", TypeSOA, ClassINET, 14400, 0}
	soa.Ns = "open.nlnetlabs.nl."
	soa.Mbox = "miekg.atoom.net."
	soa.Serial = 1293945905
	soa.Refresh = 14400
	soa.Retry = 3600
	soa.Expire = 604800
	soa.Minttl = 86400

	soa1 := new(SOA)
	soa1.Hdr = RR_Header{"*.miek.nl.", TypeSOA, ClassINET, 14400, 0}
	soa1.Ns = "open.nlnetlabs.nl."
	soa1.Mbox = "miekg.atoom.net."
	soa1.Serial = 1293945905
	soa1.Refresh = 14400
	soa1.Retry = 3600
	soa1.Expire = 604800
	soa1.Minttl = 86400

	srv := new(SRV)
	srv.Hdr = RR_Header{"srv.miek.nl.", TypeSRV, ClassINET, 14400, 0}
	srv.Port = 1000
	srv.Weight = 800
	srv.Target = "web1.miek.nl."

	hinfo := &HINFO{
		Hdr: RR_Header{
			Name:   "miek.nl.",
			Rrtype: TypeHINFO,
			Class:  ClassINET,
			Ttl:    3789,
		},
		Cpu: "X",
		Os:  "Y",
	}

	// Test with different algorithms
	algorithms := []struct {
		name      string
		algorithm uint8
		bitsize   int
	}{
		{"RSA", RSASHA256, 2048},
		{"ECDSA", ECDSAP256SHA256, 256},
		{"EdDSA", ED25519, 256},
		{"FALCON512", FALCON512, 1281},
		{"FALCON512", FALCON1024, 2305},
		{"FALCON512", P521_FALCON1024, 2532},
		{"FALCON512", RSA3072_FALCON512, 3055},
		{"FALCON512", P256_FALCON512, 1406},
	}

	for _, algo := range algorithms {
		t.Run(algo.name, func(t *testing.T) {
			// With this key
			key := new(DNSKEY)
			key.Hdr.Rrtype = TypeDNSKEY
			key.Hdr.Name = "miek.nl."
			key.Hdr.Class = ClassINET
			key.Hdr.Ttl = 14400
			key.Flags = 256
			key.Protocol = 3
			key.Algorithm = algo.algorithm
			privkey, err := key.Generate(algo.bitsize)
			if err != nil {
				t.Fatal("failure to generate private key:", err)
			}

			// Fill in the values of the Sig, before signing
			sig := new(RRSIG)
			sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
			sig.TypeCovered = soa.Hdr.Rrtype
			sig.Labels = uint8(CountLabel(soa.Hdr.Name)) // works for all 3
			sig.OrigTtl = soa.Hdr.Ttl
			sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
			sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
			sig.KeyTag = key.KeyTag()   // Get the keyfrom the Key
			sig.SignerName = key.Hdr.Name
			sig.Algorithm = algo.algorithm
			for _, r := range []RR{soa, soa1, srv, hinfo} {
				if err := sig.Sign(privkey, []RR{r}); err != nil {
					t.Error("failure to sign the record:", err)
					continue
				}
				if err := sig.Verify(key, []RR{r}); err != nil {
					t.Errorf("failure to validate: %s, error: %s", r.Header().Name, err)
					continue
				}
			}
		})
	}
}

// Test if RRSIG.Verify() conforms to RFC 4035 Section 5.3.1
func TestShouldNotVerifyInvalidSig(t *testing.T) {
	// The RRSIG RR and the RRset MUST have the same owner name
	rrNameMismatch := getSoa()
	rrNameMismatch.Hdr.Name = "example.com."

	// ... and the same class
	rrClassMismatch := getSoa()
	rrClassMismatch.Hdr.Class = ClassCHAOS

	// The RRSIG RR's Type Covered field MUST equal the RRset's type.
	rrTypeMismatch := getSoa()
	rrTypeMismatch.Hdr.Rrtype = TypeA

	// The number of labels in the RRset owner name MUST be greater than
	// or equal to the value in the RRSIG RR's Labels field.
	rrLabelLessThan := getSoa()
	rrLabelLessThan.Hdr.Name = "nl."

	// Time checks are done in ValidityPeriod

	// With this key
	key := new(DNSKEY)
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = RSASHA256
	privkey, err := key.Generate(1024)
	if err != nil {
		t.Fatal("failure to generate private key:", err)
	}

	normalSoa := getSoa()

	// Fill in the normal values of the Sig, before signing
	sig := new(RRSIG)
	sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.TypeCovered = TypeSOA
	sig.Labels = uint8(CountLabel(normalSoa.Hdr.Name))
	sig.OrigTtl = normalSoa.Hdr.Ttl
	sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
	sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.KeyTag = key.KeyTag()   // Get the keyfrom the Key
	sig.SignerName = key.Hdr.Name
	sig.Algorithm = RSASHA256

	for i, rr := range []RR{rrNameMismatch, rrClassMismatch, rrTypeMismatch, rrLabelLessThan} {
		if i != 0 { // Just for the rrNameMismatch case, we need the name to mismatch
			sig := sig.copy().(*RRSIG)
			sig.SignerName = rr.Header().Name
			sig.Hdr.Name = rr.Header().Name
			key := key.copy().(*DNSKEY)
			key.Hdr.Name = rr.Header().Name
		}

		if err := sig.signAsIs(privkey, []RR{rr}); err != nil {
			t.Error("failure to sign the record:", err)
			continue
		}

		if err := sig.Verify(key, []RR{rr}); err == nil {
			t.Error("should not validate: ", rr)
			continue
		} else {
			t.Logf("expected failure: %v for RR name %s, class %d, type %d, rrsig labels %d", err, rr.Header().Name, rr.Header().Class, rr.Header().Rrtype, CountLabel(rr.Header().Name))
		}
	}

	// The RRSIG RR's Signer's Name field MUST be the name of the zone that contains the RRset.
	// The RRSIG RR's Signer's Name, Algorithm, and Key Tag fields MUST match the owner name,
	// algorithm, and key tag for some DNSKEY RR in the zone's apex DNSKEY RRset.
	sigMismatchName := sig.copy().(*RRSIG)
	sigMismatchName.SignerName = "example.com."
	soaMismatchName := getSoa()
	soaMismatchName.Hdr.Name = "example.com."
	keyMismatchName := key.copy().(*DNSKEY)
	keyMismatchName.Hdr.Name = "example.com."
	if err := sigMismatchName.signAsIs(privkey, []RR{soaMismatchName}); err != nil {
		t.Error("failure to sign the record:", err)
	} else if err := sigMismatchName.Verify(keyMismatchName, []RR{soaMismatchName}); err == nil {
		t.Error("should not validate: ", soaMismatchName, ", RRSIG's signer's name does not match the owner name")
	} else {
		t.Logf("expected failure: %v for signer %s and owner %s", err, sigMismatchName.SignerName, sigMismatchName.Hdr.Name)
	}

	sigMismatchAlgo := sig.copy().(*RRSIG)
	sigMismatchAlgo.Algorithm = RSASHA1
	sigMismatchKeyTag := sig.copy().(*RRSIG)
	sigMismatchKeyTag.KeyTag = 12345
	for _, sigMismatch := range []*RRSIG{sigMismatchAlgo, sigMismatchKeyTag} {
		if err := sigMismatch.Sign(privkey, []RR{normalSoa}); err != nil {
			t.Error("failure to sign the record:", err)
		} else if err := sigMismatch.Verify(key, []RR{normalSoa}); err == nil {
			t.Error("should not validate: ", normalSoa)
		} else {
			t.Logf("expected failure: %v for signer %s algo %d keytag %d", err, sigMismatch.SignerName, sigMismatch.Algorithm, sigMismatch.KeyTag)
		}
	}

	// The matching DNSKEY RR MUST have the Zone Flag bit (DNSKEY RDATA Flag bit 7) set.
	keyZoneBitWrong := key.copy().(*DNSKEY)
	keyZoneBitWrong.Flags = key.Flags &^ ZONE
	if err := sig.Sign(privkey, []RR{normalSoa}); err != nil {
		t.Error("failure to sign the record:", err)
	} else if err := sig.Verify(keyZoneBitWrong, []RR{normalSoa}); err == nil {
		t.Error("should not validate: ", normalSoa)
	} else {
		t.Logf("expected failure: %v for key flags %d", err, keyZoneBitWrong.Flags)
	}
}

func Test65534(t *testing.T) {
	t6 := new(RFC3597)
	t6.Hdr = RR_Header{"miek.nl.", 65534, ClassINET, 14400, 0}
	t6.Rdata = "505D870001"
	key := new(DNSKEY)
	key.Hdr.Name = "miek.nl."
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = RSASHA256
	privkey, err := key.Generate(1024)
	if err != nil {
		t.Fatal("failure to generate private key:", err)
	}

	sig := new(RRSIG)
	sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.TypeCovered = t6.Hdr.Rrtype
	sig.Labels = uint8(CountLabel(t6.Hdr.Name))
	sig.OrigTtl = t6.Hdr.Ttl
	sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
	sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.KeyTag = key.KeyTag()
	sig.SignerName = key.Hdr.Name
	sig.Algorithm = RSASHA256
	if err := sig.Sign(privkey, []RR{t6}); err != nil {
		t.Error(err)
		t.Error("failure to sign the TYPE65534 record")
	}
	if err := sig.Verify(key, []RR{t6}); err != nil {
		t.Error(err)
		t.Errorf("failure to validate %s", t6.Header().Name)
	}
}

func TestDnskey(t *testing.T) {
	pubkey, err := ReadRR(strings.NewReader(`
miek.nl.	IN	DNSKEY	256 3 10 AwEAAZuMCu2FdugHkTrXYgl5qixvcDw1aDDlvL46/xJKbHBAHY16fNUb2b65cwko2Js/aJxUYJbZk5dwCDZxYfrfbZVtDPQuc3o8QaChVxC7/JYz2AHc9qHvqQ1j4VrH71RWINlQo6VYjzN/BGpMhOZoZOEwzp1HfsOE3lNYcoWU1smL ;{id = 5240 (zsk), size = 1024b}
`), "Kmiek.nl.+010+05240.key")
	if err != nil {
		t.Fatal(err)
	}
	privStr := `Private-key-format: v1.3
Algorithm: 10 (RSASHA512)
Modulus: m4wK7YV26AeROtdiCXmqLG9wPDVoMOW8vjr/EkpscEAdjXp81RvZvrlzCSjYmz9onFRgltmTl3AINnFh+t9tlW0M9C5zejxBoKFXELv8ljPYAdz2oe+pDWPhWsfvVFYg2VCjpViPM38EakyE5mhk4TDOnUd+w4TeU1hyhZTWyYs=
PublicExponent: AQAB
PrivateExponent: UfCoIQ/Z38l8vB6SSqOI/feGjHEl/fxIPX4euKf0D/32k30fHbSaNFrFOuIFmWMB3LimWVEs6u3dpbB9CQeCVg7hwU5puG7OtuiZJgDAhNeOnxvo5btp4XzPZrJSxR4WNQnwIiYWbl0aFlL1VGgHC/3By89ENZyWaZcMLW4KGWE=
Prime1: yxwC6ogAu8aVcDx2wg1V0b5M5P6jP8qkRFVMxWNTw60Vkn+ECvw6YAZZBHZPaMyRYZLzPgUlyYRd0cjupy4+fQ==
Prime2: xA1bF8M0RTIQ6+A11AoVG6GIR/aPGg5sogRkIZ7ID/sF6g9HMVU/CM2TqVEBJLRPp73cv6ZeC3bcqOCqZhz+pw==
Exponent1: xzkblyZ96bGYxTVZm2/vHMOXswod4KWIyMoOepK6B/ZPcZoIT6omLCgtypWtwHLfqyCz3MK51Nc0G2EGzg8rFQ==
Exponent2: Pu5+mCEb7T5F+kFNZhQadHUklt0JUHbi3hsEvVoHpEGSw3BGDQrtIflDde0/rbWHgDPM4WQY+hscd8UuTXrvLw==
Coefficient: UuRoNqe7YHnKmQzE6iDWKTMIWTuoqqrFAmXPmKQnC+Y+BQzOVEHUo9bXdDnoI9hzXP1gf8zENMYwYLeWpuYlFQ==
`
	privkey, err := pubkey.(*DNSKEY).ReadPrivateKey(strings.NewReader(privStr),
		"Kmiek.nl.+010+05240.private")
	if err != nil {
		t.Fatal(err)
	}
	if pubkey.(*DNSKEY).PublicKey != "AwEAAZuMCu2FdugHkTrXYgl5qixvcDw1aDDlvL46/xJKbHBAHY16fNUb2b65cwko2Js/aJxUYJbZk5dwCDZxYfrfbZVtDPQuc3o8QaChVxC7/JYz2AHc9qHvqQ1j4VrH71RWINlQo6VYjzN/BGpMhOZoZOEwzp1HfsOE3lNYcoWU1smL" {
		t.Error("pubkey is not what we've read")
	}
	if pubkey.(*DNSKEY).PrivateKeyString(privkey) != privStr {
		t.Error("privkey is not what we've read")
		t.Errorf("%v", pubkey.(*DNSKEY).PrivateKeyString(privkey))
	}
}

func TestTag(t *testing.T) {
	key := new(DNSKEY)
	key.Hdr.Name = "miek.nl."
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 3600
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = RSASHA256
	key.PublicKey = "AwEAAcNEU67LJI5GEgF9QLNqLO1SMq1EdoQ6E9f85ha0k0ewQGCblyW2836GiVsm6k8Kr5ECIoMJ6fZWf3CQSQ9ycWfTyOHfmI3eQ/1Covhb2y4bAmL/07PhrL7ozWBW3wBfM335Ft9xjtXHPy7ztCbV9qZ4TVDTW/Iyg0PiwgoXVesz"

	tag := key.KeyTag()
	if tag != 12051 {
		t.Errorf("wrong key tag: %d for key %v", tag, key)
	}
}

func TestKeyRSA(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	key := new(DNSKEY)
	key.Hdr.Name = "miek.nl."
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 3600
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = RSASHA256
	priv, err := key.Generate(1024)
	if err != nil {
		t.Fatal("failure to generate private key:", err)
	}

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
	sig.Algorithm = RSASHA256
	sig.Labels = 2
	sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
	sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.OrigTtl = soa.Hdr.Ttl
	sig.KeyTag = key.KeyTag()
	sig.SignerName = key.Hdr.Name

	if err := sig.Sign(priv, []RR{soa}); err != nil {
		t.Error("failed to sign")
		return
	}
	if err := sig.Verify(key, []RR{soa}); err != nil {
		t.Error("failed to verify")
	}
}

// TestKeyToDS tests if the DS record is generated correctly.
// You can use the following to generate records:
//  1. dnssec-keygen -a [ALGORITHM] -b 2048 -n ZONE -f KSK example.com
//  2. dnssec-dsfromkey [-1/-2] [NAME].key
func TestKeyToDS(t *testing.T) {
	key := new(DNSKEY)
	key.Hdr.Name = "miek.nl."
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 3600
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = RSASHA256
	key.PublicKey = "AwEAAcNEU67LJI5GEgF9QLNqLO1SMq1EdoQ6E9f85ha0k0ewQGCblyW2836GiVsm6k8Kr5ECIoMJ6fZWf3CQSQ9ycWfTyOHfmI3eQ/1Covhb2y4bAmL/07PhrL7ozWBW3wBfM335Ft9xjtXHPy7ztCbV9qZ4TVDTW/Iyg0PiwgoXVesz"

	ds := key.ToDS(SHA1)
	if strings.ToUpper(ds.Digest) != "B5121BDB5B8D86D0CC5FFAFBAAABE26C3E20BAC1" {
		t.Errorf("wrong DS digest for SHA1\n%v", ds)
	}

	key = new(DNSKEY)
	key.Hdr.Name = "example.com."
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 3600
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = RSASHA512
	key.PublicKey = "AwEAAfXlz23ENZBWhb7Di40JF7Zo5dPR80sbJ/LfAo9GXGefXWJet7NYLoMrJz5jGyz04GR+pfrg7CnFmAVXblgoy7QFMPN3YU7nLmpybw8CWC9WVxlsQPdm0XC1UXUIjsTSG8KnsYdGLEhP2LxMssamxOCyEDEmKERPL/ifWwUPjo6gFQcrw+IHaRuizF+Jx8t8b8IswvU0undeFCh9z2zgzPcs1n7PqGn/ZA62j0zY2u1Uki1U1+6nj1WS+SsrPXnATebCbC0voHHbQQlSUARtj8tPBZgCUbxEhF2I15QfwQPnswmSbFqHJMKf3jC67BqhH+0QVWmy74LLDxgLWEV11os="
	ds = key.ToDS(SHA1)
	require.NotNil(t, ds, "ds should not be nil")
	assert.NotEqual(t, "01D718FD5B2E38FE95836EF85D258502F747D14A", strings.ToUpper(ds.Digest), "SHA1 hashes should not match")
	key.Algorithm = RSASHA256
	ds = key.ToDS(SHA1)
	require.NotNil(t, ds, "ds should not be nil")
	assert.Equal(t, "01D718FD5B2E38FE95836EF85D258502F747D14A", strings.ToUpper(ds.Digest), "SHA1 hashes should match")
	ds = key.ToDS(SHA256)
	require.NotNil(t, ds, "ds should not be nil")
	assert.Equal(t, "9765B0367EB8684147909B51FF7BEFC89EE06A703CF0DEE68677D77C33862F55", strings.ToUpper(ds.Digest), "SHA256 hashes should match")
	ds = key.ToDS(SHA384)
	require.NotNil(t, ds, "ds should not be nil")
	assert.Equal(t, "43C38C65FE251FC08130C69D2C10704720916BCD390D5C44E9AF91A598DE7BF581811E5EE8B57EC3FCF5A8999F53C264", strings.ToUpper(ds.Digest), "SHA384 hashes should match")

	key = new(DNSKEY)
	key.Hdr.Name = "example.com."
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 3600
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = RSASHA512
	key.PublicKey = "Ule+j1b34r+28QMRLdfuXNKdZBbU/yTB27jomZZBrLlmsRDivwkr0GAv/WurTWuQczcH1Wu3cLiILaJu5sg4LjcS8IAPJMu+uQunMKR7ecOWBZJ/0mcDEPSg79CckwKP"
	ds = key.ToDS(SHA1)
	require.NotNil(t, ds, "ds should not be nil")
	assert.NotEqual(t, "6E3EC3AEED5FAC6A392E8A704BB18BAE25CAAA64", strings.ToUpper(ds.Digest), "SHA1 hashes should not match")
	key.Flags = 257
	key.Algorithm = ECDSAP384SHA384
	ds = key.ToDS(SHA1)
	require.NotNil(t, ds, "ds should not be nil")
	assert.Equal(t, "6E3EC3AEED5FAC6A392E8A704BB18BAE25CAAA64", strings.ToUpper(ds.Digest), "SHA1 hashes should match")
	ds = key.ToDS(SHA256)
	require.NotNil(t, ds, "ds should not be nil")
	assert.Equal(t, "A0AA822FCF822F64BEAAB7F9F15DAA86EC80CF4C1CF38A9D6158D2D7CCD74D48", strings.ToUpper(ds.Digest), "SHA256 hashes should match")
	ds = key.ToDS(SHA384)
	require.NotNil(t, ds, "ds should not be nil")
	assert.Equal(t, "A3FE95E1354CDF71D4701027F759B2BC36F4BE0B09D1375AAD939E0BE6328DA3813E37DD0F3F560C980B213F8416475C", strings.ToUpper(ds.Digest), "SHA384 hashes should match")

	/*
		key = new(DNSKEY)
		key.Hdr.Name = "example.com."
		key.Hdr.Rrtype = TypeDNSKEY
		key.Hdr.Class = ClassINET
		key.Hdr.Ttl = 3600
		key.Flags = 256
		key.Protocol = 3
		key.Algorithm = P521_FALCON1024
		key.PublicKey = "Ule+j1b34r+28QMRLdfuXNKdZBbU/yTB27jomZZBrLlmsRDivwkr0GAv/WurTWuQczcH1Wu3cLiILaJu5sg4LjcS8IAPJMu+uQunMKR7ecOWBZJ/0mcDEPSg79CckwKP"
		ds = key.ToDS(SHA1)
		require.NotNil(t, ds, "ds should not be nil")
		assert.NotEqual(t, "6E3EC3AEED5FAC6A392E8A704BB18BAE25CAAA64", strings.ToUpper(ds.Digest), "SHA1 hashes should not match")
		key.Flags = 257
		key.Algorithm = ECDSAP384SHA384
		ds = key.ToDS(SHA1)
		require.NotNil(t, ds, "ds should not be nil")
		assert.Equal(t, "6E3EC3AEED5FAC6A392E8A704BB18BAE25CAAA64", strings.ToUpper(ds.Digest), "SHA1 hashes should match")
		ds = key.ToDS(SHA256)
		require.NotNil(t, ds, "ds should not be nil")
		assert.Equal(t, "A0AA822FCF822F64BEAAB7F9F15DAA86EC80CF4C1CF38A9D6158D2D7CCD74D48", strings.ToUpper(ds.Digest), "SHA256 hashes should match")
		ds = key.ToDS(SHA384)
		require.NotNil(t, ds, "ds should not be nil")
		assert.Equal(t, "A3FE95E1354CDF71D4701027F759B2BC36F4BE0B09D1375AAD939E0BE6328DA3813E37DD0F3F560C980B213F8416475C", strings.ToUpper(ds.Digest), "SHA384 hashes should match")
	*/
}

func TestSignRSA(t *testing.T) {
	pub := "miek.nl. IN DNSKEY 256 3 5 AwEAAb+8lGNCxJgLS8rYVer6EnHVuIkQDghdjdtewDzU3G5R7PbMbKVRvH2Ma7pQyYceoaqWZQirSj72euPWfPxQnMy9ucCylA+FuH9cSjIcPf4PqJfdupHk9X6EBYjxrCLY4p1/yBwgyBIRJtZtAqM3ceAH2WovEJD6rTtOuHo5AluJ"

	priv := `Private-key-format: v1.3
Algorithm: 5 (RSASHA1)
Modulus: v7yUY0LEmAtLythV6voScdW4iRAOCF2N217APNTcblHs9sxspVG8fYxrulDJhx6hqpZlCKtKPvZ649Z8/FCczL25wLKUD4W4f1xKMhw9/g+ol926keT1foQFiPGsItjinX/IHCDIEhEm1m0Cozdx4AfZai8QkPqtO064ejkCW4k=
PublicExponent: AQAB
PrivateExponent: YPwEmwjk5HuiROKU4xzHQ6l1hG8Iiha4cKRG3P5W2b66/EN/GUh07ZSf0UiYB67o257jUDVEgwCuPJz776zfApcCB4oGV+YDyEu7Hp/rL8KcSN0la0k2r9scKwxTp4BTJT23zyBFXsV/1wRDK1A5NxsHPDMYi2SoK63Enm/1ptk=
Prime1: /wjOG+fD0ybNoSRn7nQ79udGeR1b0YhUA5mNjDx/x2fxtIXzygYk0Rhx9QFfDy6LOBvz92gbNQlzCLz3DJt5hw==
Prime2: wHZsJ8OGhkp5p3mrJFZXMDc2mbYusDVTA+t+iRPdS797Tj0pjvU2HN4vTnTj8KBQp6hmnY7dLp9Y1qserySGbw==
Exponent1: N0A7FsSRIg+IAN8YPQqlawoTtG1t1OkJ+nWrurPootScApX6iMvn8fyvw3p2k51rv84efnzpWAYiC8SUaQDNxQ==
Exponent2: SvuYRaGyvo0zemE3oS+WRm2scxR8eiA8WJGeOc+obwOKCcBgeZblXzfdHGcEC1KaOcetOwNW/vwMA46lpLzJNw==
Coefficient: 8+7ZN/JgByqv0NfULiFKTjtyegUcijRuyij7yNxYbCBneDvZGxJwKNi4YYXWx743pcAj4Oi4Oh86gcmxLs+hGw==
Created: 20110302104537
Publish: 20110302104537
Activate: 20110302104537`

	xk := testRR(pub)
	k := xk.(*DNSKEY)
	p, err := k.NewPrivateKey(priv)
	require.Nil(t, err, "err should be nil")
	require.NotNil(t, p, "p should not be nil")

	E, N, err := openssl.GetParamsRSA(p)
	require.Nil(t, err, "err should be nil")
	require.NotNil(t, E, "E should not be nil")
	require.NotNil(t, N, "N should not be nil")
	assert.Equal(t, big.NewInt(65537), E, "E should be 65537")

	if k.KeyTag() != 37350 {
		t.Errorf("keytag should be 37350, got %d %v", k.KeyTag(), k)
	}

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
	sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
	sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.KeyTag = k.KeyTag()
	sig.SignerName = k.Hdr.Name
	sig.Algorithm = k.Algorithm

	sig.Sign(p, []RR{soa})
	if sig.Signature != "D5zsobpQcmMmYsUMLxCVEtgAdCvTu8V/IEeP4EyLBjqPJmjt96bwM9kqihsccofA5LIJ7DN91qkCORjWSTwNhzCv7bMyr2o5vBZElrlpnRzlvsFIoAZCD9xg6ZY7ZyzUJmU6IcTwG4v3xEYajcpbJJiyaw/RqR90MuRdKPiBzSo=" {
		t.Errorf("signature is not correct: %v", sig)
	}
}

func TestSignVerifyECDSA(t *testing.T) {
	pub := `example.net. 3600 IN DNSKEY 257 3 14 (
	xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1
	w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8
	/uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40 )`
	priv := `Private-key-format: v1.2
Algorithm: 14 (ECDSAP384SHA384)
PrivateKey: WURgWHCcYIYUPWgeLmiPY2DJJk02vgrmTfitxgqcL4vwW7BOrbawVmVe0d9V94SR`

	eckey := testRR(pub)
	privkey, err := eckey.(*DNSKEY).NewPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	// TODO: Create separate test for this
	ds := eckey.(*DNSKEY).ToDS(SHA384)
	require.NotNil(t, ds, "ds should not be nil")
	if ds.KeyTag != 10771 {
		t.Fatal("wrong keytag on DS")
	}
	if ds.Digest != "72d7b62976ce06438e9c0bf319013cf801f09ecc84b8d7e9495f27e305c6a9b0563a9b5f4d288405c3008a946df983d6" {
		t.Fatal("wrong DS Digest")
	}
	a := testRR("www.example.net. 3600 IN A 192.0.2.1")
	sig := new(RRSIG)
	sig.Hdr = RR_Header{"example.net.", TypeRRSIG, ClassINET, 14400, 0}
	sig.Expiration, _ = StringToTime("20100909102025")
	sig.Inception, _ = StringToTime("20100812102025")
	sig.KeyTag = eckey.(*DNSKEY).KeyTag()
	sig.SignerName = eckey.(*DNSKEY).Hdr.Name
	sig.Algorithm = eckey.(*DNSKEY).Algorithm

	if sig.Sign(privkey, []RR{a}) != nil {
		t.Fatal("failure to sign the record")
	}

	if err := sig.Verify(eckey.(*DNSKEY), []RR{a}); err != nil {
		t.Fatalf("failure to validate:\n%s\n%s\n%s\n\n%s\n\n%v",
			eckey.(*DNSKEY).String(),
			a.String(),
			sig.String(),
			eckey.(*DNSKEY).PrivateKeyString(privkey),
			err,
		)
	}
}

func TestSignVerifyECDSA2(t *testing.T) {
	srv1 := testRR("srv.miek.nl. IN SRV 1000 800 0 web1.miek.nl.")
	srv := srv1.(*SRV)

	// With this key
	key := new(DNSKEY)
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = ECDSAP256SHA256
	privkey, err := key.Generate(256)
	if err != nil {
		t.Fatal("failure to generate key")
	}

	// Fill in the values of the Sig, before signing
	sig := new(RRSIG)
	sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.TypeCovered = srv.Hdr.Rrtype
	sig.Labels = uint8(CountLabel(srv.Hdr.Name)) // works for all 3
	sig.OrigTtl = srv.Hdr.Ttl
	sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
	sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.KeyTag = key.KeyTag()   // Get the keyfrom the Key
	sig.SignerName = key.Hdr.Name
	sig.Algorithm = ECDSAP256SHA256

	if sig.Sign(privkey, []RR{srv}) != nil {
		t.Fatal("failure to sign the record")
	}

	err = sig.Verify(key, []RR{srv})
	if err != nil {
		t.Errorf("failure to validate:\n%s\n%s\n%s\n\n%s\n\n%v",
			key.String(),
			srv.String(),
			sig.String(),
			key.PrivateKeyString(privkey),
			err,
		)
	}
}

func TestSignVerifyEd25519(t *testing.T) {
	srv1, err := NewRR("srv.miek.nl. IN SRV 1000 800 0 web1.miek.nl.")
	if err != nil {
		t.Fatal(err)
	}
	srv := srv1.(*SRV)

	// With this key
	key := new(DNSKEY)
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = ED25519
	privkey, err := key.Generate(256)
	if err != nil {
		t.Fatal("failure to generate key")
	}

	// Fill in the values of the Sig, before signing
	sig := new(RRSIG)
	sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.TypeCovered = srv.Hdr.Rrtype
	sig.Labels = uint8(CountLabel(srv.Hdr.Name)) // works for all 3
	sig.OrigTtl = srv.Hdr.Ttl
	sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
	sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.KeyTag = key.KeyTag()   // Get the keyfrom the Key
	sig.SignerName = key.Hdr.Name
	sig.Algorithm = ED25519

	if sig.Sign(privkey, []RR{srv}) != nil {
		t.Fatal("failure to sign the record")
	}

	err = sig.Verify(key, []RR{srv})
	if err != nil {
		t.Logf("failure to validate:\n%s\n%s\n%s\n\n%s\n\n%v",
			key.String(),
			srv.String(),
			sig.String(),
			key.PrivateKeyString(privkey),
			err,
		)
	}
}

// Here the test vectors from the relevant RFCs are checked.
// rfc6605 6.1
func TestRFC6605P256(t *testing.T) {
	exDNSKEY := `example.net. 3600 IN DNSKEY 257 3 13 (
                 GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edb
                 krSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA== )`
	exPriv := `Private-key-format: v1.2
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: GU6SnQ/Ou+xC5RumuIUIuJZteXT2z0O/ok1s38Et6mQ=`
	rrDNSKEY := testRR(exDNSKEY)
	priv, err := rrDNSKEY.(*DNSKEY).NewPrivateKey(exPriv)
	if err != nil {
		t.Fatal(err)
	}

	exDS := `example.net. 3600 IN DS 55648 13 2 (
             b4c8c1fe2e7477127b27115656ad6256f424625bf5c1
             e2770ce6d6e37df61d17 )`
	rrDS := testRR(exDS)
	ourDS := rrDNSKEY.(*DNSKEY).ToDS(SHA256)
	if !reflect.DeepEqual(ourDS, rrDS.(*DS)) {
		t.Errorf("DS record differs:\n%v\n%v", ourDS, rrDS.(*DS))
	}

	exA := `www.example.net. 3600 IN A 192.0.2.1`
	exRRSIG := `www.example.net. 3600 IN RRSIG A 13 3 3600 (
                20100909100439 20100812100439 55648 example.net.
                qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXA
                yGmt+3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw== )`
	rrA := testRR(exA)
	rrRRSIG := testRR(exRRSIG)
	if err := rrRRSIG.(*RRSIG).Verify(rrDNSKEY.(*DNSKEY), []RR{rrA}); err != nil {
		t.Errorf("failure to validate the spec RRSIG: %v", err)
	}

	ourRRSIG := &RRSIG{
		Hdr: RR_Header{
			Ttl: rrA.Header().Ttl,
		},
		KeyTag:     rrDNSKEY.(*DNSKEY).KeyTag(),
		SignerName: rrDNSKEY.(*DNSKEY).Hdr.Name,
		Algorithm:  rrDNSKEY.(*DNSKEY).Algorithm,
	}
	ourRRSIG.Expiration, _ = StringToTime("20100909100439")
	ourRRSIG.Inception, _ = StringToTime("20100812100439")
	err = ourRRSIG.Sign(priv, []RR{rrA})
	if err != nil {
		t.Fatal(err)
	}

	if err = ourRRSIG.Verify(rrDNSKEY.(*DNSKEY), []RR{rrA}); err != nil {
		t.Errorf("failure to validate our RRSIG: %v", err)
	}

	// Signatures are randomized
	rrRRSIG.(*RRSIG).Signature = ""
	ourRRSIG.Signature = ""
	if !reflect.DeepEqual(ourRRSIG, rrRRSIG.(*RRSIG)) {
		t.Fatalf("RRSIG record differs:\n%v\n%v", ourRRSIG, rrRRSIG.(*RRSIG))
	}
}

// rfc6605 6.2
func TestRFC6605P384(t *testing.T) {
	exDNSKEY := `example.net. 3600 IN DNSKEY 257 3 14 (
                 xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1
                 w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8
                 /uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40 )`
	exPriv := `Private-key-format: v1.2
Algorithm: 14 (ECDSAP384SHA384)
PrivateKey: WURgWHCcYIYUPWgeLmiPY2DJJk02vgrmTfitxgqcL4vwW7BOrbawVmVe0d9V94SR`
	rrDNSKEY := testRR(exDNSKEY)
	priv, err := rrDNSKEY.(*DNSKEY).NewPrivateKey(exPriv)
	if err != nil {
		t.Fatal(err)
	}

	exDS := `example.net. 3600 IN DS 10771 14 4 (
           72d7b62976ce06438e9c0bf319013cf801f09ecc84b8
           d7e9495f27e305c6a9b0563a9b5f4d288405c3008a94
           6df983d6 )`
	rrDS := testRR(exDS)
	ourDS := rrDNSKEY.(*DNSKEY).ToDS(SHA384)
	if !reflect.DeepEqual(ourDS, rrDS.(*DS)) {
		t.Fatalf("DS record differs:\n%v\n%v", ourDS, rrDS.(*DS))
	}

	exA := `www.example.net. 3600 IN A 192.0.2.1`
	exRRSIG := `www.example.net. 3600 IN RRSIG A 14 3 3600 (
           20100909102025 20100812102025 10771 example.net.
           /L5hDKIvGDyI1fcARX3z65qrmPsVz73QD1Mr5CEqOiLP
           95hxQouuroGCeZOvzFaxsT8Glr74hbavRKayJNuydCuz
           WTSSPdz7wnqXL5bdcJzusdnI0RSMROxxwGipWcJm )`
	rrA := testRR(exA)
	rrRRSIG := testRR(exRRSIG)
	if err != nil {
		t.Fatal(err)
	}
	if err = rrRRSIG.(*RRSIG).Verify(rrDNSKEY.(*DNSKEY), []RR{rrA}); err != nil {
		t.Errorf("failure to validate the spec RRSIG: %v", err)
	}

	ourRRSIG := &RRSIG{
		Hdr: RR_Header{
			Ttl: rrA.Header().Ttl,
		},
		KeyTag:     rrDNSKEY.(*DNSKEY).KeyTag(),
		SignerName: rrDNSKEY.(*DNSKEY).Hdr.Name,
		Algorithm:  rrDNSKEY.(*DNSKEY).Algorithm,
	}
	ourRRSIG.Expiration, _ = StringToTime("20100909102025")
	ourRRSIG.Inception, _ = StringToTime("20100812102025")
	err = ourRRSIG.Sign(priv, []RR{rrA})
	if err != nil {
		t.Fatal(err)
	}

	if err = ourRRSIG.Verify(rrDNSKEY.(*DNSKEY), []RR{rrA}); err != nil {
		t.Errorf("failure to validate our RRSIG: %v", err)
	}

	// Signatures are randomized
	rrRRSIG.(*RRSIG).Signature = ""
	ourRRSIG.Signature = ""
	if !reflect.DeepEqual(ourRRSIG, rrRRSIG.(*RRSIG)) {
		t.Fatalf("RRSIG record differs:\n%v\n%v", ourRRSIG, rrRRSIG.(*RRSIG))
	}
}

// rfc8080 6.1
func TestRFC8080Ed25519Example1(t *testing.T) {
	exDNSKEY := `example.com. 3600 IN DNSKEY 257 3 15 (
             l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4= )`
	exPriv := `Private-key-format: v1.2
Algorithm: 15 (ED25519)
PrivateKey: ODIyNjAzODQ2MjgwODAxMjI2NDUxOTAyMDQxNDIyNjI=`
	rrDNSKEY, err := NewRR(exDNSKEY)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := rrDNSKEY.(*DNSKEY).NewPrivateKey(exPriv)
	if err != nil {
		t.Fatal(err)
	}

	exDS := `example.com. 3600 IN DS 3613 15 2 (
             3aa5ab37efce57f737fc1627013fee07bdf241bd10f3b1964ab55c78e79
             a304b )`
	rrDS, err := NewRR(exDS)
	if err != nil {
		t.Fatal(err)
	}
	ourDS := rrDNSKEY.(*DNSKEY).ToDS(SHA256)
	if !reflect.DeepEqual(ourDS, rrDS.(*DS)) {
		t.Fatalf("DS record differs:\n%v\n%v", ourDS, rrDS.(*DS))
	}

	exMX := `example.com. 3600 IN MX 10 mail.example.com.`
	exRRSIG := `example.com. 3600 IN RRSIG MX 15 2 3600 (
             1440021600 1438207200 3613 example.com. (
             oL9krJun7xfBOIWcGHi7mag5/hdZrKWw15jPGrHpjQeRAvTdszaPD+QLs3f
             x8A4M3e23mRZ9VrbpMngwcrqNAg== ) )`
	rrMX, err := NewRR(exMX)
	if err != nil {
		t.Fatal(err)
	}
	rrRRSIG, err := NewRR(exRRSIG)
	if err != nil {
		t.Fatal(err)
	}
	if err = rrRRSIG.(*RRSIG).Verify(rrDNSKEY.(*DNSKEY), []RR{rrMX}); err != nil {
		t.Errorf("failure to validate the spec RRSIG: %v", err)
	}

	ourRRSIG := &RRSIG{
		Hdr: RR_Header{
			Ttl: rrMX.Header().Ttl,
		},
		KeyTag:     rrDNSKEY.(*DNSKEY).KeyTag(),
		SignerName: rrDNSKEY.(*DNSKEY).Hdr.Name,
		Algorithm:  rrDNSKEY.(*DNSKEY).Algorithm,
	}
	ourRRSIG.Expiration, _ = StringToTime("20150819220000")
	ourRRSIG.Inception, _ = StringToTime("20150729220000")
	err = ourRRSIG.Sign(priv, []RR{rrMX})
	if err != nil {
		t.Fatal(err)
	}

	if err = ourRRSIG.Verify(rrDNSKEY.(*DNSKEY), []RR{rrMX}); err != nil {
		t.Errorf("failure to validate our RRSIG: %v", err)
	}

	if !reflect.DeepEqual(ourRRSIG, rrRRSIG.(*RRSIG)) {
		t.Fatalf("RRSIG record differs:\n%v\n%v", ourRRSIG, rrRRSIG.(*RRSIG))
	}
}

// rfc8080 6.1
func TestRFC8080Ed25519Example2(t *testing.T) {
	exDNSKEY := `example.com. 3600 IN DNSKEY 257 3 15 (
             zPnZ/QwEe7S8C5SPz2OfS5RR40ATk2/rYnE9xHIEijs= )`
	exPriv := `Private-key-format: v1.2
Algorithm: 15 (ED25519)
PrivateKey: DSSF3o0s0f+ElWzj9E/Osxw8hLpk55chkmx0LYN5WiY=`
	rrDNSKEY, err := NewRR(exDNSKEY)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := rrDNSKEY.(*DNSKEY).NewPrivateKey(exPriv)
	if err != nil {
		t.Fatal(err)
	}

	exDS := `example.com. 3600 IN DS 35217 15 2 (
             401781b934e392de492ec77ae2e15d70f6575a1c0bc59c5275c04ebe80c
             6614c )`
	rrDS, err := NewRR(exDS)
	if err != nil {
		t.Fatal(err)
	}
	ourDS := rrDNSKEY.(*DNSKEY).ToDS(SHA256)
	if !reflect.DeepEqual(ourDS, rrDS.(*DS)) {
		t.Fatalf("DS record differs:\n%v\n%v", ourDS, rrDS.(*DS))
	}

	exMX := `example.com. 3600 IN MX 10 mail.example.com.`
	exRRSIG := `example.com. 3600 IN RRSIG MX 15 2 3600 (
             1440021600 1438207200 35217 example.com. (
             zXQ0bkYgQTEFyfLyi9QoiY6D8ZdYo4wyUhVioYZXFdT410QPRITQSqJSnzQ
             oSm5poJ7gD7AQR0O7KuI5k2pcBg== ) )`
	rrMX, err := NewRR(exMX)
	if err != nil {
		t.Fatal(err)
	}
	rrRRSIG, err := NewRR(exRRSIG)
	if err != nil {
		t.Fatal(err)
	}
	if err = rrRRSIG.(*RRSIG).Verify(rrDNSKEY.(*DNSKEY), []RR{rrMX}); err != nil {
		t.Errorf("failure to validate the spec RRSIG: %v", err)
	}

	ourRRSIG := &RRSIG{
		Hdr: RR_Header{
			Ttl: rrMX.Header().Ttl,
		},
		KeyTag:     rrDNSKEY.(*DNSKEY).KeyTag(),
		SignerName: rrDNSKEY.(*DNSKEY).Hdr.Name,
		Algorithm:  rrDNSKEY.(*DNSKEY).Algorithm,
	}
	ourRRSIG.Expiration, _ = StringToTime("20150819220000")
	ourRRSIG.Inception, _ = StringToTime("20150729220000")
	err = ourRRSIG.Sign(priv, []RR{rrMX})
	if err != nil {
		t.Fatal(err)
	}

	if err = ourRRSIG.Verify(rrDNSKEY.(*DNSKEY), []RR{rrMX}); err != nil {
		t.Errorf("failure to validate our RRSIG: %v", err)
	}

	if !reflect.DeepEqual(ourRRSIG, rrRRSIG.(*RRSIG)) {
		t.Fatalf("RRSIG record differs:\n%v\n%v", ourRRSIG, rrRRSIG.(*RRSIG))
	}
}

func TestInvalidRRSet(t *testing.T) {
	goodRecords := make([]RR, 2)
	goodRecords[0] = &TXT{Hdr: RR_Header{Name: "name.cloudflare.com.", Rrtype: TypeTXT, Class: ClassINET, Ttl: 0}, Txt: []string{"Hello world"}}
	goodRecords[1] = &TXT{Hdr: RR_Header{Name: "name.cloudflare.com.", Rrtype: TypeTXT, Class: ClassINET, Ttl: 0}, Txt: []string{"_o/"}}

	// Generate key
	keyname := "cloudflare.com."
	key := &DNSKEY{
		Hdr:       RR_Header{Name: keyname, Rrtype: TypeDNSKEY, Class: ClassINET, Ttl: 0},
		Algorithm: ECDSAP256SHA256,
		Flags:     ZONE,
		Protocol:  3,
	}
	privatekey, err := key.Generate(256)
	if err != nil {
		t.Fatal(err.Error())
	}

	// Need to fill in: Inception, Expiration, KeyTag, SignerName and Algorithm
	curTime := time.Now()
	signature := &RRSIG{
		Inception:  uint32(curTime.Unix()),
		Expiration: uint32(curTime.Add(time.Hour).Unix()),
		KeyTag:     key.KeyTag(),
		SignerName: keyname,
		Algorithm:  ECDSAP256SHA256,
	}

	// Inconsistent name between records
	badRecords := make([]RR, 2)
	badRecords[0] = &TXT{Hdr: RR_Header{Name: "name.cloudflare.com.", Rrtype: TypeTXT, Class: ClassINET, Ttl: 0}, Txt: []string{"Hello world"}}
	badRecords[1] = &TXT{Hdr: RR_Header{Name: "nama.cloudflare.com.", Rrtype: TypeTXT, Class: ClassINET, Ttl: 0}, Txt: []string{"_o/"}}

	if IsRRset(badRecords) {
		t.Fatal("Record set with inconsistent names considered valid")
	}

	badRecords[0] = &TXT{Hdr: RR_Header{Name: "name.cloudflare.com.", Rrtype: TypeTXT, Class: ClassINET, Ttl: 0}, Txt: []string{"Hello world"}}
	badRecords[1] = &A{Hdr: RR_Header{Name: "name.cloudflare.com.", Rrtype: TypeA, Class: ClassINET, Ttl: 0}}

	if IsRRset(badRecords) {
		t.Fatal("Record set with inconsistent record types considered valid")
	}

	badRecords[0] = &TXT{Hdr: RR_Header{Name: "name.cloudflare.com.", Rrtype: TypeTXT, Class: ClassINET, Ttl: 0}, Txt: []string{"Hello world"}}
	badRecords[1] = &TXT{Hdr: RR_Header{Name: "name.cloudflare.com.", Rrtype: TypeTXT, Class: ClassCHAOS, Ttl: 0}, Txt: []string{"_o/"}}

	if IsRRset(badRecords) {
		t.Fatal("Record set with inconsistent record class considered valid")
	}

	// Sign the good record set and then make sure verification fails on the bad record set
	if err := signature.Sign(privatekey, goodRecords); err != nil {
		t.Fatal("Signing good records failed")
	}

	if err := signature.Verify(key, badRecords); err != ErrRRset {
		t.Fatal("Verification did not return ErrRRset with inconsistent records")
	}
}

// Issue #688 - RSA exponent unpacked in reverse
func TestRsaExponentUnpack(t *testing.T) {
	zskRrDnskey, _ := NewRR("isc.org.                7200    IN      DNSKEY  256 3 5 AwEAAcdkaRUlsRD4gcF63PpPJJ1E6kOIb3yn/UHptVsPEQtEbgJ2y20O eix4unpwoQkz+bIAd2rrOU/95wgV530x0/qqKwBLWoGkxdcnNcvVT4hl 3SOTZy1VjwkAfyayHPU8VisXqJGbB3KWevBZlb6AtrXzFu8AHuBeeAAe /fOgreCh")
	kskRrDnskey, _ := NewRR("isc.org.                7200    IN      DNSKEY  257 3 5 BEAAAAOhHQDBrhQbtphgq2wQUpEQ5t4DtUHxoMVFu2hWLDMvoOMRXjGr hhCeFvAZih7yJHf8ZGfW6hd38hXG/xylYCO6Krpbdojwx8YMXLA5/kA+ u50WIL8ZR1R6KTbsYVMf/Qx5RiNbPClw+vT+U8eXEJmO20jIS1ULgqy3 47cBB1zMnnz/4LJpA0da9CbKj3A254T515sNIMcwsB8/2+2E63/zZrQz Bkj0BrN/9Bexjpiks3jRhZatEsXn3dTy47R09Uix5WcJt+xzqZ7+ysyL KOOedS39Z7SDmsn2eA0FKtQpwA6LXeG2w+jxmw3oA8lVUgEf/rzeC/bB yBNsO70aEFTd")
	kskRrRrsig, _ := NewRR("isc.org.                7200    IN      RRSIG   DNSKEY 5 2 7200 20180627230244 20180528230244 12892 isc.org. ebKBlhYi1hPGTdPg6zSwvprOIkoFMs+WIhMSjoYW6/K5CS9lDDFdK4cu TgXJRT3etrltTuJiFe2HRpp+7t5cKLy+CeJZVzqrCz200MoHiFuLI9yI DJQGaS5YYCiFbw5+jUGU6aUhZ7Y5/YufeqATkRZzdrKwgK+zri8LPw9T WLoVJPAOW7GR0dgxl9WKmO7Fzi9P8BZR3NuwLV7329X94j+4zyswaw7q e5vif0ybzFveODLsEi/E0a2rTXc4QzzyM0fSVxRkVQyQ7ifIPP4ohnnT d5qpPUbE8xxBzTdWR/TaKADC5aCFkppG9lVAq5CPfClii2949X5RYzy1 rxhuSA==")
	zskRrRrsig, _ := NewRR("isc.org.                7200    IN      RRSIG   DNSKEY 5 2 7200 20180627230244 20180528230244 19923 isc.org. RgCfzUeq4RJPGoe9RRB6cWf6d/Du+tHK5SxI5QL1waA3O5qVtQKFkY1C dq/yyVjwzfjD9F62TObujOaktv8X80ZMcNPmgHbvK1xOqelMBWv5hxj3 xRe+QQObLZ5NPfHFsphQKXvwgO5Sjk8py2B2iCr3BHCZ8S38oIfuSrQx sn8=")

	zsk, ksk := zskRrDnskey.(*DNSKEY), kskRrDnskey.(*DNSKEY)
	zskSig, kskSig := zskRrRrsig.(*RRSIG), kskRrRrsig.(*RRSIG)

	if e := zskSig.Verify(zsk, []RR{zsk, ksk}); e != nil {
		t.Fatalf("cannot verify RRSIG with keytag [%d]. Cause [%s]", zsk.KeyTag(), e.Error())
	}

	if e := kskSig.Verify(ksk, []RR{zsk, ksk}); e != nil {
		t.Fatalf("cannot verify RRSIG with keytag [%d]. Cause [%s]", ksk.KeyTag(), e.Error())
	}
}

func TestParseKeyReadError(t *testing.T) {
	m, err := parseKey(errReader{}, "")
	if err == nil || !strings.Contains(err.Error(), errTestReadError.Error()) {
		t.Errorf("expected error to contain %q, but got %v", errTestReadError, err)
	}
	if m != nil {
		t.Errorf("expected a nil map, but got %v", m)
	}
}

func TestRSAMD5KeyTag(t *testing.T) {
	rr1, _ := NewRR("test.  IN DNSKEY  257 3 1 AwEAAcntNdoMnY8pvyPcpDTAaiqHyAhf53XUBANq166won/fjBFvmuzhTuP5r4el/pV0tzEBL73zpoU48BqF66uiL+qRijXCySJiaBUvLNll5rpwuduAOoVpmwOmkC4fV6izHOAx/Uy8c+pYP0YR8+1P7GuTFxgnMmt9sUGtoe+la0X/ ;{id = 27461 (ksk), size = 1024b}")
	rr2, _ := NewRR("test.  IN DNSKEY  257 3 1 AwEAAf0bKO/m45ylk5BlSLmQHQRBLx1m/ZUXvyPFB387bJXxnTk6so3ub97L1RQ+8bOoiRh3Qm5EaYihjco7J8b/W5WbS3tVsE79nY584RfTKT2zcZ9AoFP2XLChXxPIf/6l0H9n6sH0aBjsG8vabEIp8e06INM3CXVPiMRPPeGNa0Ub ;{id = 27461 (ksk), size = 1024b}")

	exp := uint16(27461)
	if x := rr1.(*DNSKEY).KeyTag(); x != exp {
		t.Errorf("expected %d, got %d, as keytag for rr1", exp, x)
	}
	if x := rr2.(*DNSKEY).KeyTag(); x != exp { // yes, same key tag
		t.Errorf("expected %d, got %d, as keytag for rr2", exp, x)
	}
}

// Benchmarks

// Generate benchmarks

// BenchmarkGenerateRSA generates a DNSKEY record using RSASHA256
func BenchmarkGenerateRSA(b *testing.B) {
	// create DNSKEY RR
	key := new(DNSKEY)
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = RSASHA256
	for i := 0; i < b.N; i++ {
		_, err := key.Generate(2048)
		require.Nil(b, err, "err should be nil")
	}
}

// BenchmarkGenerateECDSA generates a DNSKEY record using ECDSAP256SHA256
func BenchmarkGenerateECDSA(b *testing.B) {
	// create DNSKEY RR
	key := new(DNSKEY)
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = ECDSAP256SHA256
	for i := 0; i < b.N; i++ {
		_, err := key.Generate(256)
		require.Nil(b, err, "err should be nil")
	}
}

// BenchmarkGenerateRawKeyED25519 generates a DNSKEY record using ED25519
func BenchmarkGenerateED25519(b *testing.B) {
	// create DNSKEY RR
	key := new(DNSKEY)
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = ED25519
	for i := 0; i < b.N; i++ {
		_, err := key.Generate(256)
		require.Nil(b, err, "err should be nil")
	}
}

// BenchmarkGenerateFALCON512 generates a DNSKEY record using FALCON512
func BenchmarkGenerateFALCON512(b *testing.B) {
	// create DNSKEY RR
	key := new(DNSKEY)
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = FALCON512
	for i := 0; i < b.N; i++ {
		_, err := key.Generate(1281)
		require.Nil(b, err, "err should be nil")
	}
}

// BenchmarkGenerateP256FALCON512 generates a DNSKEY record using P256_FALCON512
func BenchmarkGenerateP256FALCON512(b *testing.B) {
	// create DNSKEY RR
	key := new(DNSKEY)
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = P256_FALCON512
	for i := 0; i < b.N; i++ {
		_, err := key.Generate(1406)
		require.Nil(b, err, "err should be nil")
	}
}

// BenchmarkGenerateRSA3072FALCON512 generates a DNSKEY record using RSA3072_FALCON512
func BenchmarkGenerateRSA3072FALCON512(b *testing.B) {
	// create DNSKEY RR
	key := new(DNSKEY)
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = RSA3072_FALCON512
	for i := 0; i < b.N; i++ {
		_, err := key.Generate(3055)
		require.Nil(b, err, "err should be nil")
	}
}

// BenchmarkGenerateFALCON1024 generates a DNSKEY record using FALCON1024
func BenchmarkGenerateFALCON1024(b *testing.B) {
	// create DNSKEY RR
	key := new(DNSKEY)
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = FALCON1024
	for i := 0; i < b.N; i++ {
		_, err := key.Generate(2305)
		require.Nil(b, err, "err should be nil")
	}
}

// BenchmarkGenerateP521FALCON1024 generates a DNSKEY record using P521_FALCON1024
func BenchmarkGenerateP521FALCON1024(b *testing.B) {
	// create DNSKEY RR
	key := new(DNSKEY)
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = P521_FALCON1024
	for i := 0; i < b.N; i++ {
		_, err := key.Generate(2532)
		require.Nil(b, err, "err should be nil")
	}
}

// Sign benchmarks

func BenchmarkSignRSA(b *testing.B) {
	var err error
	// create record to sign
	soa := new(SOA)
	soa.Hdr = RR_Header{"*.miek.nl.", TypeSOA, ClassINET, 14400, 0}
	soa.Ns = "open.nlnetlabs.nl."
	soa.Mbox = "miekg.atoom.net."
	soa.Serial = 1293945905
	soa.Refresh = 14400
	soa.Retry = 3600
	soa.Expire = 604800
	soa.Minttl = 86400

	// create DNSKEY RR
	key := new(DNSKEY)
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = RSASHA256
	privkey, err := key.Generate(2048)
	require.Nil(b, err, "err should be nil")

	// create RRSIG
	sig := new(RRSIG)
	sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.TypeCovered = soa.Hdr.Rrtype
	sig.Labels = uint8(CountLabel(soa.Hdr.Name)) // works for all 3
	sig.OrigTtl = soa.Hdr.Ttl
	sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
	sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.KeyTag = key.KeyTag()   // Get the keyfrom the Key
	sig.SignerName = key.Hdr.Name
	sig.Algorithm = RSASHA256

	for i := 0; i < b.N; i++ {
		err = sig.Sign(privkey, []RR{soa})
		require.Nil(b, err, "sign err should be nil")
	}
}

func BenchmarkSignECDSA(b *testing.B) {
	var err error
	// create record to sign
	soa := new(SOA)
	soa.Hdr = RR_Header{"*.miek.nl.", TypeSOA, ClassINET, 14400, 0}
	soa.Ns = "open.nlnetlabs.nl."
	soa.Mbox = "miekg.atoom.net."
	soa.Serial = 1293945905
	soa.Refresh = 14400
	soa.Retry = 3600
	soa.Expire = 604800
	soa.Minttl = 86400

	// create DNSKEY RR
	key := new(DNSKEY)
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = ECDSAP256SHA256
	privkey, err := key.Generate(256)
	require.Nil(b, err, "err should be nil")

	// create RRSIG
	sig := new(RRSIG)
	sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.TypeCovered = soa.Hdr.Rrtype
	sig.Labels = uint8(CountLabel(soa.Hdr.Name)) // works for all 3
	sig.OrigTtl = soa.Hdr.Ttl
	sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
	sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.KeyTag = key.KeyTag()   // Get the keyfrom the Key
	sig.SignerName = key.Hdr.Name
	sig.Algorithm = ECDSAP256SHA256

	for i := 0; i < b.N; i++ {
		err = sig.Sign(privkey, []RR{soa})
		require.Nil(b, err, "sign err should be nil")
	}
}

func BenchmarkSignED25519(b *testing.B) {
	var err error
	// create record to sign
	soa := new(SOA)
	soa.Hdr = RR_Header{"*.miek.nl.", TypeSOA, ClassINET, 14400, 0}
	soa.Ns = "open.nlnetlabs.nl."
	soa.Mbox = "miekg.atoom.net."
	soa.Serial = 1293945905
	soa.Refresh = 14400
	soa.Retry = 3600
	soa.Expire = 604800
	soa.Minttl = 86400

	// create DNSKEY RR
	key := new(DNSKEY)
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = ED25519
	privkey, err := key.Generate(256)
	require.Nil(b, err, "err should be nil")

	// create RRSIG
	sig := new(RRSIG)
	sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.TypeCovered = soa.Hdr.Rrtype
	sig.Labels = uint8(CountLabel(soa.Hdr.Name)) // works for all 3
	sig.OrigTtl = soa.Hdr.Ttl
	sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
	sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.KeyTag = key.KeyTag()   // Get the keyfrom the Key
	sig.SignerName = key.Hdr.Name
	sig.Algorithm = ED25519

	for i := 0; i < b.N; i++ {
		err = sig.Sign(privkey, []RR{soa})
		require.Nil(b, err, "sign err should be nil")
	}
}

func BenchmarkSignFALCON512(b *testing.B) {
	var err error
	// create record to sign
	soa := new(SOA)
	soa.Hdr = RR_Header{"*.miek.nl.", TypeSOA, ClassINET, 14400, 0}
	soa.Ns = "open.nlnetlabs.nl."
	soa.Mbox = "miekg.atoom.net."
	soa.Serial = 1293945905
	soa.Refresh = 14400
	soa.Retry = 3600
	soa.Expire = 604800
	soa.Minttl = 86400

	// create DNSKEY RR
	key := new(DNSKEY)
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = FALCON512
	privkey, err := key.Generate(1281)
	require.Nil(b, err, "err should be nil")

	// create RRSIG
	sig := new(RRSIG)
	sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.TypeCovered = soa.Hdr.Rrtype
	sig.Labels = uint8(CountLabel(soa.Hdr.Name)) // works for all 3
	sig.OrigTtl = soa.Hdr.Ttl
	sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
	sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.KeyTag = key.KeyTag()   // Get the keyfrom the Key
	sig.SignerName = key.Hdr.Name
	sig.Algorithm = FALCON512

	for i := 0; i < b.N; i++ {
		err = sig.Sign(privkey, []RR{soa})
		require.Nil(b, err, "sign err should be nil")
	}
}

func BenchmarkSignP256_FALCON512(b *testing.B) {
	var err error
	// create record to sign
	soa := new(SOA)
	soa.Hdr = RR_Header{"*.miek.nl.", TypeSOA, ClassINET, 14400, 0}
	soa.Ns = "open.nlnetlabs.nl."
	soa.Mbox = "miekg.atoom.net."
	soa.Serial = 1293945905
	soa.Refresh = 14400
	soa.Retry = 3600
	soa.Expire = 604800
	soa.Minttl = 86400

	// create DNSKEY RR
	key := new(DNSKEY)
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = P256_FALCON512
	privkey, err := key.Generate(1406)
	require.Nil(b, err, "err should be nil")

	// create RRSIG
	sig := new(RRSIG)
	sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.TypeCovered = soa.Hdr.Rrtype
	sig.Labels = uint8(CountLabel(soa.Hdr.Name)) // works for all 3
	sig.OrigTtl = soa.Hdr.Ttl
	sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
	sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.KeyTag = key.KeyTag()   // Get the keyfrom the Key
	sig.SignerName = key.Hdr.Name
	sig.Algorithm = P256_FALCON512

	for i := 0; i < b.N; i++ {
		err = sig.Sign(privkey, []RR{soa})
		require.Nil(b, err, "sign err should be nil")
	}
}

func BenchmarkSignRSA3072FALCON512(b *testing.B) {
	var err error
	// create record to sign
	soa := new(SOA)
	soa.Hdr = RR_Header{"*.miek.nl.", TypeSOA, ClassINET, 14400, 0}
	soa.Ns = "open.nlnetlabs.nl."
	soa.Mbox = "miekg.atoom.net."
	soa.Serial = 1293945905
	soa.Refresh = 14400
	soa.Retry = 3600
	soa.Expire = 604800
	soa.Minttl = 86400

	// create DNSKEY RR
	key := new(DNSKEY)
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = RSA3072_FALCON512
	privkey, err := key.Generate(3055)
	require.Nil(b, err, "err should be nil")

	// create RRSIG
	sig := new(RRSIG)
	sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.TypeCovered = soa.Hdr.Rrtype
	sig.Labels = uint8(CountLabel(soa.Hdr.Name)) // works for all 3
	sig.OrigTtl = soa.Hdr.Ttl
	sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
	sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.KeyTag = key.KeyTag()   // Get the keyfrom the Key
	sig.SignerName = key.Hdr.Name
	sig.Algorithm = RSA3072_FALCON512

	for i := 0; i < b.N; i++ {
		err = sig.Sign(privkey, []RR{soa})
		require.Nil(b, err, "sign err should be nil")
	}
}

func BenchmarkSignFALCON1024(b *testing.B) {
	var err error
	// create record to sign
	soa := new(SOA)
	soa.Hdr = RR_Header{"*.miek.nl.", TypeSOA, ClassINET, 14400, 0}
	soa.Ns = "open.nlnetlabs.nl."
	soa.Mbox = "miekg.atoom.net."
	soa.Serial = 1293945905
	soa.Refresh = 14400
	soa.Retry = 3600
	soa.Expire = 604800
	soa.Minttl = 86400

	// create DNSKEY RR
	key := new(DNSKEY)
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = FALCON1024
	privkey, err := key.Generate(2305)
	require.Nil(b, err, "err should be nil")

	// create RRSIG
	sig := new(RRSIG)
	sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.TypeCovered = soa.Hdr.Rrtype
	sig.Labels = uint8(CountLabel(soa.Hdr.Name)) // works for all 3
	sig.OrigTtl = soa.Hdr.Ttl
	sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
	sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.KeyTag = key.KeyTag()   // Get the keyfrom the Key
	sig.SignerName = key.Hdr.Name
	sig.Algorithm = FALCON1024

	for i := 0; i < b.N; i++ {
		err = sig.Sign(privkey, []RR{soa})
		require.Nil(b, err, "sign err should be nil")
	}
}

func BenchmarkSignP521FALCON1024(b *testing.B) {
	var err error
	// create record to sign
	soa := new(SOA)
	soa.Hdr = RR_Header{"*.miek.nl.", TypeSOA, ClassINET, 14400, 0}
	soa.Ns = "open.nlnetlabs.nl."
	soa.Mbox = "miekg.atoom.net."
	soa.Serial = 1293945905
	soa.Refresh = 14400
	soa.Retry = 3600
	soa.Expire = 604800
	soa.Minttl = 86400

	// create DNSKEY RR
	key := new(DNSKEY)
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = P521_FALCON1024
	privkey, err := key.Generate(2532)
	require.Nil(b, err, "err should be nil")

	// create RRSIG
	sig := new(RRSIG)
	sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.TypeCovered = soa.Hdr.Rrtype
	sig.Labels = uint8(CountLabel(soa.Hdr.Name)) // works for all 3
	sig.OrigTtl = soa.Hdr.Ttl
	sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
	sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.KeyTag = key.KeyTag()   // Get the keyfrom the Key
	sig.SignerName = key.Hdr.Name
	sig.Algorithm = P521_FALCON1024

	for i := 0; i < b.N; i++ {
		err = sig.Sign(privkey, []RR{soa})
		require.Nil(b, err, "sign err should be nil")
	}
}

// Verify benchmarks

func BenchmarkVerifyRSA(b *testing.B) {
	var err error
	// create record to sign
	soa := new(SOA)
	soa.Hdr = RR_Header{"*.miek.nl.", TypeSOA, ClassINET, 14400, 0}
	soa.Ns = "open.nlnetlabs.nl."
	soa.Mbox = "miekg.atoom.net."
	soa.Serial = 1293945905
	soa.Refresh = 14400
	soa.Retry = 3600
	soa.Expire = 604800
	soa.Minttl = 86400

	// create DNSKEY RR
	key := new(DNSKEY)
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = RSASHA256
	privkey, err := key.Generate(2048)
	require.Nil(b, err, "err should be nil")

	// create RRSIG
	sig := new(RRSIG)
	sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.TypeCovered = soa.Hdr.Rrtype
	sig.Labels = uint8(CountLabel(soa.Hdr.Name)) // works for all 3
	sig.OrigTtl = soa.Hdr.Ttl
	sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
	sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.KeyTag = key.KeyTag()   // Get the keyfrom the Key
	sig.SignerName = key.Hdr.Name
	sig.Algorithm = RSASHA256

	err = sig.Sign(privkey, []RR{soa})
	require.Nil(b, err, "sign err should be nil")

	for i := 0; i < b.N; i++ {
		err = sig.Verify(key, []RR{soa})
		require.Nil(b, err, "verify err should be nil")
	}
}

func BenchmarkVerifyECDSA(b *testing.B) {
	var err error
	// create record to sign
	soa := new(SOA)
	soa.Hdr = RR_Header{"*.miek.nl.", TypeSOA, ClassINET, 14400, 0}
	soa.Ns = "open.nlnetlabs.nl."
	soa.Mbox = "miekg.atoom.net."
	soa.Serial = 1293945905
	soa.Refresh = 14400
	soa.Retry = 3600
	soa.Expire = 604800
	soa.Minttl = 86400

	// create DNSKEY RR
	key := new(DNSKEY)
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = ECDSAP256SHA256
	privkey, err := key.Generate(256)
	require.Nil(b, err, "err should be nil")

	// create RRSIG
	sig := new(RRSIG)
	sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.TypeCovered = soa.Hdr.Rrtype
	sig.Labels = uint8(CountLabel(soa.Hdr.Name)) // works for all 3
	sig.OrigTtl = soa.Hdr.Ttl
	sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
	sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.KeyTag = key.KeyTag()   // Get the keyfrom the Key
	sig.SignerName = key.Hdr.Name
	sig.Algorithm = ECDSAP256SHA256

	err = sig.Sign(privkey, []RR{soa})
	require.Nil(b, err, "sign err should be nil")

	for i := 0; i < b.N; i++ {
		err = sig.Verify(key, []RR{soa})
		require.Nil(b, err, "verify err should be nil")
	}
}

func BenchmarkVerifyED25519(b *testing.B) {
	var err error
	// create record to sign
	soa := new(SOA)
	soa.Hdr = RR_Header{"*.miek.nl.", TypeSOA, ClassINET, 14400, 0}
	soa.Ns = "open.nlnetlabs.nl."
	soa.Mbox = "miekg.atoom.net."
	soa.Serial = 1293945905
	soa.Refresh = 14400
	soa.Retry = 3600
	soa.Expire = 604800
	soa.Minttl = 86400

	// create DNSKEY RR
	key := new(DNSKEY)
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = ED25519
	privkey, err := key.Generate(256)
	require.Nil(b, err, "err should be nil")

	// create RRSIG
	sig := new(RRSIG)
	sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.TypeCovered = soa.Hdr.Rrtype
	sig.Labels = uint8(CountLabel(soa.Hdr.Name)) // works for all 3
	sig.OrigTtl = soa.Hdr.Ttl
	sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
	sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.KeyTag = key.KeyTag()   // Get the keyfrom the Key
	sig.SignerName = key.Hdr.Name
	sig.Algorithm = ED25519

	err = sig.Sign(privkey, []RR{soa})
	require.Nil(b, err, "sign err should be nil")

	for i := 0; i < b.N; i++ {
		err = sig.Verify(key, []RR{soa})
		require.Nil(b, err, "verify err should be nil")
	}
}

func BenchmarkVerifyFALCON512(b *testing.B) {
	var err error
	// create record to sign
	soa := new(SOA)
	soa.Hdr = RR_Header{"*.miek.nl.", TypeSOA, ClassINET, 14400, 0}
	soa.Ns = "open.nlnetlabs.nl."
	soa.Mbox = "miekg.atoom.net."
	soa.Serial = 1293945905
	soa.Refresh = 14400
	soa.Retry = 3600
	soa.Expire = 604800
	soa.Minttl = 86400

	// create DNSKEY RR
	key := new(DNSKEY)
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = FALCON512
	privkey, err := key.Generate(1281)
	require.Nil(b, err, "err should be nil")

	// create RRSIG
	sig := new(RRSIG)
	sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.TypeCovered = soa.Hdr.Rrtype
	sig.Labels = uint8(CountLabel(soa.Hdr.Name)) // works for all 3
	sig.OrigTtl = soa.Hdr.Ttl
	sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
	sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.KeyTag = key.KeyTag()   // Get the keyfrom the Key
	sig.SignerName = key.Hdr.Name
	sig.Algorithm = FALCON512

	err = sig.Sign(privkey, []RR{soa})
	require.Nil(b, err, "sign err should be nil")

	for i := 0; i < b.N; i++ {
		err = sig.Verify(key, []RR{soa})
		require.Nil(b, err, "verify err should be nil")
	}
}

func BenchmarkVerifyP256FALCON512(b *testing.B) {
	var err error
	// create record to sign
	soa := new(SOA)
	soa.Hdr = RR_Header{"*.miek.nl.", TypeSOA, ClassINET, 14400, 0}
	soa.Ns = "open.nlnetlabs.nl."
	soa.Mbox = "miekg.atoom.net."
	soa.Serial = 1293945905
	soa.Refresh = 14400
	soa.Retry = 3600
	soa.Expire = 604800
	soa.Minttl = 86400

	// create DNSKEY RR
	key := new(DNSKEY)
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = P256_FALCON512
	privkey, err := key.Generate(1406)
	require.Nil(b, err, "err should be nil")

	// create RRSIG
	sig := new(RRSIG)
	sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.TypeCovered = soa.Hdr.Rrtype
	sig.Labels = uint8(CountLabel(soa.Hdr.Name)) // works for all 3
	sig.OrigTtl = soa.Hdr.Ttl
	sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
	sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.KeyTag = key.KeyTag()   // Get the keyfrom the Key
	sig.SignerName = key.Hdr.Name
	sig.Algorithm = P256_FALCON512

	err = sig.Sign(privkey, []RR{soa})
	require.Nil(b, err, "sign err should be nil")

	for i := 0; i < b.N; i++ {
		err = sig.Verify(key, []RR{soa})
		require.Nil(b, err, "verify err should be nil")
	}
}

func BenchmarkVerifyRSA3072FALCON512(b *testing.B) {
	var err error
	// create record to sign
	soa := new(SOA)
	soa.Hdr = RR_Header{"*.miek.nl.", TypeSOA, ClassINET, 14400, 0}
	soa.Ns = "open.nlnetlabs.nl."
	soa.Mbox = "miekg.atoom.net."
	soa.Serial = 1293945905
	soa.Refresh = 14400
	soa.Retry = 3600
	soa.Expire = 604800
	soa.Minttl = 86400

	// create DNSKEY RR
	key := new(DNSKEY)
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = RSA3072_FALCON512
	privkey, err := key.Generate(3055)
	require.Nil(b, err, "err should be nil")

	// create RRSIG
	sig := new(RRSIG)
	sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.TypeCovered = soa.Hdr.Rrtype
	sig.Labels = uint8(CountLabel(soa.Hdr.Name)) // works for all 3
	sig.OrigTtl = soa.Hdr.Ttl
	sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
	sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.KeyTag = key.KeyTag()   // Get the keyfrom the Key
	sig.SignerName = key.Hdr.Name
	sig.Algorithm = RSA3072_FALCON512

	err = sig.Sign(privkey, []RR{soa})
	require.Nil(b, err, "sign err should be nil")

	for i := 0; i < b.N; i++ {
		err = sig.Verify(key, []RR{soa})
		require.Nil(b, err, "verify err should be nil")
	}
}

func BenchmarkVerifyFALCON1024(b *testing.B) {
	var err error
	// create record to sign
	soa := new(SOA)
	soa.Hdr = RR_Header{"*.miek.nl.", TypeSOA, ClassINET, 14400, 0}
	soa.Ns = "open.nlnetlabs.nl."
	soa.Mbox = "miekg.atoom.net."
	soa.Serial = 1293945905
	soa.Refresh = 14400
	soa.Retry = 3600
	soa.Expire = 604800
	soa.Minttl = 86400

	// create DNSKEY RR
	key := new(DNSKEY)
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = FALCON1024
	privkey, err := key.Generate(2305)
	require.Nil(b, err, "err should be nil")

	// create RRSIG
	sig := new(RRSIG)
	sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.TypeCovered = soa.Hdr.Rrtype
	sig.Labels = uint8(CountLabel(soa.Hdr.Name)) // works for all 3
	sig.OrigTtl = soa.Hdr.Ttl
	sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
	sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.KeyTag = key.KeyTag()   // Get the keyfrom the Key
	sig.SignerName = key.Hdr.Name
	sig.Algorithm = FALCON1024

	err = sig.Sign(privkey, []RR{soa})
	require.Nil(b, err, "sign err should be nil")

	for i := 0; i < b.N; i++ {
		err = sig.Verify(key, []RR{soa})
		require.Nil(b, err, "verify err should be nil")
	}
}

func BenchmarkVerifyP521FALCON1024(b *testing.B) {
	var err error
	// create record to sign
	soa := new(SOA)
	soa.Hdr = RR_Header{"*.miek.nl.", TypeSOA, ClassINET, 14400, 0}
	soa.Ns = "open.nlnetlabs.nl."
	soa.Mbox = "miekg.atoom.net."
	soa.Serial = 1293945905
	soa.Refresh = 14400
	soa.Retry = 3600
	soa.Expire = 604800
	soa.Minttl = 86400

	// create DNSKEY RR
	key := new(DNSKEY)
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = P521_FALCON1024
	privkey, err := key.Generate(2532)
	require.Nil(b, err, "err should be nil")

	// create RRSIG
	sig := new(RRSIG)
	sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.TypeCovered = soa.Hdr.Rrtype
	sig.Labels = uint8(CountLabel(soa.Hdr.Name)) // works for all 3
	sig.OrigTtl = soa.Hdr.Ttl
	sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
	sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.KeyTag = key.KeyTag()   // Get the keyfrom the Key
	sig.SignerName = key.Hdr.Name
	sig.Algorithm = P521_FALCON1024

	err = sig.Sign(privkey, []RR{soa})
	require.Nil(b, err, "sign err should be nil")

	for i := 0; i < b.N; i++ {
		err = sig.Verify(key, []RR{soa})
		require.Nil(b, err, "verify err should be nil")
	}
}

// Sign and verify benchmarks

func BenchmarkSignVerifyRSA(b *testing.B) {
	var err error
	// create record to sign
	soa := new(SOA)
	soa.Hdr = RR_Header{"*.miek.nl.", TypeSOA, ClassINET, 14400, 0}
	soa.Ns = "open.nlnetlabs.nl."
	soa.Mbox = "miekg.atoom.net."
	soa.Serial = 1293945905
	soa.Refresh = 14400
	soa.Retry = 3600
	soa.Expire = 604800
	soa.Minttl = 86400

	// create DNSKEY RR
	key := new(DNSKEY)
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = RSASHA256
	privkey, err := key.Generate(2048)
	require.Nil(b, err, "err should be nil")

	// create RRSIG
	sig := new(RRSIG)
	sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.TypeCovered = soa.Hdr.Rrtype
	sig.Labels = uint8(CountLabel(soa.Hdr.Name)) // works for all 3
	sig.OrigTtl = soa.Hdr.Ttl
	sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
	sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.KeyTag = key.KeyTag()   // Get the keyfrom the Key
	sig.SignerName = key.Hdr.Name
	sig.Algorithm = RSASHA256

	for i := 0; i < b.N; i++ {
		err = sig.Sign(privkey, []RR{soa})
		require.Nil(b, err, "sign err should be nil")
		err = sig.Verify(key, []RR{soa})
		require.Nil(b, err, "verify err should be nil")
	}
}

func BenchmarkSignVerifyECDSA(b *testing.B) {
	var err error
	// create record to sign
	soa := new(SOA)
	soa.Hdr = RR_Header{"*.miek.nl.", TypeSOA, ClassINET, 14400, 0}
	soa.Ns = "open.nlnetlabs.nl."
	soa.Mbox = "miekg.atoom.net."
	soa.Serial = 1293945905
	soa.Refresh = 14400
	soa.Retry = 3600
	soa.Expire = 604800
	soa.Minttl = 86400

	// create DNSKEY RR
	key := new(DNSKEY)
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = ECDSAP256SHA256
	privkey, err := key.Generate(256)
	require.Nil(b, err, "err should be nil")

	// create RRSIG
	sig := new(RRSIG)
	sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.TypeCovered = soa.Hdr.Rrtype
	sig.Labels = uint8(CountLabel(soa.Hdr.Name)) // works for all 3
	sig.OrigTtl = soa.Hdr.Ttl
	sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
	sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.KeyTag = key.KeyTag()   // Get the keyfrom the Key
	sig.SignerName = key.Hdr.Name
	sig.Algorithm = ECDSAP256SHA256

	for i := 0; i < b.N; i++ {
		err = sig.Sign(privkey, []RR{soa})
		require.Nil(b, err, "sign err should be nil")
		err = sig.Verify(key, []RR{soa})
		require.Nil(b, err, "verify err should be nil")
	}
}

func BenchmarkSignVerifyED25519(b *testing.B) {
	var err error
	// create record to sign
	soa := new(SOA)
	soa.Hdr = RR_Header{"*.miek.nl.", TypeSOA, ClassINET, 14400, 0}
	soa.Ns = "open.nlnetlabs.nl."
	soa.Mbox = "miekg.atoom.net."
	soa.Serial = 1293945905
	soa.Refresh = 14400
	soa.Retry = 3600
	soa.Expire = 604800
	soa.Minttl = 86400

	// create DNSKEY RR
	key := new(DNSKEY)
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = ED25519
	privkey, err := key.Generate(256)
	require.Nil(b, err, "err should be nil")

	// create RRSIG
	sig := new(RRSIG)
	sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.TypeCovered = soa.Hdr.Rrtype
	sig.Labels = uint8(CountLabel(soa.Hdr.Name)) // works for all 3
	sig.OrigTtl = soa.Hdr.Ttl
	sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
	sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.KeyTag = key.KeyTag()   // Get the keyfrom the Key
	sig.SignerName = key.Hdr.Name
	sig.Algorithm = ED25519

	for i := 0; i < b.N; i++ {
		err = sig.Sign(privkey, []RR{soa})
		require.Nil(b, err, "sign err should be nil")
		err = sig.Verify(key, []RR{soa})
		require.Nil(b, err, "verify err should be nil")
	}
}

func BenchmarkSignVerifyFALCON512(b *testing.B) {
	var err error
	// create record to sign
	soa := new(SOA)
	soa.Hdr = RR_Header{"*.miek.nl.", TypeSOA, ClassINET, 14400, 0}
	soa.Ns = "open.nlnetlabs.nl."
	soa.Mbox = "miekg.atoom.net."
	soa.Serial = 1293945905
	soa.Refresh = 14400
	soa.Retry = 3600
	soa.Expire = 604800
	soa.Minttl = 86400

	// create DNSKEY RR
	key := new(DNSKEY)
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = FALCON512
	privkey, err := key.Generate(1281)
	require.Nil(b, err, "err should be nil")

	// create RRSIG
	sig := new(RRSIG)
	sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.TypeCovered = soa.Hdr.Rrtype
	sig.Labels = uint8(CountLabel(soa.Hdr.Name)) // works for all 3
	sig.OrigTtl = soa.Hdr.Ttl
	sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
	sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.KeyTag = key.KeyTag()   // Get the keyfrom the Key
	sig.SignerName = key.Hdr.Name
	sig.Algorithm = FALCON512

	for i := 0; i < b.N; i++ {
		err = sig.Sign(privkey, []RR{soa})
		require.Nil(b, err, "sign err should be nil")
		err = sig.Verify(key, []RR{soa})
		require.Nil(b, err, "verify err should be nil")
	}
}

func BenchmarkSignVerifyP256FALCON512(b *testing.B) {
	var err error
	// create record to sign
	soa := new(SOA)
	soa.Hdr = RR_Header{"*.miek.nl.", TypeSOA, ClassINET, 14400, 0}
	soa.Ns = "open.nlnetlabs.nl."
	soa.Mbox = "miekg.atoom.net."
	soa.Serial = 1293945905
	soa.Refresh = 14400
	soa.Retry = 3600
	soa.Expire = 604800
	soa.Minttl = 86400

	// create DNSKEY RR
	key := new(DNSKEY)
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = P256_FALCON512
	privkey, err := key.Generate(1406)
	require.Nil(b, err, "err should be nil")

	// create RRSIG
	sig := new(RRSIG)
	sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.TypeCovered = soa.Hdr.Rrtype
	sig.Labels = uint8(CountLabel(soa.Hdr.Name)) // works for all 3
	sig.OrigTtl = soa.Hdr.Ttl
	sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
	sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.KeyTag = key.KeyTag()   // Get the keyfrom the Key
	sig.SignerName = key.Hdr.Name
	sig.Algorithm = P256_FALCON512

	for i := 0; i < b.N; i++ {
		err = sig.Sign(privkey, []RR{soa})
		require.Nil(b, err, "sign err should be nil")
		err = sig.Verify(key, []RR{soa})
		require.Nil(b, err, "verify err should be nil")
	}
}

func BenchmarkSignVerifyRSA3072FALCON512(b *testing.B) {
	var err error
	// create record to sign
	soa := new(SOA)
	soa.Hdr = RR_Header{"*.miek.nl.", TypeSOA, ClassINET, 14400, 0}
	soa.Ns = "open.nlnetlabs.nl."
	soa.Mbox = "miekg.atoom.net."
	soa.Serial = 1293945905
	soa.Refresh = 14400
	soa.Retry = 3600
	soa.Expire = 604800
	soa.Minttl = 86400

	// create DNSKEY RR
	key := new(DNSKEY)
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = RSA3072_FALCON512
	privkey, err := key.Generate(3055)
	require.Nil(b, err, "err should be nil")

	// create RRSIG
	sig := new(RRSIG)
	sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.TypeCovered = soa.Hdr.Rrtype
	sig.Labels = uint8(CountLabel(soa.Hdr.Name)) // works for all 3
	sig.OrigTtl = soa.Hdr.Ttl
	sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
	sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.KeyTag = key.KeyTag()   // Get the keyfrom the Key
	sig.SignerName = key.Hdr.Name
	sig.Algorithm = RSA3072_FALCON512

	for i := 0; i < b.N; i++ {
		err = sig.Sign(privkey, []RR{soa})
		require.Nil(b, err, "sign err should be nil")
		err = sig.Verify(key, []RR{soa})
		require.Nil(b, err, "verify err should be nil")
	}
}

func BenchmarkSignVerifyFALCON1024(b *testing.B) {
	var err error
	// create record to sign
	soa := new(SOA)
	soa.Hdr = RR_Header{"*.miek.nl.", TypeSOA, ClassINET, 14400, 0}
	soa.Ns = "open.nlnetlabs.nl."
	soa.Mbox = "miekg.atoom.net."
	soa.Serial = 1293945905
	soa.Refresh = 14400
	soa.Retry = 3600
	soa.Expire = 604800
	soa.Minttl = 86400

	// create DNSKEY RR
	key := new(DNSKEY)
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = FALCON1024
	privkey, err := key.Generate(2305)
	require.Nil(b, err, "err should be nil")

	// create RRSIG
	sig := new(RRSIG)
	sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.TypeCovered = soa.Hdr.Rrtype
	sig.Labels = uint8(CountLabel(soa.Hdr.Name)) // works for all 3
	sig.OrigTtl = soa.Hdr.Ttl
	sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
	sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.KeyTag = key.KeyTag()   // Get the keyfrom the Key
	sig.SignerName = key.Hdr.Name
	sig.Algorithm = FALCON1024

	for i := 0; i < b.N; i++ {
		err = sig.Sign(privkey, []RR{soa})
		require.Nil(b, err, "sign err should be nil")
		err = sig.Verify(key, []RR{soa})
		require.Nil(b, err, "verify err should be nil")
	}
}

func BenchmarkSignVerifyP521FALCON1024(b *testing.B) {

	var err error
	// create record to sign
	soa := new(SOA)
	soa.Hdr = RR_Header{"*.miek.nl.", TypeSOA, ClassINET, 14400, 0}
	soa.Ns = "open.nlnetlabs.nl."
	soa.Mbox = "miekg.atoom.net."
	soa.Serial = 1293945905
	soa.Refresh = 14400
	soa.Retry = 3600
	soa.Expire = 604800
	soa.Minttl = 86400

	// create DNSKEY RR
	key := new(DNSKEY)
	key.Hdr.Rrtype = TypeDNSKEY
	key.Hdr.Name = "miek.nl."
	key.Hdr.Class = ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = P521_FALCON1024
	privkey, err := key.Generate(2532)
	require.Nil(b, err, "err should be nil")

	// create RRSIG
	sig := new(RRSIG)
	sig.Hdr = RR_Header{"miek.nl.", TypeRRSIG, ClassINET, 14400, 0}
	sig.TypeCovered = soa.Hdr.Rrtype
	sig.Labels = uint8(CountLabel(soa.Hdr.Name)) // works for all 3
	sig.OrigTtl = soa.Hdr.Ttl
	sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
	sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.KeyTag = key.KeyTag()   // Get the keyfrom the Key
	sig.SignerName = key.Hdr.Name
	sig.Algorithm = P521_FALCON1024

	for i := 0; i < b.N; i++ {
		err = sig.Sign(privkey, []RR{soa})
		require.Nil(b, err, "sign err should be nil")
		err = sig.Verify(key, []RR{soa})
		require.Nil(b, err, "verify err should be nil")
	}
}
