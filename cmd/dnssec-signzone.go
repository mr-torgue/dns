package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mr-torgue/dns"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Println("Usage: program <zonefilename> <keytype> <zone>")
		os.Exit(1)
	}

	keyTypeStr := os.Args[2]
	zone := os.Args[3]

	//

	var builder strings.Builder

	// generate the key
	key := new(dns.DNSKEY)
	key.Hdr.Rrtype = dns.TypeDNSKEY
	key.Hdr.Name = zone
	key.Hdr.Ttl = 604800
	key.Hdr.Class = dns.ClassINET
	key.Protocol = 3
	switch strings.ToUpper(keyTypeStr) {
	case "RSASHA256":
		key.Algorithm = dns.RSASHA256
		// ZSK
		key.Flags = 256
		key.Generate(2048)
		builder.WriteString(key.String() + "\n")
		// KSK
		key.Flags = 257
		key.Generate(2048)
		builder.WriteString(key.String() + "\n")
	default:
		fmt.Println("Invalid keytype. Must be either KSK or ZSK")
		os.Exit(1)
	}
	finalString := builder.String()
	fmt.Printf(finalString)
}

// Sign signs a zone file according to the parameters in s.
func Sign(now time.Time, origin string, dbfile string) (*file.Zone, error) {
	rd, err := os.Open(dbfile)
	if err != nil {
		return nil, err
	}

	z, err := Parse(rd, origin, dbfile)
	if err != nil {
		return nil, err
	}

	mttl := z.SOA.Minttl
	ttl := z.SOA.Header().Ttl
	inception, expiration := lifetime(now, s.jitterIncep, s.jitterExpir)
	z.SOA.Serial = uint32(now.Unix()) // #nosec G115 -- Unix time to SOA serial, Year 2106 problem accepted

	for _, pair := range s.keys {
		pair.Public.Header().Ttl = ttl // set TTL on key so it matches the RRSIG.
		z.Insert(pair.Public)
		z.Insert(pair.Public.ToDS(dns.SHA1).ToCDS())
		z.Insert(pair.Public.ToDS(dns.SHA256).ToCDS())
		z.Insert(pair.Public.ToCDNSKEY())
	}

	names := names(origin, z)
	ln := len(names)

	for _, pair := range s.keys {
		rrsig, err := pair.signRRs([]dns.RR{z.SOA}, s.origin, ttl, inception, expiration)
		if err != nil {
			return nil, err
		}
		z.Insert(rrsig)
		// NS apex may not be set if RR's have been discarded because the origin doesn't match.
		if len(z.NS) > 0 {
			rrsig, err = pair.signRRs(z.NS, s.origin, ttl, inception, expiration)
			if err != nil {
				return nil, err
			}
			z.Insert(rrsig)
		}
	}

	// We are walking the tree in the same direction, so names[] can be used here to indicated the next element.
	i := 1
	err = z.AuthWalk(func(e *tree.Elem, zrrs map[uint16][]dns.RR, auth bool) error {
		if !auth {
			return nil
		}

		if e.Name() == s.origin {
			nsec := NSEC(e.Name(), names[(ln+i)%ln], mttl, append(e.Types(), dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC))
			z.Insert(nsec)
		} else {
			nsec := NSEC(e.Name(), names[(ln+i)%ln], mttl, append(e.Types(), dns.TypeRRSIG, dns.TypeNSEC))
			z.Insert(nsec)
		}

		for t, rrs := range zrrs {
			// RRSIGs are not signed and NS records are not signed because we are never authoratiative for them.
			// The zone's apex nameservers records are not kept in this tree and are signed separately.
			if t == dns.TypeRRSIG || t == dns.TypeNS {
				continue
			}
			for _, pair := range s.keys {
				rrsig, err := pair.signRRs(rrs, s.origin, rrs[0].Header().Ttl, inception, expiration)
				if err != nil {
					return err
				}
				e.Insert(rrsig)
			}
		}
		i++
		return nil
	})
	return z, err
}
