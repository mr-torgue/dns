Generate a ZSK with `dnssec-keygen -a ECDSAP384SHA384 -n ZONE example.com`
Generate a KSK with `dnssec-keygen -a ECDSAP384SHA384 -n ZONE -f KSK example.com`
Generate DS record with `dnssec-dsfromkey -a SHA512/SHA256/SHA1 K[NAME].key`
