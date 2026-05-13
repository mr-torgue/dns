# Generating Keys
```
openssl genpkey -algorithm ECDSA -out ECDSA-private_key.pem
openssl pkey -pubout -in ECDSA-private_key.pem -out ECDSA-public_key.pem
openssl pkey -in ECDSA-private_key.pem -outform DER -out ECDSA-private_key.der
openssl pkey -pubin -in ECDSA-public_key.pem -outform DER -out ECDSA-public_key.der
```

# Extracting Information
Getting raw private key: `openssl pkey -in ECDSA-private_key.pem -outform DER -out ECDSA-private_key_raw.der`
Getting raw public key: `openssl pkey -pubin -in ECDSA-public_key.pem -outform DER -pubout -out ECDSA-public_key_raw.der`

Getting information about the private key: `openssl pkey -in ECDSA-private_key.pem -text -noout`
Getting information about the public key: `openssl pkey -pubin -in ECDSA-public_key.pem -text -noout`
