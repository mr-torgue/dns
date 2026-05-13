# Generating Keys
```
openssl genpkey -algorithm p256_falcon512 -out P256_FALCON512-private_key.pem
openssl pkey -pubout -in P256_FALCON512-private_key.pem -out P256_FALCON512-public_key.pem
openssl pkey -in P256_FALCON512-private_key.pem -outform DER -out P256_FALCON512-private_key.der
openssl pkey -pubin -in P256_FALCON512-public_key.pem -outform DER -out P256_FALCON512-public_key.der
```

# Extracting Information
Getting raw private key: `openssl pkey -in P256_FALCON512-private_key.pem -outform DER -out P256_FALCON512-private_key_raw.der`
Getting raw public key: `openssl pkey -pubin -in P256_FALCON512-public_key.pem -outform DER -pubout -out P256_FALCON512-public_key_raw.der`

Getting information about the private key: `openssl pkey -in P256_FALCON512-private_key.pem -text -noout`
Getting information about the public key: `openssl pkey -pubin -in P256_FALCON512-public_key.pem -text -noout`

