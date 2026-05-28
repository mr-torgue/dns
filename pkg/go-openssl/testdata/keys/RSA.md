# Generating Keys
```
openssl genpkey -algorithm RSA -out RSA2048-private_key.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in RSA2048-private_key.pem -out RSA2048-public_key.pem
openssl pkey -in RSA2048-private_key.pem -outform DER -out RSA2048-private_key.der
openssl rsa -pubin -in RSA2048-public_key.pem -outform DER -out RSA2048-public_key.der
```

# Extracting Information
Information about the RSA keys (used for testing) can be extracted with:
```
openssl rsa -in RSA2048-private_key.pem -modulus -noout | cut -d'=' -f2 | xargs -I {} echo "ibase=16; {}" | bc # for getting N
openssl rsa -in RSA2048-private_key.pem -pubin -text -noout | grep "Exponent" -A 1 | tail -n 1 | awk '{print $2}' | cut -d':' -f2 # for getting e
```

Getting information about the private key: `openssl rsa -in RSA2048-private_key.pem -text -noout`
Getting information about the public key: `openssl rsa -pubin -in RSA2048-public_key.pem -text -noout`

Getting raw private key: `openssl pkey -in RSA2048-private_key.pem -outform DER -out private_key_raw.der`
Getting raw public key: `openssl pkey -pubin -in RSA2048-public_key.pem -outform DER -pubout -out public_key_raw.der`

