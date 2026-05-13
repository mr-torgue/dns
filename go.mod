module github.com/miekg/dns

go 1.25.0

require (
	github.com/pexip/go-openssl v0.2.8
	golang.org/x/net v0.52.0
	golang.org/x/sync v0.20.0
	golang.org/x/sys v0.42.0
	golang.org/x/tools v0.43.0
)

require (
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/mattn/go-pointer v0.0.1 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	golang.org/x/mod v0.34.0 // indirect
)

replace github.com/pexip/go-openssl => ./local/go-openssl
