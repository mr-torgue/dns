module github.com/mr-torgue/dns

go 1.25.0

require (
	github.com/hashicorp/go-multierror v1.1.1
	github.com/mattn/go-pointer v0.0.1
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.7.0
	golang.org/x/net v0.52.0
	golang.org/x/sync v0.20.0
	golang.org/x/sys v0.42.0
	golang.org/x/tools v0.43.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/mod v0.34.0 // indirect
	gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c // indirect
)

//replace github.com/pexip/go-openssl => ./pkg/go-openssl
