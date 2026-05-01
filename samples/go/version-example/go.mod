module version-example

go 1.25.0

require github.com/device-management-toolkit/rpc-go/v2 v2.0.0

require (
	github.com/google/uuid v1.6.0 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/term v0.41.0 // indirect
)

replace github.com/device-management-toolkit/rpc-go/v2 => ../../../
