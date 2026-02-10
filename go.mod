module github.com/device-management-toolkit/rpc-go/v2

go 1.25

// uncomment if developing with go-wsman-messages locally
// replace github.com/device-management-toolkit/go-wsman-messages/v2 => ../go-wsman-messages

require (
	github.com/alecthomas/kong v1.14.0
	github.com/alecthomas/kong-yaml v0.2.0
	github.com/device-management-toolkit/go-wsman-messages/v2 v2.36.1
	github.com/google/uuid v1.6.0
	github.com/gorilla/websocket v1.5.3
	github.com/hirochachacha/go-smb2 v1.1.0
	github.com/sirupsen/logrus v1.9.4
	github.com/stretchr/testify v1.11.1
	go.uber.org/mock v0.6.0
	golang.org/x/sys v0.41.0
)

require (
	al.essio.dev/pkg/shellescape v1.5.1 // indirect
	github.com/danieljoos/wincred v1.2.2 // indirect
	github.com/geoffgarside/ber v1.1.0 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/kr/text v0.1.0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/zalando/go-keyring v0.2.6 // indirect
	golang.org/x/crypto v0.45.0 // indirect
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/term v0.40.0
	gopkg.in/yaml.v3 v3.0.1
	software.sslmate.com/src/go-pkcs12 v0.7.0
)
