module github.com/open-amt-cloud-toolkit/rpc-go/v2

go 1.23.0

toolchain go1.23.7

// uncomment if developing with go-wsman-messages locally
// replace github.com/open-amt-cloud-toolkit/go-wsman-messages/v2 => ../go-wsman-messages

require (
	github.com/google/uuid v1.6.0
	github.com/gorilla/websocket v1.5.3
	github.com/hirochachacha/go-smb2 v1.1.0
	github.com/ilyakaznacheev/cleanenv v1.5.0
	github.com/open-amt-cloud-toolkit/go-wsman-messages/v2 v2.26.0
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.10.0
	golang.org/x/sys v0.32.0
)

require (
	github.com/99designs/go-keychain v0.0.0-20191008050251-8e49817e8af4 // indirect
	github.com/99designs/keyring v1.2.2 // indirect
	github.com/danieljoos/wincred v1.2.2 // indirect
	github.com/dvsekhvalnov/jose2go v1.8.0 // indirect
	github.com/geoffgarside/ber v1.1.0 // indirect
	github.com/godbus/dbus v0.0.0-20190726142602-4481cbc300e2 // indirect
	github.com/gsterjov/go-libsecret v0.0.0-20161001094733-a6f4afe4910c // indirect
	github.com/mtibben/percent v0.2.1 // indirect
	golang.org/x/crypto v0.36.0 // indirect
)

require (
	github.com/BurntSushi/toml v1.5.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/joho/godotenv v1.5.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/term v0.30.0
	gopkg.in/yaml.v3 v3.0.1
	olympos.io/encoding/edn v0.0.0-20201019073823-d3554ca0b0a3 // indirect
	software.sslmate.com/src/go-pkcs12 v0.5.0
)
