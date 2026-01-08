package commands

import (
	"crypto/tls"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
)

// Context holds shared dependencies injected into commands
type Context struct {
	AMTCommand    amt.Interface
	ControlMode   int
	LogLevel      string
	JsonOutput    bool
	Verbose       bool
	SkipCertCheck bool
	// SkipAMTCertCheck controls whether to skip TLS verification when connecting to AMT/LMS over TLS
	// This is distinct from SkipCertCheck which applies to remote RPS HTTPS/WSS connections.
	SkipAMTCertCheck bool
	TLSConfig        *tls.Config
	TenantID         string
	AMTPassword      string // Centralized AMT admin password (from global flag/env or interactive prompt)
	// Provisioning certificate for mutual TLS with AMT (required after ACM activation on AMT 19+)
	ProvisioningCert    string
	ProvisioningCertPwd string
	ServerAuthFlags
}
