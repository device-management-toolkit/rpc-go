package commands

import (
	"crypto/tls"

	"github.com/device-management-toolkit/rpc-go/v2/internal/amt"
)

// Context holds shared dependencies injected into commands
type Context struct {
	AMTCommand       amt.Interface
	ControlMode      int
	LogLevel         string
	JsonOutput       bool
	Verbose          bool
	LocalTLSEnforced bool
	SkipCertCheck    bool
	TLSConfig        *tls.Config
}
