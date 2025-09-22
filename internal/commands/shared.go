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
	TLSConfig     *tls.Config
	// Extra allows commands to pass optional, non-core data between layers without expanding the struct frequently
	Extra map[string]any
}
