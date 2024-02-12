package flags

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHandleVersionCommand(t *testing.T) {
	f := NewFlags([]string{
		"rpc",
		"version",
	}, MockPRSuccess)

	result := f.handleVersionCommand()
	assert.Equal(t, nil, result)
	assert.Equal(t, true, f.Local)
}
