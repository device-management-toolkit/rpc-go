//go:build amt

/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

// Hardware tests: built only with the "amt" tag and run from an elevated
// shell (make test-amt).
package mkhi

import (
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/require"
)

func TestHWGetFWCapabilities(t *testing.T) {
	if !utils.IsElevated() {
		t.Fatal("hardware tests need an elevated (Administrator/root) shell")
	}

	caps, err := NewCommand().GetFWCapabilities()
	require.NoError(t, err)

	t.Logf("FW caps: 0x%08x (AMT=%v KVM=%v TEP=%v UPID=%v)",
		uint32(caps), caps.Has(FWCapsAMT), caps.Has(FWCapsKVM), caps.Has(FWCapsTEP), caps.Has(FWCapsUPID))
}
