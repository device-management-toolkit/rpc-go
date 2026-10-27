//go:build amt

/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

// Hardware tests: built only with the "amt" tag and run from an elevated
// shell (make test-amt). They use read-only commands.
package amt

import (
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/require"
)

func TestHWGetProvisioningLog(t *testing.T) {
	if !utils.IsElevated() {
		t.Fatal("hardware tests need an elevated (Administrator/root) shell")
	}

	log, err := NewAMTCommand().GetProvisioningLog()
	require.NoError(t, err)

	t.Logf("CCM: %s (%d) at %d", log.CcmProvisioningStatus, log.CcmProvisioningStatus, log.CcmProvisioningTime)
	t.Logf("ACM: %s (%d) started %d completed %d",
		log.AcmProvisioningStatus, log.AcmProvisioningStatus, log.AcmStartingTime, log.AcmCompletionTime)
}
