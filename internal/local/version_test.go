/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	"testing"

	"github.com/open-amt-cloud-toolkit/rpc-go/v2/internal/flags"
	"github.com/open-amt-cloud-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func TestDisplayVersion(t *testing.T) {
	f := &flags.Flags{}
	f.Command = utils.CommandVersion

	t.Run("should return Success", func(t *testing.T) {
		lps := setupService(f)
		err := lps.DisplayVersion()
		assert.NoError(t, err)
		assert.Equal(t, nil, err)
	})

	t.Run("should return Success with json output", func(t *testing.T) {
		f.JsonOutput = true
		lps := setupService(f)
		err := lps.DisplayVersion()
		assert.NoError(t, err)
		assert.Equal(t, nil, err)
		f.JsonOutput = false
	})

}
