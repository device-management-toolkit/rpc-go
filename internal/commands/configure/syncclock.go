/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	"fmt"
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// SyncClockCmd represents clock synchronization
type SyncClockCmd struct {
	ConfigureBaseCmd
}

// Run executes the sync clock command
func (cmd *SyncClockCmd) Run(ctx *commands.Context) error {
	// Ensure runtime initialization (password + WSMAN client)
	if err := cmd.EnsureRuntime(ctx); err != nil {
		return err
	}

	log.Info("synchronizing time")

	// Validate that device is activated before synchronizing time
	controlMode := cmd.GetControlMode()

	// Device must be activated (not in pre-provisioning state)
	if controlMode == 0 {
		log.Error(ErrDeviceNotActivated)

		return ErrDeviceNotActivated
	}

	// Get low accuracy time synchronization
	ta0, err := cmd.getLowAccuracyTimeSynch()
	if err != nil {
		return fmt.Errorf("failed to get low accuracy time: %w", err)
	}

	// Set high accuracy time synchronization
	err = cmd.setHighAccuracyTimeSynch(ta0)
	if err != nil {
		return fmt.Errorf("failed to set high accuracy time: %w", err)
	}

	log.Info("synchronizing time completed successfully")

	return nil
}

// Helper methods for clock synchronization

func (cmd *SyncClockCmd) getLowAccuracyTimeSynch() (ta0 int64, err error) {
	log.Info("getting low accuracy time")

	response, err := cmd.WSMan.GetLowAccuracyTimeSynch()
	if err != nil {
		log.Error("failed GetTimeOffset")

		return ta0, err
	}

	ptCode := response.Body.GetLowAccuracyTimeSynchResponse.ReturnValue
	if ptCode != 0 {
		log.Errorf("failed GetLowAccuracyTimeSynch with PT Code: %v", ptCode)

		return ta0, utils.AmtPtStatusCodeBase
	}

	ta0 = response.Body.GetLowAccuracyTimeSynchResponse.Ta0

	return ta0, nil
}

func (cmd *SyncClockCmd) setHighAccuracyTimeSynch(ta0 int64) error {
	log.Info("setting high accuracy time")

	tm1 := time.Now().Unix()

	rsp, err := cmd.WSMan.SetHighAccuracyTimeSynch(ta0, tm1, tm1)
	if err != nil {
		log.Error("failed SetHighAccuracyTimeSynch")

		return err
	}

	ptCode := rsp.Body.SetHighAccuracyTimeSynchResponse.ReturnValue
	if ptCode != 0 {
		log.Errorf("failed SetHighAccuracyTimeSynch with PT Code: %v", ptCode)

		return utils.AmtPtStatusCodeBase
	}

	return nil
}
