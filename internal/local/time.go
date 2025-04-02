/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	"time"

	"github.com/open-amt-cloud-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

func (service *ProvisioningService) SynchronizeTime() error {
	log.Info("synchronizing time")
	ta0, err := service.GetLowAccuracyTimeSynch()
	if err != nil {
		return err
	}
	err = service.SetHighAccuracyTimeSynch(ta0)
	if err == nil {
		log.Info("synchronizing time completed successfully")
	}
	return err
}

func (service *ProvisioningService) GetLowAccuracyTimeSynch() (ta0 int64, err error) {
	log.Info("getting low accuracy time")
	response, err := service.interfacedWsmanMessage.GetLowAccuracyTimeSynch()
	if err != nil {
		log.Error("failed GetTimeOffset")
		return ta0, err
	}
	ptCode := response.Body.GetLowAccuracyTimeSynchResponse.ReturnValue
	if ptCode != 0 {
		log.Errorf("failed GetLowAccuracyTimeSynch with PT Code: %v", ptCode)
		err = utils.AmtPtStatusCodeBase
	}
	ta0 = response.Body.GetLowAccuracyTimeSynchResponse.Ta0
	return ta0, nil
}

func (service *ProvisioningService) SetHighAccuracyTimeSynch(ta0 int64) error {
	log.Info("setting high accuracy time")
	tm1 := time.Now().Unix()
	rsp, err := service.interfacedWsmanMessage.SetHighAccuracyTimeSynch(ta0, tm1, tm1)
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
