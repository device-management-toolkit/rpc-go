/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	"net/url"

	internalAMT "github.com/device-management-toolkit/rpc-go/v2/internal/amt"
	"github.com/device-management-toolkit/rpc-go/v2/internal/config"
	"github.com/device-management-toolkit/rpc-go/v2/internal/flags"
	"github.com/device-management-toolkit/rpc-go/v2/internal/interfaces"
	"github.com/device-management-toolkit/rpc-go/v2/internal/local/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/network"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
)

type ProvisioningService struct {
	serverURL              *url.URL
	interfacedWsmanMessage interfaces.WSMANer
	config                 *config.Config
	amtCommand             internalAMT.Interface
	handlesWithCerts       map[string]string
	networker              network.OSNetworker
}

func NewProvisioningService(flags *flags.Flags) ProvisioningService {
	serverURL := &url.URL{
		Scheme: "http",
		Host:   utils.LMSAddress + ":" + utils.LMSPort,
		Path:   "/wsman",
	}

	return ProvisioningService{
		serverURL:              serverURL,
		config:                 &flags.LocalConfig,
		amtCommand:             internalAMT.NewAMTCommand(),
		handlesWithCerts:       make(map[string]string),
		networker:              network.NewOSNetworker(),
		interfacedWsmanMessage: amt.NewGoWSMANMessages(flags.LMSAddress),
	}
}
