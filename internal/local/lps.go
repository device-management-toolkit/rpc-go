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
	"github.com/device-management-toolkit/rpc-go/v2/internal/local/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
)

type OSNetworker interface {
	RenewDHCPLease() error
}

type RealOSNetworker struct{}

type ProvisioningService struct {
	flags                  *flags.Flags
	serverURL              *url.URL
	interfacedWsmanMessage amt.WSMANer
	config                 *config.Config
	amtCommand             internalAMT.Interface
	handlesWithCerts       map[string]string
	networker              OSNetworker
}

func NewProvisioningService(flags *flags.Flags) ProvisioningService {
	serverURL := &url.URL{
		Scheme: "http",
		Host:   utils.LMSAddress + ":" + utils.LMSPort,
		Path:   "/wsman",
	}

	return ProvisioningService{
		flags:                  flags,
		serverURL:              serverURL,
		config:                 &flags.LocalConfig,
		amtCommand:             internalAMT.NewAMTCommand(),
		handlesWithCerts:       make(map[string]string),
		networker:              &RealOSNetworker{},
		interfacedWsmanMessage: amt.NewGoWSMANMessages(flags.LMSAddress),
	}
}

func ExecuteCommand(flags *flags.Flags) error {
	var err error

	service := NewProvisioningService(flags)

	switch flags.Command {
	case utils.CommandConfigure:
		err = service.Configure()
	}

	if err != nil {
		return err
	}

	return nil
}
