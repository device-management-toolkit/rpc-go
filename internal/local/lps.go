package local

import (
	"net/url"
	internalAMT "rpc/internal/amt"
	"rpc/internal/config"
	"rpc/internal/flags"
	bacon "rpc/internal/local/amt"
	"rpc/pkg/utils"

	log "github.com/sirupsen/logrus"
)

type OSNetworker interface {
	RenewDHCPLease() error
}

type RealOSNetworker struct{}

type ProvisioningService struct {
	flags                  *flags.Flags
	serverURL              *url.URL
	interfacedWsmanMessage bacon.WSMANer
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
		interfacedWsmanMessage: bacon.NewGoWSMANMessages(flags.LMSAddress),
	}

}

func ExecuteCommand(flags *flags.Flags) error {
	var err error
	service := NewProvisioningService(flags)
	switch flags.Command {
	case utils.CommandActivate:
		err = service.Activate()
		if err == nil {
			log.Info("Status: AMT successfully activated")
		}
	case utils.CommandAMTInfo:
		err = service.DisplayAMTInfo()
	case utils.CommandDeactivate:
		err = service.Deactivate()
	case utils.CommandConfigure:
		err = service.Configure()
	case utils.CommandVersion:
		err = service.DisplayVersion()
	}
	if err != nil {
		log.Error(err)
	}
	return err
}
