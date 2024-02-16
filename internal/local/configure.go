package local

import (
	"rpc/pkg/utils"

	"github.com/sirupsen/logrus"
)

func (service *ProvisioningService) Configure() (err error) {
	service.interfacedWsmanMessage.SetupWsmanClient("admin", service.flags.Password, logrus.GetLevel() == logrus.TraceLevel)
	switch service.flags.SubCommand {
	case utils.SubCommandAddWifiSettings:
		return service.AddWifiSettings()
	case utils.SubCommandEnableWifiPort:
		return service.EnableWifiPort()
	case utils.SubCommandSetMEBx:
		return service.SetMebx()
	case utils.SubCommandConfigureTLS:
		return service.ConfigureTLS()
	case utils.SubCommandSyncClock:
		return service.SynchronizeTime()
	default:
	}
	return utils.IncorrectCommandLineParameters
}

func (service *ProvisioningService) EnableWifiPort() (err error) {
	err = service.interfacedWsmanMessage.EnableWiFi()
	if err != nil {
		logrus.Error("Failed to enable wifi port and local profile synchronization.")
		return
	}
	logrus.Info("Successfully enabled wifi port and local profile synchronization.")
	return
}
