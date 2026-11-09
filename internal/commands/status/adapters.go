package status

import (
	"net"
	"strings"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
)

var statusGetAMTNetworkAdapters = utils.GetAMTNetworkAdapters

func matchedOSAdapter(adapter *amt.InterfaceSettings, inventory []utils.OSNetworkInterface) *utils.OSNetworkInterface {
	if adapter == nil {
		return nil
	}

	mac, err := net.ParseMAC(adapter.MACAddress)
	if err != nil || mac.String() == "00:00:00:00:00:00" {
		return nil
	}

	for index := range inventory {
		candidate, err := net.ParseMAC(inventory[index].MACAddress)
		if err == nil && strings.EqualFold(candidate.String(), mac.String()) {
			return &inventory[index]
		}
	}

	return nil
}

func matchedAdapterDetails(adapter *amt.InterfaceSettings, inventory []utils.OSNetworkInterface) (string, string) {
	link := "unavailable"
	if adapter != nil && strings.TrimSpace(adapter.LinkStatus) != "" {
		link = adapter.LinkStatus
	}

	matched := matchedOSAdapter(adapter, inventory)
	if matched == nil {
		return "No matching OS adapter", "AMT link " + link + "; OS state not verified"
	}

	name := matched.Description
	if strings.TrimSpace(name) == "" {
		name = matched.Name
	}

	return name, "AMT link " + link + "; OS state " + connectivityValue(matched.LinkStatus)
}

func hostNetworkCheck(adapters []*amt.InterfaceSettings, inventory []utils.OSNetworkInterface, inventoryErr error) Check {
	check := Check{ID: checkIDHostNetwork, Name: "Host networking for remote activation", Status: checkUnavailable,
		Message: "Host networking on the AMT adapters could not be verified; RPS/Console-profile activation requires host networking"}
	if inventoryErr != nil {
		return check
	}

	matchedCount := 0
	unknownState := false

	for _, adapter := range adapters {
		matched := matchedOSAdapter(adapter, inventory)
		if matched == nil {
			continue
		}

		matchedCount++

		if strings.EqualFold(matched.LinkStatus, statusLinkUp) {
			check.Status = checkPass
			check.Message = "OS adapter matching an AMT MAC is enabled; verify RPS/Console endpoint reachability"

			return check
		}

		if matched.LinkStatus == "" || strings.EqualFold(matched.LinkStatus, "unknown") {
			unknownState = true
		}
	}

	if matchedCount > 0 && !unknownState {
		check.Status = checkWarn
		check.Reason = reasonRemoteNetworkBlocked
		check.Message = "AMT-matched OS adapters are down or disabled: RPS and Console-profile activation are blocked; local activation may still proceed"
	}

	return check
}
