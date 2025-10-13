/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package flags

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/internal/config"
	"github.com/device-management-toolkit/rpc-go/v2/internal/smb"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/pthi"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

const trickyPassword string = "!@#$%^&*(()-+="

var (
	mode                 = 0
	result               = 0
	controlModeErr error = nil
)

var (
	MockPRSuccess = new(MockPasswordReaderSuccess)
	MockPRFail    = new(MockPasswordReaderFail)
)

type MockPasswordReaderSuccess struct{}

func (mpr *MockPasswordReaderSuccess) ReadPassword() (string, error) {
	return utils.TestPassword, nil
}

type MockPasswordReaderFail struct{}

func (mpr *MockPasswordReaderFail) ReadPassword() (string, error) {
	return "", errors.New("Read password failed")
}

type MockPTHICommands struct{}

func (c MockPTHICommands) OpenWatchdog() error {
	return nil
}

func (c MockPTHICommands) Open(bool) error {
	return nil
}

func (c MockPTHICommands) GetIsAMTEnabled() (state uint8, err error) {
	return uint8(0x41), nil
}

func (c MockPTHICommands) SetAmtOperationalState(state pthi.AMTOperationalState) (pthi.Status, error) {
	return 0, nil
}

func (c MockPTHICommands) Close() {}

func (c MockPTHICommands) Call([]byte, uint32) (result []byte, err error) {
	return []byte{}, nil
}

func (c MockPTHICommands) GetCodeVersions() (pthi.GetCodeVersionsResponse, error) {
	return pthi.GetCodeVersionsResponse{}, nil
}

func (c MockPTHICommands) GetUUID() (uuid string, err error) {
	return "", nil
}

func (c MockPTHICommands) GetControlMode() (state int, err error) {
	return mode, controlModeErr
}

func (c MockPTHICommands) GetDNSSuffix() (suffix string, err error) {
	return "", nil
}

func (c MockPTHICommands) GetCertificateHashes(pthi.AMTHashHandles) (hashEntryList []pthi.CertHashEntry, err error) {
	return []pthi.CertHashEntry{}, nil
}

func (c MockPTHICommands) GetRemoteAccessConnectionStatus() (RAStatus pthi.GetRemoteAccessConnectionStatusResponse, err error) {
	return pthi.GetRemoteAccessConnectionStatusResponse{}, nil
}

func (c MockPTHICommands) GetLocalSystemAccount() (localAccount pthi.GetLocalSystemAccountResponse, err error) {
	return pthi.GetLocalSystemAccountResponse{}, nil
}

func (c MockPTHICommands) GetLANInterfaceSettings(useWireless bool) (LANInterface pthi.GetLANInterfaceSettingsResponse, err error) {
	if useWireless {
		return pthi.GetLANInterfaceSettingsResponse{}, nil
	} else {
		return pthi.GetLANInterfaceSettingsResponse{
			Enabled:     1,
			Ipv4Address: 0,
			DhcpEnabled: 1,
			DhcpIpMode:  2,
			LinkStatus:  1,
			MacAddress:  [6]uint8{0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
		}, nil
	}
}

func (c MockPTHICommands) Unprovision() (mode int, err error) {
	return result, nil
}

func (c MockPTHICommands) StartConfigurationHBased(serverHashAlgorithm uint8, serverCertHash [64]byte, hostVPNEnable bool, suffixListLen int32, networkDNSSuffixList [320]byte) (response pthi.StartConfigurationHBasedResponse, err error) {
	return pthi.StartConfigurationHBasedResponse{}, nil
}

func (c MockPTHICommands) StopConfiguration() (response pthi.StopConfigurationResponse, err error) {
	return pthi.StopConfigurationResponse{}, nil
}

var testNetEnumerator = NetEnumerator{
	Interfaces: func() ([]net.Interface, error) {
		return []net.Interface{
			{
				Index: 0, MTU: 1200, Name: "wlanTest01",
				HardwareAddr: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
				Flags:        0,
			},
			{
				Index: 0, MTU: 1200, Name: "errTest01",
				HardwareAddr: []byte{0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
				Flags:        0,
			},
			{
				Index: 0, MTU: 1200, Name: "ethTest01",
				HardwareAddr: []byte{0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
				Flags:        0,
			},
		}, nil
	},
	InterfaceAddrs: func(i *net.Interface) ([]net.Addr, error) {
		if i.Name == "errTest01" {
			return nil, errors.New("test message")
		} else {
			return []net.Addr{
				&net.IPNet{
					IP:   net.ParseIP("127.0.0.1"),
					Mask: net.CIDRMask(8, 32),
				},
				&net.IPNet{
					IP:   net.ParseIP("::1234:5678"),
					Mask: net.CIDRMask(64, 128),
				},
				&net.IPNet{
					IP:   net.ParseIP("192.168.1.1"),
					Mask: net.CIDRMask(24, 32),
				},
			}, nil
		}
	},
}

func userInput(t *testing.T, input string) func() {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	_, err = w.Write([]byte(input))
	if err != nil {
		t.Error(err)
	}

	err = w.Close()
	if err != nil {
		t.Error(err)
	}

	stdin := os.Stdin
	os.Stdin = r

	return func() {
		os.Stdin = stdin
	}
}

func TestNewFlags(t *testing.T) {
	args := []string{"./rpc"}
	flags := NewFlags(args, MockPRSuccess)
	assert.NotNil(t, flags)
}

func TestPrintUsage(t *testing.T) {
	executable := filepath.Base(os.Args[0])
	args := []string{executable}

	flags := NewFlags(args, MockPRSuccess)
	output := flags.printUsage()
	usage := utils.HelpHeader
	usage = usage + "Usage: " + executable + " COMMAND [OPTIONS]\n\n"
	usage = usage + "Supported Commands:\n"
	usage = usage + "  activate    Activate this device with a specified profile\n"
	usage = usage + "              Example: " + executable + " activate -u wss://server/activate --profile acmprofile\n"
	usage = usage + "  amtinfo     Displays information about AMT status and configuration\n"
	usage = usage + "              Example: " + executable + " amtinfo\n"
	usage = usage + "  configure   Local configuration of a feature on this device. AMT password is required\n"
	usage = usage + "              Example: " + executable + " configure " + utils.SubCommandWireless + " ...\n"
	usage = usage + "  deactivate  Deactivates this device. AMT password is required\n"
	usage = usage + "              Example: " + executable + " deactivate -u wss://server/activate\n"
	usage = usage + "  maintenance Execute a maintenance task for the device. AMT password is required\n"
	usage = usage + "              Example: " + executable + " maintenance syncclock -u wss://server/activate \n"
	usage = usage + "  version     Displays the current version of RPC and the RPC Protocol version\n"
	usage = usage + "              Example: " + executable + " version\n"
	usage = usage + "\nRun '" + executable + " COMMAND' for more information on a command.\n"
	assert.Equal(t, usage, output)
}

func TestParseFlagsAMTInfo(t *testing.T) {
	args := []string{"./rpc", "amtinfo"}
	flags := NewFlags(args, MockPRSuccess)
	result := flags.ParseFlags()
	assert.EqualValues(t, result, nil)
	assert.Equal(t, flags.Command, utils.CommandAMTInfo)
	assert.Equal(t, false, flags.JsonOutput)
}

func TestParseFlagsAMTInfoBadParam(t *testing.T) {
	args := []string{"./rpc", "amtinfo", "-help"}
	flags := NewFlags(args, MockPRSuccess)
	result := flags.ParseFlags()
	assert.EqualValues(t, utils.IncorrectCommandLineParameters, result)
	assert.Equal(t, flags.Command, utils.CommandAMTInfo)
	assert.Equal(t, false, flags.JsonOutput)
}

func TestParseFlagsAMTInfoJSON(t *testing.T) {
	args := []string{"./rpc", "amtinfo", "-json"}
	flags := NewFlags(args, MockPRSuccess)
	result := flags.ParseFlags()
	assert.EqualValues(t, result, nil)
	assert.Equal(t, flags.Command, utils.CommandAMTInfo)
	assert.Equal(t, true, flags.JsonOutput)
}

func TestParseFlagsAMTInfoCert(t *testing.T) {
	args := []string{"./rpc", "amtinfo", "-cert"}
	flags := NewFlags(args, MockPRSuccess)
	result := flags.ParseFlags()
	assert.EqualValues(t, result, nil)
	assert.Equal(t, flags.Command, utils.CommandAMTInfo)
	assert.Equal(t, false, flags.JsonOutput)
}

func TestParseFlagsAMTInfoOSDNSSuffix(t *testing.T) {
	args := []string{"./rpc", "amtinfo", "-dns"}
	flags := NewFlags(args, MockPRSuccess)
	result := flags.ParseFlags()
	assert.EqualValues(t, result, nil)
	assert.Equal(t, flags.Command, utils.CommandAMTInfo)
	assert.Equal(t, false, flags.JsonOutput)
}

func TestParseFlagsActivate(t *testing.T) {
	args := []string{"./rpc", "activate"}
	flags := NewFlags(args, MockPRSuccess)
	result := flags.ParseFlags()
	assert.EqualValues(t, result, utils.IncorrectCommandLineParameters)
	assert.Equal(t, flags.Command, utils.CommandActivate)
}

func TestParseFlagsVersion(t *testing.T) {
	args := []string{"./rpc", "version"}
	flags := NewFlags(args, MockPRSuccess)
	result := flags.ParseFlags()
	assert.EqualValues(t, result, nil)
	assert.Equal(t, flags.Command, utils.CommandVersion)
	assert.Equal(t, false, flags.JsonOutput)
}

func TestParseFlagsConfigure(t *testing.T) {
	args := []string{"./rpc", "configure"}
	flags := NewFlags(args, MockPRSuccess)
	result := flags.ParseFlags()
	assert.EqualValues(t, utils.IncorrectCommandLineParameters, result)
	assert.Equal(t, flags.Command, utils.CommandConfigure)
	assert.Equal(t, false, flags.JsonOutput)
}

func TestParseFlagsConfigureEmpty(t *testing.T) {
	args := []string{"./rpc", "configure"}
	flags := NewFlags(args, MockPRSuccess)
	result := flags.ParseFlags()
	assert.EqualValues(t, result, utils.IncorrectCommandLineParameters)
	assert.Equal(t, "configure", flags.Command)
}

func TestParseFlagsConfigureNoFile(t *testing.T) {
	args := []string{"./rpc", "configure", "-config"}
	flags := NewFlags(args, MockPRSuccess)
	result := flags.ParseFlags()
	assert.EqualValues(t, result, utils.IncorrectCommandLineParameters)
	assert.Equal(t, "configure", flags.Command)
}

func TestParseFlagsVersionJSON(t *testing.T) {
	args := []string{"./rpc", "version", "-json"}
	flags := NewFlags(args, MockPRSuccess)
	result := flags.ParseFlags()
	assert.EqualValues(t, result, nil)
	assert.Equal(t, flags.Command, utils.CommandVersion)
	assert.Equal(t, true, flags.JsonOutput)
}

func TestParseFlagsNone(t *testing.T) {
	args := []string{"./rpc"}
	flags := NewFlags(args, MockPRSuccess)
	result := flags.ParseFlags()
	assert.EqualValues(t, result, utils.IncorrectCommandLineParameters)
	assert.Equal(t, "", flags.Command)
}

func TestParseFlagsEmptyCommand(t *testing.T) {
	args := []string{"./rpc", ""}
	flags := NewFlags(args, MockPRSuccess)
	result := flags.ParseFlags()
	assert.EqualValues(t, result, utils.IncorrectCommandLineParameters)
	assert.Equal(t, "", flags.Command)
}

func TestLookupEnvOrBool_Default(t *testing.T) {
	args := []string{"./rpc", ""}
	flags := NewFlags(args, MockPRSuccess)
	result := flags.lookupEnvOrBool("SKIP_CERT_CHECK", false)
	assert.Equal(t, false, result)
}

func TestLookupEnvOrBool_Env(t *testing.T) {
	args := []string{"./rpc", ""}

	if err := os.Setenv("SKIP_CERT_CHECK", "true"); err != nil {
		t.Error(err)
	}

	flags := NewFlags(args, MockPRSuccess)
	result := flags.lookupEnvOrBool("SKIP_CERT_CHECK", false)
	assert.Equal(t, true, result)
}

func TestLookupEnvOrBool_EnvError(t *testing.T) {
	args := []string{"./rpc", ""}

	if err := os.Setenv("SKIP_CERT_CHECK", "notparsable"); err != nil {
		t.Error(err)
	}

	flags := NewFlags(args, MockPRSuccess)
	result := flags.lookupEnvOrBool("SKIP_CERT_CHECK", false)
	assert.Equal(t, false, result)
}

type MockSambaService struct {
	contentsErr error
}

func NewMockSambaService(err error) smb.ServiceInterface {
	return &MockSambaService{
		contentsErr: err,
	}
}

func (s *MockSambaService) FetchFileContents(url string) ([]byte, error) {
	var contents []byte

	service := smb.NewSambaService(MockPRSuccess)

	p, err := service.ParseUrl(url)
	if err != nil {
		return contents, err
	}

	return os.ReadFile(p.FilePath)
}

func (s *MockSambaService) ParseUrl(url string) (smb.Properties, error) {
	prop := new(smb.Properties)

	return *prop, nil
}

func writeTestCfgFiles(t *testing.T, cfg *config.Config, ext string) (cfgFilePath string) {
	tempDir := t.TempDir()
	cfgFilePath = filepath.Join(tempDir, "test-config."+ext)

	var cfgBytes []byte

	var err error = nil

	switch ext {
	case "json":
		cfgBytes, err = json.MarshalIndent(cfg, "", "  ")
	case "yaml":
		cfgBytes, err = yaml.Marshal(cfg)
	case "pfx":
		cfgBytes, err = base64.StdEncoding.DecodeString(cfg.ACMSettings.ProvisioningCert)
	}

	assert.Nil(t, err)
	err = os.WriteFile(cfgFilePath, cfgBytes, 0o644)
	assert.Nil(t, err)

	return cfgFilePath
}

func TestHandleLocalConfig(t *testing.T) {
	cfg := config.Config{
		Password: "localTRICKYPWD-amt_(J!@#$$%^&",
		ACMSettings: config.ACMSettings{
			AMTPassword:         "amtTRICKypwd",
			ProvisioningCert:    "c29tZSBkYXRhIHdpdGggACBhbmQg77u/",
			ProvisioningCertPwd: "anotherstring",
		},
	}

	tests := []string{"json", "yaml", "pfx"}
	for _, ext := range tests {
		cfgFilePath := writeTestCfgFiles(t, &cfg, ext)
		t.Run(fmt.Sprintf("expect smb happy path with %s", ext), func(t *testing.T) {
			args := []string{"./rpc"}
			flags := NewFlags(args, MockPRSuccess)
			flags.SambaService = NewMockSambaService(nil)
			flags.configContent = "smb://localhost/xxx/" + cfgFilePath
			rc := flags.handleLocalConfig()
			assert.Equal(t, nil, rc)

			if ext == "json" || ext == "yaml" {
				assert.Equal(t, cfg.Password, flags.LocalConfig.Password)
				assert.Equal(t, cfg.ACMSettings, flags.LocalConfig.ACMSettings)
			}

			if ext == "pfx" {
				assert.Equal(t, cfg.ACMSettings.ProvisioningCert, flags.LocalConfig.ACMSettings.ProvisioningCert)
			}
		})

		t.Run(fmt.Sprintf("expect local happy path with %s", ext), func(t *testing.T) {
			args := []string{"./rpc"}
			flags := NewFlags(args, MockPRSuccess)
			flags.configContent = cfgFilePath
			rc := flags.handleLocalConfig()
			assert.Equal(t, nil, rc)

			if ext == "json" || ext == "yaml" {
				assert.Equal(t, cfg.Password, flags.LocalConfig.Password)
				assert.Equal(t, cfg.ACMSettings, flags.LocalConfig.ACMSettings)
			}

			if ext == "pfx" {
				assert.Equal(t, cfg.ACMSettings.ProvisioningCert, flags.LocalConfig.ACMSettings.ProvisioningCert)
			}
		})
	}

	t.Run("expect FailedReadingConfiguration for smb unsupported extension", func(t *testing.T) {
		args := []string{"./rpc"}
		flags := NewFlags(args, MockPRSuccess)
		flags.configContent = "smb://localhost/xxx/nope.html"
		flags.SambaService = NewMockSambaService(nil)
		err := flags.handleLocalConfig()
		assert.Equal(t, utils.FailedReadingConfiguration, err)
	})

	t.Run("expect FailedReadingConfiguration for smb fetch file error", func(t *testing.T) {
		args := []string{"./rpc"}
		flags := NewFlags(args, MockPRSuccess)
		flags.configContent = "smb://localhost/xxx/yep.yaml"
		flags.SambaService = NewMockSambaService(errors.New("test error"))
		err := flags.handleLocalConfig()
		assert.Equal(t, utils.FailedReadingConfiguration, err)
	})

	t.Run("expect FailedReadingConfiguration for local pfx ReadFile", func(t *testing.T) {
		args := []string{"./rpc"}
		flags := NewFlags(args, MockPRSuccess)
		flags.configContent = "/tmp/thisfilebetterneverexist.pfx"
		err := flags.handleLocalConfig()
		assert.Equal(t, utils.FailedReadingConfiguration, err)
	})
}

func TestReadNewPasswordTo(t *testing.T) {
	args := []string{"./rpc"}
	flags := NewFlags(args, MockPRSuccess)

	var password string

	flags.ReadNewPasswordTo(&password, "TEST")
	assert.Equal(t, utils.TestPassword, password)
}
