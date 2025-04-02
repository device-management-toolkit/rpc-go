/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package flags

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/cim/wifi"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/ips/ieee8021x"
	"github.com/open-amt-cloud-toolkit/rpc-go/v2/internal/config"
	"github.com/open-amt-cloud-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func getPromptForSecretsFlags() Flags {
	f := Flags{}
	f.LocalConfig.WifiConfigs = append(f.LocalConfig.WifiConfigs, wifiCfgWPA2)
	f.LocalConfig.WifiConfigs[0].PskPassphrase = ""
	f.LocalConfig.Ieee8021xConfigs = append(f.LocalConfig.Ieee8021xConfigs, ieee8021xCfgEAPTLS)
	f.LocalConfig.Ieee8021xConfigs[0].PrivateKey = ""
	f.LocalConfig.Ieee8021xConfigs = append(f.LocalConfig.Ieee8021xConfigs, ieee8021xCfgPEAPv0_EAPMSCHAPv2)
	f.LocalConfig.Ieee8021xConfigs[1].Password = ""
	return f
}

func TestHandleSetAMTFeatures(t *testing.T) {
	cases := []struct {
		description    string
		cmdLine        string
		expectedResult error
	}{
		{
			description:    "Incorrect number of command-line parameters",
			cmdLine:        "rpc configure setamtfeatures",
			expectedResult: utils.IncorrectCommandLineParameters,
		},
		{
			description:    "Valid command-line parameters with kvm enabled",
			cmdLine:        "rpc configure setamtfeatures -kvm",
			expectedResult: nil,
		},
		{
			description:    "Invalid user consent value",
			cmdLine:        "rpc configure setamtfeatures -userConsent invalid",
			expectedResult: utils.IncorrectCommandLineParameters,
		},
		{
			description:    "Valid user consent value 'none'",
			cmdLine:        "rpc configure setamtfeatures -userConsent none",
			expectedResult: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.description, func(t *testing.T) {
			args := strings.Fields(tc.cmdLine)
			flags := NewFlags(args, MockPRSuccess)
			gotResult := flags.handleSetAMTFeatures()
			assert.Equal(t, tc.expectedResult, gotResult)
		})
	}
}

func TestPromptForSecrets(t *testing.T) {
	t.Run("expect success on valid user input", func(t *testing.T) {
		defer userInput(t, "userInput\nuserInput\nuserInput")()
		f := getPromptForSecretsFlags()
		rc := f.promptForSecrets()
		assert.Equal(t, nil, rc)
		assert.Equal(t, "userInput", f.LocalConfig.WifiConfigs[0].PskPassphrase)
		assert.Equal(t, "userInput", f.LocalConfig.Ieee8021xConfigs[0].PrivateKey)
		assert.Equal(t, "userInput", f.LocalConfig.Ieee8021xConfigs[1].Password)
	})
	t.Run("expect InvalidUserInput", func(t *testing.T) {
		defer userInput(t, "userInput\nuserInput")()
		f := getPromptForSecretsFlags()
		rc := f.promptForSecrets()
		assert.Equal(t, utils.InvalidUserInput, rc)
		assert.Equal(t, "userInput", f.LocalConfig.WifiConfigs[0].PskPassphrase)
		assert.Equal(t, "userInput", f.LocalConfig.Ieee8021xConfigs[0].PrivateKey)
		assert.Equal(t, "", f.LocalConfig.Ieee8021xConfigs[1].Password)
	})
	t.Run("expect InvalidUserInput", func(t *testing.T) {
		defer userInput(t, "userInput")()
		f := getPromptForSecretsFlags()
		rc := f.promptForSecrets()
		assert.Equal(t, utils.InvalidUserInput, rc)
		assert.Equal(t, "userInput", f.LocalConfig.WifiConfigs[0].PskPassphrase)
		assert.Equal(t, "", f.LocalConfig.Ieee8021xConfigs[0].Password)
		assert.Equal(t, "", f.LocalConfig.Ieee8021xConfigs[0].PrivateKey)
	})
	t.Run("expect InvalidUserInput", func(t *testing.T) {
		f := getPromptForSecretsFlags()
		rc := f.promptForSecrets()
		assert.Equal(t, utils.InvalidUserInput, rc)
		assert.Equal(t, "", f.LocalConfig.WifiConfigs[0].PskPassphrase)
		assert.Equal(t, "", f.LocalConfig.Ieee8021xConfigs[0].Password)
		assert.Equal(t, "", f.LocalConfig.Ieee8021xConfigs[0].PrivateKey)
	})
}

func TestHandleConfigureCommand(t *testing.T) {
	t.Run("expect IncorrectCommandLineParameters with no subcommand", func(t *testing.T) {
		f := NewFlags([]string{`rpc`, `configure`}, MockPRSuccess)
		gotResult := f.ParseFlags()
		assert.Equal(t, utils.IncorrectCommandLineParameters, gotResult)
	})
	t.Run("expect IncorrectCommandLineParameters with unknown subcommand", func(t *testing.T) {
		f := NewFlags([]string{`rpc`, `configure`, `what-the-heck?`}, MockPRSuccess)
		gotResult := f.ParseFlags()
		assert.Equal(t, utils.IncorrectCommandLineParameters, gotResult)
	})
	t.Run("expect Success password on command line", func(t *testing.T) {
		cmdLine := []string{
			`rpc`, `configure`, `enablewifiport`,
			`-password`, `cliP@ss0rd!`,
		}
		f := NewFlags(cmdLine, MockPRSuccess)
		gotResult := f.ParseFlags()
		assert.Equal(t, nil, gotResult)
		assert.Equal(t, true, f.Local)
		assert.Equal(t, f.Password, f.LocalConfig.Password)
	})
	t.Run("expect Success password from prompt", func(t *testing.T) {
		cmdLine := []string{
			`rpc`, `configure`, `enablewifiport`,
		}
		f := NewFlags(cmdLine, MockPRSuccess)
		gotResult := f.ParseFlags()
		assert.Equal(t, nil, gotResult)
		assert.Equal(t, utils.TestPassword, f.Password)
	})
	t.Run("expect Success password from environment", func(t *testing.T) {
		orig, origPresent := os.LookupEnv("AMT_PASSWORD")
		expected := "userP@ssw0rd!"
		err := os.Setenv("AMT_PASSWORD", expected)
		assert.Nil(t, err)
		cmdLine := []string{
			`rpc`, `configure`, `enablewifiport`,
		}
		f := NewFlags(cmdLine, MockPRSuccess)
		gotResult := f.ParseFlags()
		assert.Equal(t, nil, gotResult)
		assert.Equal(t, expected, f.Password)
		if origPresent {
			err = os.Setenv("AMT_PASSWORD", orig)
		} else {
			err = os.Unsetenv("AMT_PASSWORD")
		}
		assert.Nil(t, err)
	})
}

func TestAddWifiSettings(t *testing.T) {
	jsonCfgStr := `{"WifiConfigs":[{"ProfileName":"wifiWPA", "SSID":"ssid", "PskPassphrase": "testPSK", "Priority":1, "AuthenticationMethod":4, "EncryptionMethod":4}]}`

	t.Run("expect Success", func(t *testing.T) {
		cmdLine := []string{
			`rpc`, `configure`, `wireless`,
			`-password`, `cliP@ss0rd!`,
			`-configJson`, jsonCfgStr,
		}
		f := NewFlags(cmdLine, MockPRSuccess)
		gotResult := f.ParseFlags()
		assert.Equal(t, nil, gotResult)
		assert.Equal(t, true, f.Local)
		assert.Equal(t, f.Password, f.LocalConfig.Password)
	})
	t.Run("expect MissingOrIncorrectPassword", func(t *testing.T) {
		f := NewFlags([]string{
			`rpc`, `configure`, `wireless`,
			`-configJson`, jsonCfgStr,
		}, MockPRFail)
		gotResult := f.ParseFlags()
		assert.Equal(t, utils.MissingOrIncorrectPassword, gotResult)
	})
	t.Run("expect Success on password prompt", func(t *testing.T) {
		f := NewFlags([]string{
			`rpc`, `configure`, `wireless`,
			`-configJson`, jsonCfgStr,
		}, MockPRSuccess)
		gotResult := f.ParseFlags()
		assert.Equal(t, nil, gotResult)
	})
	t.Run("expect Success when password is in config file", func(t *testing.T) {
		f := NewFlags([]string{
			`rpc`, `configure`, `wireless`,
			`-configJson`, jsonCfgStr,
		}, MockPRSuccess)
		f.LocalConfig.Password = "localP@ssw0rd!"
		gotResult := f.ParseFlags()
		assert.Equal(t, nil, gotResult)
	})
	t.Run("expect MissingOrIncorrectPassword when passwords do not match", func(t *testing.T) {
		f := NewFlags([]string{
			`rpc`, `configure`, `wireless`,
			`-password`, `cliP@ss0rd!`,
			`-configJson`, jsonCfgStr,
		}, MockPRSuccess)
		f.LocalConfig.Password = "localP@ssw0rd!"
		gotResult := f.ParseFlags()
		assert.Equal(t, utils.MissingOrIncorrectPassword, gotResult)
	})
}

// Tests Deprecated SubCommand addwifisettings
func TestAddWifiSettingsDeprecated(t *testing.T) {
	jsonCfgStr := `{"WifiConfigs":[{"ProfileName":"wifiWPA", "SSID":"ssid", "PskPassphrase": "testPSK", "Priority":1, "AuthenticationMethod":4, "EncryptionMethod":4}]}`

	t.Run("expect Success", func(t *testing.T) {
		cmdLine := []string{
			`rpc`, `configure`, `addwifisettings`,
			`-password`, `cliP@ss0rd!`,
			`-configJson`, jsonCfgStr,
		}
		f := NewFlags(cmdLine, MockPRSuccess)
		gotResult := f.ParseFlags()
		assert.Equal(t, nil, gotResult)
		assert.Equal(t, true, f.Local)
		assert.Equal(t, f.Password, f.LocalConfig.Password)
	})
	t.Run("expect MissingOrIncorrectPassword", func(t *testing.T) {
		f := NewFlags([]string{
			`rpc`, `configure`, `addwifisettings`,
			`-configJson`, jsonCfgStr,
		}, MockPRFail)
		gotResult := f.ParseFlags()
		assert.Equal(t, utils.MissingOrIncorrectPassword, gotResult)
	})
	t.Run("expect Success on password prompt", func(t *testing.T) {
		f := NewFlags([]string{
			`rpc`, `configure`, `addwifisettings`,
			`-configJson`, jsonCfgStr,
		}, MockPRSuccess)
		gotResult := f.ParseFlags()
		assert.Equal(t, nil, gotResult)
	})
	t.Run("expect Success when password is in config file", func(t *testing.T) {
		f := NewFlags([]string{
			`rpc`, `configure`, `addwifisettings`,
			`-configJson`, jsonCfgStr,
		}, MockPRSuccess)
		f.LocalConfig.Password = "localP@ssw0rd!"
		gotResult := f.ParseFlags()
		assert.Equal(t, nil, gotResult)
	})
	t.Run("expect MissingOrIncorrectPassword when passwords do not match", func(t *testing.T) {
		f := NewFlags([]string{
			`rpc`, `configure`, `addwifisettings`,
			`-password`, `cliP@ss0rd!`,
			`-configJson`, jsonCfgStr,
		}, MockPRSuccess)
		f.LocalConfig.Password = "localP@ssw0rd!"
		gotResult := f.ParseFlags()
		assert.Equal(t, utils.MissingOrIncorrectPassword, gotResult)
	})
}

func TestEnableWifiPort(t *testing.T) {
	t.Run("enablewifiport: expect Success", func(t *testing.T) {
		expectedPassword := `cliP@ss0rd!`
		cmdLine := []string{
			`rpc`, `configure`, `enablewifiport`,
			`-password`, expectedPassword,
		}
		f := NewFlags(cmdLine, MockPRSuccess)
		gotResult := f.ParseFlags()
		assert.Equal(t, nil, gotResult)
		assert.Equal(t, true, f.Local)
		assert.Equal(t, f.Password, f.LocalConfig.Password)
	})
	t.Run("enablewifiport: expect MissingOrIncorrectPassword", func(t *testing.T) {
		f := NewFlags([]string{
			`rpc`, `configure`, `enablewifiport`, `-password`,
		}, MockPRSuccess)
		gotResult := f.ParseFlags()
		assert.Equal(t, utils.IncorrectCommandLineParameters, gotResult)
	})
	t.Run("enablewifiport: expect Success on password prompt", func(t *testing.T) {
		defer userInput(t, "userP@ssw0rd!")()
		f := NewFlags([]string{
			`rpc`, `configure`, `enablewifiport`,
		}, MockPRSuccess)
		gotResult := f.ParseFlags()
		assert.Equal(t, nil, gotResult)
	})
	t.Run("enablewifiport: expect IncorrectCommandLineParameters", func(t *testing.T) {
		f := NewFlags([]string{
			`rpc`, `configure`, `enablewifiport`, `-password`, `testpw`, `toomany`,
		}, MockPRSuccess)
		gotResult := f.ParseFlags()
		assert.Equal(t, utils.IncorrectCommandLineParameters, gotResult)
	})
	t.Run("enablewifiport: expect IncorrectCommandLineParameters", func(t *testing.T) {
		f := NewFlags([]string{
			`rpc`, `configure`, `enablewifiport`, `-bogus`, `testpw`,
		}, MockPRSuccess)
		gotResult := f.ParseFlags()
		assert.Equal(t, utils.IncorrectCommandLineParameters, gotResult)
	})
}

func TestConfigureTLS(t *testing.T) {
	for _, m := range []TLSMode{TLSModeServer, TLSModeServerAndNonTLS, TLSModeMutual, TLSModeMutualAndNonTLS} {
		t.Run(fmt.Sprintf("expect Success for mode: %s", m), func(t *testing.T) {
			expectedPassword := `cliP@ss0rd!`
			cmdLine := []string{
				`rpc`, `configure`, utils.SubCommandConfigureTLS,
				`-mode`, m.String(),
				`-password`, expectedPassword,
			}
			f := NewFlags(cmdLine, MockPRSuccess)

			gotResult := f.ParseFlags()
			assert.NoError(t, gotResult)
			assert.Equal(t, utils.SubCommandConfigureTLS, f.SubCommand)
			assert.Equal(t, m, f.ConfigTLSInfo.TLSMode)
			assert.Equal(t, true, f.Local)
			assert.Equal(t, f.Password, expectedPassword)
		})
	}
	t.Run(fmt.Sprintf("expect default tlsMode of server: %s", TLSModeServer), func(t *testing.T) {
		expectedPassword := `cliP@ss0rd!`
		cmdLine := []string{
			`rpc`, `configure`, utils.SubCommandConfigureTLS,
			`-password`, expectedPassword,
		}
		f := NewFlags(cmdLine, MockPRSuccess)
		_ = f.ParseFlags()
		assert.Equal(t, TLSModeServer, f.ConfigTLSInfo.TLSMode)
	})
	t.Run("expect error from additional arguments", func(t *testing.T) {
		cmdLine := []string{
			`rpc`, `configure`, utils.SubCommandConfigureTLS,
			`-mode`, `Server`,
			`-this_is_not_right`,
			`-password`, `somepassword`,
		}
		f := NewFlags(cmdLine, MockPRSuccess)
		rc := f.ParseFlags()
		assert.Equal(t, utils.IncorrectCommandLineParameters, rc)
	})
	t.Run("expect error from unknown string", func(t *testing.T) {
		mode, e := ParseTLSMode("unkown")
		assert.NotNil(t, e)
		assert.Equal(t, TLSModeServer, mode)
	})
	t.Run("expect Unknown tls mode as string", func(t *testing.T) {
		badMode := TLSMode(22)
		assert.Equal(t, "Unknown", badMode.String())
	})
}

func TestConfigJson(t *testing.T) {
	cmdLine := `rpc configure wireless -secrets ../../secrets.yaml -password test -configJson {"Password":"","FilePath":"../../config.yaml","WifiConfigs":[{"ProfileName":"wifiWPA2","SSID":"ssid","Priority":1,"AuthenticationMethod":6,"EncryptionMethod":4,"PskPassphrase":"","Ieee8021xProfileName":""},{"ProfileName":"wifi8021x","SSID":"ssid","Priority":2,"AuthenticationMethod":7,"EncryptionMethod":4,"PskPassphrase":"","Ieee8021xProfileName":"ieee8021xEAP-TLS"}],"Ieee8021xConfigs":[{"ProfileName":"ieee8021xEAP-TLS","Username":"test","Password":"","AuthenticationProtocol":0,"ClientCert":"test","CACert":"test","PrivateKey":""},{"ProfileName":"ieee8021xPEAPv0","Username":"test","Password":"","AuthenticationProtocol":2,"ClientCert":"testClientCert","CACert":"testCaCert","PrivateKey":"testPrivateKey"}],"AMTPassword":"","ProvisioningCert":"","ProvisioningCertPwd":""}`
	defer userInput(t, "userInput\nuserInput\nuserInput")()
	args := strings.Fields(cmdLine)
	flags := NewFlags(args, MockPRSuccess)
	gotResult := flags.ParseFlags()
	assert.Equal(t, nil, gotResult)
}

func TestHandleAddWifiSettings(t *testing.T) {
	cases := []struct {
		description    string
		cmdLine        string
		expectedResult error
	}{
		{description: "Missing Ieee8021xProfileName value",
			cmdLine:        "rpc configure wireless -password Passw0rd! -profilename cliprofname -authenticationMethod 6 -encryptionMethod 4 -ssid \"myclissid\" -priority 1 -PskPassphrase \"mypassword\" -Ieee8021xProfileName",
			expectedResult: utils.IncorrectCommandLineParameters,
		},
		{description: "Missing PskPassphrase value",
			cmdLine:        "rpc configure wireless -password Passw0rd! -profilename cliprofname -authenticationMethod 6 -encryptionMethod 4 -ssid \"myclissid\" -priority 1 -PskPassphrase",
			expectedResult: utils.IncorrectCommandLineParameters,
		},
		{description: "Missing priority value",
			cmdLine:        "rpc configure wireless -password Passw0rd! -profilename cliprofname -authenticationMethod 6 -encryptionMethod 4 -ssid \"myclissid\" -priority",
			expectedResult: utils.IncorrectCommandLineParameters,
		},
		{description: "Missing ssid value",
			cmdLine:        "rpc configure wireless -password Passw0rd! -profilename cliprofname -authenticationMethod 6 -encryptionMethod 4 -ssid",
			expectedResult: utils.IncorrectCommandLineParameters,
		},
		{description: "Missing authenticationMethod value",
			cmdLine:        "rpc configure wireless -password Passw0rd! -profilename cliprofname -authenticationMethod",
			expectedResult: utils.IncorrectCommandLineParameters,
		},
		{description: "Missing profile name",
			cmdLine:        "rpc configure wireless -password Passw0rd! -profilename",
			expectedResult: utils.IncorrectCommandLineParameters,
		},
		{description: "Missing filename",
			cmdLine:        "rpc configure wireless -password Passw0rd! -config",
			expectedResult: utils.IncorrectCommandLineParameters,
		},
		{description: "Missing password",
			cmdLine:        "rpc configure wireless -password Passw0rd! -config",
			expectedResult: utils.IncorrectCommandLineParameters,
		},
		{description: "Missing all params",
			cmdLine:        "rpc configure wireless",
			expectedResult: utils.IncorrectCommandLineParameters,
		},
		{description: "Unknown param",
			cmdLine:        "rpc configure wireless -h",
			expectedResult: utils.IncorrectCommandLineParameters,
		},
		{description: "Basic wifi config command line",
			cmdLine:        `rpc configure wireless -password Passw0rd! -profileName cliprofname -authenticationMethod 6 -encryptionMethod 4 -ssid "myclissid" -priority 1 -pskPassphrase "mypassword"`,
			expectedResult: nil,
		},
		{description: "Valid with reading from file",
			cmdLine:        "rpc configure wireless -password Passw0rd! -config ../../config.yaml -secrets ../../secrets.yaml",
			expectedResult: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.description, func(t *testing.T) {
			args := strings.Fields(tc.cmdLine)
			flags := NewFlags(args, MockPRSuccess)
			gotResult := flags.handleAddWifiSettings()
			assert.Equal(t, tc.expectedResult, gotResult)
		})
	}
}

var wifiCfgWPA = config.WifiConfig{
	ProfileName:          "wifiWPA",
	SSID:                 "ssid",
	Priority:             1,
	AuthenticationMethod: int(wifi.AuthenticationMethodWPAPSK),
	EncryptionMethod:     int(wifi.EncryptionMethod_TKIP),
	PskPassphrase:        "wifiWPAPassPhrase",
}

var wifiCfgWPA2 = config.WifiConfig{
	ProfileName:          "wifiWPA2",
	SSID:                 "ssid",
	Priority:             2,
	AuthenticationMethod: int(wifi.AuthenticationMethodWPA2PSK),
	EncryptionMethod:     int(wifi.EncryptionMethod_CCMP),
	PskPassphrase:        "wifiWPA2PassPhrase",
}

var wifiCfgWPA8021xEAPTLS = config.WifiConfig{
	ProfileName:          "wifiWPA28021x",
	SSID:                 "ssid",
	Priority:             3,
	AuthenticationMethod: int(wifi.AuthenticationMethodWPAIEEE8021x),
	EncryptionMethod:     int(wifi.EncryptionMethod_CCMP),
	Ieee8021xProfileName: "ieee8021xCfgEAPTLS",
}

var ieee8021xCfgEAPTLS = config.Ieee8021xConfig{
	ProfileName:            "ieee8021xCfgEAPTLS",
	Username:               "username",
	Password:               "",
	AuthenticationProtocol: int(ieee8021x.AuthenticationProtocolEAPTLS),
	ClientCert:             "clientCert",
	CACert:                 "caCert",
	PrivateKey:             "privateKey",
}

var wifiCfgWPA28021xPEAPv0_EAPMSCHAPv2 = config.WifiConfig{
	ProfileName:          "wifiWPA28021x",
	SSID:                 "ssid",
	Priority:             4,
	AuthenticationMethod: int(wifi.AuthenticationMethodWPA2IEEE8021x),
	EncryptionMethod:     int(wifi.EncryptionMethod_CCMP),
	Ieee8021xProfileName: "ieee8021xCfgPEAPv0_EAPMSCHAPv2",
}

var ieee8021xCfgPEAPv0_EAPMSCHAPv2 = config.Ieee8021xConfig{
	ProfileName:            "ieee8021xCfgPEAPv0_EAPMSCHAPv2",
	Username:               "username",
	Password:               "password",
	AuthenticationProtocol: int(ieee8021x.AuthenticationProtocolPEAPv0_EAPMSCHAPv2),
	ClientCert:             "",
	CACert:                 "caCert",
	PrivateKey:             "",
}

func runVerifyWifiConfiguration(t *testing.T, expectedResult error, wifiCfgs []config.WifiConfig, ieee8021xCfgs []config.Ieee8021xConfig) {
	f := Flags{}
	f.LocalConfig.WifiConfigs = append(f.LocalConfig.WifiConfigs, wifiCfgs...)
	f.LocalConfig.Ieee8021xConfigs = append(f.LocalConfig.Ieee8021xConfigs, ieee8021xCfgs...)
	gotResult := f.verifyWifiConfigurations()
	assert.Equal(t, expectedResult, gotResult)
}

func TestVerifyWifiConfiguration(t *testing.T) {
	t.Run("expect Success for correct configs", func(t *testing.T) {
		runVerifyWifiConfiguration(t, nil,
			[]config.WifiConfig{wifiCfgWPA, wifiCfgWPA2, wifiCfgWPA8021xEAPTLS, wifiCfgWPA28021xPEAPv0_EAPMSCHAPv2},
			[]config.Ieee8021xConfig{ieee8021xCfgEAPTLS, ieee8021xCfgPEAPv0_EAPMSCHAPv2})
	})
	t.Run("expect MissingOrInvalidConfiguration when missing ProfileName", func(t *testing.T) {
		orig := wifiCfgWPA.ProfileName
		wifiCfgWPA.ProfileName = ""
		runVerifyWifiConfiguration(t, utils.MissingOrInvalidConfiguration,
			[]config.WifiConfig{wifiCfgWPA},
			[]config.Ieee8021xConfig{})
		wifiCfgWPA.ProfileName = orig
	})
	t.Run("expect MissingOrInvalidConfiguration when missing SSID", func(t *testing.T) {
		orig := wifiCfgWPA.SSID
		wifiCfgWPA.SSID = ""
		runVerifyWifiConfiguration(t, utils.MissingOrInvalidConfiguration,
			[]config.WifiConfig{wifiCfgWPA},
			[]config.Ieee8021xConfig{})
		wifiCfgWPA.SSID = orig
	})
	t.Run("expect MissingOrInvalidConfiguration with invalid Priority", func(t *testing.T) {
		orig := wifiCfgWPA.Priority
		wifiCfgWPA.Priority = 0
		runVerifyWifiConfiguration(t, utils.MissingOrInvalidConfiguration,
			[]config.WifiConfig{wifiCfgWPA},
			[]config.Ieee8021xConfig{})
		wifiCfgWPA.Priority = orig
	})
	t.Run("expect MissingOrInvalidConfiguration with duplicate Priority", func(t *testing.T) {
		orig := wifiCfgWPA.Priority
		wifiCfgWPA.Priority = wifiCfgWPA2.Priority
		runVerifyWifiConfiguration(t, utils.MissingOrInvalidConfiguration,
			[]config.WifiConfig{wifiCfgWPA, wifiCfgWPA2},
			[]config.Ieee8021xConfig{})
		wifiCfgWPA.Priority = orig
	})
	t.Run("expect MissingOrInvalidConfiguration with invalid AuthenticationMethod", func(t *testing.T) {
		orig := wifiCfgWPA.AuthenticationMethod
		wifiCfgWPA.AuthenticationMethod = int(wifi.AuthenticationMethodWPA2IEEE8021x + 99)
		runVerifyWifiConfiguration(t, utils.MissingOrInvalidConfiguration,
			[]config.WifiConfig{wifiCfgWPA},
			[]config.Ieee8021xConfig{})
		wifiCfgWPA.AuthenticationMethod = orig
	})
	t.Run("expect MissingOrInvalidConfiguration with invalid EncryptionMethod", func(t *testing.T) {
		orig := wifiCfgWPA.EncryptionMethod
		wifiCfgWPA.EncryptionMethod = int(wifi.EncryptionMethod_None + 99)
		runVerifyWifiConfiguration(t, utils.MissingOrInvalidConfiguration,
			[]config.WifiConfig{wifiCfgWPA},
			[]config.Ieee8021xConfig{})
		wifiCfgWPA.EncryptionMethod = orig
	})
	t.Run("expect MissingOrInvalidConfiguration with missing passphrase", func(t *testing.T) {
		orig := wifiCfgWPA2.PskPassphrase
		wifiCfgWPA2.PskPassphrase = ""
		runVerifyWifiConfiguration(t, utils.MissingOrInvalidConfiguration,
			[]config.WifiConfig{wifiCfgWPA2},
			[]config.Ieee8021xConfig{})
		wifiCfgWPA2.PskPassphrase = orig
	})
	t.Run("expect MissingOrInvalidConfiguration with missing ieee8021x ProfileName", func(t *testing.T) {
		orig8021xName := ieee8021xCfgEAPTLS.ProfileName
		ieee8021xCfgEAPTLS.ProfileName = ""
		runVerifyWifiConfiguration(t, utils.MissingOrInvalidConfiguration,
			[]config.WifiConfig{wifiCfgWPA8021xEAPTLS},
			[]config.Ieee8021xConfig{ieee8021xCfgEAPTLS})
		ieee8021xCfgEAPTLS.ProfileName = orig8021xName
	})
	t.Run("expect MissingOrInvalidConfiguration with PskPassphrase is present for ieee8021x profile", func(t *testing.T) {
		wifiCfgWPA8021xEAPTLS.PskPassphrase = "shouldn't be here"
		runVerifyWifiConfiguration(t, utils.MissingOrInvalidConfiguration,
			[]config.WifiConfig{wifiCfgWPA8021xEAPTLS},
			[]config.Ieee8021xConfig{ieee8021xCfgEAPTLS})
		wifiCfgWPA8021xEAPTLS.PskPassphrase = ""
	})
	t.Run("expect MissingOrInvalidConfiguration with PskPassphrase is present for ieee8021x profile", func(t *testing.T) {
		wifiCfgWPA28021xPEAPv0_EAPMSCHAPv2.PskPassphrase = "shouldn't be here"
		runVerifyWifiConfiguration(t, utils.MissingOrInvalidConfiguration,
			[]config.WifiConfig{wifiCfgWPA28021xPEAPv0_EAPMSCHAPv2},
			[]config.Ieee8021xConfig{ieee8021xCfgPEAPv0_EAPMSCHAPv2})
		wifiCfgWPA28021xPEAPv0_EAPMSCHAPv2.PskPassphrase = ""
	})

	t.Run("expect MissingOrInvalidConfiguration with duplicate ieee8021x ProfileName", func(t *testing.T) {
		orig8021xName := ieee8021xCfgEAPTLS.ProfileName
		ieee8021xCfgEAPTLS.ProfileName = ieee8021xCfgPEAPv0_EAPMSCHAPv2.ProfileName
		wifiCfgWPA8021xEAPTLS.Ieee8021xProfileName = ieee8021xCfgPEAPv0_EAPMSCHAPv2.ProfileName
		// authMethod 5
		runVerifyWifiConfiguration(t, utils.MissingOrInvalidConfiguration,
			[]config.WifiConfig{wifiCfgWPA8021xEAPTLS},
			[]config.Ieee8021xConfig{ieee8021xCfgEAPTLS, ieee8021xCfgPEAPv0_EAPMSCHAPv2})
		// authMethod 7
		runVerifyWifiConfiguration(t, utils.MissingOrInvalidConfiguration,
			[]config.WifiConfig{wifiCfgWPA28021xPEAPv0_EAPMSCHAPv2},
			[]config.Ieee8021xConfig{ieee8021xCfgEAPTLS, ieee8021xCfgPEAPv0_EAPMSCHAPv2})
		ieee8021xCfgEAPTLS.ProfileName = orig8021xName
		wifiCfgWPA8021xEAPTLS.Ieee8021xProfileName = ieee8021xCfgEAPTLS.ProfileName
	})
}

func TestVerifyMatchingIeee8021xConfig(t *testing.T) {
	name := "profileName"
	f := Flags{}
	f.LocalConfig.Ieee8021xConfigs = append(f.LocalConfig.Ieee8021xConfigs, config.Ieee8021xConfig{})
	t.Run("expect MissingOrInvalidConfiguration with missing configuration", func(t *testing.T) {
		f2 := Flags{}
		rc := f2.verifyMatchingIeee8021xConfig("")
		assert.Equal(t, utils.MissingOrInvalidConfiguration, rc)
	})
	t.Run("expect MissingOrInvalidConfiguration if no matching profile", func(t *testing.T) {
		rc := f.verifyMatchingIeee8021xConfig(name)
		assert.Equal(t, utils.MissingOrInvalidConfiguration, rc)
	})
	t.Run("expect MissingOrInvalidConfiguration if missing username", func(t *testing.T) {
		f.LocalConfig.Ieee8021xConfigs[0].ProfileName = name
		rc := f.verifyMatchingIeee8021xConfig(name)
		assert.Equal(t, utils.MissingOrInvalidConfiguration, rc)
	})
	t.Run("expect MissingOrInvalidConfiguration if missing ClientCert", func(t *testing.T) {
		f.LocalConfig.Ieee8021xConfigs[0].Username = "UserName"
		rc := f.verifyMatchingIeee8021xConfig(name)
		assert.Equal(t, utils.MissingOrInvalidConfiguration, rc)
	})
	t.Run("expect MissingOrInvalidConfiguration if missing CACert", func(t *testing.T) {
		f.LocalConfig.Ieee8021xConfigs[0].ClientCert = "AABBCCDDEEFF"
		rc := f.verifyMatchingIeee8021xConfig(name)
		assert.Equal(t, utils.MissingOrInvalidConfiguration, rc)
	})
	t.Run("expect MissingOrInvalidConfiguration if missing PrivateKey", func(t *testing.T) {
		f.LocalConfig.Ieee8021xConfigs[0].CACert = "AABBCCDDEEFF"
		rc := f.verifyMatchingIeee8021xConfig(name)
		assert.Equal(t, utils.MissingOrInvalidConfiguration, rc)
	})
	t.Run("expect MissingOrInvalidConfiguration if missing PskPassphrase", func(t *testing.T) {
		f.LocalConfig.Ieee8021xConfigs[0].PrivateKey = "AABBCCDDEEFF"
		f.LocalConfig.Ieee8021xConfigs[0].AuthenticationProtocol = int(ieee8021x.AuthenticationProtocolPEAPv0_EAPMSCHAPv2)
		rc := f.verifyMatchingIeee8021xConfig(name)
		assert.Equal(t, utils.MissingOrInvalidConfiguration, rc)
	})
	t.Run("expect Success", func(t *testing.T) {
		f.LocalConfig.Ieee8021xConfigs[0].AuthenticationProtocol = int(ieee8021x.AuthenticationProtocolEAPTLS)
		rc := f.verifyMatchingIeee8021xConfig(name)
		assert.Equal(t, nil, rc)
	})
	t.Run("expect MissingOrInvalidConfiguration for unsupported AuthenticationProtocolEAPTTLS_MSCHAPv2", func(t *testing.T) {
		f.LocalConfig.Ieee8021xConfigs[0].AuthenticationProtocol = int(ieee8021x.AuthenticationProtocolEAPTTLS_MSCHAPv2)
		rc := f.verifyMatchingIeee8021xConfig(name)
		assert.Equal(t, utils.MissingOrInvalidConfiguration, rc)
	})
}
func TestVerifyWiredIeee8021xConfig(t *testing.T) {
	name := "test8021xProfile"
	secrets := config.SecretConfig{
		Secrets: []config.Secret{
			{
				ProfileName:   "profileName",
				PskPassphrase: "pskPassphrase",
				PrivateKey:    "privateKey",
				Password:      "password",
			},
		},
	}

	f := Flags{}
	f.LocalConfig.Ieee8021xConfigs = append(f.LocalConfig.Ieee8021xConfigs, config.Ieee8021xConfig{})
	f.LocalConfig.WiredConfig.Ieee8021xProfileName = name

	t.Run("expect nil with missing Ieee8021x Profile name", func(t *testing.T) {
		f.LocalConfig.WiredConfig.Ieee8021xProfileName = ""
		f2 := Flags{}
		rc := f2.verifyWiredIeee8021xConfig(secrets)
		assert.Equal(t, nil, rc)
	})

	t.Run("expect wired8021xConfig to be nil", func(t *testing.T) {
		defer userInput(t, "userInput")()
		f.LocalConfig.WiredConfig.Ieee8021xProfileName = name
		f.LocalConfig.EnterpriseAssistant.EAAddress = "http://test"
		f.LocalConfig.EnterpriseAssistant.EAUsername = "testEAUser"
		rc := f.verifyWiredIeee8021xConfig(secrets)
		assert.Equal(t, utils.MissingOrInvalidConfiguration, rc)
		assert.Equal(t, "userInput", f.LocalConfig.EnterpriseAssistant.EAPassword)
	})

	t.Run("expect MissingOrInvalidConfiguration if missing username", func(t *testing.T) {
		f.LocalConfig.EnterpriseAssistant.EAAddress = "testpassword"
		rc := f.verifyWiredIeee8021xConfig(secrets)
		assert.Equal(t, utils.MissingOrInvalidConfiguration, rc)
	})
	t.Run("expect end of function", func(t *testing.T) {
		f.LocalConfig.WiredConfig.Ieee8021xProfileName = "test8021xProfile"
		f.LocalConfig.Ieee8021xConfigs[0].ProfileName = "test8021xProfile"
		f.LocalConfig.Ieee8021xConfigs[0].Username = "testUsername"
		f.LocalConfig.Ieee8021xConfigs[0].CACert = "testCACert"
		f.LocalConfig.Ieee8021xConfigs[0].ClientCert = "testClientCert"
		f.LocalConfig.Ieee8021xConfigs[0].PrivateKey = "testPrivateKey"
		rc := f.verifyWiredIeee8021xConfig(secrets)
		assert.Equal(t, nil, rc)
	})
}
func TestInvalidAuthenticationMethods(t *testing.T) {
	f := Flags{}
	f.LocalConfig.WifiConfigs = append(f.LocalConfig.WifiConfigs, wifiCfgWPA)
	cases := []struct {
		method wifi.AuthenticationMethod
	}{
		{method: wifi.AuthenticationMethodOther},
		{method: wifi.AuthenticationMethodOpenSystem},
		{method: wifi.AuthenticationMethodSharedKey},
		{method: wifi.AuthenticationMethodWPA3SAE},
		{method: wifi.AuthenticationMethodWPA3OWE},
		{method: 599},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("expect MissingOrInvalidConfiguration for AuthenticationProtocol %d", tc.method),
			func(t *testing.T) {
				f.LocalConfig.WifiConfigs[0].AuthenticationMethod = int(tc.method)
				rc := f.verifyWifiConfigurations()
				assert.Equal(t, utils.MissingOrInvalidConfiguration, rc)
			})
	}
}

func TestInvalidEncryptionMethods(t *testing.T) {
	f := Flags{}
	f.LocalConfig.WifiConfigs = append(f.LocalConfig.WifiConfigs, wifiCfgWPA)
	cases := []struct {
		method wifi.EncryptionMethod
	}{
		{method: wifi.EncryptionMethod_Other},
		{method: wifi.EncryptionMethod_WEP},
		{method: wifi.EncryptionMethod_None},
		{method: 599},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("expect MissingOrInvalidConfiguration for AuthenticationProtocol %d", tc.method),
			func(t *testing.T) {
				f.LocalConfig.WifiConfigs[0].EncryptionMethod = int(tc.method)
				rc := f.verifyWifiConfigurations()
				assert.Equal(t, utils.MissingOrInvalidConfiguration, rc)
			})
	}
}

func TestInvalidAuthenticationProtocols(t *testing.T) {
	f := Flags{}
	f.LocalConfig.Ieee8021xConfigs = append(f.LocalConfig.Ieee8021xConfigs, ieee8021xCfgEAPTLS)
	cases := []struct {
		protocol int
	}{
		{protocol: ieee8021x.AuthenticationProtocolEAPTTLS_MSCHAPv2},
		{protocol: ieee8021x.AuthenticationProtocolPEAPv1_EAPGTC},
		{protocol: ieee8021x.AuthenticationProtocolEAPFAST_MSCHAPv2},
		{protocol: ieee8021x.AuthenticationProtocolEAPFAST_GTC},
		{protocol: ieee8021x.AuthenticationProtocolEAP_MD5},
		{protocol: ieee8021x.AuthenticationProtocolEAP_PSK},
		{protocol: ieee8021x.AuthenticationProtocolEAP_SIM},
		{protocol: ieee8021x.AuthenticationProtocolEAP_AKA},
		{protocol: ieee8021x.AuthenticationProtocolEAPFAST_TLS},
		{protocol: 599},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("expect MissingOrInvalidConfiguration for AuthenticationProtocol %d", tc.protocol),
			func(t *testing.T) {
				f.LocalConfig.Ieee8021xConfigs[0].AuthenticationProtocol = int(tc.protocol)
				err := f.verifyIeee8021xConfig(f.LocalConfig.Ieee8021xConfigs[0])
				assert.Equal(t, utils.MissingOrInvalidConfiguration, err)
			})
	}
}

func TestHandleAddEthernetSettings(t *testing.T) {
	cases := []struct {
		description    string
		cmdLine        string
		expectedResult error
	}{
		{description: "fail - dchp without ipsync",
			cmdLine:        "rpc configure wired -dhcp -password Passw0rd!",
			expectedResult: utils.InvalidParameterCombination,
		},
		{description: "fail - no flags",
			cmdLine:        "rpc configure wired -password Passw0rd!",
			expectedResult: utils.InvalidParameterCombination,
		},
		{description: "fail - static missing subnetmask",
			cmdLine:        "rpc configure wired -static -ipaddress 192.168.1.7 -password Passw0rd!",
			expectedResult: utils.MissingOrIncorrectNetworkMask,
		},
		{description: "dhcp and ipsync",
			cmdLine:        "rpc configure wired -dhcp -ipsync -password Passw0rd!",
			expectedResult: nil,
		},
		{description: "static and ipsync",
			cmdLine:        "rpc configure wired -static -ipsync -password Passw0rd!",
			expectedResult: nil,
		},
		{description: "static and params",
			cmdLine:        "rpc configure wired -static -ipaddress 192.168.1.7 -subnetmask 255.255.255.0 -gateway 192.168.1.1 -primarydns 8.8.8.8 -password Passw0rd!",
			expectedResult: nil,
		},
		{description: "config",
			cmdLine:        "rpc configure wired -config ../../config.yaml -password Passw0rd!",
			expectedResult: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.description, func(t *testing.T) {
			args := strings.Fields(tc.cmdLine)
			flags := NewFlags(args, MockPRSuccess)
			gotResult := flags.handleAddEthernetSettings()
			assert.Equal(t, tc.expectedResult, gotResult)
		})
	}
}
