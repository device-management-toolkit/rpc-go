/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package flags

import (
	"fmt"
	"testing"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/wifi"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/ips/ieee8021x"
	"github.com/device-management-toolkit/rpc-go/v2/internal/config"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
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
	AuthenticationProtocol: ieee8021x.AuthenticationProtocolEAPTLS,
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
	AuthenticationProtocol: ieee8021x.AuthenticationProtocolPEAPv0_EAPMSCHAPv2,
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
		f.LocalConfig.Ieee8021xConfigs[0].AuthenticationProtocol = ieee8021x.AuthenticationProtocolPEAPv0_EAPMSCHAPv2
		rc := f.verifyMatchingIeee8021xConfig(name)
		assert.Equal(t, utils.MissingOrInvalidConfiguration, rc)
	})
	t.Run("expect Success", func(t *testing.T) {
		f.LocalConfig.Ieee8021xConfigs[0].AuthenticationProtocol = ieee8021x.AuthenticationProtocolEAPTLS
		rc := f.verifyMatchingIeee8021xConfig(name)
		assert.Equal(t, nil, rc)
	})
	t.Run("expect MissingOrInvalidConfiguration for unsupported AuthenticationProtocolEAPTTLS_MSCHAPv2", func(t *testing.T) {
		f.LocalConfig.Ieee8021xConfigs[0].AuthenticationProtocol = ieee8021x.AuthenticationProtocolEAPTTLS_MSCHAPv2
		rc := f.verifyMatchingIeee8021xConfig(name)
		assert.Equal(t, utils.MissingOrInvalidConfiguration, rc)
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
				f.LocalConfig.Ieee8021xConfigs[0].AuthenticationProtocol = tc.protocol
				err := f.verifyIeee8021xConfig(f.LocalConfig.Ieee8021xConfigs[0])
				assert.Equal(t, utils.MissingOrInvalidConfiguration, err)
			})
	}
}
