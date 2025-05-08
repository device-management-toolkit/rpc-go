/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package config

type (
	Config struct {
		Password            string              `yaml:"password"`
		TlsConfig           TlsConfig           `yaml:"tlsConfig"`
		WiredConfig         EthernetConfig      `yaml:"wiredConfig"`
		WifiConfigs         []WifiConfig        `yaml:"wifiConfigs"`
		WiFiSyncEnabled     bool                `yaml:"wifiSyncEnabled"`
		Ieee8021xConfigs    []Ieee8021xConfig   `yaml:"ieee8021xConfigs"`
		ACMSettings         ACMSettings         `yaml:"acmactivate"`
		EnterpriseAssistant EnterpriseAssistant `yaml:"enterpriseAssistant"`
		StopConfiguration   bool                `yaml:"stopConfig"`
		CCMSettings         CCMSettings         `yaml:"ccmactivate"`
	}
	TlsConfig struct {
		Delay int    `yaml:"delay" env-default:"3"`
		Mode  string `yaml:"mode"`
	}
	WifiConfig struct {
		ProfileName          string `yaml:"profileName"`
		SSID                 string `yaml:"ssid"`
		Priority             int    `yaml:"priority"`
		AuthenticationMethod int    `yaml:"authenticationMethod"`
		EncryptionMethod     int    `yaml:"encryptionMethod"`
		PskPassphrase        string `yaml:"pskPassphrase"`
		Ieee8021xProfileName string `yaml:"ieee8021xProfileName"`
	}
	EthernetConfig struct {
		DHCP                 bool   `yaml:"dhcp"`
		Static               bool   `yaml:"static"`
		IpSync               bool   `yaml:"ipsync"`
		IpAddress            string `yaml:"ipaddress"`
		Subnetmask           string `yaml:"subnetmask"`
		Gateway              string `yaml:"gateway"`
		PrimaryDNS           string `yaml:"primarydns"`
		SecondaryDNS         string `yaml:"secondarydns"`
		Ieee8021xProfileName string `yaml:"ieee8021xProfileName"`
	}
	SecretConfig struct {
		Secrets []Secret `yaml:"secrets"`
	}
	Secret struct {
		ProfileName   string `yaml:"profileName"`
		PskPassphrase string `yaml:"pskPassphrase"`
		PrivateKey    string `yaml:"privateKey"`
		Password      string `yaml:"password"`
	}
	Ieee8021xConfig struct {
		ProfileName            string `yaml:"profileName"`
		Username               string `yaml:"username"`
		Password               string `yaml:"password"`
		AuthenticationProtocol int    `yaml:"authenticationProtocol"`
		ClientCert             string `yaml:"clientCert"`
		CACert                 string `yaml:"caCert"`
		PrivateKey             string `yaml:"privateKey"`
	}

	ACMSettings struct {
		AMTPassword         string `yaml:"amtPassword"`
		ProvisioningCert    string `yaml:"provisioningCert"`
		ProvisioningCertPwd string `yaml:"provisioningCertPwd"`
	}
	EnterpriseAssistant struct {
		EAAddress    string `yaml:"eaAddress"`
		EAUsername   string `yaml:"eaUsername"`
		EAPassword   string `yaml:"eaPassword"`
		EAConfigured bool   `yaml:"eaConfigured"`
	}
	CCMSettings struct {
		AMTPassword string `yaml:"amtPassword"`
	}
)
