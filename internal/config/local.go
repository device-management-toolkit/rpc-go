package config

type (
	Config struct {
		Password          string
		IEEE8021XSettings `yaml:"ieee801xConfig"`
		WifiConfigs       `yaml:"wifiConfigs"`
		Ieee8021xConfigs  `yaml:"ieee8021xConfigs"`
		SecretConfigs     `yaml:"secretConfig"`
		ACMSettings       `yaml:"acmactivate"`
	}
	IEEE8021XSettings struct {
		Name                   string `yaml:"name"`
		AuthenticationMethod   int    `yaml:"authenticationMethod"`
		EncryptionMethod       int    `yaml:"encryptionMethod"`
		SSID                   string `yaml:"ssid"`
		Username               string `yaml:"username"`
		AuthenticationProtocol int    `yaml:"authenticationProtocol"`
		Priority               int    `yaml:"priority"`
		ClientCert             string `yaml:"clientCert"`
		CACert                 string `yaml:"caCert"`
		PrivateKey             string `yaml:"privateKey"`
	}
	WifiConfigs []WifiConfig
	WifiConfig  struct {
		ProfileName          string `yaml:"profileName"`
		SSID                 string `yaml:"ssid"`
		Priority             int    `yaml:"priority"`
		AuthenticationMethod int    `yaml:"authenticationMethod"`
		EncryptionMethod     int    `yaml:"encryptionMethod"`
		PskPassphrase        string `yaml:"pskPassphrase"`
		Ieee8021xProfileName string `yaml:"ieee8021xProfileName"`
	}
	SecretConfigs []SecretConfig
	SecretConfig  struct {
		ClientCert string `yaml:"secretClientCert"`
		CACert     string `yaml:"secretCaCert"`
		PrivateKey string `yaml:"secretPrivateKey"`
	}
	Ieee8021xConfigs []Ieee8021xConfig
	Ieee8021xConfig  struct {
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
)
