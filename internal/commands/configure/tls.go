/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/publickey"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/tls"
	"github.com/device-management-toolkit/rpc-go/v2/internal/certs"
	"github.com/device-management-toolkit/rpc-go/v2/internal/certs/ea"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// TLSMode represents the TLS authentication mode
type TLSMode int

const (
	TLSModeServer TLSMode = iota
	TLSModeServerAndNonTLS
	TLSModeMutual
	TLSModeMutualAndNonTLS
	TLSModeDisabled
)

const (
	TLSModeServerValue          = "Server"
	TLSModeServerAndNonTLSValue = "ServerAndNonTLS"
	TLSModeMutualValue          = "Mutual"
	TLSModeMutualAndNonTLSValue = "MutualAndNonTLS"
	TLSModeDisabledValue        = "None"
	TLSModeUnknownValue         = "Unknown"
	RemoteTLSInstanceId         = `Intel(r) AMT 802.3 TLS Settings`
	LocalTLSInstanceId          = `Intel(r) AMT LMS TLS Settings`
)

// CertificateHandles holds certificate and key handles for TLS configuration
type CertificateHandles struct {
	RootCertHandle   string
	ClientCertHandle string
	KeyPairHandle    string
	PrivateKeyHandle string
}

func (m TLSMode) String() string {
	switch m {
	case TLSModeServer:
		return TLSModeServerValue
	case TLSModeServerAndNonTLS:
		return TLSModeServerAndNonTLSValue
	case TLSModeMutual:
		return TLSModeMutualValue
	case TLSModeMutualAndNonTLS:
		return TLSModeMutualAndNonTLSValue
	case TLSModeDisabled:
		return TLSModeDisabledValue
	default:
		return TLSModeUnknownValue
	}
}

func TLSModesToString() string {
	return strings.Join([]string{
		TLSModeServerValue,
		TLSModeServerAndNonTLSValue,
		TLSModeMutualValue,
		TLSModeMutualAndNonTLSValue,
		TLSModeDisabledValue,
	}, ", ")
}

func ParseTLSMode(s string) (TLSMode, error) {
	switch s {
	case TLSModeServerValue:
		return TLSModeServer, nil
	case TLSModeServerAndNonTLSValue:
		return TLSModeServerAndNonTLS, nil
	case TLSModeMutualValue:
		return TLSModeMutual, nil
	case TLSModeMutualAndNonTLSValue:
		return TLSModeMutualAndNonTLS, nil
	case TLSModeDisabledValue:
		return TLSModeDisabled, nil
	default:
		return TLSModeServer, fmt.Errorf("invalid TLS mode: %s", s)
	}
}

// DetermineTLSMode converts boolean flags to TLS mode string
func DetermineTLSMode(mutualAuth, enabled, allowNonTLS bool) string {
	switch {
	case enabled && !allowNonTLS && !mutualAuth:
		return TLSModeServerValue
	case enabled && allowNonTLS && !mutualAuth:
		return TLSModeServerAndNonTLSValue
	case enabled && !allowNonTLS && mutualAuth:
		return TLSModeMutualValue
	case enabled && allowNonTLS && mutualAuth:
		return TLSModeMutualAndNonTLSValue
	case !enabled:
		return TLSModeDisabledValue
	default:
		return TLSModeUnknownValue
	}
}

// TLSCmd represents TLS configuration
type TLSCmd struct {
	ConfigureBaseCmd

	// Enterprise Assistant settings
	EAAddress  string `help:"Enterprise Assistant address" name:"eaAddress"`
	EAUsername string `help:"Enterprise Assistant username" name:"eaUsername"`
	EAPassword string `help:"Enterprise Assistant password" name:"eaPassword"`

	Mode  string `help:"TLS authentication mode" enum:"Server,ServerAndNonTLS,Mutual,MutualAndNonTLS,None" default:"Server" name:"mode"`
	Delay int    `help:"Delay time in seconds after putting remote TLS settings" default:"3" name:"delay"`
}

// Validate implements Kong's Validate interface for MEBx command validation
func (cmd *TLSCmd) Validate() error {
	// First call the base Validate to handle password validation
	if err := cmd.ConfigureBaseCmd.Validate(); err != nil {
		return err
	}

	// Validate delay is reasonable
	if cmd.Delay < 0 {
		return fmt.Errorf("delay must be non-negative")
	}

	// Validate Enterprise Assistant settings if provided
	eaProvided := cmd.EAAddress != "" || cmd.EAUsername != "" || cmd.EAPassword != ""
	if eaProvided {
		if cmd.EAAddress == "" {
			return fmt.Errorf("EA address is required when using Enterprise Assistant")
		}

		if cmd.EAUsername == "" {
			return fmt.Errorf("EA username is required when using Enterprise Assistant")
		}

		if cmd.EAPassword == "" {
			return fmt.Errorf("EA password is required when using Enterprise Assistant")
		}

		// Validate EA URL format
		err := utils.ValidateURL(cmd.EAAddress)
		if err != nil {
			return fmt.Errorf("invalid EA address: %w", err)
		}
	}

	return nil
}

// Run executes the TLS configuration command
func (cmd *TLSCmd) Run(ctx *commands.Context) error {
	// Ensure runtime initialization (password + WSMAN client)
	if err := cmd.EnsureRuntime(ctx); err != nil {
		return err
	}

	log.Info("Configuring TLS settings...")

	// Parse the TLS mode
	tlsMode, err := cmd.parseTLSMode()
	if err != nil {
		return fmt.Errorf("invalid TLS mode: %w", err)
	}

	var handles CertificateHandles

	// Only provision certificates if TLS is enabled
	if tlsMode != TLSModeDisabled {
		// Defer certificate cleanup on error
		defer func() {
			if err != nil {
				cmd.pruneCerts()
			}
		}()

		// Configure certificates based on EA settings
		if cmd.EAAddress != "" && cmd.EAUsername != "" && cmd.EAPassword != "" {
			log.Info("Configuring TLS with Enterprise Assistant")

			handles, err = cmd.configureTLSWithEA()
			if err != nil {
				return err
			}
		} else {
			log.Info("Configuring TLS with self-signed certificate")

			handles, err = cmd.configureTLSWithSelfSignedCert()
			if err != nil {
				return err
			}
		}
	}

	// Synchronize time
	err = cmd.synchronizeTime(ctx)
	if err != nil {
		log.Warn("Time synchronization failed, continuing: ", err)
	}

	// Configure TLS settings
	err = cmd.enableTLS(tlsMode)
	if err != nil {
		log.Error("Failed to configure TLS")

		return fmt.Errorf("TLS configuration failed: %w", err)
	}

	// Update TLS credential context if certificates were provisioned
	if tlsMode != TLSModeDisabled && handles.ClientCertHandle != "" {
		err = cmd.updateTLSCredentialContext(handles.ClientCertHandle)
		if err != nil {
			return fmt.Errorf("failed to update TLS credential context: %w", err)
		}
	}

	// Apply delay after configuration
	if cmd.Delay > 0 {
		log.Infof("Waiting %d seconds after TLS configuration...", cmd.Delay)
		time.Sleep(time.Duration(cmd.Delay) * time.Second)
	}

	// Prune unused certificates
	err = cmd.pruneCerts()
	if err != nil {
		log.Warn("Failed to prune certificates: ", err)
	}

	log.Info("TLS configuration completed successfully")

	return nil
}

// parseTLSMode converts the string mode to TLSMode
func (cmd *TLSCmd) parseTLSMode() (TLSMode, error) {
	return ParseTLSMode(cmd.Mode)
}

// enableTLS configures TLS settings based on the mode
func (cmd *TLSCmd) enableTLS(tlsMode TLSMode) error {
	log.Infof("Start TLS configuration: %s", tlsMode.String())

	// Enumerate TLS settings
	enumerateRsp, err := cmd.WSMan.EnumerateTLSSettingData()
	if err != nil {
		return fmt.Errorf("failed to enumerate TLS settings: %w", err)
	}

	// Pull TLS settings
	pullRsp, err := cmd.WSMan.PullTLSSettingData(enumerateRsp.Body.EnumerateResponse.EnumerationContext)
	if err != nil {
		return fmt.Errorf("failed to pull TLS settings: %w", err)
	}

	// Configure each TLS setting (Remote and Local)
	for _, item := range pullRsp.Body.PullResponse.SettingDataItems {
		if item.InstanceID == RemoteTLSInstanceId || item.InstanceID == LocalTLSInstanceId {
			err = cmd.configureTLSSettings(item, tlsMode)
			if err != nil {
				return err
			}
		}
	}

	// Commit changes
	_, err = cmd.WSMan.CommitChanges()
	if err != nil {
		log.Error("commit changes failed")

		return fmt.Errorf("failed to commit TLS changes: %w", err)
	}

	return nil
}

// configureTLSSettings configures individual TLS settings
func (cmd *TLSCmd) configureTLSSettings(setting tls.SettingDataResponse, tlsMode TLSMode) error {
	log.Infof("configuring TLS settings: %s", setting.InstanceID)

	// Create TLS settings request based on current settings and desired mode
	data := tls.SettingDataRequest{
		AcceptNonSecureConnections: setting.AcceptNonSecureConnections,
		ElementName:                setting.ElementName,
		Enabled:                    true,
		InstanceID:                 setting.InstanceID,
		MutualAuthentication:       setting.MutualAuthentication,
	}

	// Configure based on TLS mode
	if setting.NonSecureConnectionsSupported == nil || *setting.NonSecureConnectionsSupported {
		data.AcceptNonSecureConnections = tlsMode == TLSModeServerAndNonTLS || tlsMode == TLSModeMutualAndNonTLS
	}

	if setting.NonSecureConnectionsSupported != nil {
		if tlsMode == TLSModeDisabled && !*setting.NonSecureConnectionsSupported {
			log.Error("TLS cannot be disabled on this device")

			return fmt.Errorf("TLS cannot be disabled on this device")
		}
	}

	data.MutualAuthentication = tlsMode == TLSModeMutual || tlsMode == TLSModeMutualAndNonTLS
	data.Enabled = tlsMode != TLSModeDisabled

	// Apply the TLS settings
	_, err := cmd.WSMan.PUTTLSSettings(data.InstanceID, data)
	if err != nil {
		log.Errorf("failed to configure TLS Settings (%s)", data.InstanceID)

		return fmt.Errorf("failed to configure TLS settings: %w", err)
	}

	return nil
}

// configureTLSWithEA configures TLS using Enterprise Assistant for certificate provisioning
func (cmd *TLSCmd) configureTLSWithEA() (CertificateHandles, error) {
	log.Info("configuring TLS with Microsoft EA")

	var (
		handles CertificateHandles
		err     error
	)

	// Setup EA authentication
	amtCmd := amt.NewAMTCommand()

	guid, err := amtCmd.GetUUID()
	if err != nil {
		return handles, fmt.Errorf("failed to get UUID: %w", err)
	}

	credentials := ea.AuthRequest{
		Username: cmd.EAUsername,
		Password: cmd.EAPassword,
	}

	// Get authentication token from EA
	url := cmd.EAAddress + "/api/authenticate/" + guid

	token, err := ea.GetAuthToken(url, credentials)
	if err != nil {
		return handles, fmt.Errorf("failed to get auth token: %w", err)
	}

	// Get device name
	devName, err := os.Hostname()
	if err != nil {
		return handles, fmt.Errorf("failed to get hostname: %w", err)
	}

	// Create EA profile request
	reqProfile := ea.Profile{
		NodeID:       guid,
		Domain:       "",
		ReqID:        "",
		AuthProtocol: 0,
		OSName:       "win11",
		DevName:      devName,
		Icon:         1,
		Ver:          "",
	}

	// Request profile from EA
	url = cmd.EAAddress + "/api/configure/profile/" + guid

	_, err = ea.ConfigureCertificate(url, token, reqProfile)
	if err != nil {
		return handles, fmt.Errorf("failed to request EA profile: %w", err)
	}

	// Generate key pair
	handles.KeyPairHandle, err = cmd.generateKeyPair()
	if err != nil {
		return handles, err
	}

	handles.PrivateKeyHandle = handles.KeyPairHandle

	// Get DER key
	derKey, err := cmd.getDERKey(handles.KeyPairHandle)
	if err != nil {
		return handles, fmt.Errorf("failed to get DER key for handle %s: %w", handles.KeyPairHandle, err)
	}

	if derKey == "" {
		return handles, fmt.Errorf("failed to get DER key for handle: %s", handles.KeyPairHandle)
	}

	// Update profile with key information
	reqProfile.DERKey = derKey
	reqProfile.KeyInstanceId = handles.KeyPairHandle
	url = cmd.EAAddress + "/api/configure/keypair/" + guid

	keyPairResponse, err := ea.ConfigureCertificate(url, token, reqProfile)
	if err != nil {
		return handles, fmt.Errorf("failed to configure keypair with EA: %w", err)
	}

	// Generate PKCS10 request
	response, err := cmd.WSMan.GeneratePKCS10RequestEx(
		keyPairResponse.Response.KeyInstanceId,
		keyPairResponse.Response.CSR,
		1,
	)
	if err != nil {
		return handles, fmt.Errorf("failed to generate PKCS10 request: %w", err)
	}

	// Submit CSR to EA
	reqProfile.SignedCSR = response.Body.GeneratePKCS10RequestEx_OUTPUT.SignedCertificateRequest
	url = cmd.EAAddress + "/api/configure/csr/" + guid

	eaResponse, err := ea.ConfigureCertificate(url, token, reqProfile)
	if err != nil {
		return handles, fmt.Errorf("failed to sign certificate: %w", err)
	}

	// Add client certificate
	handles.ClientCertHandle, err = cmd.getClientCertHandle(eaResponse.Response.Certificate)
	if err != nil {
		return handles, fmt.Errorf("failed to add client certificate: %w", err)
	}

	return handles, nil
}

// configureTLSWithSelfSignedCert configures TLS using self-signed certificates
func (cmd *TLSCmd) configureTLSWithSelfSignedCert() (CertificateHandles, error) {
	var (
		handles CertificateHandles
		err     error
	)

	// Create root certificate
	rootComposite, err := certs.NewRootComposite()
	if err != nil {
		return handles, fmt.Errorf("failed to create root certificate: %w", err)
	}

	// Add root certificate to AMT
	handles.RootCertHandle, err = cmd.WSMan.AddTrustedRootCert(rootComposite.StripPem())
	if err != nil {
		return handles, fmt.Errorf("failed to add root certificate: %w", err)
	}

	// Generate key pair
	handles.KeyPairHandle, err = cmd.generateKeyPair()
	if err != nil {
		return handles, err
	}

	handles.PrivateKeyHandle = handles.KeyPairHandle

	// Get DER key
	derKey, err := cmd.getDERKey(handles.KeyPairHandle)
	if err != nil {
		return handles, fmt.Errorf("failed to get DER key for handle %s: %w", handles.KeyPairHandle, err)
	}

	if derKey == "" {
		return handles, fmt.Errorf("failed to get DER key for handle: %s", handles.KeyPairHandle)
	}

	// Create client certificate
	clientComposite, err := certs.NewSignedAMTComposite(derKey, &rootComposite)
	if err != nil {
		return handles, fmt.Errorf("failed to create client certificate: %w", err)
	}

	// Add client certificate to AMT
	handles.ClientCertHandle, err = cmd.WSMan.AddClientCert(clientComposite.StripPem())
	if err != nil {
		return handles, fmt.Errorf("failed to add client certificate: %w", err)
	}

	log.Debug("TLS rootCertHandle:", handles.RootCertHandle)
	log.Debug("TLS clientCertHandle:", handles.ClientCertHandle)
	log.Debug("TLS keyPairHandle:", handles.KeyPairHandle)

	return handles, nil
}

// generateKeyPair generates a new RSA key pair
func (cmd *TLSCmd) generateKeyPair() (string, error) {
	log.Info("generating key pair")

	response, err := cmd.WSMan.GenerateKeyPair(publickey.RSA, 2048)
	if err != nil {
		return "", fmt.Errorf("failed to generate key pair: %w", err)
	}

	if response.Body.GenerateKeyPair_OUTPUT.ReturnValue != 0 {
		return "", fmt.Errorf("generate key pair failed with return value: %d",
			response.Body.GenerateKeyPair_OUTPUT.ReturnValue)
	}

	if len(response.Body.GenerateKeyPair_OUTPUT.KeyPair.ReferenceParameters.SelectorSet.Selectors) == 0 {
		return "", fmt.Errorf("generate key pair did not return a valid handle")
	}

	handle := response.Body.GenerateKeyPair_OUTPUT.KeyPair.ReferenceParameters.SelectorSet.Selectors[0].Text

	return handle, nil
}

// getDERKey retrieves the DER key for a given key pair handle
func (cmd *TLSCmd) getDERKey(keyPairHandle string) (string, error) {
	keyPairs, err := cmd.WSMan.GetPublicPrivateKeyPairs()
	if err != nil {
		return "", fmt.Errorf("failed to get key pairs: %w", err)
	}

	for _, keyPair := range keyPairs {
		if keyPair.InstanceID == keyPairHandle {
			return keyPair.DERKey, nil
		}
	}

	return "", fmt.Errorf("key pair not found for handle: %s", keyPairHandle)
}

// getClientCertHandle adds a client certificate and returns its handle
func (cmd *TLSCmd) getClientCertHandle(certificate string) (string, error) {
	// Add the client certificate
	handle, err := cmd.WSMan.AddClientCert(certificate)
	if err != nil {
		return "", fmt.Errorf("failed to add client certificate: %w", err)
	}

	return handle, nil
}

// synchronizeTime synchronizes the AMT time
func (cmd *TLSCmd) synchronizeTime(ctx *commands.Context) error {
	log.Info("synchronizing time")

	syncclock := SyncClockCmd{
		ConfigureBaseCmd: cmd.ConfigureBaseCmd,
	}
	syncclock.WSMan = cmd.WSMan

	return syncclock.Run(ctx)
}

// updateTLSCredentialContext updates or creates TLS credential context
func (cmd *TLSCmd) updateTLSCredentialContext(certHandle string) error {
	log.Info("updating TLS credential context")

	// Get current TLS settings to check if TLS is enabled
	enumerateRsp, err := cmd.WSMan.EnumerateTLSSettingData()
	if err != nil {
		return fmt.Errorf("failed to enumerate TLS settings: %w", err)
	}

	pullRsp, err := cmd.WSMan.PullTLSSettingData(enumerateRsp.Body.EnumerateResponse.EnumerationContext)
	if err != nil {
		return fmt.Errorf("failed to pull TLS settings: %w", err)
	}

	var isRemoteTLSEnabled, isLocalTLSEnabled bool

	for _, item := range pullRsp.Body.PullResponse.SettingDataItems {
		if item.InstanceID == RemoteTLSInstanceId && item.Enabled {
			isRemoteTLSEnabled = true
		}

		if item.InstanceID == LocalTLSInstanceId && item.Enabled {
			isLocalTLSEnabled = true
		}
	}

	if isRemoteTLSEnabled || isLocalTLSEnabled {
		// TLS is already enabled, update credential context
		_, err = cmd.WSMan.PutTLSCredentialContext(certHandle)
		if err != nil {
			return fmt.Errorf("failed to update TLS credential context: %w", err)
		}

		_, err = cmd.WSMan.CommitChanges()
		if err != nil {
			return fmt.Errorf("failed to commit TLS credential context changes: %w", err)
		}
	} else {
		// TLS not yet enabled, create credential context
		err = cmd.createTLSCredentialContext(certHandle)
		if err != nil {
			return err
		}
	}

	return nil
}

// createTLSCredentialContext creates a new TLS credential context
func (cmd *TLSCmd) createTLSCredentialContext(certHandle string) error {
	log.Info("creating TLS credential context")

	_, err := cmd.WSMan.CreateTLSCredentialContext(certHandle)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "alreadyexists") {
			log.Info("TLS credential context already exists: ", certHandle)

			return nil
		}

		return fmt.Errorf("failed to create TLS credential context: %w", err)
	}

	return nil
}

// pruneCerts removes unused certificates
func (cmd *TLSCmd) pruneCerts() error {
	log.Info("pruning unused certificates")

	return certs.PruneCerts(cmd.WSMan)
}
