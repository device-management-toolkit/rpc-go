/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package activate

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/client"
	"github.com/device-management-toolkit/rpc-go/v2/internal/certs"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/internal/interfaces"
	localamt "github.com/device-management-toolkit/rpc-go/v2/internal/local/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// LocalActivateCmd handles local AMT activation
type LocalActivateCmd struct {
	commands.AMTBaseCmd

	// Legacy compatibility flag (hidden from main help but still functional)
	LocalFlag bool `help:"[DEPRECATED] Command now defaults to local activation" hidden:"" name:"local"`

	// Mode selection (mutually exclusive, but not required for stopConfig)
	CCM bool `help:"Activate in Client Control Mode"`
	ACM bool `help:"Activate in Admin Control Mode"`

	// Common flags with environment variable support
	DNS      string `help:"DNS suffix override" env:"DNS_SUFFIX" short:"d"`
	Hostname string `help:"Hostname override" env:"HOSTNAME" short:"h"`

	// ACM/CCM specific settings
	ProvisioningCert    string `help:"Provisioning certificate (base64 encoded)" env:"PROVISIONING_CERT" name:"provisioningCert"`
	ProvisioningCertPwd string `help:"Provisioning certificate password" env:"PROVISIONING_CERT_PASSWORD" name:"provisioningCertPwd"`

	// Additional options
	FriendlyName string `help:"Friendly name to associate with this device" name:"name"`
	SkipIPRenew  bool   `help:"Skip DHCP renewal of IP address if AMT becomes enabled" name:"skipIPRenew"`
	StopConfig   bool   `help:"Transition AMT from in-provisioning to pre-provisioning state" name:"stopConfig"`
}

// LocalActivationConfig holds the configuration for local activation
type LocalActivationConfig struct {
	Mode                ActivationMode
	DNS                 string
	Hostname            string
	AMTPassword         string
	ProvisioningCert    string
	ProvisioningCertPwd string
	FriendlyName        string
	SkipIPRenew         bool
	ConfigFile          string
	ConfigV2File        string
	ConfigKey           string
	ControlMode         int // Store the control mode from AMTBaseCmd
}

// ActivationMode represents the activation mode
type ActivationMode int

const (
	ModeCCM ActivationMode = iota + 1
	ModeACM
)

func (m ActivationMode) String() string {
	switch m {
	case ModeCCM:
		return "CCM"
	case ModeACM:
		return "ACM"
	default:
		return "Unknown"
	}
}

// LocalActivationService handles the actual local activation logic
type LocalActivationService struct {
	wsman            interfaces.WSMANer
	amtCommand       amt.Interface
	config           LocalActivationConfig
	context          *commands.Context
	localTLSEnforced bool
	isUpgrade        bool
}

// NewLocalActivationService creates a new local activation service
func NewLocalActivationService(amtCommand amt.Interface, config LocalActivationConfig, ctx *commands.Context) *LocalActivationService {
	return &LocalActivationService{
		amtCommand:       amtCommand,
		config:           config,
		context:          ctx,
		localTLSEnforced: false,
	}
}

// BeforeApply implements Kong's hook for backwards compatibility warnings
func (cmd *LocalActivateCmd) BeforeApply() error {
	if cmd.LocalFlag {
		log.Warn("--local flag is deprecated. Command now defaults to local activation.")
	}

	return nil
}

// RequiresAMTPassword indicates whether this command requires AMT password
// For local activate, password is required for stopConfig operations
func (cmd *LocalActivateCmd) RequiresAMTPassword() bool {
	return cmd.StopConfig
}

// Validate implements Kong's validation interface for local activation
func (cmd *LocalActivateCmd) Validate() error {
	// Stop configuration doesn't require mode selection
	if cmd.StopConfig {
		return nil
	}

	// Ensure exactly one mode is selected for normal activation
	if !cmd.CCM && !cmd.ACM {
		return fmt.Errorf("must specify either --ccm or --acm activation mode")
	}

	// Ensure both modes are not selected simultaneously
	if cmd.CCM && cmd.ACM {
		return fmt.Errorf("cannot specify both --ccm and --acm activation modes")
	}

	return nil
}

// Run executes the local activation command
func (cmd *LocalActivateCmd) Run(ctx *commands.Context) error {
	// Handle stop configuration first
	if cmd.StopConfig {
		return cmd.handleStopConfiguration(ctx)
	}

	// Convert Kong CLI flags to activation config
	config := cmd.toActivationConfig(ctx)

	// Create and run the activation service
	service := NewLocalActivationService(ctx.AMTCommand, config, ctx)
	service.localTLSEnforced = cmd.LocalTLSEnforced

	return service.Activate()
}

// handleStopConfiguration handles the stop configuration request
func (cmd *LocalActivateCmd) handleStopConfiguration(ctx *commands.Context) error {
	log.Info("Stopping AMT configuration...")

	// Create AMT command if not provided
	amtCmd := ctx.AMTCommand
	if amtCmd == nil {
		amtCmd = amt.NewAMTCommand()
		if err := amtCmd.Initialize(); err != nil {
			return fmt.Errorf("failed to initialize AMT connection: %w", err)
		}
	}

	// Call unprovision to stop configuration
	mode, err := amtCmd.Unprovision()
	if err != nil {
		return fmt.Errorf("failed to stop configuration: %w", err)
	}

	if ctx.JsonOutput {
		result := map[string]interface{}{
			"status":  "success",
			"message": "AMT configuration stopped",
			"mode":    mode,
		}

		jsonBytes, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}

		fmt.Println(string(jsonBytes))

		return nil
	}

	fmt.Printf("AMT configuration stopped successfully (mode: %d)\n", mode)

	return nil
}

// toActivationConfig converts Kong CLI flags to LocalActivationConfig
func (cmd *LocalActivateCmd) toActivationConfig(ctx *commands.Context) LocalActivationConfig {
	var mode ActivationMode
	if cmd.CCM {
		mode = ModeCCM
	} else if cmd.ACM {
		mode = ModeACM
	}

	return LocalActivationConfig{
		Mode:                mode,
		DNS:                 cmd.DNS,
		Hostname:            cmd.Hostname,
		AMTPassword:         ctx.AMTPassword,
		ProvisioningCert:    cmd.ProvisioningCert,
		ProvisioningCertPwd: cmd.ProvisioningCertPwd,
		FriendlyName:        cmd.FriendlyName,
		SkipIPRenew:         cmd.SkipIPRenew,
		ControlMode:         cmd.GetControlMode(), // Use the stored control mode from AMTBaseCmd
	}
}

// Activate performs the local AMT activation
func (service *LocalActivationService) Activate() error {
	log.Infof("Starting local AMT activation in %s mode", service.config.Mode)

	// Step 1: Validate current AMT state
	if err := service.validateAMTState(); err != nil {
		return err
	}

	// Step 2: Validate and prepare configuration
	if err := service.validateConfiguration(); err != nil {
		return err
	}

	// Step 3: Enable AMT if needed
	if err := service.enableAMT(); err != nil {
		return err
	}

	// Step 4: Perform activation based on mode
	switch service.config.Mode {
	case ModeCCM:
		return service.activateCCM()
	case ModeACM:
		return service.activateACM()
	default:
		return fmt.Errorf("invalid activation mode: %v", service.config.Mode)
	}
}

// validateAMTState checks if AMT is in a valid state for activation
func (service *LocalActivationService) validateAMTState() error {
	// Check if device is already activated using the stored control mode
	if service.config.ControlMode != 0 {
		// Always allow upgrade path CCM (1) -> ACM when ACM mode is requested.
		// Provisioning certificate requirements are validated later in validateConfiguration.
		if service.config.Mode == ModeACM && service.config.ControlMode == 1 {
			log.Info("Upgrading device from Client Control Mode to Admin Control Mode")

			service.isUpgrade = true

			return nil
		}

		return fmt.Errorf("device is already activated (control mode: %d)", service.config.ControlMode)
	}

	log.Debug("AMT is in pre-provisioning state, ready for activation")

	return nil
}

// validateConfiguration validates the activation configuration
func (service *LocalActivationService) validateConfiguration() error {
	// Password should already be provided by this point (prompted in Run method if needed)
	if service.config.AMTPassword == "" {
		return fmt.Errorf("internal error: AMT password was not provided")
	}

	// For ACM mode, validate additional requirements
	if service.config.Mode == ModeACM {
		if service.config.ProvisioningCert == "" {
			return fmt.Errorf("provisioning certificate is required for ACM activation")
		}

		if service.config.ProvisioningCertPwd == "" {
			return fmt.Errorf("provisioning certificate password is required for ACM activation")
		}
	}

	log.Debug("Configuration validation passed")

	return nil
}

// enableAMT enables AMT if it's not already enabled
func (service *LocalActivationService) enableAMT() error {
	// Check if AMT needs to be enabled
	changeEnabled, err := service.amtCommand.GetChangeEnabled()
	if err != nil {
		return fmt.Errorf("failed to get change enabled status: %w", err)
	}

	if !changeEnabled.IsNewInterfaceVersion() {
		log.Debug("this AMT version does not support SetAmtOperationalState")

		return nil
	}

	if !changeEnabled.IsAMTEnabled() {
		log.Info("Enabling AMT...")

		if err := service.amtCommand.EnableAMT(); err != nil {
			return fmt.Errorf("failed to enable AMT: %w", err)
		}

		// Handle IP renewal if needed
		if !service.config.SkipIPRenew {
			log.Info("Requesting DHCP renewal...")
			// TODO: Implement DHCP renewal logic
		}
	}

	log.Debug("AMT is enabled and ready")

	return nil
}

// activateCCM performs CCM activation
func (service *LocalActivationService) activateCCM() error {
	log.Info("Performing CCM activation...")

	// Get local system account for WSMAN connection
	lsa, err := service.amtCommand.GetLocalSystemAccount()
	if err != nil {
		log.Error(err)

		return utils.AMTConnectionFailed
	}

	// Setup TLS configuration
	tlsConfig := &tls.Config{}

	if service.localTLSEnforced {
		controlMode := service.config.ControlMode // Use stored control mode
		tlsConfig = certs.GetTLSConfig(&controlMode, nil, service.context.SkipAMTCertCheck)
	}

	// Create WSMAN client
	service.wsman = localamt.NewGoWSMANMessages(utils.LMSAddress)

	err = service.wsman.SetupWsmanClient(lsa.Username, lsa.Password, service.localTLSEnforced, log.GetLevel() == log.TraceLevel, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to setup WSMAN client: %w", err)
	}

	// Get general settings for digest realm
	generalSettings, err := service.wsman.GetGeneralSettings()
	if err != nil {
		return utils.ActivationFailedGeneralSettings
	}

	// Perform host-based setup for CCM
	_, err = service.wsman.HostBasedSetupService(generalSettings.Body.GetResponse.DigestRealm, service.config.AMTPassword)
	if err != nil {
		return utils.ActivationFailedSetupService
	}

	// If TLS is enforced, commit changes with admin credentials
	if service.localTLSEnforced {
		err := service.commitCCMChanges()
		if err != nil {
			return utils.ActivationFailed
		}
	}

	// Output success result
	if service.context.JsonOutput {
		result := map[string]interface{}{
			"status":        "success",
			"mode":          "CCM",
			"message":       "Device activated in Client Control Mode",
			"friendly_name": service.config.FriendlyName,
		}

		jsonBytes, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}

		fmt.Println(string(jsonBytes))

		return nil
	}

	log.Info("Status: Device activated in Client Control Mode")

	return nil
}

// activateACM performs ACM activation
func (service *LocalActivationService) activateACM() error {
	log.Info("Performing ACM activation...")

	// Get local system account for WSMAN connection
	lsa, err := service.amtCommand.GetLocalSystemAccount()
	if err != nil {
		log.Error(err)

		return utils.AMTConnectionFailed
	}

	// Setup TLS configuration for ACM, if applicable
	tlsConfig, err := service.setupACMTLSConfig()
	if err != nil {
		return err
	}

	// Create WSMAN client
	service.wsman = localamt.NewGoWSMANMessages(utils.LMSAddress)

	err = service.wsman.SetupWsmanClient(lsa.Username, lsa.Password, service.localTLSEnforced, log.GetLevel() == log.TraceLevel, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to setup WSMAN client: %w", err)
	}

	// Perform ACM activation using appropriate method
	// For initial activation, always use legacy path (certificate-based)
	// For upgrades, use simplified TLS path (password-based)
	if service.isUpgrade && service.localTLSEnforced {
		err = service.activateACMWithTLS()
	} else {
		err = service.activateACMLegacy()
	}

	if err != nil {
		return err
	}

	// Output success result
	if service.context.JsonOutput {
		result := map[string]interface{}{
			"status":        "success",
			"mode":          "ACM",
			"message":       "Device activated in Admin Control Mode",
			"friendly_name": service.config.FriendlyName,
		}

		jsonBytes, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}

		fmt.Println(string(jsonBytes))

		return nil
	}

	log.Info("Status: Device activated in Admin Control Mode")

	return nil
}

// commitCCMChanges commits changes for CCM activation with admin credentials
func (service *LocalActivationService) commitCCMChanges() error {
	// Commit changes
	_, err := service.wsman.CommitChanges()
	if err != nil {
		log.Error("Failed to activate device:", err)
		log.Info("Putting the device back to pre-provisioning mode")

		// Try to unprovision on failure
		_, unprovisionErr := service.wsman.Unprovision(1)
		if unprovisionErr != nil {
			log.Error("Status: Unable to deactivate ", unprovisionErr)
		}

		return fmt.Errorf("failed to commit changes: %w", err)
	}

	return nil
}

// Certificate types for ACM activation
type CertsAndKeys struct {
	certs []*x509.Certificate
	keys  []interface{}
}

type CertificateObject struct {
	pem     string
	subject string
	issuer  string
}

type ProvisioningCertObj struct {
	certChain            []string
	privateKey           crypto.PrivateKey
	certificateAlgorithm x509.SignatureAlgorithm
}

// setupACMTLSConfig sets up TLS configuration for ACM activation
func (service *LocalActivationService) setupACMTLSConfig() (*tls.Config, error) {
	controlMode := service.config.ControlMode
	tlsConfig := certs.GetTLSConfig(&controlMode, nil, service.context.SkipAMTCertCheck)

	if service.localTLSEnforced {
		log.Info("TLS is enforced - setting up client certificate for activation")

		// Convert certificate for TLS
		certsAndKeys, err := service.convertPfxToObject(service.config.ProvisioningCert, service.config.ProvisioningCertPwd)
		if err != nil {
			log.Error("Failed to convert provisioning certificate:", err)
			return nil, err
		}
		log.Info("Successfully loaded provisioning certificate, chain length:", len(certsAndKeys.certs))

		// Add client certificate to TLS config for mutual TLS
		tlsCert := tls.Certificate{
			PrivateKey: certsAndKeys.keys[0],
			Leaf:       certsAndKeys.certs[0],
		}

		for _, cert := range certsAndKeys.certs {
			tlsCert.Certificate = append(tlsCert.Certificate, cert.Raw)
		}

		tlsConfig.Certificates = []tls.Certificate{tlsCert}
		tlsConfig.MinVersion = tls.VersionTLS12

		// Set GetClientCertificate callback for proper client certificate selection during TLS handshake
		clientCert := tlsCert
		tlsConfig.GetClientCertificate = func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			log.Debug("Client certificate requested by server")
			return &clientCert, nil
		}
	}

	return tlsConfig, nil
}

// activateACMWithTLS performs ACM activation with TLS (new cleaner path)
func (service *LocalActivationService) activateACMWithTLS() error {
	// For TLS path, we just change the AMT password and commit
	// Setup WSMAN client with admin credentials
	// Use proper TLS config with VerifyConnection callback for AMT 19+ support
	controlMode := service.config.ControlMode
	tlsConfig := certs.GetTLSConfig(&controlMode, nil, service.context.SkipAMTCertCheck)

	// Add client certificate for post-activation mutual TLS
	if service.localTLSEnforced {
		tlsConfig.MinVersion = tls.VersionTLS12

		certsAndKeys, err := service.convertPfxToObject(service.config.ProvisioningCert, service.config.ProvisioningCertPwd)
		if err != nil {
			log.Error("Failed to load provisioning certificate for post-activation:", err)
			return fmt.Errorf("failed to load provisioning certificate: %w", err)
		}

		// Build the certificate chain properly
		tlsCert := tls.Certificate{
			PrivateKey: certsAndKeys.keys[0],
			Leaf:       certsAndKeys.certs[0],
		}

		for _, cert := range certsAndKeys.certs {
			tlsCert.Certificate = append(tlsCert.Certificate, cert.Raw)
		}

		tlsConfig.Certificates = append(tlsConfig.Certificates, tlsCert)

		// Ensure GetClientCertificate callback is set for proper client certificate selection
		clientCert := tlsCert
		tlsConfig.GetClientCertificate = func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			log.Trace("Client certificate requested by server (post-activation)")
			return &clientCert, nil
		}
	}

	err := service.wsman.SetupWsmanClient("admin", service.config.AMTPassword, service.localTLSEnforced, log.GetLevel() == log.TraceLevel, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to setup admin WSMAN client: %w", err)
	}

	// Change AMT password - this triggers activation on pre-provisioning devices
	// Get general settings to obtain digest realm
	generalSettings, err := service.wsman.GetGeneralSettings()
	if err != nil {
		log.Debug("Error during password change: ", err)

		// Check if activation actually succeeded despite the error
		controlMode, checkErr := service.amtCommand.GetControlMode()
		if checkErr != nil {
			return utils.ActivationFailedGetControlMode
		}

		if controlMode != 2 {
			return utils.ActivationFailedControlMode
		}

		// Activation succeeded despite the error
		log.Debug("Activation succeeded, ignoring password change error")

		return nil
	}

	// Hash and update the AMT password
	challenge := client.AuthChallenge{
		Username: utils.AMTUserName,
		Password: service.config.AMTPassword,
		Realm:    generalSettings.Body.GetResponse.DigestRealm,
	}

	hashedMessage := challenge.HashCredentials()

	bytes, errDecode := hex.DecodeString(hashedMessage)
	if errDecode != nil {
		return fmt.Errorf("failed to decode hex string: %w", errDecode)
	}

	encodedMessage := base64.StdEncoding.EncodeToString(bytes)

	_, err = service.wsman.UpdateAMTPassword(encodedMessage)
	if err != nil {
		log.Debug("Error during password change: ", err)

		// Check if activation actually succeeded despite the error
		controlMode, checkErr := service.amtCommand.GetControlMode()
		if checkErr != nil {
			return utils.ActivationFailedGetControlMode
		}

		if controlMode != 2 {
			return utils.ActivationFailedControlMode
		}

		// Activation succeeded despite the error
		log.Debug("Activation succeeded, ignoring password change error")

		return nil
	}

	// Commit changes
	result, err := service.wsman.CommitChanges()
	if err != nil {
		log.Debug("Error during commit: ", err)

		// Check if activation actually succeeded despite the error
		controlMode, checkErr := service.amtCommand.GetControlMode()
		if checkErr != nil {
			return utils.ActivationFailedGetControlMode
		}

		if controlMode != 2 {
			return utils.ActivationFailedControlMode
		}

		// Activation succeeded despite the error
		log.Debug("Activation succeeded, ignoring commit error")

		return nil
	}

	log.Debug(result)

	return nil
}

// activateACMLegacy performs ACM activation using the legacy certificate-based method
func (service *LocalActivationService) activateACMLegacy() error {
	// Note: WSMAN client is already set up in activateACM() with proper TLS config
	// For non-TLS upgrade only, we need to re-setup with admin credentials
	if service.isUpgrade && !service.localTLSEnforced {
		controlMode := service.config.ControlMode
		tlsConfig := certs.GetTLSConfig(&controlMode, nil, service.context.SkipAMTCertCheck)

		err := service.wsman.SetupWsmanClient("admin", service.config.AMTPassword, service.localTLSEnforced, log.GetLevel() == log.TraceLevel, tlsConfig)
		if err != nil {
			return fmt.Errorf("failed to setup admin WSMAN client: %w", err)
		}
	}

	// Get provisioning certificate object for activation
	certObject, fingerPrint, err := service.getProvisioningCertObj()
	if err != nil {
		return err
	}

	// For TLS-enforced initial activation, call PTHI/MEI StartConfigurationHBased
	// This completes the activation for AMT 19+ devices (AMT transitions immediately)
	// Skip compareCertHashes check for TLS-enforced initial activation since WSMAN
	// cannot be called in pre-provisioning mode. PTHI validates certificate internally.
	if service.localTLSEnforced && !service.isUpgrade {
		log.Info("Calling PTHI/MEI StartConfigurationHBased for TLS-enforced activation...")
		certsAndKeys, err := service.convertPfxToObject(service.config.ProvisioningCert, service.config.ProvisioningCertPwd)
		if err != nil {
			log.Error("Failed to convert provisioning cert for PTHI:", err)
			return err
		}

		_, err = service.startSecureHostBasedConfiguration(certsAndKeys)
		if err != nil {
			return fmt.Errorf("failed to start secure host-based configuration: %w", err)
		}

		log.Info("PTHI/MEI activation completed - verifying control mode...")
		// Give AMT a moment to complete the transition
		time.Sleep(500 * time.Millisecond)

		// Verify activation succeeded by checking control mode
		controlMode, err := service.amtCommand.GetControlMode()
		if err != nil {
			return utils.ActivationFailedGetControlMode
		}

		if controlMode == 2 { // 2 = ACM mode
			log.Info("ACM activation successful via PTHI/MEI")
			return nil
		}

		// If not in ACM yet, continue with WSMAN activation flow
		log.Warn("Control mode not yet ACM after PTHI call, continuing with WSMAN flow...")
	}

	// Check provisioning certificate is accepted by AMT (WSMAN path only)
	// For TLS-enforced initial activation, this was skipped earlier
	if !service.localTLSEnforced || service.isUpgrade {
		err = service.compareCertHashes(fingerPrint)
		if err != nil {
			return err
		}
	}

	// Get general settings for digest realm
	generalSettings, err := service.wsman.GetGeneralSettings()
	if err != nil {
		// If this fails after PTHI call, check if activation actually succeeded
		if service.localTLSEnforced && !service.isUpgrade {
			controlMode, controlErr := service.amtCommand.GetControlMode()
			if controlErr == nil && controlMode == 2 {
				log.Info("Activation succeeded - WSMAN connection closed during AMT transition")
				return nil
			}
		}
		return utils.ActivationFailedGeneralSettings
	}

	// Get host-based setup service for configuration nonce
	getHostBasedSetupResponse, err := service.wsman.GetHostBasedSetupService()
	if err != nil {
		return utils.ActivationFailedSetupService
	}

	// Decode the firmware nonce
	decodedNonce := getHostBasedSetupResponse.Body.GetResponse.ConfigurationNonce

	fwNonce, err := base64.StdEncoding.DecodeString(decodedNonce)
	if err != nil {
		return utils.ActivationFailedDecode64
	}

	// Inject certificate chain
	err = service.injectCertificate(certObject.certChain)
	if err != nil {
		return err
	}

	// Generate client nonce
	nonce, err := utils.GenerateNonce()
	if err != nil {
		return err
	}

	// Create signed signature
	signedSignature, err := service.createSignedString(nonce, fwNonce, certObject.privateKey)
	if err != nil {
		return err
	}

	// Perform host-based setup with admin credentials
	_, err = service.wsman.HostBasedSetupServiceAdmin(service.config.AMTPassword, generalSettings.Body.GetResponse.DigestRealm, nonce, signedSignature, service.isUpgrade)
	if err != nil {
		// Check if activation was successful despite error
		// We can check the stored control mode, but it won't reflect the new state
		// So we still need to call GetControlMode() here to verify activation success
		controlMode, controlErr := service.amtCommand.GetControlMode()
		if controlErr != nil {
			return utils.ActivationFailedGetControlMode
		}

		if controlMode != 2 { // 2 = ACM mode
			return utils.ActivationFailedControlMode
		}

		// Activation was successful
		log.Info("Activation succeeded despite HostBasedSetupServiceAdmin error")
		return nil
	}
	log.Info("HostBasedSetupServiceAdmin succeeded")

	return nil
}

// Certificate handling methods for ACM activation

// convertPfxToObject converts a base64 PFX certificate to a CertsAndKeys object
func (service *LocalActivationService) convertPfxToObject(pfxb64, passphrase string) (CertsAndKeys, error) {
	pfx, err := base64.StdEncoding.DecodeString(pfxb64)
	if err != nil {
		return CertsAndKeys{}, utils.ActivationFailedDecode64
	}

	privateKey, certificate, extraCerts, err := pkcs12.DecodeChain(pfx, passphrase)
	if err != nil {
		if strings.Contains(err.Error(), "decryption password incorrect") {
			return CertsAndKeys{}, utils.ActivationFailedWrongCertPass
		}

		return CertsAndKeys{}, utils.ActivationFailedInvalidProvCert
	}

	certs := append([]*x509.Certificate{certificate}, extraCerts...)
	pfxOut := CertsAndKeys{certs: certs, keys: []interface{}{privateKey}}

	pfxOut.certs, err = utils.OrderCertsChain(pfxOut.certs)
	if err != nil {
		return pfxOut, err
	}

	return pfxOut, nil
}

// startSecureHostBasedConfiguration starts secure host-based configuration
func (service *LocalActivationService) startSecureHostBasedConfiguration(certsAndKeys CertsAndKeys) (amt.SecureHBasedResponse, error) {
	// Create leaf certificate hash
	var certHashByteArray [64]byte

	leafHash := sha256.Sum256(certsAndKeys.certs[0].Raw)
	copy(certHashByteArray[:], leafHash[:])

	certAlgo, err := utils.CheckCertificateAlgorithmSupported(certsAndKeys.certs[0].SignatureAlgorithm)
	if err != nil {
		return amt.SecureHBasedResponse{}, utils.ActivationFailedCertHash
	}

	// Call StartConfigurationHBased
	params := amt.SecureHBasedParameters{
		CertHash:      certHashByteArray,
		CertAlgorithm: certAlgo,
	}

	response, err := service.amtCommand.StartConfigurationHBased(params)
	if err != nil {
		return amt.SecureHBasedResponse{}, err
	}

	return response, nil
}

// getProvisioningCertObj gets the provisioning certificate object
func (service *LocalActivationService) getProvisioningCertObj() (ProvisioningCertObj, string, error) {
	certsAndKeys, err := service.convertPfxToObject(service.config.ProvisioningCert, service.config.ProvisioningCertPwd)
	if err != nil {
		return ProvisioningCertObj{}, "", err
	}

	result, fingerprint, err := service.dumpPfx(certsAndKeys)
	if err != nil {
		return ProvisioningCertObj{}, "", err
	}

	return result, fingerprint, nil
}

// dumpPfx processes the PFX certificate object
func (service *LocalActivationService) dumpPfx(pfxobj CertsAndKeys) (ProvisioningCertObj, string, error) {
	if len(pfxobj.certs) == 0 {
		return ProvisioningCertObj{}, "", utils.ActivationFailedNoCertFound
	}

	if len(pfxobj.keys) == 0 {
		return ProvisioningCertObj{}, "", utils.ActivationFailedNoPrivKeys
	}

	var (
		provisioningCertificateObj ProvisioningCertObj
		certificateList            []*CertificateObject
		fingerprint                string
	)

	for _, cert := range pfxobj.certs {
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}

		pemStr := utils.CleanPEM(string(pem.EncodeToMemory(pemBlock)))
		certificateObject := CertificateObject{pem: pemStr, subject: cert.Subject.String(), issuer: cert.Issuer.String()}

		// Get the fingerprint from the Root certificate
		if cert.Subject.String() == cert.Issuer.String() {
			der := cert.Raw
			hash := sha256.Sum256(der)
			fingerprint = hex.EncodeToString(hash[:])
		}

		// Put all the certificateObjects into a single list
		certificateList = append(certificateList, &certificateObject)
	}

	if fingerprint == "" {
		return provisioningCertificateObj, "", utils.ActivationFailedNoRootCertFound
	}

	// Add them to the certChain in order
	for _, cert := range certificateList {
		provisioningCertificateObj.certChain = append(provisioningCertificateObj.certChain, cert.pem)
	}

	// Add the private key
	provisioningCertificateObj.privateKey = pfxobj.keys[0]

	// Add the certificate algorithm
	provisioningCertificateObj.certificateAlgorithm = pfxobj.certs[0].SignatureAlgorithm

	return provisioningCertificateObj, fingerprint, nil
}

// compareCertHashes compares certificate hash with AMT stored hashes
func (service *LocalActivationService) compareCertHashes(fingerPrint string) error {
	result, err := service.amtCommand.GetCertificateHashes()
	if err != nil {
		return utils.ActivationFailedGetCertHash
	}

	for _, v := range result {
		if v.Hash == fingerPrint {
			return nil
		}
	}

	return utils.ActivationFailedProvCertNoMatch
}

// injectCertificate injects certificate chain into AMT
func (service *LocalActivationService) injectCertificate(certChain []string) error {
	firstIndex := 0
	lastIndex := len(certChain) - 1

	for i, cert := range certChain {
		isLeaf := i == firstIndex
		isRoot := i == lastIndex

		_, err := service.wsman.AddNextCertInChain(cert, isLeaf, isRoot)
		if err != nil {
			return utils.ActivationFailedAddCert
		}
	}

	return nil
}

// signString signs a message with the private key
func (service *LocalActivationService) signString(message []byte, privateKey crypto.PrivateKey) (string, error) {
	rsaKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return "", errors.New("not an RSA private key")
	}

	keyBytes := x509.MarshalPKCS1PrivateKey(rsaKey)
	privatekeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: keyBytes,
		},
	)

	block, _ := pem.Decode([]byte(string(privatekeyPEM)))
	if block == nil {
		return "", errors.New("failed to decode PEM block containing private key")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", errors.New("failed to parse private key")
	}

	hashed := sha256.Sum256(message)

	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed[:])
	if err != nil {
		return "", errors.New("failed to sign message")
	}

	signatureBase64 := base64.StdEncoding.EncodeToString(signature)

	return signatureBase64, nil
}

// createSignedString creates a signed string from nonces and private key
func (service *LocalActivationService) createSignedString(nonce, fwNonce []byte, privateKey crypto.PrivateKey) (string, error) {
	arr := append(fwNonce, nonce...)

	signature, err := service.signString(arr, privateKey)
	if err != nil {
		return "", utils.ActivationFailedSignString
	}

	return signature, nil
}
