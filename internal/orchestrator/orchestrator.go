/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package orchestrator

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/config"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/wifi"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// ErrCIRAConfiguration is returned when CIRA configuration fails.
var ErrCIRAConfiguration = errors.New("CIRA configuration failed")

const (
	ACMMODE            = "acmactivate"
	commandConfigure   = "configure"
	commandAMTPassword = "amtpassword"
	flagPassword       = "--password"
	flagNewAMTPassword = "--newamtpassword"

	// msgPasswordAlignSkipped is logged when AMT password alignment is skipped
	// because the device is not yet activated; activation continues afterward.
	msgPasswordAlignSkipped = "AMT password alignment skipped: device is not activated yet; will continue with activation"

	// postActivationSettleAttempts bounds how many extra times a configuration
	// step is retried when it fails while the AMT firmware is still settling
	// after activation. Right after activation the firmware restarts its local
	// management (LMS) port stack and can briefly lock the admin account, so a
	// step fired into that window fails with a dropped connection (EOF/reset) or
	// a transient "account temporarily locked" 401 even though the password is
	// correct. A fresh subprocess retried after a delay re-authenticates against
	// the now-settled firmware and succeeds.
	postActivationSettleAttempts = 4
	// postActivationSettleDelaySeconds is the wait between post-activation settle
	// retries, giving the firmware time to finish the port-stack restart and
	// clear the transient account lock.
	postActivationSettleDelaySeconds = 3
)

// ProfileOrchestrator orchestrates the execution of commands from a profile configuration
type ProfileOrchestrator struct {
	profile  config.Configuration
	executor CommandExecutor
	// cached control mode at start of orchestration
	currentControlMode int
	// optional current AMT password provided by caller (e.g., activate --password)
	currentPassword string
	// optional MEBx password provided by caller (e.g., activate --mebxpassword)
	mebxPassword string
	// global password argument to pass once to root rpc invocation
	globalPassword string
	// skip AMT certificate verification when connecting over TLS
	skipAMTCertCheck bool
	// activatedThisRun is set once this orchestration performs activation. It
	// gates the post-activation settle retries so they only apply while the
	// firmware is restarting its port stack; on an already-activated device a
	// configuration failure is genuine and must fail fast.
	activatedThisRun bool
	// settleDelaySeconds is the wait between post-activation settle retries.
	// Defaults to postActivationSettleDelaySeconds; overridable in tests to
	// avoid real sleeps.
	settleDelaySeconds int
}

// NewProfileOrchestrator creates a new profile orchestrator. The currentPassword argument
// is treated as the existing AMT admin password and will be used to rotate to the profile's
// AdminPassword without prompting when provided. The mebxPassword argument is an optional
// MEBx password to pass through to activation for AMT19+ TLS devices. The skipAMTCertCheck
// argument controls whether AMT TLS certificate verification should be skipped for sub-commands.
func NewProfileOrchestrator(cfg config.Configuration, currentPassword, mebxPassword string, skipAMTCertCheck bool) *ProfileOrchestrator {
	return &ProfileOrchestrator{
		profile:            cfg,
		executor:           &CLIExecutor{},
		currentPassword:    strings.TrimSpace(currentPassword),
		mebxPassword:       strings.TrimSpace(mebxPassword),
		globalPassword:     strings.TrimSpace(cfg.Configuration.AMTSpecific.AdminPassword),
		skipAMTCertCheck:   skipAMTCertCheck,
		settleDelaySeconds: postActivationSettleDelaySeconds,
	}
}

// baseArgs returns the common CLI arguments including global flags like password and skip-amt-cert-check.
func (po *ProfileOrchestrator) baseArgs() []string {
	args := []string{rpcExecutableName}
	if po.skipAMTCertCheck {
		args = append(args, "--skip-amt-cert-check")
	}

	if po.globalPassword != "" {
		args = append(args, flagPassword, po.globalPassword)
	}

	// Only propagate verbose logging to subprocesses when the parent is already
	// at debug/trace; forcing -v unconditionally would clobber the operator's
	// chosen log level and can leak extra detail into the output.
	if log.IsLevelEnabled(log.DebugLevel) {
		args = append(args, "-v")
	}

	return args
}

// ExecuteProfile orchestrates the execution of all commands based on the profile
func (po *ProfileOrchestrator) ExecuteProfile() error {
	log.Info("Starting profile orchestration...")

	amtCommand := amt.NewAMTCommand()
	if err := amtCommand.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize AMT command: %w", err)
	}

	currentControlMode, err := amtCommand.GetControlMode()
	if err != nil {
		amtCommand.Close()

		return fmt.Errorf("failed to get current control mode: %w", err)
	}

	// Release the MEI handle; holding it in the parent blocks child subprocesses on Windows.
	amtCommand.Close()

	po.currentControlMode = currentControlMode

	// If the device is already activated and the profile supplies an AdminPassword,
	// proactively verify that the provided password works. If not, prompt for the
	// current AMT password and rotate it to the profile value before proceeding.
	if po.currentControlMode != 0 {
		if strings.TrimSpace(po.profile.Configuration.AMTSpecific.AdminPassword) != "" {
			if err := po.verifyAndAlignAMTPassword(); err != nil {
				return fmt.Errorf("password verification/rotation failed: %w", err)
			}
		} else {
			log.Debug("Device is activated but no AdminPassword provided in profile; skipping password alignment")
		}
	}

	// Step 1: Activation or upgrade if needed
	if po.profile.Configuration.AMTSpecific.ControlMode == ACMMODE && currentControlMode == 1 {
		// Upgrade CCM -> ACM using local activation path with provisioning cert
		if err := po.executeActivation(); err != nil {
			return fmt.Errorf("activation failed: %w", err)
		}

		po.activatedThisRun = true
	} else if currentControlMode == 0 {
		if err := po.executeActivation(); err != nil {
			return fmt.Errorf("activation failed: %w", err)
		}

		po.activatedThisRun = true
	} else {
		log.Info("AMT already activated, skipping activation step")
	}

	// Give the firmware time to settle before the first configuration step. When
	// we just activated, the firmware is restarting its local management (LMS)
	// port stack and briefly locks the admin account, so a longer initial wait
	// lets the first step authenticate on a settled stack rather than burning a
	// settle retry (and adding to the lockout counter) on a doomed attempt.
	if po.activatedThisRun {
		utils.Pause(postActivationSettleDelaySeconds)
	} else {
		utils.Pause(1)
	}

	// Step 2: MEBx password configuration (ACM only)
	if err := po.executeMEBxConfiguration(); err != nil {
		return fmt.Errorf("MEBx configuration failed: %w", err)
	}

	// Step 3: AMT Features configuration
	if err := po.executeAMTFeaturesConfiguration(); err != nil {
		return fmt.Errorf("AMT features configuration failed: %w", err)
	}

	// Step 4: Wired network configuration
	if err := po.executeWiredNetworkConfiguration(); err != nil {
		return fmt.Errorf("wired network configuration failed: %w", err)
	}

	// Step 5: Enable WiFi port if needed
	if err := po.executeEnableWiFi(); err != nil {
		return fmt.Errorf("WiFi sync enable failed: %w", err)
	}

	// Step 6: Wireless profile configurations
	if err := po.executeWirelessConfigurations(); err != nil {
		return fmt.Errorf("wireless configuration failed: %w", err)
	}

	// Step 7: TLS configuration
	if err := po.executeTLSConfiguration(); err != nil {
		return fmt.Errorf("TLS configuration failed: %w", err)
	}

	// Step 8: CIRA configuration
	if err := po.executeCIRAConfiguration(); err != nil {
		return fmt.Errorf("%w: %w", ErrCIRAConfiguration, err)
	}

	// Step 9: HTTP Proxy configuration
	if err := po.executeHTTPProxyConfiguration(); err != nil {
		return fmt.Errorf("HTTP proxy configuration failed: %w", err)
	}

	log.Info("Profile orchestration completed successfully!")

	return nil
}

// executeWithPasswordFallback runs a configuration step, absorbing the transient
// failures that occur while the AMT firmware is still settling after activation.
//
// Right after activation the firmware restarts its local management (LMS) port
// stack and can briefly lock the admin account. A step fired into that window
// fails with a dropped connection (EOF/reset) or a transient "account
// temporarily locked" 401 even though the password is correct — the same
// port-stack-restart race already handled on the activation commit and the LMS
// dial. Because each step is a fresh subprocess that re-authenticates (new
// digest challenge) and re-reads control mode, simply retrying after a short
// delay lets it succeed once the firmware settles. Retries apply only when this
// run performed activation; on an already-activated device a failure is genuine
// and returned immediately. The underlying state-set operations are idempotent,
// so re-applying a step that partially succeeded is safe.
func (po *ProfileOrchestrator) executeWithPasswordFallback(args []string) error {
	err := po.executeWithPasswordRotation(args)
	if err == nil || !po.activatedThisRun {
		return err
	}

	// The initial execution above is attempt 1; the loop covers retries 2..N so
	// the logged "attempt X/N" matches the real execution count.
	for attempt := 2; attempt <= postActivationSettleAttempts; attempt++ {
		// A device-not-activated failure is not a settling symptom; retrying
		// won't help, so surface it right away.
		if isDeviceNotActivatedErr(err) {
			return err
		}

		log.Warnf("Configuration step failed while AMT may still be settling after activation (attempt %d/%d): %v. Retrying in %ds...",
			attempt, postActivationSettleAttempts, err, po.settleDelaySeconds)
		utils.Pause(po.settleDelaySeconds)

		err = po.executeWithPasswordRotation(args)
		if err == nil {
			return nil
		}
	}

	return err
}

// executeWithPasswordRotation executes a CLI command and, on authentication failure,
// prompts for the old AMT password to rotate it to the profile's new password, then retries.
func (po *ProfileOrchestrator) executeWithPasswordRotation(args []string) error {
	err := po.executor.Execute(args)
	if err == nil {
		return nil
	}

	// Do not prompt/rotate when device is in pre-provisioning (control mode 0)
	if po.currentControlMode == 0 {
		return err
	}

	// Only attempt fallback if a new AdminPassword is provided in the profile.
	newPass := strings.TrimSpace(po.profile.Configuration.AMTSpecific.AdminPassword)
	if newPass == "" {
		return err
	}

	// Gate rotation on the exit code; verbose Digest logs make substring-matching unreliable.
	var execErr *ExecError
	if !errors.As(err, &execErr) || execErr.ExitCode != utils.AMTAuthenticationFailed.Code {
		return err
	}

	log.Warn("Authentication failed with provided AMT password; attempting password rotation to profile value...")

	// If caller supplied a currentPassword, try non-interactive rotation once
	if po.currentPassword != "" {
		change := []string{rpcExecutableName, commandConfigure, commandAMTPassword, flagPassword, po.currentPassword, flagNewAMTPassword, newPass}
		if po.skipAMTCertCheck {
			change = append(change, "--skip-amt-cert-check")
		}

		if cerr := po.executor.Execute(change); cerr == nil {
			log.Info("AMT password updated to profile value using provided current password; retrying previous operation")

			return po.executeWithPasswordFallback(args)
		}
		// otherwise fall through to prompt loop
	}

	const maxTries = 3
	for attempt := 1; attempt <= maxTries; attempt++ {
		if attempt == 1 {
			fmt.Print("Current AMT Password (to rotate to new profile password): ")
		} else {
			fmt.Print("Current AMT Password (try again): ")
		}

		oldPass, perr := utils.PR.ReadPassword()

		fmt.Println()

		if perr != nil {
			return fmt.Errorf("failed to read current AMT password: %w", perr)
		}

		if strings.TrimSpace(oldPass) == "" {
			if attempt < maxTries {
				log.Warn("Password cannot be empty")

				continue
			}

			return fmt.Errorf("current AMT password cannot be empty")
		}

		// Execute password change: configure amtpassword --password <old> --newamtpassword <new>
		change := []string{rpcExecutableName, commandConfigure, commandAMTPassword, flagPassword, oldPass, flagNewAMTPassword, newPass}
		if po.skipAMTCertCheck {
			change = append(change, "--skip-amt-cert-check")
		}

		if cerr := po.executor.Execute(change); cerr != nil {
			var cexecErr *ExecError
			if attempt < maxTries && errors.As(cerr, &cexecErr) && cexecErr.ExitCode == utils.AMTAuthenticationFailed.Code {
				log.Warn("Incorrect AMT password. Please try again.")

				continue
			}

			return fmt.Errorf("failed to update AMT password using provided current password: %w", cerr)
		}

		log.Info("AMT password updated to profile value; retrying previous operation")

		return po.executeWithPasswordFallback(args)
	}

	return fmt.Errorf("failed to update AMT password after %d attempts", maxTries)
}

// executeActivation performs the activation step
func (po *ProfileOrchestrator) executeActivation() error {
	if po.profile.Configuration.AMTSpecific.ControlMode == "" {
		log.Info("No activation mode specified, skipping activation")

		return nil
	}

	log.Infof("Executing activation with control mode: %s", po.profile.Configuration.AMTSpecific.ControlMode)

	base := po.baseArgs()
	base = append(base, "activate")

	switch po.profile.Configuration.AMTSpecific.ControlMode {
	case ACMMODE:
		base = append(base, "--acm")
		if po.profile.Configuration.AMTSpecific.ProvisioningCert != "" {
			base = append(base, "--provisioningCert", po.profile.Configuration.AMTSpecific.ProvisioningCert)
		}

		if po.profile.Configuration.AMTSpecific.ProvisioningCertPwd != "" {
			base = append(base, "--provisioningCertPwd", po.profile.Configuration.AMTSpecific.ProvisioningCertPwd)
		}

		// Pass MEBx password for AMT19+ TLS activation; prefer profile value over CLI value
		mebxPwd := po.profile.Configuration.AMTSpecific.MEBXPassword
		if mebxPwd == "" {
			mebxPwd = po.mebxPassword
		}

		if mebxPwd != "" {
			base = append(base, "--mebxpassword", mebxPwd)
		}
	case "ccmactivate":
		base = append(base, "--ccm")
	default:
		return fmt.Errorf("unsupported control mode: %s", po.profile.Configuration.AMTSpecific.ControlMode)
	}

	base = append(base, "--local")

	return po.executor.Execute(base)
}

// executeACMUpgrade performs an in-place upgrade from CCM to ACM when already activated
func (po *ProfileOrchestrator) executeACMUpgrade() error {
	if po.profile.Configuration.AMTSpecific.ProvisioningCert == "" || po.profile.Configuration.AMTSpecific.ProvisioningCertPwd == "" {
		return fmt.Errorf("ACM upgrade requires provisioning certificate and password")
	}

	args := po.baseArgs()
	args = append(args, "activate", "--acm", "--local")
	// no special flag needed; local activation will auto-upgrade CCM->ACM when ACM mode is requested

	args = append(args, "--provisioningCert", po.profile.Configuration.AMTSpecific.ProvisioningCert)
	args = append(args, "--provisioningCertPwd", po.profile.Configuration.AMTSpecific.ProvisioningCertPwd)

	return po.executeWithPasswordFallback(args)
}

// executeMEBxConfiguration performs MEBx password configuration
func (po *ProfileOrchestrator) executeMEBxConfiguration() error {
	if po.profile.Configuration.AMTSpecific.MEBXPassword == "" ||
		po.profile.Configuration.AMTSpecific.ControlMode != ACMMODE {
		log.Info("MEBx password not configured or not in ACM mode, skipping MEBx configuration")

		return nil
	}

	// If the device was in pre-provisioning at orchestration start, MEBx was already
	// handled during activation (via --mebxpassword or retry logic), so skip the
	// separate post-activation MEBx step.
	if po.currentControlMode == 0 {
		log.Info("MEBx password was set during activation, skipping separate MEBx configuration")

		return nil
	}

	log.Info("Executing MEBx password configuration")

	args := po.baseArgs()
	args = append(args, commandConfigure, "mebx", "--mebxpassword", po.profile.Configuration.AMTSpecific.MEBXPassword)

	return po.executeWithPasswordFallback(args)
}

// executeAMTFeaturesConfiguration performs AMT features configuration
func (po *ProfileOrchestrator) executeAMTFeaturesConfiguration() error {
	redirection := po.profile.Configuration.Redirection

	// Intentionally always configure AMT features when profile provides Redirection section.
	// This ensures features can be explicitly disabled when set to false.
	// If Services fields are all false and section present, we still run to disable them.

	log.Info("Executing AMT features configuration")

	args := po.baseArgs()
	args = append(args, commandConfigure, "amtfeatures")

	if redirection.Services.KVM {
		args = append(args, "--kvm")
	}

	if redirection.Services.SOL {
		args = append(args, "--sol")
	}

	if redirection.Services.IDER {
		args = append(args, "--ider")
	}

	// If all features are explicitly false, request explicit disable behavior
	if !redirection.Services.KVM && !redirection.Services.SOL && !redirection.Services.IDER {
		args = append(args, "--disableAll")
	}

	// Set user consent if in ACM mode
	if po.profile.Configuration.AMTSpecific.ControlMode == ACMMODE {
		switch redirection.UserConsent {
		case "None":
			args = append(args, "--userConsent", "none")
		case "KVM":
			args = append(args, "--userConsent", "kvm")
		default:
			args = append(args, "--userConsent", "all")
		}
	}

	return po.executeWithPasswordFallback(args)
}

// executeWiredNetworkConfiguration performs wired network configuration
func (po *ProfileOrchestrator) executeWiredNetworkConfiguration() error {
	wired := po.profile.Configuration.Network.Wired

	// Check if wired configuration is needed
	if wired.IPAddress == "" && !wired.DHCPEnabled &&
		wired.PrimaryDNS == "" && wired.SecondaryDNS == "" {
		log.Info("No wired network configuration specified, skipping")

		return nil
	}

	log.Info("Executing wired network configuration")

	args := po.baseArgs()
	args = append(args, commandConfigure, "wired")

	if wired.DHCPEnabled {
		args = append(args, "--dhcp")
	} else {
		// Static IP configuration
		if wired.IPAddress != "" {
			args = append(args, "--ipaddress", wired.IPAddress)
		}

		if wired.SubnetMask != "" {
			args = append(args, "--subnetmask", wired.SubnetMask)
		}

		if wired.DefaultGateway != "" {
			args = append(args, "--gateway", wired.DefaultGateway)
		}

		if wired.PrimaryDNS != "" {
			args = append(args, "--primarydns", wired.PrimaryDNS)
		}

		if wired.SecondaryDNS != "" {
			args = append(args, "--secondarydns", wired.SecondaryDNS)
		}
	}

	return po.executeWithPasswordFallback(args)
}

// executeEnableWiFi enables WiFi port if needed
func (po *ProfileOrchestrator) executeEnableWiFi() error {
	log.Info("Executing WiFi sync configuration")

	args := po.baseArgs()
	args = append(args, commandConfigure, "wifisync")

	// Pass through explicit values from the strongly-typed profile
	args = append(args, "--oswifisync="+strconv.FormatBool(po.profile.Configuration.Network.Wireless.WiFiSyncEnabled))
	args = append(args, "--uefiwifisync="+strconv.FormatBool(po.profile.Configuration.Network.Wireless.UEFIWiFiSyncEnabled))

	return po.executeWithPasswordFallback(args)
}

// executeWirelessConfigurations performs wireless profile configurations
func (po *ProfileOrchestrator) executeWirelessConfigurations() error {
	// Always purge existing Wi-Fi profiles before applying new ones
	log.Info("Purging existing AMT wireless profiles before applying new configuration")

	purgeArgs := po.baseArgs()
	purgeArgs = append(purgeArgs, commandConfigure, "wireless", "--purge")

	if err := po.executeWithPasswordFallback(purgeArgs); err != nil {
		return fmt.Errorf("wireless purge failed: %w", err)
	}

	if len(po.profile.Configuration.Network.Wireless.Profiles) == 0 {
		log.Info("No wireless profiles specified in profile; nothing more to apply after purge")

		return nil
	}

	for i, profile := range po.profile.Configuration.Network.Wireless.Profiles {
		log.Infof("Executing wireless profile configuration %d/%d: %s", i+1, len(po.profile.Configuration.Network.Wireless.Profiles), profile.ProfileName)

		if err := po.executeWirelessProfile(profile); err != nil {
			return fmt.Errorf("failed to configure wireless profile %s: %w", profile.ProfileName, err)
		}
	}

	return nil
}

// executeWirelessProfile configures a single wireless profile
func (po *ProfileOrchestrator) executeWirelessProfile(profile config.WirelessProfile) error {
	args := po.baseArgs()
	args = append(args, commandConfigure, "wireless")

	args = append(args, "--profileName", profile.ProfileName)
	args = append(args, "--ssid", profile.SSID)
	args = append(args, "--priority", strconv.Itoa(profile.Priority))

	method, success := wifi.ParseAuthenticationMethod(profile.AuthenticationMethod)
	if !success {
		return fmt.Errorf("invalid authentication method: %s", profile.AuthenticationMethod)
	}

	args = append(args, "--authenticationMethod", strconv.Itoa((int)(method)))

	encryptionMethod, success := wifi.ParseEncryptionMethod(profile.EncryptionMethod)
	if !success {
		return fmt.Errorf("invalid encryption method: %s", profile.EncryptionMethod)
	}

	args = append(args, "--encryptionMethod", strconv.Itoa((int)(encryptionMethod)))

	// Add PSK passphrase if provided
	if profile.Password != "" {
		args = append(args, "--pskPassphrase", profile.Password)
	}

	// Add 802.1x settings if configured
	if profile.IEEE8021x != nil {
		ieee := profile.IEEE8021x
		args = append(args, "--ieee8021xProfileName", fmt.Sprintf("%s_8021x", profile.ProfileName))

		if ieee.Username != "" {
			args = append(args, "--ieee8021xUsername", ieee.Username)
		}

		if ieee.Password != "" {
			args = append(args, "--ieee8021xPassword", ieee.Password)
		}

		if ieee.AuthenticationProtocol != 0 {
			args = append(args, "--ieee8021xAuthenticationProtocol", strconv.Itoa(ieee.AuthenticationProtocol))
		}

		if ieee.PrivateKey != "" {
			args = append(args, "--ieee8021xPrivateKey", ieee.PrivateKey)
		}

		if ieee.ClientCert != "" {
			args = append(args, "--ieee8021xClientCert", ieee.ClientCert)
		}

		if ieee.CACert != "" {
			args = append(args, "--ieee8021xCACert", ieee.CACert)
		}
	}

	return po.executeWithPasswordFallback(args)
}

// executeTLSConfiguration performs TLS configuration
func (po *ProfileOrchestrator) executeTLSConfiguration() error {
	if !po.profile.Configuration.TLS.Enabled {
		log.Info("TLS not enabled, skipping TLS configuration")

		return nil
	}

	log.Info("Executing TLS configuration")

	args := po.baseArgs()
	args = append(args, commandConfigure, "tls")

	// Determine TLS mode
	var mode string

	if po.profile.Configuration.TLS.MutualAuthentication {
		if po.profile.Configuration.TLS.AllowNonTLS {
			mode = "MutualAndNonTLS"
		} else {
			mode = "Mutual"
		}
	} else {
		if po.profile.Configuration.TLS.AllowNonTLS {
			mode = "ServerAndNonTLS"
		} else {
			mode = "Server"
		}
	}

	args = append(args, "--mode", mode)

	if po.profile.Configuration.TLS.SigningAuthority == "SelfSigned" {
	} else {
		// Add Enterprise Assistant settings if configured
		if po.profile.Configuration.EnterpriseAssistant.URL != "" {
			args = append(args, "--eaAddress", po.profile.Configuration.EnterpriseAssistant.URL)
			if po.profile.Configuration.EnterpriseAssistant.Username != "" {
				args = append(args, "--eaUsername", po.profile.Configuration.EnterpriseAssistant.Username)
			}

			if po.profile.Configuration.EnterpriseAssistant.Password != "" {
				args = append(args, "--eaPassword", po.profile.Configuration.EnterpriseAssistant.Password)
			}
		}
	}

	return po.executeWithPasswordFallback(args)
}

// executeCIRAConfiguration performs CIRA (Cloud-Initiated Remote Access) configuration
func (po *ProfileOrchestrator) executeCIRAConfiguration() error {
	cira := po.profile.Configuration.AMTSpecific.CIRA

	// Check if CIRA is configured (need at least address and cert)
	if cira.MPSAddress == "" || cira.MPSCert == "" {
		log.Info("No CIRA configuration specified, skipping")

		return nil
	}

	log.Info("Executing CIRA configuration")

	args := po.baseArgs()

	args = append(args, commandConfigure, "cira")

	// MPS Address is required
	args = append(args, "--mps-address", cira.MPSAddress)

	// MPS Certificate is required
	args = append(args, "--mps-cert", cira.MPSCert)

	// MPS Password - if not provided, the CLI will prompt
	if cira.MPSPassword != "" {
		args = append(args, "--mpspassword", cira.MPSPassword)
	}

	if cira.GenerateRandomPassword {
		args = append(args, "--generateRandomPassword")
	}

	// Environment Detection - optional
	if len(cira.EnvironmentDetection) > 0 {
		// Join multiple environment detection strings with comma
		envDetection := strings.Join(cira.EnvironmentDetection, ",")
		args = append(args, "--envdetection", envDetection)
	}

	return po.executeWithPasswordFallback(args)
}

// executeHTTPProxyConfiguration performs HTTP proxy configuration
func (po *ProfileOrchestrator) executeHTTPProxyConfiguration() error {
	proxies := po.profile.Configuration.Network.Proxies

	if len(proxies) == 0 {
		log.Info("No HTTP proxy configurations specified, skipping")

		return nil
	}

	for i, proxy := range proxies {
		log.Infof("Executing HTTP proxy configuration %d/%d: %s", i+1, len(proxies), proxy.Address)

		if err := po.executeHTTPProxy(proxy); err != nil {
			return fmt.Errorf("failed to configure HTTP proxy %s: %w", proxy.Address, err)
		}
	}

	return nil
}

// executeHTTPProxy configures a single HTTP proxy
func (po *ProfileOrchestrator) executeHTTPProxy(proxy config.Proxy) error {
	args := po.baseArgs()
	args = append(args, commandConfigure, "proxy")

	args = append(args, "--address", proxy.Address)

	if proxy.Port > 0 {
		args = append(args, "--port", strconv.Itoa(proxy.Port))
	}

	if proxy.NetworkDnsSuffix != "" {
		args = append(args, "--networkdnssuffix", proxy.NetworkDnsSuffix)
	}

	return po.executeWithPasswordFallback(args)
}

// verifyAndAlignAMTPassword ensures the AMT admin password matches the profile value.
// It performs a harmless authenticated call (amtinfo). On auth failure it will prompt
// for the current AMT password and rotate it to the profile-provided AdminPassword.
func (po *ProfileOrchestrator) verifyAndAlignAMTPassword() error {
	newPass := strings.TrimSpace(po.profile.Configuration.AMTSpecific.AdminPassword)
	if newPass == "" {
		return nil
	}

	log.Info("Verifying AMT admin password matches profile; will prompt to rotate if needed")

	// If a current password was supplied by the caller, try a direct non-interactive rotation first
	if po.currentPassword != "" {
		change := []string{rpcExecutableName, commandConfigure, commandAMTPassword, flagPassword, po.currentPassword, flagNewAMTPassword, newPass}
		if po.skipAMTCertCheck {
			change = append(change, "--skip-amt-cert-check")
		}

		if err := po.executor.Execute(change); err == nil {
			log.Info("AMT password aligned to profile value using provided current password")

			return nil
		} else if isDeviceNotActivatedErr(err) {
			log.Warn(msgPasswordAlignSkipped)

			return nil
		}
		// If it failed (e.g., wrong provided current), proceed to auth-probe and interactive fallback
	}

	// Use an idempotent password-change-to-same-value operation as an auth probe.
	// If the provided password is already set, this succeeds and changes nothing.
	// If authentication fails (wrong password), our fallback will prompt for the
	// current password, rotate to the profile value, and retry.
	args := po.baseArgs()
	args = append(args, commandConfigure, commandAMTPassword, flagNewAMTPassword, newPass)

	err := po.executeWithPasswordFallback(args)
	if isDeviceNotActivatedErr(err) {
		log.Warn(msgPasswordAlignSkipped)

		return nil
	}

	return err
}

// isDeviceNotActivatedErr reports whether err signals that a configure subprocess
// refused because the device is not yet activated. The orchestrator drives every
// step through CLIExecutor, which reports failures as *ExecError, so we match on
// the typed exit code rather than substring-matching subprocess output (verbose
// Digest logs make substring matching unreliable — see CLAUDE.md).
func isDeviceNotActivatedErr(err error) bool {
	if err == nil {
		return false
	}

	var execErr *ExecError
	if errors.As(err, &execErr) {
		return execErr.ExitCode == utils.DeviceNotActivated.Code
	}

	return false
}
