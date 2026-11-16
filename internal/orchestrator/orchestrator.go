/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package orchestrator

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/config"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/wifi"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/configure"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// ErrCIRAConfiguration is returned when CIRA configuration fails.
var ErrCIRAConfiguration = errors.New("CIRA configuration failed")

// errNoActivator is returned by the activation step when no activator is set.
var errNoActivator = errors.New("no activator set for the activation step")

// LocalActivation is what the activation step passes to the activator: local
// activation into ACM (or CCM when ACM is false) with these credentials.
type LocalActivation struct {
	ACM                      bool
	ProvisioningCert         string
	ProvisioningCertPassword string
	AMTPassword              string
	MEBxPassword             string
	SkipAMTCertCheck         bool
}

// newAMTCommand opens the local AMT (MEI) command interface ExecuteProfile
// reads the control mode from; replaced in tests.
var newAMTCommand = func() amt.Interface { return amt.NewAMTCommand() }

const (
	ACMMODE = "acmactivate"

	// Environment variable names for passing credentials securely to subprocesses.
	// Using env vars avoids credential exposure in /proc/<pid>/cmdline and ps output.
	envAMTPassword         = "AMT_PASSWORD"
	envMEBXPassword        = "MEBX_PASSWORD"
	envProvisioningCertPwd = "PROVISIONING_CERT_PASSWORD"
	envProvisioningCert    = "PROVISIONING_CERT"

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

// stepFunc runs one profile step with the given AMT admin password. The
// retry and rotation wrappers call it with po.globalPassword as read at the
// moment of the call, so a step never sees a stale password after a rotation.
type stepFunc func(amtPassword string) error

// ProfileOrchestrator orchestrates the execution of commands from a profile configuration
type ProfileOrchestrator struct {
	profile  config.Configuration
	executor CommandExecutor
	// activator runs the activation step; set with SetActivator.
	activator func(LocalActivation) error
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
	po := &ProfileOrchestrator{
		profile:            cfg,
		executor:           &CLIExecutor{},
		currentPassword:    strings.TrimSpace(currentPassword),
		mebxPassword:       strings.TrimSpace(mebxPassword),
		globalPassword:     strings.TrimSpace(cfg.Configuration.AMTSpecific.AdminPassword),
		skipAMTCertCheck:   skipAMTCertCheck,
		settleDelaySeconds: postActivationSettleDelaySeconds,
	}

	return po
}

// SetExecutor replaces the executor that runs each profile step, which by
// default is a CLIExecutor for the current executable.
func (po *ProfileOrchestrator) SetExecutor(executor CommandExecutor) {
	po.executor = executor
}

// SetActivator sets the function that runs the activation step. The
// orchestrator cannot import the activate command, so its caller injects it.
func (po *ProfileOrchestrator) SetActivator(fn func(LocalActivation) error) {
	po.activator = fn
}

// baseArgs returns the common CLI arguments including global flags like skip-amt-cert-check.
// Note: AMT password is now passed via AMT_PASSWORD environment variable instead of --password flag
// to avoid credential exposure in process argument listings (ps, /proc/<pid>/cmdline).
// Environment variables are still readable via /proc/<pid>/environ, but this approach also
// prevents global process environment pollution in c-shared library mode (see Execute).
func (po *ProfileOrchestrator) baseArgs() []string {
	args := []string{rpcExecutableName}

	if po.skipAMTCertCheck {
		args = append(args, "--skip-amt-cert-check")
	}

	// AMT password is no longer passed via --password flag for security.
	// It's now passed via AMT_PASSWORD environment variable per-subprocess.

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

	amtCommand := newAMTCommand()
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
				return fmt.Errorf("password verification/rotation failed: %w", hideStepCode(err))
			}
		} else {
			log.Debug("Device is activated but no AdminPassword provided in profile; skipping password alignment")
		}
	}

	// Step 1: Activation or upgrade if needed
	if po.profile.Configuration.AMTSpecific.ControlMode == ACMMODE && currentControlMode == 1 {
		// Upgrade CCM -> ACM using local activation path with provisioning cert
		if err := po.executeActivation(); err != nil {
			return fmt.Errorf("activation failed: %w", hideStepCode(err))
		}

		po.activatedThisRun = true
	} else if currentControlMode == 0 {
		if err := po.executeActivation(); err != nil {
			return fmt.Errorf("activation failed: %w", hideStepCode(err))
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
		return fmt.Errorf("MEBx configuration failed: %w", hideStepCode(err))
	}

	// Step 3: AMT Features configuration
	if err := po.executeAMTFeaturesConfiguration(); err != nil {
		return fmt.Errorf("AMT features configuration failed: %w", hideStepCode(err))
	}

	// Step 4: Wired network configuration
	if err := po.executeWiredNetworkConfiguration(); err != nil {
		return fmt.Errorf("wired network configuration failed: %w", hideStepCode(err))
	}

	// Step 5: Enable WiFi port if needed
	if err := po.executeEnableWiFi(); err != nil {
		return fmt.Errorf("WiFi sync enable failed: %w", hideStepCode(err))
	}

	// Step 6: Wireless profile configurations
	if err := po.executeWirelessConfigurations(); err != nil {
		return fmt.Errorf("wireless configuration failed: %w", hideStepCode(err))
	}

	// Step 7: TLS configuration
	if err := po.executeTLSConfiguration(); err != nil {
		return fmt.Errorf("TLS configuration failed: %w", hideStepCode(err))
	}

	// Step 8: CIRA configuration
	if err := po.executeCIRAConfiguration(); err != nil {
		return fmt.Errorf("%w: %w", ErrCIRAConfiguration, hideStepCode(err))
	}

	// Step 9: HTTP Proxy configuration
	if err := po.executeHTTPProxyConfiguration(); err != nil {
		return fmt.Errorf("HTTP proxy configuration failed: %w", hideStepCode(err))
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
func (po *ProfileOrchestrator) executeWithPasswordFallback(step stepFunc) error {
	err := po.executeWithPasswordRotation(step)
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

		// Retry the step directly rather than through executeWithPasswordRotation.
		// Rotation already ran on the initial execution above; re-entering it here
		// would prompt for the current password again on every settle attempt
		// (worst case attempts × maxTries prompts) and, on success, recurse back
		// into this loop. Settle retries exist to wait out a restarting port stack,
		// which needs no credential interaction. The AMT password always comes
		// from po.globalPassword, which is kept current across rotations.
		err = step(po.globalPassword)
		if err == nil {
			return nil
		}
	}

	return err
}

// executeWithPasswordRotation runs a step and, on authentication failure,
// prompts for the old AMT password to rotate it to the profile's new password, then retries.
// The step always receives po.globalPassword (kept current across rotations), never a
// stale caller value.
func (po *ProfileOrchestrator) executeWithPasswordRotation(step stepFunc) error {
	err := step(po.globalPassword)
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
	if code, ok := failureCode(err); !ok || code != utils.AMTAuthenticationFailed.Code {
		return err
	}

	log.Warn("Authentication failed with provided AMT password; attempting password rotation to profile value...")

	// If caller supplied a currentPassword, try non-interactive rotation once
	if po.currentPassword != "" {
		if cerr := po.changeAMTPassword(po.currentPassword, newPass); cerr == nil {
			log.Info("AMT password updated to profile value using provided current password; retrying previous operation")

			// Update the password for subsequent subprocess invocations
			po.globalPassword = newPass

			return po.executeWithPasswordFallback(step)
		}
	}
	// otherwise fall through to prompt loop

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

		if cerr := po.changeAMTPassword(oldPass, newPass); cerr != nil {
			if code, ok := failureCode(cerr); attempt < maxTries && ok && code == utils.AMTAuthenticationFailed.Code {
				log.Warn("Incorrect AMT password. Please try again.")

				continue
			}

			return fmt.Errorf("failed to update AMT password using provided current password: %w", cerr)
		}

		log.Info("AMT password updated to profile value; retrying previous operation")

		// Update the password for subsequent subprocess invocations
		po.globalPassword = newPass

		return po.executeWithPasswordFallback(step)
	}

	return fmt.Errorf("failed to update AMT password after %d attempts", maxTries)
}

// changeAMTPassword changes the AMT admin password from current to next
// in-process; both passwords travel in the options struct.
func (po *ProfileOrchestrator) changeAMTPassword(current, next string) error {
	return configureChangeAMTPassword(configure.AMTPasswordOptions{
		BaseOptions: configure.BaseOptions{AMTPassword: current, SkipAMTCertCheck: po.skipAMTCertCheck},
		NewPassword: next,
	})
}

// execStep returns a step that runs the rpc CLI with args. The step's AMT
// password argument is passed as AMT_PASSWORD (when non-empty); any
// AMT_PASSWORD in extraEnv is dropped because it may be stale after a rotation.
func (po *ProfileOrchestrator) execStep(args []string, extraEnv map[string]string) stepFunc {
	return func(amtPassword string) error {
		env := make(map[string]string, len(extraEnv)+1)

		for k, v := range extraEnv {
			if k != envAMTPassword {
				env[k] = v
			}
		}

		if amtPassword != "" {
			env[envAMTPassword] = amtPassword
		}

		return po.executor.Execute(args, env)
	}
}

// executeActivation performs the activation step
func (po *ProfileOrchestrator) executeActivation() error {
	if po.profile.Configuration.AMTSpecific.ControlMode == "" {
		log.Info("No activation mode specified, skipping activation")

		return nil
	}

	log.Infof("Executing activation with control mode: %s", po.profile.Configuration.AMTSpecific.ControlMode)

	activation := LocalActivation{
		AMTPassword:      po.globalPassword,
		SkipAMTCertCheck: po.skipAMTCertCheck,
	}

	switch po.profile.Configuration.AMTSpecific.ControlMode {
	case ACMMODE:
		activation.ACM = true
		activation.ProvisioningCert = po.profile.Configuration.AMTSpecific.ProvisioningCert
		activation.ProvisioningCertPassword = po.profile.Configuration.AMTSpecific.ProvisioningCertPwd

		// MEBx password for AMT19+ TLS activation; prefer profile value over CLI value
		activation.MEBxPassword = po.profile.Configuration.AMTSpecific.MEBXPassword
		if activation.MEBxPassword == "" {
			activation.MEBxPassword = po.mebxPassword
		}
	case "ccmactivate":
	default:
		return fmt.Errorf("unsupported control mode: %s", po.profile.Configuration.AMTSpecific.ControlMode)
	}

	if po.activator == nil {
		return errNoActivator
	}

	return po.activator(activation)
}

// executeACMUpgrade performs an in-place upgrade from CCM to ACM when already activated
func (po *ProfileOrchestrator) executeACMUpgrade() error {
	if po.profile.Configuration.AMTSpecific.ProvisioningCert == "" || po.profile.Configuration.AMTSpecific.ProvisioningCertPwd == "" {
		return fmt.Errorf("ACM upgrade requires provisioning certificate and password")
	}

	args := po.baseArgs()
	args = append(args, "activate", "--acm", "--local")
	// no special flag needed; local activation will auto-upgrade CCM->ACM when ACM mode is requested

	// Pass provisioning certificate via per-subprocess environment to avoid
	// exposing sensitive PFX content in command-line arguments (ps, /proc/<pid>/cmdline).
	env := make(map[string]string)
	env[envProvisioningCert] = po.profile.Configuration.AMTSpecific.ProvisioningCert
	env[envProvisioningCertPwd] = po.profile.Configuration.AMTSpecific.ProvisioningCertPwd

	return po.executeWithPasswordFallback(po.execStep(args, env))
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

	// Both passwords travel in the options struct; the AMT password is the
	// current po.globalPassword the fallback wrapper passes in.
	step := func(amtPassword string) error {
		return configureSetMEBx(configure.MEBxOptions{
			BaseOptions:  configure.BaseOptions{AMTPassword: amtPassword, SkipAMTCertCheck: po.skipAMTCertCheck},
			MEBxPassword: po.profile.Configuration.AMTSpecific.MEBXPassword,
		})
	}

	return po.executeWithPasswordFallback(step)
}

// executeAMTFeaturesConfiguration performs AMT features configuration
func (po *ProfileOrchestrator) executeAMTFeaturesConfiguration() error {
	redirection := po.profile.Configuration.Redirection

	// Intentionally always configure AMT features when profile provides Redirection section.
	// This ensures features can be explicitly disabled when set to false.
	// If Services fields are all false and section present, we still run to disable them.

	log.Info("Executing AMT features configuration")

	// User consent is set only in ACM. In CCM it stays empty and pkg
	// SetAMTFeatures defaults it to "all", as Kong's default did for the old
	// child. That non-empty consent also lets an all-false profile pass
	// validation, so no DisableAll option is needed to turn every feature off.
	var userConsent string

	if po.profile.Configuration.AMTSpecific.ControlMode == ACMMODE {
		switch redirection.UserConsent {
		case "None":
			userConsent = "none"
		case "KVM":
			userConsent = "kvm"
		default:
			userConsent = "all"
		}
	}

	// The AMT password is the current po.globalPassword the fallback wrapper
	// passes in.
	step := func(amtPassword string) error {
		return configureSetAMTFeatures(configure.AMTFeaturesOptions{
			BaseOptions: configure.BaseOptions{AMTPassword: amtPassword, SkipAMTCertCheck: po.skipAMTCertCheck},
			UserConsent: userConsent,
			KVM:         redirection.Services.KVM,
			SOL:         redirection.Services.SOL,
			IDER:        redirection.Services.IDER,
		})
	}

	return po.executeWithPasswordFallback(step)
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

	// DHCP sets only DHCPEnabled, as the old child got only --dhcp; a static
	// profile copies its address fields and leaves DHCPEnabled nil. IP sync,
	// 802.1x and EA fields stay unset because the old child never got them.
	var opts configure.WiredOptions

	if wired.DHCPEnabled {
		dhcp := true
		opts.DHCPEnabled = &dhcp
	} else {
		opts.IPAddress = wired.IPAddress
		opts.SubnetMask = wired.SubnetMask
		opts.Gateway = wired.DefaultGateway
		opts.PrimaryDNS = wired.PrimaryDNS
		opts.SecondaryDNS = wired.SecondaryDNS
	}

	// The AMT password is the current po.globalPassword the fallback wrapper
	// passes in.
	step := func(amtPassword string) error {
		opts.BaseOptions = configure.BaseOptions{AMTPassword: amtPassword, SkipAMTCertCheck: po.skipAMTCertCheck}

		return configureWired(opts)
	}

	return po.executeWithPasswordFallback(step)
}

// executeEnableWiFi enables WiFi port if needed
func (po *ProfileOrchestrator) executeEnableWiFi() error {
	log.Info("Executing WiFi sync configuration")

	// Both values pass through as-is: the old child always got
	// --oswifisync=<bool> and --uefiwifisync=<bool>, so the CLI defaults
	// never applied. The AMT password is the current po.globalPassword the
	// fallback wrapper passes in.
	wireless := po.profile.Configuration.Network.Wireless

	step := func(amtPassword string) error {
		return configureWiFiSync(configure.WiFiSyncOptions{
			BaseOptions:  configure.BaseOptions{AMTPassword: amtPassword, SkipAMTCertCheck: po.skipAMTCertCheck},
			OSWiFiSync:   wireless.WiFiSyncEnabled,
			UEFIWiFiSync: wireless.UEFIWiFiSyncEnabled,
		})
	}

	return po.executeWithPasswordFallback(step)
}

// executeWirelessConfigurations performs wireless profile configurations
func (po *ProfileOrchestrator) executeWirelessConfigurations() error {
	// Always purge existing Wi-Fi profiles before applying new ones
	log.Info("Purging existing AMT wireless profiles before applying new configuration")

	// The purge sets only Purge, as the old child got only --purge;
	// pkg/configure fills the defaults the CLI's flags did. The AMT password
	// is the current po.globalPassword the fallback wrapper passes in.
	purge := func(amtPassword string) error {
		return configureWireless(configure.WirelessOptions{
			BaseOptions: configure.BaseOptions{AMTPassword: amtPassword, SkipAMTCertCheck: po.skipAMTCertCheck},
			Purge:       true,
		})
	}

	if err := po.executeWithPasswordFallback(purge); err != nil {
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

// executeWirelessProfile configures a single wireless profile. Only the
// profile's values are used: unlike the old child, empty secrets are not
// filled from PSK_PASSPHRASE or IEEE8021X_* in the operator's environment.
func (po *ProfileOrchestrator) executeWirelessProfile(profile config.WirelessProfile) error {
	method, success := wifi.ParseAuthenticationMethod(profile.AuthenticationMethod)
	if !success {
		return fmt.Errorf("invalid authentication method: %s", profile.AuthenticationMethod)
	}

	encryptionMethod, success := wifi.ParseEncryptionMethod(profile.EncryptionMethod)
	if !success {
		return fmt.Errorf("invalid encryption method: %s", profile.EncryptionMethod)
	}

	opts := configure.WirelessOptions{
		ProfileName:          profile.ProfileName,
		SSID:                 profile.SSID,
		Priority:             profile.Priority,
		AuthenticationMethod: int(method),
		EncryptionMethod:     int(encryptionMethod),
		PSKPassphrase:        profile.Password,
	}

	if ieee := profile.IEEE8021x; ieee != nil {
		opts.IEEE8021xProfileName = fmt.Sprintf("%s_8021x", profile.ProfileName)
		opts.IEEE8021xUsername = ieee.Username
		opts.IEEE8021xPassword = ieee.Password
		opts.IEEE8021xAuthenticationProtocol = ieee.AuthenticationProtocol
		opts.IEEE8021xPrivateKey = ieee.PrivateKey
		opts.IEEE8021xClientCert = ieee.ClientCert
		opts.IEEE8021xCACert = ieee.CACert
	}

	if err := validateWirelessOptions(opts); err != nil {
		return err
	}

	// The AMT password is the current po.globalPassword the fallback wrapper
	// passes in.
	step := func(amtPassword string) error {
		opts.BaseOptions = configure.BaseOptions{AMTPassword: amtPassword, SkipAMTCertCheck: po.skipAMTCertCheck}

		return configureWireless(opts)
	}

	return po.executeWithPasswordFallback(step)
}

// validateWirelessOptions rejects the values the CLI rejected and
// pkg/configure would default or accept: Kong's enums on the authentication
// method, encryption method and 802.1x authentication protocol, and the
// Validate check on priority (pkg/configure turns 0 into 1).
func validateWirelessOptions(opts configure.WirelessOptions) error {
	enums := []struct {
		name    string
		value   int
		allowed []int
	}{
		{"authenticationMethod", opts.AuthenticationMethod, []int{4, 6, 7}},
		{"encryptionMethod", opts.EncryptionMethod, []int{3, 4}},
		{"ieee8021xAuthenticationProtocol", opts.IEEE8021xAuthenticationProtocol, []int{0, 2}},
	}

	for _, e := range enums {
		if slices.Contains(e.allowed, e.value) {
			continue
		}

		quoted := make([]string, len(e.allowed))
		for i, v := range e.allowed {
			quoted[i] = strconv.Quote(strconv.Itoa(v))
		}

		return fmt.Errorf("%s must be one of %s but got %q", e.name, strings.Join(quoted, ","), strconv.Itoa(e.value))
	}

	if opts.Priority <= 0 {
		return fmt.Errorf("priority must be greater than 0")
	}

	return nil
}

// executeTLSConfiguration performs TLS configuration. The Enterprise
// Assistant password comes from the profile only: unlike the old child, an
// empty one is not filled from EA_PASSWORD in the operator's environment.
func (po *ProfileOrchestrator) executeTLSConfiguration() error {
	if !po.profile.Configuration.TLS.Enabled {
		log.Info("TLS not enabled, skipping TLS configuration")

		return nil
	}

	log.Info("Executing TLS configuration")

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

	// Delay stays 0 so pkg/configure applies its default of 3, the CLI
	// default the old child got.
	opts := configure.TLSOptions{Mode: mode}

	// Add Enterprise Assistant settings if configured and not self-signed
	ea := po.profile.Configuration.EnterpriseAssistant
	if po.profile.Configuration.TLS.SigningAuthority != "SelfSigned" && ea.URL != "" {
		opts.EAAddress = ea.URL
		opts.EAUsername = ea.Username
		opts.EAPassword = ea.Password
	}

	// The AMT password is the current po.globalPassword the fallback wrapper
	// passes in.
	step := func(amtPassword string) error {
		opts.BaseOptions = configure.BaseOptions{AMTPassword: amtPassword, SkipAMTCertCheck: po.skipAMTCertCheck}

		return configureTLS(opts)
	}

	return po.executeWithPasswordFallback(step)
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

	// Every CIRA field comes from the profile only: unlike the old child, none
	// is filled from the operator's environment (MPS_PASSWORD,
	// GENERATE_RANDOM_PASSWORD, ENVIRONMENT_DETECTION, RPC_*) or config.yaml.
	opts := configure.CIRAOptions{
		MPSAddress:             cira.MPSAddress,
		MPSCert:                cira.MPSCert,
		MPSPassword:            cira.MPSPassword,
		GenerateRandomPassword: cira.GenerateRandomPassword,
	}

	// The old child got the list comma-joined in one --envdetection flag and
	// Kong split it with SplitEscaped: a comma inside one profile entry yields
	// two strings, a backslash-escaped comma stays literal and a trailing
	// empty entry is dropped. Use Kong's own splitter for the same strings; an
	// empty list (or [""]) stays nil, as the child got no value.
	opts.EnvironmentDetection = kong.SplitEscaped(strings.Join(cira.EnvironmentDetection, ","), ',')

	// The AMT password is the current po.globalPassword the fallback wrapper
	// passes in.
	step := func(amtPassword string) error {
		opts.BaseOptions = configure.BaseOptions{AMTPassword: amtPassword, SkipAMTCertCheck: po.skipAMTCertCheck}

		return configureCIRA(opts)
	}

	return po.executeWithPasswordFallback(step)
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
	opts := configure.ProxyOptions{
		Address:          proxy.Address,
		NetworkDnsSuffix: proxy.NetworkDnsSuffix,
	}

	// The old child got --port only when > 0, else the CLI default of 80; a
	// zero Port gets the same default from pkg/configure.
	if proxy.Port > 0 {
		opts.Port = proxy.Port
	}

	// The AMT password is the current po.globalPassword the fallback wrapper
	// passes in.
	step := func(amtPassword string) error {
		opts.BaseOptions = configure.BaseOptions{AMTPassword: amtPassword, SkipAMTCertCheck: po.skipAMTCertCheck}

		return configureProxy(opts)
	}

	return po.executeWithPasswordFallback(step)
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
		if err := po.changeAMTPassword(po.currentPassword, newPass); err == nil {
			log.Info("AMT password aligned to profile value using provided current password")

			// Update globalPassword so subsequent subprocess invocations use the new password
			po.globalPassword = newPass

			return nil
		} else if isDeviceNotActivatedErr(err) {
			log.Warn(msgPasswordAlignSkipped)

			return nil
		}
	}
	// If it failed (e.g., wrong provided current), proceed to auth-probe and interactive fallback

	// Use an idempotent password-change-to-same-value operation as an auth probe.
	// If the provided password is already set, this succeeds and changes nothing.
	// If authentication fails (wrong password), our fallback will prompt for the
	// current password, rotate to the profile value, and retry. The probe gets
	// the current po.globalPassword from the fallback wrapper.
	probe := func(password string) error {
		return po.changeAMTPassword(password, newPass)
	}

	err := po.executeWithPasswordFallback(probe)
	if isDeviceNotActivatedErr(err) {
		log.Warn(msgPasswordAlignSkipped)

		return nil
	}

	return err
}

// isDeviceNotActivatedErr reports whether err signals that a step refused
// because the device is not yet activated. It matches on the typed failure code
// rather than substring-matching subprocess output (verbose Digest logs make
// substring matching unreliable — see CLAUDE.md).
func isDeviceNotActivatedErr(err error) bool {
	code, ok := failureCode(err)

	return ok && code == utils.DeviceNotActivated.Code
}

// failureCode returns the failure code err carries: the exit code of a
// subprocess step (*ExecError) or the code of an in-process step's
// utils.CustomError. ok is false when err carries neither.
func failureCode(err error) (int, bool) {
	if err == nil {
		return 0, false
	}

	var execErr *ExecError
	if errors.As(err, &execErr) {
		return execErr.ExitCode, true
	}

	var customErr utils.CustomError
	if errors.As(err, &customErr) {
		return customErr.Code, true
	}

	return 0, false
}

// hideStepCode returns an error with err's message that carries neither a
// utils.CustomError nor an *ExecError, so a failed profile run keeps exiting
// with the generic failure code (10) even when a step fails in-process.
//
// TODO: the step's own exit code could be surfaced to the CLI here instead of
// the generic failure.
func hideStepCode(err error) error {
	if err == nil {
		return nil
	}

	return errors.New(err.Error())
}
