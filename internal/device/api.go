/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package device

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

const maxErrorBodySize = 1024

// readErrorBody reads up to maxErrorBodySize bytes from the response body for error reporting.
func readErrorBody(body io.Reader) string {
	b, err := io.ReadAll(io.LimitReader(body, maxErrorBodySize))
	if err != nil || len(b) == 0 {
		return ""
	}

	return strings.TrimSpace(string(b))
}

const (
	DefaultDevicesPath = "/api/v1/devices"
	requestTimeout     = 10 * time.Second
)

// resolveDevicesEndpoint returns the full devices API base URL.
// If devicesEndpoint is non-empty, it is used directly; otherwise consoleBaseURL + DefaultDevicesPath.
func resolveDevicesEndpoint(consoleBaseURL, devicesEndpoint string) string {
	endpoint := strings.TrimSpace(devicesEndpoint)
	if endpoint != "" {
		return strings.TrimRight(endpoint, "/")
	}

	return strings.TrimRight(strings.TrimSpace(consoleBaseURL), "/") + DefaultDevicesPath
}

// StatusError represents a non-2xx HTTP response.
type StatusError struct {
	StatusCode int
	Status     string
	Detail     string
}

func (e *StatusError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("request failed with status %s: %s", e.Status, e.Detail)
	}

	return fmt.Sprintf("request failed with status %s", e.Status)
}

// doJSONRequest executes an HTTP request; returns *StatusError for non-2xx responses.
func doJSONRequest(method, requestURL, token string, body []byte, skipCertCheck bool) error {
	httpClient := &http.Client{
		Timeout: requestTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: skipCertCheck, //nolint:gosec // user-controlled flag for self-signed certs
			},
		},
	}

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(context.Background(), method, requestURL, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &StatusError{
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			Detail:     readErrorBody(resp.Body),
		}
	}

	return nil
}

func sendDeviceJSONRequest(method, endpoint, token string, payload interface{}, skipCertCheck bool, errContext string) error {
	var body []byte

	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("%s: marshal failed: %w", errContext, err)
		}

		body = encoded
	}

	if err := doJSONRequest(method, endpoint, token, body, skipCertCheck); err != nil {
		return fmt.Errorf("%s: %w", errContext, err)
	}

	return nil
}

// DevicePayload is the JSON body sent to /api/v1/devices.
type DevicePayload struct {
	GUID            string      `json:"guid"`
	Hostname        string      `json:"hostname"`
	FriendlyName    string      `json:"friendlyName,omitempty"`
	Tags            []string    `json:"tags"`
	MPSUsername     string      `json:"mpsusername"`
	Username        string      `json:"username"`
	Password        string      `json:"password,omitempty"`
	MEBXPassword    string      `json:"mebxpassword,omitempty"`
	MPSPassword     string      `json:"mpspassword,omitempty"`
	UseTLS          bool        `json:"useTLS"`
	AllowSelfSigned bool        `json:"allowSelfSigned"`
	DeviceInfo      *DeviceInfo `json:"deviceInfo,omitempty"`
}

type deviceTLSPatchPayload struct {
	GUID            string `json:"guid"`
	Hostname        string `json:"hostname"`
	Username        string `json:"username"`
	UseTLS          bool   `json:"useTLS"`
	AllowSelfSigned bool   `json:"allowSelfSigned"`
}

// TLSSettingsUpdate encapsulates parameters for updating device TLS settings.
type TLSSettingsUpdate struct {
	ConsoleBaseURL  string
	Token           string
	GUID            string
	Hostname        string
	Username        string
	UseTLS          bool
	AllowSelfSigned bool
	SkipCertCheck   bool
	DevicesEndpoint string
}

// DeviceInfo carries device metadata sent to the console.
type DeviceInfo struct {
	FWVersion            string     `json:"fwVersion,omitempty"`
	FWBuild              string     `json:"fwBuild,omitempty"`
	FWSku                string     `json:"fwSku,omitempty"`
	Discovered           *bool      `json:"discovered,omitempty"`
	FirstDiscovered      *time.Time `json:"firstDiscovered,omitempty"`
	CurrentMode          string     `json:"currentMode,omitempty"`
	Features             string     `json:"features,omitempty"`
	IPAddress            string     `json:"ipAddress,omitempty"`
	LastSynced           *time.Time `json:"lastSynced,omitempty"`
	TLSMode              string     `json:"tlsMode,omitempty"`
	UPID                 *UPIDInfo  `json:"upid,omitempty"`
	AMTEnabledInBIOS     *bool      `json:"amtEnabledInBIOS,omitempty"`
	MEInterfaceVersion   string     `json:"meInterfaceVersion,omitempty"`
	DHCPEnabled          *bool      `json:"dhcpEnabled,omitempty"`
	CertHashes           []string   `json:"certHashes,omitempty"`
	LMSInstalled         *bool      `json:"lmsInstalled,omitempty"`
	LMSVersion           string     `json:"lmsVersion,omitempty"`
	OSName               string     `json:"osName,omitempty"`
	OSVersion            string     `json:"osVersion,omitempty"`
	OSDistro             string     `json:"osDistro,omitempty"`
	CPUModel             string     `json:"cpuModel,omitempty"`
	OSIPAddress          string     `json:"osIpAddress,omitempty"`
	EthernetAdapterCount int        `json:"ethernetAdapterCount,omitempty"`
	MonitorConnected     *bool      `json:"monitorConnected,omitempty"`
	IEEE8021xEnabled     *bool      `json:"ieee8021xEnabled,omitempty"`
}

// UPIDInfo carries UPID details for the console.
type UPIDInfo struct {
	CSMEId            string `json:"csmeId,omitempty"`
	OEMId             string `json:"oemId,omitempty"`
	OEMPlatformIdType string `json:"oemPlatformIdType,omitempty"`
}

// AddDevice registers a device via POST to the devices API endpoint.
func AddDevice(consoleBaseURL, token string, d DevicePayload, skipCertCheck bool, devicesEndpoint string) error {
	endpoint := resolveDevicesEndpoint(consoleBaseURL, devicesEndpoint)

	log.Debugf("Adding device to console: POST %s", endpoint)

	if err := sendDeviceJSONRequest(http.MethodPost, endpoint, token, d, skipCertCheck, "add device failed"); err != nil {
		return err
	}

	log.Infof("Device %s added to console successfully", d.GUID)

	return nil
}

// UpdateDevice updates an existing device in the console via PATCH to the devices API endpoint.
func UpdateDevice(consoleBaseURL, token string, d DevicePayload, skipCertCheck bool, devicesEndpoint string) error {
	endpoint := resolveDevicesEndpoint(consoleBaseURL, devicesEndpoint)

	log.Debugf("Updating device in console: PATCH %s", endpoint)

	if err := sendDeviceJSONRequest(http.MethodPatch, endpoint, token, d, skipCertCheck, "update device failed"); err != nil {
		return err
	}

	log.Infof("Device %s updated in console successfully", d.GUID)

	return nil
}

// UpdateDeviceTLSSettings updates only TLS-related fields via PATCH to avoid
// unintentionally clearing unrelated device fields.
func UpdateDeviceTLSSettings(settings TLSSettingsUpdate) error {
	// Validate required fields
	if settings.GUID == "" {
		return fmt.Errorf("GUID is required for TLS settings update")
	}

	if settings.Hostname == "" {
		return fmt.Errorf("hostname is required for TLS settings update")
	}

	if settings.Username == "" {
		return fmt.Errorf("username is required for TLS settings update")
	}

	endpoint := resolveDevicesEndpoint(settings.ConsoleBaseURL, settings.DevicesEndpoint)

	payload := deviceTLSPatchPayload{
		GUID:            settings.GUID,
		Hostname:        settings.Hostname,
		Username:        settings.Username,
		UseTLS:          settings.UseTLS,
		AllowSelfSigned: settings.AllowSelfSigned,
	}

	log.Debugf("Updating device TLS settings in console: PATCH %s", endpoint)

	if err := sendDeviceJSONRequest(http.MethodPatch, endpoint, settings.Token, payload, settings.SkipCertCheck, "update device TLS settings failed"); err != nil {
		return err
	}

	log.Infof("Device %s TLS settings updated in console successfully", settings.GUID)

	return nil
}

// ClearDeviceMPSPassword removes the MPS password from a device via PATCH to the devices API endpoint.
func ClearDeviceMPSPassword(consoleBaseURL, token, guid string, skipCertCheck bool, devicesEndpoint string) error {
	endpoint := resolveDevicesEndpoint(consoleBaseURL, devicesEndpoint)

	log.Debugf("Clearing MPS password from device: PATCH %s", endpoint)

	// Map avoids omitempty so the empty string is sent explicitly.
	payload := map[string]string{"guid": guid, "mpspassword": ""}
	if err := sendDeviceJSONRequest(http.MethodPatch, endpoint, token, payload, skipCertCheck, "clear MPS password failed"); err != nil {
		return err
	}

	log.Infof("MPS password cleared from device %s", guid)

	return nil
}

// DeleteDevice removes a device from the console via DELETE to the devices API endpoint.
func DeleteDevice(consoleBaseURL, token, guid string, skipCertCheck bool, devicesEndpoint string) error {
	endpoint := resolveDevicesEndpoint(consoleBaseURL, devicesEndpoint) + "/" + guid

	log.Debugf("Deleting device from console: DELETE %s", endpoint)

	if err := sendDeviceJSONRequest(http.MethodDelete, endpoint, token, nil, skipCertCheck, "delete device failed"); err != nil {
		return err
	}

	log.Infof("Device %s deleted from console successfully", guid)

	return nil
}
