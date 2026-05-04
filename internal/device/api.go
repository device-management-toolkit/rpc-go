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
	if devicesEndpoint != "" {
		return strings.TrimRight(devicesEndpoint, "/")
	}

	return strings.TrimRight(consoleBaseURL, "/") + DefaultDevicesPath
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

// DevicePayload is the JSON body sent to /api/v1/devices.
type DevicePayload struct {
	GUID            string   `json:"guid"`
	Hostname        string   `json:"hostname"`
	FriendlyName    string   `json:"friendlyName,omitempty"`
	Tags            []string `json:"tags"`
	MPSUsername     string   `json:"mpsusername"`
	Username        string   `json:"username"`
	Password        string   `json:"password,omitempty"`
	MEBXPassword    string   `json:"mebxpassword,omitempty"`
	MPSPassword     string   `json:"mpspassword,omitempty"`
	UseTLS          bool     `json:"useTLS"`
	AllowSelfSigned bool     `json:"allowSelfSigned"`
	IsLMSAvailable  bool     `json:"isLMSAvailable"`
}

// AddDevice registers a device via POST to the devices API endpoint.
func AddDevice(consoleBaseURL, token string, d DevicePayload, skipCertCheck bool, devicesEndpoint string) error {
	endpoint := resolveDevicesEndpoint(consoleBaseURL, devicesEndpoint)

	body, err := json.Marshal(d)
	if err != nil {
		return fmt.Errorf("failed to marshal device payload: %w", err)
	}

	log.Debugf("Adding device to console: POST %s", endpoint)

	if err := doJSONRequest(http.MethodPost, endpoint, token, body, skipCertCheck); err != nil {
		return fmt.Errorf("add device failed: %w", err)
	}

	log.Infof("Device %s added to console successfully", d.GUID)

	return nil
}

// UpdateDevice updates an existing device in the console via PATCH to the devices API endpoint.
func UpdateDevice(consoleBaseURL, token string, d DevicePayload, skipCertCheck bool, devicesEndpoint string) error {
	endpoint := resolveDevicesEndpoint(consoleBaseURL, devicesEndpoint)

	body, err := json.Marshal(d)
	if err != nil {
		return fmt.Errorf("failed to marshal device payload: %w", err)
	}

	log.Debugf("Updating device in console: PATCH %s", endpoint)

	if err := doJSONRequest(http.MethodPatch, endpoint, token, body, skipCertCheck); err != nil {
		return fmt.Errorf("update device failed: %w", err)
	}

	log.Infof("Device %s updated in console successfully", d.GUID)

	return nil
}

// ClearDeviceMPSPassword removes the MPS password from a device via PATCH to the devices API endpoint.
func ClearDeviceMPSPassword(consoleBaseURL, token, guid string, skipCertCheck bool, devicesEndpoint string) error {
	endpoint := resolveDevicesEndpoint(consoleBaseURL, devicesEndpoint)

	log.Debugf("Clearing MPS password from device: PATCH %s", endpoint)

	// Map avoids omitempty so the empty string is sent explicitly.
	body, err := json.Marshal(map[string]string{"guid": guid, "mpspassword": ""})
	if err != nil {
		return fmt.Errorf("failed to marshal clear-password payload: %w", err)
	}

	if err := doJSONRequest(http.MethodPatch, endpoint, token, body, skipCertCheck); err != nil {
		return fmt.Errorf("clear MPS password failed: %w", err)
	}

	log.Infof("MPS password cleared from device %s", guid)

	return nil
}

// DeleteDevice removes a device from the console via DELETE to the devices API endpoint.
func DeleteDevice(consoleBaseURL, token, guid string, skipCertCheck bool, devicesEndpoint string) error {
	endpoint := resolveDevicesEndpoint(consoleBaseURL, devicesEndpoint) + "/" + guid

	log.Debugf("Deleting device from console: DELETE %s", endpoint)

	if err := doJSONRequest(http.MethodDelete, endpoint, token, nil, skipCertCheck); err != nil {
		return fmt.Errorf("delete device failed: %w", err)
	}

	log.Infof("Device %s deleted from console successfully", guid)

	return nil
}
