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
	devicesAPIPath = "/api/v1/devices"
	requestTimeout = 10 * time.Second
)

// DevicePayload represents the JSON body for POST /api/v1/devices.
type DevicePayload struct {
	GUID         string   `json:"guid"`
	Hostname     string   `json:"hostname"`
	FriendlyName string   `json:"friendlyName,omitempty"`
	Tags         []string `json:"tags"`
	MPSUsername  string   `json:"mpsusername"`
	Username     string   `json:"username"`
	Password     string   `json:"password,omitempty"`
	MEBXPassword string   `json:"mebxpassword,omitempty"`
	MPSPassword  string   `json:"mpspassword,omitempty"`
}

// AddDevice registers a device in the console database by calling POST /api/v1/devices.
// consoleBaseURL is the scheme://host portion (e.g. "https://console:8181").
// token is a Bearer token for authorization.
func AddDevice(consoleBaseURL, token string, device DevicePayload, skipCertCheck bool) error {
	endpoint := strings.TrimRight(consoleBaseURL, "/") + devicesAPIPath

	body, err := json.Marshal(device)
	if err != nil {
		return fmt.Errorf("failed to marshal device payload: %w", err)
	}

	log.Debugf("Adding device to console: POST %s", endpoint)

	httpClient := &http.Client{Timeout: requestTimeout}

	if strings.HasPrefix(strings.ToLower(consoleBaseURL), "https://") && skipCertCheck {
		httpClient.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: skipCertCheck}} //nolint:gosec // user-controlled skip-cert-check flag
	}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("add device request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		detail := readErrorBody(resp.Body)
		if detail != "" {
			return fmt.Errorf("add device failed with status %s: %s", resp.Status, detail)
		}

		return fmt.Errorf("add device failed with status %s", resp.Status)
	}

	log.Infof("Device %s added to console successfully", device.GUID)

	return nil
}

// UpdateDevice updates an existing device in the console via PATCH /api/v1/devices.
func UpdateDevice(consoleBaseURL, token string, d DevicePayload, skipCertCheck bool) error {
	endpoint := strings.TrimRight(consoleBaseURL, "/") + devicesAPIPath

	body, err := json.Marshal(d)
	if err != nil {
		return fmt.Errorf("failed to marshal device payload: %w", err)
	}

	log.Debugf("Updating device in console: PATCH %s", endpoint)

	httpClient := &http.Client{Timeout: requestTimeout}

	if strings.HasPrefix(strings.ToLower(consoleBaseURL), "https://") && skipCertCheck {
		httpClient.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: skipCertCheck}} //nolint:gosec // user-controlled skip-cert-check flag
	}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("update device request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		detail := readErrorBody(resp.Body)
		if detail != "" {
			return fmt.Errorf("update device failed with status %s: %s", resp.Status, detail)
		}

		return fmt.Errorf("update device failed with status %s", resp.Status)
	}

	log.Infof("Device %s updated in console successfully", d.GUID)

	return nil
}

// ClearDeviceMPSPassword removes the MPS password from a device record via PATCH /api/v1/devices/{guid}.
// This is used to clean up the MPS password when CIRA configuration fails, as a stale
// password in the console confuses users.
func ClearDeviceMPSPassword(consoleBaseURL, token, guid string, skipCertCheck bool) error {
	endpoint := strings.TrimRight(consoleBaseURL, "/") + devicesAPIPath

	log.Debugf("Clearing MPS password from device: PATCH %s", endpoint)

	// Use a raw JSON literal so the empty string is included (not omitted).
	body := []byte(fmt.Sprintf(`{"guid":"%s","mpspassword":""}`, guid))

	httpClient := &http.Client{Timeout: requestTimeout}

	if strings.HasPrefix(strings.ToLower(consoleBaseURL), "https://") && skipCertCheck {
		httpClient.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: skipCertCheck}} //nolint:gosec // user-controlled skip-cert-check flag
	}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("clear MPS password request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		detail := readErrorBody(resp.Body)
		if detail != "" {
			return fmt.Errorf("clear MPS password failed with status %s: %s", resp.Status, detail)
		}

		return fmt.Errorf("clear MPS password failed with status %s", resp.Status)
	}

	log.Infof("MPS password cleared from device %s", guid)

	return nil
}

// DeleteDevice removes a device from the console via DELETE /api/v1/devices/{guid}.
func DeleteDevice(consoleBaseURL, token, guid string, skipCertCheck bool) error {
	endpoint := strings.TrimRight(consoleBaseURL, "/") + devicesAPIPath + "/" + guid

	log.Debugf("Deleting device from console: DELETE %s", endpoint)

	httpClient := &http.Client{Timeout: requestTimeout}

	if strings.HasPrefix(strings.ToLower(consoleBaseURL), "https://") && skipCertCheck {
		httpClient.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: skipCertCheck}} //nolint:gosec // user-controlled skip-cert-check flag
	}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("delete device request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		detail := readErrorBody(resp.Body)
		if detail != "" {
			return fmt.Errorf("delete device failed with status %s: %s", resp.Status, detail)
		}

		return fmt.Errorf("delete device failed with status %s", resp.Status)
	}

	log.Infof("Device %s deleted from console successfully", guid)

	return nil
}

