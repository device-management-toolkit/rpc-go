/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package ea

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// AuthRequest represents the authentication request for Enterprise Assistant
type AuthRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// AuthResponse represents the authentication response from Enterprise Assistant
type AuthResponse struct {
	Token  string `json:"jwtToken"`
	Status string `json:"status"`
}

// Response represents the response from Enterprise Assistant
type Response struct {
	CSR           string `json:"csr"`
	KeyInstanceId string `json:"keyInstanceId"`
	AuthProtocol  int    `json:"authProtocol"`
	Certificate   string `json:"certificate"`
	Domain        string `json:"domain"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	RootCert      string `json:"rootcert"`
}

// Profile represents the profile request for Enterprise Assistant
type Profile struct {
	NodeID        string   `json:"nodeid"`
	Domain        string   `json:"domain"`
	ReqID         string   `json:"reqid"`
	AuthProtocol  int      `json:"authProtocol"`
	OSName        string   `json:"osname"`
	DevName       string   `json:"devname"`
	Icon          int      `json:"icon"`
	Ver           string   `json:"ver"`
	SignedCSR     string   `json:"signedcsr"`
	DERKey        string   `json:"DERKey"`
	KeyInstanceId string   `json:"keyInstanceId"`
	Response      Response `json:"response"`
}

// performPostRequest performs an HTTP POST request to the given URL with optional authentication
func performPostRequest(url string, requestBody []byte, token string) ([]byte, error) {
	ctx := context.Background()

	request, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("creating request: %v", err)
	}

	request.Header.Set("Content-Type", "application/json")

	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{}

	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("sending request: %v", err)
	}

	defer response.Body.Close()

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %v", err)
	}

	return responseBody, nil
}

// GetAuthToken authenticates with Enterprise Assistant and returns a JWT token
func GetAuthToken(url string, credentials AuthRequest) (string, error) {
	requestBody, err := json.Marshal(credentials)
	if err != nil {
		return "", fmt.Errorf("marshaling credentials: %v", err)
	}

	responseBody, err := performPostRequest(url, requestBody, "")
	if err != nil {
		return "", err
	}

	var authResponse AuthResponse
	if err := json.Unmarshal(responseBody, &authResponse); err != nil {
		return "", fmt.Errorf("decoding response: %v", err)
	}

	return authResponse.Token, nil
}

// ConfigureCertificate requests certificate configuration from Enterprise Assistant
func ConfigureCertificate(url, token string, profileRequest Profile) (Profile, error) {
	requestBody, err := json.Marshal(profileRequest)
	if err != nil {
		return Profile{}, fmt.Errorf("marshaling profile request: %v", err)
	}

	responseBody, err := performPostRequest(url, requestBody, token)
	if err != nil {
		return Profile{}, err
	}

	var profile Profile
	if err := json.Unmarshal(responseBody, &profile); err != nil {
		return Profile{}, fmt.Errorf("decoding response: %v", err)
	}

	return profile, nil
}
