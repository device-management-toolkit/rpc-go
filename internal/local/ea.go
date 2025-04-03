/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type AuthRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AuthResponse struct {
	Token  string `json:"jwtToken"`
	Status string `json:"status"`
}

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

type EAProfile struct {
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

func (service *ProvisioningService) PerformPostRequest(url string, requestBody []byte, token string) ([]byte, error) {
	request, err := http.NewRequest("POST", url, bytes.NewBuffer(requestBody))
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

func (service *ProvisioningService) GetAuthToken(url string, credentials AuthRequest) (string, error) {
	requestBody, err := json.Marshal(credentials)
	if err != nil {
		return "", fmt.Errorf("marshaling credentials: %v", err)
	}

	responseBody, err := service.PerformPostRequest(url, requestBody, "")
	if err != nil {
		return "", err
	}

	var authResponse AuthResponse
	if err := json.Unmarshal(responseBody, &authResponse); err != nil {
		return "", fmt.Errorf("decoding response: %v", err)
	}

	return authResponse.Token, nil
}

func (service *ProvisioningService) EAConfigureRequest(url string, token string, profileRequest EAProfile) (EAProfile, error) {
	requestBody, err := json.Marshal(profileRequest)
	if err != nil {
		return EAProfile{}, fmt.Errorf("marshaling profile request: %v", err)
	}

	responseBody, err := service.PerformPostRequest(url, requestBody, token)
	if err != nil {
		return EAProfile{}, err
	}

	var profile EAProfile
	if err := json.Unmarshal(responseBody, &profile); err != nil {
		return EAProfile{}, fmt.Errorf("decoding response: %v", err)
	}

	return profile, nil
}
