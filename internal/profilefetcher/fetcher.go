/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package profilefetcher

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/config"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/security"
	"gopkg.in/yaml.v3"
)

type ProfileFetcher struct {
	URL           string
	Token         string
	Username      string
	Password      string
	Timeout       time.Duration
	SkipCertCheck bool
	ClientKey     string
	AuthEndpoint  string
}

type AuthRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AuthResponse struct {
	Token    string `json:"token,omitempty"`
	JWT      string `json:"jwt,omitempty"`
	JWTToken string `json:"jwtToken,omitempty"`
	Status   string `json:"status,omitempty"`
	Message  string `json:"message,omitempty"`
}

type EncryptedProfileResponse struct {
	Filename string `json:"filename"`
	Content  string `json:"content"`
	Key      string `json:"key"`
}

func (f *ProfileFetcher) FetchProfile() (config.Configuration, error) {
	var cfg config.Configuration

	if f.Timeout == 0 {
		f.Timeout = 30 * time.Second
	}

	token := f.Token
	if token == "" && f.Username != "" && f.Password != "" {
		t, err := f.authenticate()
		if err != nil {
			return cfg, fmt.Errorf("authentication failed: %w", err)
		}

		token = t
	}

	body, err := f.fetchData(f.URL, token)
	if err != nil {
		return cfg, fmt.Errorf("failed to fetch profile: %w", err)
	}

	return f.parseProfile(body)
}

func (f *ProfileFetcher) authenticate() (string, error) {
	baseURL, err := f.getBaseURL()
	if err != nil {
		return "", err
	}

	// Endpoints to try: user-provided only, otherwise known defaults
	var endpoints []string
	if f.AuthEndpoint != "" {
		endpoints = []string{f.AuthEndpoint}
	} else {
		endpoints = []string{"/api/v1/authorize", "/mps/login/api/v1/authorize"}
	}

	reqBody, _ := json.Marshal(AuthRequest{Username: f.Username, Password: f.Password})

	var last error

	for _, ep := range endpoints {
		// Allow absolute URL for flexibility; otherwise treat as path on baseURL
		loginURL := ep
		if !strings.HasPrefix(ep, "http://") && !strings.HasPrefix(ep, "https://") {
			loginURL = baseURL + ep
		}

		token, err := f.tryAuthenticate(loginURL, reqBody)
		if err == nil && token != "" {
			return token, nil
		}

		last = err
	}

	if last != nil {
		return "", fmt.Errorf("authentication failed: %w", last)
	}

	return "", fmt.Errorf("no valid login endpoint found")
}

func (f *ProfileFetcher) tryAuthenticate(loginURL string, reqBody []byte) (string, error) {
	client := f.createHTTPClient()

	req, err := http.NewRequestWithContext(context.Background(), "POST", loginURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)

		return "", fmt.Errorf("authentication failed with status %d: %s", resp.StatusCode, string(b))
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	var ar AuthResponse
	if err := json.Unmarshal(b, &ar); err != nil {
		return "", fmt.Errorf("failed to parse auth response: %w", err)
	}

	if ar.Token != "" {
		return ar.Token, nil
	}

	if ar.JWT != "" {
		return ar.JWT, nil
	}

	if ar.JWTToken != "" {
		return ar.JWTToken, nil
	}

	return "", fmt.Errorf("no token found in authentication response")
}

func (f *ProfileFetcher) fetchData(u, token string) ([]byte, error) {
	client := f.createHTTPClient()

	req, err := http.NewRequestWithContext(context.Background(), "GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	req.Header.Set("Accept", "application/json, application/yaml, text/yaml, text/plain")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("unauthorized: authentication required or token invalid")
	}

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)

		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(b))
	}

	return io.ReadAll(resp.Body)
}

func (f *ProfileFetcher) parseProfile(data []byte) (config.Configuration, error) {
	var cfg config.Configuration

	if f.isEncryptedResponse(data) {
		return f.decryptProfile(data)
	}

	if err := json.Unmarshal(data, &cfg); err == nil {
		return cfg, nil
	}

	if err := yaml.Unmarshal(data, &cfg); err == nil {
		return cfg, nil
	}

	if f.ClientKey != "" {
		tmp, err := f.writeTempFile(data)
		if err != nil {
			return cfg, fmt.Errorf("failed to write temp body: %w", err)
		}
		defer os.Remove(tmp)

		sec := security.Crypto{EncryptionKey: f.ClientKey}

		return sec.ReadAndDecryptFile(tmp)
	}

	return cfg, fmt.Errorf("unable to parse profile as JSON, YAML, or encrypted format")
}

func (f *ProfileFetcher) isEncryptedResponse(data []byte) bool {
	var resp EncryptedProfileResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return false
	}

	return resp.Filename != "" && resp.Content != "" && resp.Key != ""
}

func (f *ProfileFetcher) decryptProfile(data []byte) (config.Configuration, error) {
	var (
		cfg  config.Configuration
		resp EncryptedProfileResponse
	)

	if err := json.Unmarshal(data, &resp); err != nil {
		return cfg, fmt.Errorf("failed to parse encrypted response: %w", err)
	}

	tmp, err := f.writeTempFile([]byte(resp.Content))
	if err != nil {
		return cfg, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmp)

	key := resp.Key
	if f.ClientKey != "" {
		key = f.ClientKey
	}

	sec := security.Crypto{EncryptionKey: key}

	return sec.ReadAndDecryptFile(tmp)
}

func (f *ProfileFetcher) writeTempFile(b []byte) (string, error) {
	tmp, err := os.CreateTemp("", "encrypted-profile-*.tmp")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	defer tmp.Close()

	if _, err := tmp.Write(b); err != nil {
		os.Remove(tmp.Name())

		return "", fmt.Errorf("failed to write to temp file: %w", err)
	}

	return tmp.Name(), nil
}

func (f *ProfileFetcher) createHTTPClient() *http.Client {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: f.SkipCertCheck}}

	return &http.Client{Timeout: f.Timeout, Transport: tr}
}

func (f *ProfileFetcher) getBaseURL() (string, error) {
	pu, err := url.Parse(f.URL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	base := fmt.Sprintf("%s://%s", pu.Scheme, pu.Host)

	return base, nil
}
