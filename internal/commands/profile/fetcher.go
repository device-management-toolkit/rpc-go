/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package profile

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
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// ProfileFetcher handles fetching profiles from HTTP/S endpoints
type ProfileFetcher struct {
	URL      string
	Token    string
	Username string
	Password string
	
	// Optional configuration
	Timeout       time.Duration
	SkipCertCheck bool
}

// AuthRequest represents the authentication request
type AuthRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// AuthResponse represents the authentication response
type AuthResponse struct {
	Token   string `json:"token,omitempty"`
	JWT     string `json:"jwt,omitempty"`
	JWTToken string `json:"jwtToken,omitempty"`
	Status  string `json:"status,omitempty"`
	Message string `json:"message,omitempty"`
}

// EncryptedProfileResponse represents the encrypted response from the endpoint
type EncryptedProfileResponse struct {
	Filename string `json:"filename"`
	Content  string `json:"content"`  // encrypted data
	Key      string `json:"key"`      // encryption key
}

// FetchProfile fetches a profile from the configured HTTP/S endpoint
func (f *ProfileFetcher) FetchProfile() (config.Configuration, error) {
	var cfg config.Configuration

	// Set default timeout if not specified
	if f.Timeout == 0 {
		f.Timeout = 30 * time.Second
	}

	// Get authentication token if needed
	token := f.Token
	if token == "" && f.Username != "" && f.Password != "" {
		log.Debug("Authenticating to obtain token...")
		authToken, err := f.authenticate()
		if err != nil {
			return cfg, fmt.Errorf("authentication failed: %w", err)
		}
		token = authToken
		log.Debug("Authentication successful")
	}

	// Fetch the profile
	log.Debugf("Fetching profile from: %s", f.URL)
	profileData, err := f.fetchData(f.URL, token)
	if err != nil {
		return cfg, fmt.Errorf("failed to fetch profile: %w", err)
	}

	// Parse the profile (try JSON first, then YAML)
	cfg, err = f.parseProfile(profileData)
	if err != nil {
		return cfg, fmt.Errorf("failed to parse profile: %w", err)
	}

	log.Debug("Profile fetched and parsed successfully")
	return cfg, nil
}

// authenticate performs authentication to get a token
func (f *ProfileFetcher) authenticate() (string, error) {
	// Parse base URL to construct login endpoint
	baseURL, err := f.getBaseURL()
	if err != nil {
		return "", err
	}

	// Try common login endpoints
	loginEndpoints := []string{
		"/login",
		"/auth/login",
		"/api/login",
		"/api/auth/login",
		"/authenticate",
		"/api/authenticate",
	}

	authReq := AuthRequest{
		Username: f.Username,
		Password: f.Password,
	}

	reqBody, err := json.Marshal(authReq)
	if err != nil {
		return "", fmt.Errorf("failed to marshal auth request: %w", err)
	}

	var lastError error
	for _, endpoint := range loginEndpoints {
		loginURL := baseURL + endpoint
		log.Debugf("Trying login endpoint: %s", loginURL)

		token, err := f.tryAuthenticate(loginURL, reqBody)
		if err != nil {
			lastError = err
			log.Debugf("Login attempt failed: %v", err)
			continue
		}

		if token != "" {
			return token, nil
		}
	}

	if lastError != nil {
		return "", fmt.Errorf("authentication failed: %w", lastError)
	}

	return "", fmt.Errorf("no valid login endpoint found")
}

// tryAuthenticate attempts authentication at a specific endpoint
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
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("authentication failed with status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	var authResp AuthResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		return "", fmt.Errorf("failed to parse auth response: %w", err)
	}

	// Try different field names for the token
	if authResp.Token != "" {
		return authResp.Token, nil
	}
	if authResp.JWT != "" {
		return authResp.JWT, nil
	}
	if authResp.JWTToken != "" {
		return authResp.JWTToken, nil
	}

	return "", fmt.Errorf("no token found in authentication response")
}

// fetchData fetches data from a URL with optional authentication
func (f *ProfileFetcher) fetchData(dataURL string, token string) ([]byte, error) {
	client := f.createHTTPClient()

	req, err := http.NewRequestWithContext(context.Background(), "GET", dataURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add authentication header if token is provided
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
		log.Debug("Added authorization header")
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
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return body, nil
}

// parseProfile attempts to parse profile data as JSON, YAML, or encrypted format
func (f *ProfileFetcher) parseProfile(data []byte) (config.Configuration, error) {
	var cfg config.Configuration

	// Check if this might be an encrypted response (has filename, content, key fields)
	if f.isEncryptedResponse(data) {
		log.Debug("Detected encrypted response format")
		return f.decryptProfile(data)
	}

	// Try parsing as direct JSON configuration
	if err := json.Unmarshal(data, &cfg); err == nil {
		log.Debug("Profile parsed as JSON")
		return cfg, nil
	}

	// Try parsing as YAML
	if err := yaml.Unmarshal(data, &cfg); err == nil {
		log.Debug("Profile parsed as YAML")
		return cfg, nil
	}

	// If all parsing attempts fail, return error
	return cfg, fmt.Errorf("unable to parse profile as JSON, YAML, or encrypted format")
}

// isEncryptedResponse checks if the data appears to be an encrypted profile response
func (f *ProfileFetcher) isEncryptedResponse(data []byte) bool {
	var response EncryptedProfileResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return false
	}
	
	// Check if response has the expected encrypted format fields
	return response.Filename != "" && response.Content != "" && response.Key != ""
}

// decryptProfile decrypts an encrypted profile response
func (f *ProfileFetcher) decryptProfile(data []byte) (config.Configuration, error) {
	var cfg config.Configuration
	
	// Parse the encrypted response
	var encryptedResp EncryptedProfileResponse
	if err := json.Unmarshal(data, &encryptedResp); err != nil {
		return cfg, fmt.Errorf("failed to parse encrypted response: %w", err)
	}
	
	log.Debugf("Decrypting profile: %s", encryptedResp.Filename)
	
	// Write encrypted content to temporary file
	tempFile, err := f.writeTempFile([]byte(encryptedResp.Content))
	if err != nil {
		return cfg, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer func() {
		if err := os.Remove(tempFile); err != nil {
			log.Debugf("Failed to remove temp file: %v", err)
		}
	}()
	
	// Create security instance and decrypt
	security := security.Crypto{EncryptionKey: encryptedResp.Key}
	cfg, err = security.ReadAndDecryptFile(tempFile)
	if err != nil {
		return cfg, fmt.Errorf("decryption failed: %w", err)
	}
	
	log.Debug("Profile decrypted and parsed successfully")
	return cfg, nil
}

// writeTempFile writes data to a temporary file and returns the file path
func (f *ProfileFetcher) writeTempFile(data []byte) (string, error) {
	tempFile, err := os.CreateTemp("", "encrypted-profile-*.tmp")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	
	defer tempFile.Close()
	
	if _, err := tempFile.Write(data); err != nil {
		os.Remove(tempFile.Name())
		return "", fmt.Errorf("failed to write to temp file: %w", err)
	}
	
	return tempFile.Name(), nil
}

// createHTTPClient creates an HTTP client with appropriate settings
func (f *ProfileFetcher) createHTTPClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: f.SkipCertCheck,
		},
	}

	return &http.Client{
		Timeout:   f.Timeout,
		Transport: transport,
	}
}

// getBaseURL extracts the base URL from the profile URL
func (f *ProfileFetcher) getBaseURL() (string, error) {
	parsedURL, err := url.Parse(f.URL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	// Get base URL (scheme + host)
	baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	// If the path contains /api/ or /profile, extract base path
	path := parsedURL.Path
	if idx := strings.Index(path, "/profile"); idx > 0 {
		baseURL += path[:idx]
	} else if idx := strings.LastIndex(path, "/api/"); idx >= 0 {
		baseURL += path[:idx+4] // Include /api/
	}

	return baseURL, nil
}