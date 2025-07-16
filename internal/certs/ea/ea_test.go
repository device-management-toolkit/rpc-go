/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package ea

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetEAAuthToken(t *testing.T) {
	tests := []struct {
		name         string
		credentials  AuthRequest
		mockResponse AuthResponse
		statusCode   int
		wantToken    string
		wantErr      bool
	}{
		{
			name:         "Valid credentials",
			credentials:  AuthRequest{Username: "user", Password: "pass"},
			mockResponse: AuthResponse{Token: "someToken"},
			statusCode:   http.StatusOK,
			wantToken:    "someToken",
			wantErr:      false,
		},
		{
			name:         "Empty response",
			credentials:  AuthRequest{Username: "wrong", Password: "user"},
			mockResponse: AuthResponse{},
			statusCode:   http.StatusOK,
			wantToken:    "",
			wantErr:      false,
		},
		{
			name:         "Server error",
			credentials:  AuthRequest{Username: "user", Password: "pass"},
			mockResponse: AuthResponse{},
			statusCode:   http.StatusInternalServerError,
			wantToken:    "",
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)

				if tt.statusCode == http.StatusOK {
					json.NewEncoder(w).Encode(tt.mockResponse)
				}
			}))
			defer server.Close()

			gotToken, err := GetAuthToken(server.URL+"/api/authenticate/", tt.credentials)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetEAAuthToken() error = %v, wantErr %v", err, tt.wantErr)

				return
			}

			if gotToken != tt.wantToken {
				t.Errorf("GetEAAuthToken() gotToken = %v, want %v", gotToken, tt.wantToken)
			}
		})
	}
}
func TestConfigureEACertificate(t *testing.T) {
	tests := []struct {
		name         string
		token        string
		profileReq   Profile
		mockResponse Profile
		statusCode   int
		wantProfile  Profile
		wantErr      bool
	}{
		{
			name:         "Valid profile request",
			token:        "someToken",
			profileReq:   Profile{NodeID: "someID", Domain: "someDomain", ReqID: "someReqID", AuthProtocol: 0, OSName: "win11", DevName: "someDevName", Icon: 1, Ver: "someVer"},
			mockResponse: Profile{NodeID: "someID", Domain: "someDomain", ReqID: "someReqID", AuthProtocol: 0, OSName: "win11", DevName: "someDevName", Icon: 1, Ver: "someVer"},
			statusCode:   http.StatusOK,
			wantProfile:  Profile{NodeID: "someID", Domain: "someDomain", ReqID: "someReqID", AuthProtocol: 0, OSName: "win11", DevName: "someDevName", Icon: 1, Ver: "someVer"},
			wantErr:      false,
		},
		{
			name:       "Server error",
			token:      "someToken",
			profileReq: Profile{NodeID: "someID", Domain: "someDomain", ReqID: "someReqID", AuthProtocol: 0, OSName: "win11", DevName: "someDevName", Icon: 1, Ver: "someVer"},
			statusCode: http.StatusInternalServerError,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)

				if tt.statusCode == http.StatusOK {
					json.NewEncoder(w).Encode(tt.mockResponse)
				}
			}))
			defer server.Close()

			gotProfile, err := ConfigureCertificate(server.URL+"/configure", tt.token, tt.profileReq)
			if tt.wantErr {
				assert.Error(t, err, "ConfigureEACertificate() expected an error")
			} else {
				assert.NoError(t, err, "ConfigureEACertificate() unexpected error")
				assert.Equal(t, tt.wantProfile, gotProfile, "ConfigureEACertificate() profile mismatch")
			}
		})
	}
}
