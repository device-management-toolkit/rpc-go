/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/open-amt-cloud-toolkit/rpc-go/v2/internal/flags"

	"github.com/stretchr/testify/assert"
)

func TestGetAuthToken(t *testing.T) {
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
			wantToken:    "someToken",
			wantErr:      false,
		},
		{
			name:         "Empty credentials",
			credentials:  AuthRequest{Username: "wrong", Password: "user"},
			mockResponse: AuthResponse{},
			wantToken:    "",
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(tt.mockResponse)
			}))
			defer server.Close()

			f := &flags.Flags{}
			mockAMT := new(MockAMT)
			mockWsman := new(MockWSMAN)
			service := NewProvisioningService(f)
			service.amtCommand = mockAMT
			service.interfacedWsmanMessage = mockWsman

			gotToken, err := service.GetAuthToken(server.URL+"/api/authenticate/", tt.credentials)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAuthToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotToken != tt.wantToken {
				t.Errorf("GetAuthToken() gotToken = %v, want %v", gotToken, tt.wantToken)
			}
		})
	}
}
func TestEAConfigureRequest(t *testing.T) {
	tests := []struct {
		name         string
		token        string
		profileReq   EAProfile
		mockResponse EAProfile
		wantProfile  EAProfile
		wantErr      bool
	}{
		{
			name:         "Valid profile request",
			token:        "someToken",
			profileReq:   EAProfile{NodeID: "someID", Domain: "someDomain", ReqID: "someReqID", AuthProtocol: 0, OSName: "win11", DevName: "someDevName", Icon: 1, Ver: "someVer"},
			mockResponse: EAProfile{NodeID: "someID", Domain: "someDomain", ReqID: "someReqID", AuthProtocol: 0, OSName: "win11", DevName: "someDevName", Icon: 1, Ver: "someVer"},
			wantProfile:  EAProfile{NodeID: "someID", Domain: "someDomain", ReqID: "someReqID", AuthProtocol: 0, OSName: "win11", DevName: "someDevName", Icon: 1, Ver: "someVer"},
			wantErr:      false,
		},
		{
			name:       "Valid profile request",
			token:      "someToken",
			profileReq: EAProfile{NodeID: "someID", Domain: "someDomain", ReqID: "someReqID", AuthProtocol: 0, OSName: "win11", DevName: "someDevName", Icon: 1, Ver: "someVer"},
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &flags.Flags{}
			mockAMT := new(MockAMT)
			mockWsman := new(MockWSMAN)
			service := NewProvisioningService(f)
			service.amtCommand = mockAMT
			service.interfacedWsmanMessage = mockWsman
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.wantErr {
					w.WriteHeader(http.StatusInternalServerError)
				} else {
					json.NewEncoder(w).Encode(tt.mockResponse)
				}
			}))
			defer server.Close()

			service.flags.ConfigTLSInfo.EAAddress = server.URL

			gotProfile, err := service.EAConfigureRequest(server.URL+"/configure", tt.token, tt.profileReq)
			if tt.wantErr {
				assert.Error(t, err, "EAConfigureRequest() expected an error")
			} else {
				assert.NoError(t, err, "EAConfigureRequest() unexpected error")
				assert.Equal(t, tt.wantProfile, gotProfile, "EAConfigureRequest() profile mismatch")
			}
		})
	}
}
