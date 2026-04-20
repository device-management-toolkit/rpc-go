/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package device

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDevicePayload_JSON_WithPasswords(t *testing.T) {
	payload := DevicePayload{
		GUID:         "test-guid",
		Hostname:     "test-host",
		Tags:         []string{},
		MPSUsername:  "admin",
		Password:     "AMT-Pass1!",
		MEBXPassword: "MEBx-Pass1!",
		MPSPassword:  "MPS-Pass1!",
	}

	data, err := json.Marshal(payload)
	require.NoError(t, err)

	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &m))

	assert.Equal(t, "AMT-Pass1!", m["password"])
	assert.Equal(t, "MEBx-Pass1!", m["mebxpassword"])
	assert.Equal(t, "MPS-Pass1!", m["mpspassword"])
}

func TestDevicePayload_JSON_WithoutPasswords(t *testing.T) {
	payload := DevicePayload{
		GUID:        "test-guid",
		Hostname:    "test-host",
		Tags:        []string{},
		MPSUsername: "admin",
	}

	data, err := json.Marshal(payload)
	require.NoError(t, err)

	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &m))

	_, hasPassword := m["password"]
	_, hasMEBX := m["mebxpassword"]
	_, hasMPS := m["mpspassword"]

	assert.False(t, hasPassword, "password should be omitted when empty")
	assert.False(t, hasMEBX, "mebxpassword should be omitted when empty")
	assert.False(t, hasMPS, "mpspassword should be omitted when empty")
}

func TestAddDevice_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/devices", r.URL.Path)
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))

		body, _ := io.ReadAll(r.Body)

		var p DevicePayload
		require.NoError(t, json.Unmarshal(body, &p))
		assert.Equal(t, "guid-123", p.GUID)

		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	payload := DevicePayload{
		GUID:        "guid-123",
		Hostname:    "host",
		Tags:        []string{},
		MPSUsername: "admin",
	}

	err := AddDevice(server.URL, "test-token", payload, false, "")
	assert.NoError(t, err)
}

func TestAddDevice_Failure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
	}))
	defer server.Close()

	payload := DevicePayload{
		GUID:        "guid-123",
		Hostname:    "host",
		Tags:        []string{},
		MPSUsername: "admin",
	}

	err := AddDevice(server.URL, "test-token", payload, false, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "409")
}

func TestUpdateDevice_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPatch, r.Method)
		assert.Equal(t, "/api/v1/devices", r.URL.Path)
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))

		body, _ := io.ReadAll(r.Body)

		var p DevicePayload
		require.NoError(t, json.Unmarshal(body, &p))
		assert.Equal(t, "guid-123", p.GUID)
		assert.Equal(t, "MPS-Pass1!", p.MPSPassword)

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	payload := DevicePayload{
		GUID:        "guid-123",
		Hostname:    "host",
		Tags:        []string{},
		MPSUsername: "admin",
		MPSPassword: "MPS-Pass1!",
	}

	err := UpdateDevice(server.URL, "test-token", payload, false, "")
	assert.NoError(t, err)
}

func TestUpdateDevice_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	payload := DevicePayload{
		GUID:        "guid-123",
		Hostname:    "host",
		Tags:        []string{},
		MPSUsername: "admin",
	}

	err := UpdateDevice(server.URL, "test-token", payload, false, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "404")
}

func TestClearDeviceMPSPassword_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPatch, r.Method)
		assert.Equal(t, "/api/v1/devices", r.URL.Path)
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		body, _ := io.ReadAll(r.Body)

		var m map[string]interface{}
		require.NoError(t, json.Unmarshal(body, &m))
		assert.Equal(t, "guid-123", m["guid"])
		assert.Equal(t, "", m["mpspassword"])

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	err := ClearDeviceMPSPassword(server.URL, "test-token", "guid-123", false, "")
	assert.NoError(t, err)
}

func TestClearDeviceMPSPassword_Failure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	err := ClearDeviceMPSPassword(server.URL, "test-token", "guid-123", false, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestDeleteDevice_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodDelete, r.Method)
		assert.Equal(t, "/api/v1/devices/guid-123", r.URL.Path)
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))

		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	err := DeleteDevice(server.URL, "test-token", "guid-123", false, "")
	assert.NoError(t, err)
}

func TestDeleteDevice_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	err := DeleteDevice(server.URL, "test-token", "guid-123", false, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "404")
}

func TestResolveDevicesEndpoint_Default(t *testing.T) {
	result := resolveDevicesEndpoint("http://localhost:8181", "")
	assert.Equal(t, "http://localhost:8181/api/v1/devices", result)
}

func TestResolveDevicesEndpoint_Custom(t *testing.T) {
	result := resolveDevicesEndpoint("http://localhost:8181", "http://other-host:9090/custom/v2/devices")
	assert.Equal(t, "http://other-host:9090/custom/v2/devices", result)
}

func TestResolveDevicesEndpoint_TrailingSlash(t *testing.T) {
	result := resolveDevicesEndpoint("http://localhost:8181/", "")
	assert.Equal(t, "http://localhost:8181/api/v1/devices", result)

	result = resolveDevicesEndpoint("", "http://other-host:9090/custom/v2/devices/")
	assert.Equal(t, "http://other-host:9090/custom/v2/devices", result)
}

func TestAddDevice_CustomEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/custom/v2/devices", r.URL.Path)

		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	payload := DevicePayload{
		GUID:        "guid-123",
		Hostname:    "host",
		Tags:        []string{},
		MPSUsername: "admin",
	}

	err := AddDevice(server.URL, "test-token", payload, false, server.URL+"/custom/v2/devices")
	assert.NoError(t, err)
}

func TestUpdateDevice_CustomEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPatch, r.Method)
		assert.Equal(t, "/custom/v2/devices", r.URL.Path)

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	payload := DevicePayload{
		GUID:        "guid-123",
		Hostname:    "host",
		Tags:        []string{},
		MPSUsername: "admin",
	}

	err := UpdateDevice(server.URL, "test-token", payload, false, server.URL+"/custom/v2/devices")
	assert.NoError(t, err)
}

func TestClearDeviceMPSPassword_CustomEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPatch, r.Method)
		assert.Equal(t, "/custom/v2/devices", r.URL.Path)

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	err := ClearDeviceMPSPassword(server.URL, "test-token", "guid-123", false, server.URL+"/custom/v2/devices")
	assert.NoError(t, err)
}

func TestDeleteDevice_CustomEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodDelete, r.Method)
		assert.Equal(t, "/custom/v2/devices/guid-123", r.URL.Path)

		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	err := DeleteDevice(server.URL, "test-token", "guid-123", false, server.URL+"/custom/v2/devices")
	assert.NoError(t, err)
}
