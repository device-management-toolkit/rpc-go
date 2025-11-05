/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	"errors"
	"testing"

	ipshttp "github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/ips/http"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestProxyCmd_Validate(t *testing.T) {
	cmd := &ProxyCmd{}
	cmd.ControlMode = 1
	// Missing address for adding
	err := cmd.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "address is required for adding a proxy")

	cmd = &ProxyCmd{Address: "proxy.example.com", Port: 8080}
	cmd.ControlMode = 1
	// Missing NetworkDnsSuffix for adding
	err = cmd.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "network DNS suffix is required for adding a proxy")

	cmd = &ProxyCmd{Address: "proxy.example.com", Port: 8080, NetworkDnsSuffix: "example.com"}
	cmd.ControlMode = 1
	err = cmd.Validate()
	assert.NoError(t, err)

	// Test with --list flag (no other params required)
	cmd = &ProxyCmd{List: true}
	cmd.ControlMode = 1
	err = cmd.Validate()
	assert.NoError(t, err)

	// Test with --delete flag (only address required)
	cmd = &ProxyCmd{Delete: true, Address: "proxy.example.com"}
	cmd.ControlMode = 1
	err = cmd.Validate()
	assert.NoError(t, err)

	// Test --delete without address
	cmd = &ProxyCmd{Delete: true}
	cmd.ControlMode = 1
	err = cmd.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "address is required when using --delete")

	// Test conflicting flags
	cmd = &ProxyCmd{List: true, Delete: true}
	cmd.ControlMode = 1
	err = cmd.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot use --list and --delete flags together")
}

func TestProxyCmd_Run_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ws := mock.NewMockWSMANer(ctrl)
	ws.EXPECT().AddHTTPProxyAccessPoint("proxy.example.com", int(ipshttp.InfoFormatFQDN), 8080, "example.com").Return(ipshttp.Response{}, nil)

	cmd := &ProxyCmd{Address: "proxy.example.com", Port: 8080, NetworkDnsSuffix: "example.com"}
	cmd.ControlMode = 1
	cmd.WSMan = ws

	ctx := &commands.Context{
		AMTPassword: "test-pass",
	}
	err := cmd.Run(ctx)
	assert.NoError(t, err)
}

func TestProxyCmd_Run_NotActivated(t *testing.T) {
	cmd := &ProxyCmd{Address: "proxy.example.com", Port: 8080}
	cmd.ControlMode = 0

	err := cmd.Run(&commands.Context{})
	assert.Error(t, err)
}

func TestProxyCmd_Run_ErrorFromWSMAN(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ws := mock.NewMockWSMANer(ctrl)
	ws.EXPECT().AddHTTPProxyAccessPoint("192.0.2.1", int(ipshttp.InfoFormatIPv4), 3128, "test.com").Return(ipshttp.Response{}, errors.New("boom"))

	cmd := &ProxyCmd{Address: "192.0.2.1", Port: 3128, NetworkDnsSuffix: "test.com"}
	cmd.ControlMode = 1
	cmd.WSMan = ws

	err := cmd.Run(&commands.Context{AMTPassword: "test-pass"})
	assert.Error(t, err)
}

func TestProxyCmd_Run_List_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ws := mock.NewMockWSMANer(ctrl)

	// Mock response with proxy access points
	accessPoints := []ipshttp.HTTPProxyAccessPointItem{
		{
			Name:             "Intel(r) ME:HTTP Proxy Access Point 1",
			AccessInfo:       "proxy.example.com",
			Port:             8080,
			NetworkDnsSuffix: "example.com",
			InfoFormat:       201, // FQDN
		},
	}

	ws.EXPECT().GetHTTPProxyAccessPoints().Return(accessPoints, nil)

	cmd := &ProxyCmd{List: true}
	cmd.ControlMode = 1
	cmd.WSMan = ws

	ctx := &commands.Context{
		AMTPassword: "test-pass",
	}
	err := cmd.Run(ctx)
	assert.NoError(t, err)
}

func TestProxyCmd_Run_List_Empty(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ws := mock.NewMockWSMANer(ctrl)

	// Mock response with no proxy access points
	var emptyAccessPoints []ipshttp.HTTPProxyAccessPointItem
	ws.EXPECT().GetHTTPProxyAccessPoints().Return(emptyAccessPoints, nil)

	cmd := &ProxyCmd{List: true}
	cmd.ControlMode = 1
	cmd.WSMan = ws

	ctx := &commands.Context{
		AMTPassword: "test-pass",
	}
	err := cmd.Run(ctx)
	assert.NoError(t, err)
}

func TestProxyCmd_Run_List_Error(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ws := mock.NewMockWSMANer(ctrl)
	ws.EXPECT().GetHTTPProxyAccessPoints().Return(nil, errors.New("failed to retrieve"))

	cmd := &ProxyCmd{List: true}
	cmd.ControlMode = 1
	cmd.WSMan = ws

	ctx := &commands.Context{
		AMTPassword: "test-pass",
	}
	err := cmd.Run(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to retrieve HTTP proxy access points")
}

func TestProxyCmd_Run_Delete_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ws := mock.NewMockWSMANer(ctrl)

	// Mock response with proxy access points
	accessPoints := []ipshttp.HTTPProxyAccessPointItem{
		{
			Name:             "Intel(r) ME:HTTP Proxy Access Point 1",
			AccessInfo:       "proxy.example.com",
			Port:             8080,
			NetworkDnsSuffix: "example.com",
			InfoFormat:       201, // FQDN
		},
	}

	ws.EXPECT().GetHTTPProxyAccessPoints().Return(accessPoints, nil)

	// Mock delete response
	deleteResp := ipshttp.ProxyAccessPointResponse{}
	ws.EXPECT().DeleteHTTPProxyAccessPoint("Intel(r) ME:HTTP Proxy Access Point 1").Return(deleteResp, nil)

	cmd := &ProxyCmd{Delete: true, Address: "proxy.example.com", Port: 8080}
	cmd.ControlMode = 1
	cmd.WSMan = ws

	ctx := &commands.Context{
		AMTPassword: "test-pass",
	}
	err := cmd.Run(ctx)
	assert.NoError(t, err)
}

func TestProxyCmd_Run_Delete_NotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ws := mock.NewMockWSMANer(ctrl)

	// Mock response with no matching proxy access points
	accessPoints := []ipshttp.HTTPProxyAccessPointItem{
		{
			Name:             "Intel(r) ME:HTTP Proxy Access Point 1",
			AccessInfo:       "other.proxy.com",
			Port:             8080,
			NetworkDnsSuffix: "example.com",
			InfoFormat:       201, // FQDN
		},
	}

	ws.EXPECT().GetHTTPProxyAccessPoints().Return(accessPoints, nil)

	cmd := &ProxyCmd{Delete: true, Address: "proxy.example.com"}
	cmd.ControlMode = 1
	cmd.WSMan = ws

	ctx := &commands.Context{
		AMTPassword: "test-pass",
	}
	err := cmd.Run(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no HTTP proxy access point found with address: proxy.example.com")
}

func TestProxyCmd_Run_Delete_GetAccessPointsError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ws := mock.NewMockWSMANer(ctrl)
	ws.EXPECT().GetHTTPProxyAccessPoints().Return(nil, errors.New("failed to retrieve"))

	cmd := &ProxyCmd{Delete: true, Address: "proxy.example.com"}
	cmd.ControlMode = 1
	cmd.WSMan = ws

	ctx := &commands.Context{
		AMTPassword: "test-pass",
	}
	err := cmd.Run(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to retrieve HTTP proxy access points")
}

func TestProxyCmd_Run_Delete_RemoveError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ws := mock.NewMockWSMANer(ctrl)

	// Mock response with proxy access points
	accessPoints := []ipshttp.HTTPProxyAccessPointItem{
		{
			Name:             "Intel(r) ME:HTTP Proxy Access Point 1",
			AccessInfo:       "proxy.example.com",
			Port:             8080,
			NetworkDnsSuffix: "example.com",
			InfoFormat:       201, // FQDN
		},
	}

	ws.EXPECT().GetHTTPProxyAccessPoints().Return(accessPoints, nil)
	ws.EXPECT().DeleteHTTPProxyAccessPoint("Intel(r) ME:HTTP Proxy Access Point 1").Return(ipshttp.ProxyAccessPointResponse{}, errors.New("delete failed"))

	cmd := &ProxyCmd{Delete: true, Address: "proxy.example.com", Port: 8080}
	cmd.ControlMode = 1
	cmd.WSMan = ws

	ctx := &commands.Context{
		AMTPassword: "test-pass",
	}
	err := cmd.Run(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete HTTP proxy access point")
}
