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
	// Missing address
	err := cmd.Validate()
	assert.Error(t, err)

	cmd = &ProxyCmd{Address: "proxy.example.com", Port: 8080}
	// No base password provided; base Validate will prompt but not in tests, so set password and control mode via base
	cmd.Password = "test123"
	cmd.ControlMode = 1
	err = cmd.Validate()
	assert.NoError(t, err)
}

func TestProxyCmd_Run_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ws := mock.NewMockWSMANer(ctrl)
	ws.EXPECT().AddHTTPProxyAccessPoint("proxy.example.com", int(ipshttp.InfoFormatFQDN), 8080, "example.com").Return(ipshttp.Response{}, nil)

	cmd := &ProxyCmd{Address: "proxy.example.com", Port: 8080, NetworkDnsSuffix: "example.com"}
	cmd.Password = "test123"
	cmd.ControlMode = 1
	cmd.WSMan = ws

	ctx := &commands.Context{}
	err := cmd.Run(ctx)
	assert.NoError(t, err)
}

func TestProxyCmd_Run_NotActivated(t *testing.T) {
	cmd := &ProxyCmd{Address: "proxy.example.com", Port: 8080}
	cmd.Password = "test123"
	cmd.ControlMode = 0

	err := cmd.Run(&commands.Context{})
	assert.Error(t, err)
}

func TestProxyCmd_Run_ErrorFromWSMAN(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ws := mock.NewMockWSMANer(ctrl)
	ws.EXPECT().AddHTTPProxyAccessPoint("192.0.2.1", int(ipshttp.InfoFormatIPv4), 3128, "").Return(ipshttp.Response{}, errors.New("boom"))

	cmd := &ProxyCmd{Address: "192.0.2.1", Port: 3128}
	cmd.Password = "test123"
	cmd.ControlMode = 1
	cmd.WSMan = ws

	err := cmd.Run(&commands.Context{})
	assert.Error(t, err)
}
