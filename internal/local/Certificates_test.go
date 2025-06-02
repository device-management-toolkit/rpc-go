package local

import (
	// "encoding/xml"
	"testing"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/publickey"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/publicprivate"
	"github.com/device-management-toolkit/rpc-go/v2/internal/flags"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func TestPruneCerts(t *testing.T) {
	tests := []struct {
		name          string
		expectedError bool
	}{
		{
			name:          "successful pruning",
			expectedError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &flags.Flags{}
			mockAMT := new(MockAMT)
			mockWsman := new(MockWSMAN)
			service := NewProvisioningService(f)
			service.amtCommand = mockAMT
			service.interfacedWsmanMessage = mockWsman

			service.PruneCerts()
		})
	}
}

type test struct {
	name       string
	setupMocks func(*MockWSMAN)
	res        any
	err        error
}

func TestGetCertificates(t *testing.T) {
	tests := []test{
		{
			name: "success",
			setupMocks: func(mock *MockWSMAN) {
			},
			res: SecuritySettings{
				ProfileAssociation: []ProfileAssociation{
					{
						Type:              "Wireless",
						ProfileID:         "wifi8021x",
						RootCertificate:   interface{}(nil),
						ClientCertificate: interface{}(nil),
						Key:               interface{}(nil),
					},
				},
				Certificates: []publickey.RefinedPublicKeyCertificateResponse{},
				Keys:         []publicprivate.RefinedPublicPrivateKeyPair(nil),
			},
			err: nil,
		},
		{
			name: "GetCertificates fails",
			setupMocks: func(mock *MockWSMAN) {
				errGetConcreteDependencies = utils.WSMANMessageError
			},
			res: SecuritySettings{},
			err: utils.WSMANMessageError,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			service, mockWsman := setupProvisioningService()
			tc.setupMocks(mockWsman)

			response, err := service.GetCertificates()

			if tc.err != nil {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tc.res, response)
		})
	}

	errGetConcreteDependencies = nil
}
