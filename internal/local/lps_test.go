package local

import (
	"encoding/xml"
	"errors"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/amt/general"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/amt/setupandconfiguration"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/ips/hostbasedsetup"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	amt2 "rpc/internal/amt"
	"rpc/internal/flags"
	"rpc/pkg/utils"
	"testing"
	"time"
)

// Mock the AMT Hardware
type MockAMT struct{}

var mockStandardErr error = errors.New("yep, it failed")

func (c MockAMT) Initialize() (int, error) {
	return utils.Success, nil
}

var mockVersionDataErr error = nil

func (c MockAMT) GetVersionDataFromME(key string, amtTimeout time.Duration) (string, error) {
	return "Version", mockVersionDataErr
}

var mockUUID = "123-456-789"
var mockUUIDErr error = nil

func (c MockAMT) GetUUID() (string, error) { return mockUUID, mockUUIDErr }

var mockControlMode = 0
var mockControlModeErr error = nil

func (c MockAMT) GetControlMode() (int, error) { return mockControlMode, mockControlModeErr }

var mockDNSSuffix = "dns.org"
var mockDNSSuffixErr error = nil

func (c MockAMT) GetDNSSuffix() (string, error) { return mockDNSSuffix, mockDNSSuffixErr }

var mockOSDNSSuffix = "os.dns.org"
var mockOSDNSSuffixErr error = nil

func (c MockAMT) GetOSDNSSuffix() (string, error) { return mockOSDNSSuffix, mockOSDNSSuffixErr }

var mockCertHashes []amt2.CertHashEntry
var mockCertHashesErr error = nil

func (c MockAMT) GetCertificateHashes() ([]amt2.CertHashEntry, error) {
	return mockCertHashes, mockCertHashesErr
}

var mockRemoteAcessConnectionStatus = amt2.RemoteAccessStatus{}
var mockRemoteAcessConnectionStatusErr error = nil

func (c MockAMT) GetRemoteAccessConnectionStatus() (amt2.RemoteAccessStatus, error) {
	return mockRemoteAcessConnectionStatus, mockRemoteAcessConnectionStatusErr
}

var mockLANInterfaceSettings = amt2.InterfaceSettings{}
var mockLANInterfaceSettingsErr error = nil

func (c MockAMT) GetLANInterfaceSettings(useWireless bool) (amt2.InterfaceSettings, error) {
	return mockLANInterfaceSettings, mockLANInterfaceSettingsErr
}

var mockLocalSystemAccountErr error = nil

func (c MockAMT) GetLocalSystemAccount() (amt2.LocalSystemAccount, error) {
	return amt2.LocalSystemAccount{Username: "Username", Password: "Password"}, mockLocalSystemAccountErr
}

var mockUnprovisionCode = 0
var mockUnprovisionErr error = nil

func (c MockAMT) Unprovision() (int, error) { return mockUnprovisionCode, mockUnprovisionErr }

// TODO: remove these when local-acm-activation branch is available in main
type ResponseFuncArray []func(w http.ResponseWriter, r *http.Request)

func setupWsmanResponses(t *testing.T, f *flags.Flags, responses ResponseFuncArray) ProvisioningService {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		if len(responses) > 0 {
			responses[0](w, r)
			responses = responses[1:]
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	})
	return setupWithWsmanClient(f, handler)
}

func respondServerErrFunc() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func respondBadXmlFunc(t *testing.T) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		_, resultCode := w.Write([]byte(`not really xml is it?`))
		assert.Nil(t, resultCode)
	}
}

func respondMsgFunc(t *testing.T, msg any) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		bytes, err := xml.Marshal(msg)
		assert.Nil(t, err)
		_, err = w.Write(bytes)
		assert.Nil(t, err)
	}
}

func respondStringFunc(t *testing.T, msg string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(msg))
		assert.Nil(t, err)
	}
}

func setupService(f *flags.Flags) ProvisioningService {
	service := NewProvisioningService(f)
	service.amtCommand = MockAMT{}
	return service
}

func setupWithTestServer(f *flags.Flags, handler http.Handler) ProvisioningService {
	service := setupService(f)
	server := httptest.NewServer(handler)
	service.serverURL = server.URL
	return service
}

func setupWithWsmanClient(f *flags.Flags, handler http.Handler) ProvisioningService {
	service := setupWithTestServer(f, handler)
	service.setupWsmanClient("admin", "password")
	return service
}

func TestExecute(t *testing.T) {
	f := &flags.Flags{}

	t.Run("execute CommandAMTInfo should succeed", func(t *testing.T) {
		f.Command = utils.CommandAMTInfo
		resultCode := ExecuteCommand(f)
		assert.Equal(t, utils.Success, resultCode)
	})

	t.Run("execute CommandVersion should succeed", func(t *testing.T) {
		f.Command = utils.CommandVersion
		resultCode := ExecuteCommand(f)
		assert.Equal(t, utils.Success, resultCode)
	})

	t.Run("execute CommandConfigure with no SubCommand fails", func(t *testing.T) {
		f.Command = utils.CommandConfigure
		resultCode := ExecuteCommand(f)
		assert.Equal(t, utils.IncorrectCommandLineParameters, resultCode)
	})
}

func respondServerError(w http.ResponseWriter) {
	w.WriteHeader(http.StatusInternalServerError)
}

func respondBadXML(t *testing.T, w http.ResponseWriter) {
	_, err := w.Write([]byte(`not really xml is it?`))
	assert.Nil(t, err)
}

var mockGenerlSettingsResponse = general.Response{}

func respondGeneralSettings(t *testing.T, w http.ResponseWriter) {
	xmlString, err := xml.Marshal(mockGenerlSettingsResponse)
	assert.Nil(t, err)
	_, err = w.Write(xmlString)
	assert.Nil(t, err)
}

var mockHostBasedSetupResponse = hostbasedsetup.Response{}

func respondHostBasedSetup(t *testing.T, w http.ResponseWriter) {
	xmlString, err := xml.Marshal(mockHostBasedSetupResponse)
	assert.Nil(t, err)
	_, err = w.Write(xmlString)
	assert.Nil(t, err)
}

var mockUnprovisionResponse = setupandconfiguration.UnprovisionResponse{}

func respondUnprovision(t *testing.T, w http.ResponseWriter) {
	xmlString, err := xml.Marshal(mockUnprovisionResponse)
	assert.Nil(t, err)
	_, err = w.Write(xmlString)
	assert.Nil(t, err)
}
