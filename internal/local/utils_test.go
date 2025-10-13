/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/publickey"
)

var mpsCert = publickey.PublicKeyCertificateResponse{
	ElementName:            "Intel(r) AMT Certificate",
	InstanceID:             "Intel(r) AMT Certificate: Handle: 0",
	X509Certificate:        `MIIEkzCCA3ugAwIBAgIUL3WtF7HfMKxQOHcZy65Z0tsSoLwwDQYJKoZIhvc`,
	TrustedRootCertificate: true,
	Issuer:                 "C=unknown,O=unknown,CN=MPSRoot-5bb511",
	Subject:                "C=unknown,O=unknown,CN=MPSRoot-5bb511",
	ReadOnlyCertificate:    true,
}

var caCert = publickey.PublicKeyCertificateResponse{
	ElementName:            "Intel(r) AMT Certificate",
	InstanceID:             "Intel(r) AMT Certificate: Handle: 1",
	X509Certificate:        `CERTHANDLE1MIIEkzCCA3ugAwIBAgIUL3WtF7HfMKxQOHcZy65Z0tsSoLwwDQYJKoZIhvc`,
	TrustedRootCertificate: true,
	Issuer:                 `C=US,S=Arizona,L=Chandler,CN=Unit Tests Are Us`,
	Subject:                `C=US,S=Arizona,L=Chandler,CN=Unit Test CA Root Certificate`,
}

var clientCert = publickey.PublicKeyCertificateResponse{
	ElementName:            "Intel(r) AMT Certificate",
	InstanceID:             "Intel(r) AMT Certificate: Handle: 3",
	X509Certificate:        `CERTHANDLE2AwIBAgIUBgF0PsmOxA/KJVDCcbW+n5IbemgwDQYJKoZIhvc`,
	TrustedRootCertificate: false,
	Issuer:                 `C=US,S=Arizona,L=Chandler,CN=Unit Tests Are Us`,
	Subject:                `C=US,S=Arizona,L=Chandler,CN=Unit Test Client Certificate`,
	ReadOnlyCertificate:    true,
}
