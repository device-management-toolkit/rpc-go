/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"software.sslmate.com/src/go-pkcs12"
)

type Composite struct {
	Cert        *x509.Certificate
	Pem         string
	Fingerprint string
	privateKey  *rsa.PrivateKey
}

type CompositeChain struct {
	Root         Composite
	Intermediate Composite
	Leaf         Composite
	PfxData      []byte
	Pfxb64       string
	PfxPassword  string
}

func (c *Composite) StripPem() string {
	stripped := strings.Replace(c.Pem, "-----BEGIN CERTIFICATE-----", "", -1)
	stripped = strings.Replace(stripped, "-----END CERTIFICATE-----", "", -1)

	return strings.Replace(stripped, "\n", "", -1)
}

func (c *Composite) GenerateCert(template, parent *x509.Certificate, pub, priv any) error {
	rawBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		log.Error(err)
		return err
	}

	c.Cert, err = x509.ParseCertificate(rawBytes)
	if err != nil {
		log.Error(err)
		return err
	}

	hash := sha256.Sum256(c.Cert.Raw)
	c.Fingerprint = hex.EncodeToString(hash[:])
	c.Pem = string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.Cert.Raw,
	}))

	return nil
}

func GetRootCATemplate() x509.Certificate {
	// subject and issuer are the same
	//template.Issuer = template.Subject
	sharedName := pkix.Name{
		Organization:       []string{"vPro"},
		OrganizationalUnit: []string{"Remote Provisioning Client"},
		CommonName:         "RPC Root CA Certificate",
	}

	return x509.Certificate{
		SerialNumber: big.NewInt(1000),
		Subject:      sharedName,
		NotBefore:    time.Now().AddDate(-1, 0, 0),
		NotAfter:     time.Now().AddDate(20, 0, 0),
		IsCA:         true,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign |
			x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDataEncipherment,
		BasicConstraintsValid: true,
	}
}

func GetIntermediateCATemplate() x509.Certificate {
	return x509.Certificate{
		SerialNumber: big.NewInt(1500),
		Subject: pkix.Name{
			Organization:       []string{"Intel"},
			OrganizationalUnit: []string{"Remote Provisioning Client"},
			CommonName:         "RPC Intermediate CA Certificate",
			Country:            []string{"US"},
		},
		NotBefore: time.Now().AddDate(-1, 0, 0),
		NotAfter:  time.Now().AddDate(20, 0, 0),
		IsCA:      true,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign |
			x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDataEncipherment,
		BasicConstraintsValid: true,
	}
}

func GetLeafTemplate() x509.Certificate {
	return x509.Certificate{
		SerialNumber: big.NewInt(1500),
		Subject: pkix.Name{
			Organization:       []string{"Intel"},
			OrganizationalUnit: []string{"Remote Provisioning Client"},
			CommonName:         "RPC Leaf Certificate",
			Country:            []string{"US"},
		},
		NotBefore:   time.Now().AddDate(-1, 0, 0),
		NotAfter:    time.Now().AddDate(20, 0, 0),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign |
			x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDataEncipherment,
		BasicConstraintsValid: true,
	}
}

func GetAMTClientTemplate() x509.Certificate {
	return x509.Certificate{
		SerialNumber: big.NewInt(2000),
		Subject: pkix.Name{
			Organization:       []string{"vPro"},
			OrganizationalUnit: []string{"AMT Client"},
			CommonName:         "Self Signed TLS Certificate",
		},
		NotBefore:   time.Now().AddDate(-1, 0, 0),
		NotAfter:    time.Now().AddDate(20, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign |
			x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDataEncipherment,
		BasicConstraintsValid: true,
	}
}

func NewRootComposite() (Composite, error) {
	var err error

	composite := Composite{}

	composite.privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Error(err)
		return composite, err
	}

	rootCATemplate := GetRootCATemplate()

	err = composite.GenerateCert(&rootCATemplate, &rootCATemplate, &composite.privateKey.PublicKey, composite.privateKey)
	if err != nil {
		log.Error(err)
	}

	return composite, err
}

func NewSignedAMTComposite(derKey string, parent *Composite) (Composite, error) {
	composite := Composite{}
	clientPubKey, err := ParseAMTPublicKey(derKey)
	template := GetAMTClientTemplate()

	err = composite.GenerateCert(&template, parent.Cert, clientPubKey, parent.privateKey)
	if err != nil {
		log.Error(err)
	}

	return composite, err
}

func ParseAMTPublicKey(derKey string) (any, error) {
	var err error

	var pubKey any

	pemFormat := fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----", derKey)
	pemBlock, _ := pem.Decode([]byte(pemFormat))
	pubKey, err = x509.ParsePKCS1PublicKey(pemBlock.Bytes)
	// AMT uses different formats on different versions evidently
	if strings.Contains(fmt.Sprint(err), "use ParsePKIXPublicKey instead") {
		pubKey, err = x509.ParsePKIXPublicKey(pemBlock.Bytes)
	}

	return pubKey, err
}

func NewCompositeChain(password string) (CompositeChain, error) {
	chain := CompositeChain{}
	chain.Root, _ = NewRootComposite()

	chain.Intermediate = Composite{}
	template := GetIntermediateCATemplate()

	var err error

	chain.Intermediate.privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Error(err)
		return chain, err
	}

	err = chain.Intermediate.GenerateCert(&template, chain.Root.Cert, &chain.Intermediate.privateKey.PublicKey, chain.Root.privateKey)
	if err != nil {
		log.Error(err)
		return chain, err
	}

	chain.Leaf = Composite{}
	template = GetLeafTemplate()

	chain.Leaf.privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Error(err)
		return chain, err
	}

	err = chain.Leaf.GenerateCert(&template, chain.Intermediate.Cert, &chain.Leaf.privateKey.PublicKey, chain.Intermediate.privateKey)
	if err != nil {
		log.Error(err)
		return chain, err
	}

	chain.PfxPassword = password
	chain.PfxData, err = pkcs12.Legacy.Encode(
		chain.Leaf.privateKey,
		chain.Leaf.Cert,
		[]*x509.Certificate{
			chain.Intermediate.Cert,
			chain.Root.Cert},
		chain.PfxPassword)
	chain.Pfxb64 = base64.StdEncoding.EncodeToString(chain.PfxData)

	return chain, err
}
