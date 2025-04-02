package local

import (
	"reflect"
	"strings"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/publickey"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/publicprivate"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/cim/concrete"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/cim/credential"
	"github.com/open-amt-cloud-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

const (
	TypeWireless string = "Wireless"
	TypeTLS      string = "TLS"
	TypeWired    string = "Wired"
)

type (
	SecuritySettings struct {
		ProfileAssociation []ProfileAssociation `json:"ProfileAssociation"`
		Certificates       interface{}          `json:"Certificates"`
		Keys               interface{}          `json:"PublicKeys"`
	}

	ProfileAssociation struct {
		Type              string      `json:"Type"`
		ProfileID         string      `json:"ProfileID"`
		RootCertificate   interface{} `json:"RootCertificate,omitempty"`
		ClientCertificate interface{} `json:"ClientCertificate,omitempty"`
		Key               interface{} `json:"PublicKey,omitempty"`
	}
	Certificates struct {
		ConcreteDependencyResponse   []concrete.ConcreteDependency
		PublicKeyCertificateResponse []publickey.RefinedPublicKeyCertificateResponse
		PublicPrivateKeyPairResponse []publicprivate.RefinedPublicPrivateKeyPair
		CIMCredentialContextResponse credential.Items
	}
)

func (service *ProvisioningService) PruneCerts() error {
	getCertificateResponse, err := service.GetCertificates()
	if err != nil {
		return nil
	}

	for i := range getCertificateResponse.Certificates.([]publickey.RefinedPublicKeyCertificateResponse) {
		cert := getCertificateResponse.Certificates.([]publickey.RefinedPublicKeyCertificateResponse)[i]
		if cert.AssociatedProfiles == nil {
			err := service.interfacedWsmanMessage.DeletePublicCert(cert.InstanceID)
			if err != nil {
				log.Debugf("unable to delete: %s %s", cert.InstanceID, err)
			}
		}
	}

	for i := range getCertificateResponse.Keys.([]publicprivate.RefinedPublicPrivateKeyPair) {
		key := getCertificateResponse.Keys.([]publicprivate.RefinedPublicPrivateKeyPair)[i]
		if key.CertificateHandle == "" {
			err := service.interfacedWsmanMessage.DeletePublicPrivateKeyPair(key.InstanceID)
			if err != nil {
				log.Debugf("unable to delete: %s %s", key.InstanceID, err)
			}
		}
	}
	return nil
}

func (service *ProvisioningService) GetCertificates() (SecuritySettings, error) {
	concreteDepResponse, err := service.interfacedWsmanMessage.GetConcreteDependencies()
	if err != nil {
		return SecuritySettings{}, err
	}

	pubKeyCertResponse, err := service.interfacedWsmanMessage.GetPublicKeyCerts()
	if err != nil {
		return SecuritySettings{}, err
	}

	pubPrivKeyPairResponse, err := service.interfacedWsmanMessage.GetPublicPrivateKeyPairs()
	if err != nil {
		return SecuritySettings{}, err
	}

	credentialResponse, err := service.interfacedWsmanMessage.GetCredentialRelationships()
	if err != nil {
		return SecuritySettings{}, err
	}

	certificates := Certificates{
		ConcreteDependencyResponse:   concreteDepResponse,
		PublicKeyCertificateResponse: pubKeyCertResponse,
		PublicPrivateKeyPairResponse: pubPrivKeyPairResponse,
		CIMCredentialContextResponse: credentialResponse,
	}

	securitySettings := SecuritySettings{
		Certificates: certificates.PublicKeyCertificateResponse,
		Keys:         certificates.PublicPrivateKeyPairResponse,
	}

	if !reflect.DeepEqual(certificates.CIMCredentialContextResponse, credential.PullResponse{}) {
		processCertificates(certificates.CIMCredentialContextResponse.CredentialContextTLS, certificates, TypeTLS, &securitySettings)
		processCertificates(certificates.CIMCredentialContextResponse.CredentialContext, certificates, TypeWireless, &securitySettings)
		processCertificates(certificates.CIMCredentialContextResponse.CredentialContext8021x, certificates, TypeWired, &securitySettings)
	}

	return securitySettings, nil
}

func processConcreteDependencies(certificateHandle string, profileAssociation *ProfileAssociation, dependancyItems []concrete.ConcreteDependency, keyPairItems []publicprivate.RefinedPublicPrivateKeyPair) {
	for x := range dependancyItems {
		if dependancyItems[x].Antecedent.ReferenceParameters.SelectorSet.Selectors[0].Text != certificateHandle {
			continue
		}

		keyHandle := dependancyItems[x].Dependent.ReferenceParameters.SelectorSet.Selectors[0].Text

		for i := range keyPairItems {
			if keyPairItems[i].InstanceID == keyHandle {
				profileAssociation.Key = keyPairItems[i]

				break
			}
		}
	}
}

func buildCertificateAssociations(profileAssociation ProfileAssociation, securitySettings *SecuritySettings) {
	var publicKeyHandle string

	// If a client cert, update the associated public key w/ the cert's handle
	if profileAssociation.ClientCertificate != nil {
		// Loop thru public keys looking for the one that matches the current profileAssociation's key
		for i, existingKeyPair := range securitySettings.Keys.([]publicprivate.RefinedPublicPrivateKeyPair) {
			// If found update that key with the profileAssociation's certificate handle
			if existingKeyPair.InstanceID == profileAssociation.Key.(publicprivate.RefinedPublicPrivateKeyPair).InstanceID {
				securitySettings.Keys.([]publicprivate.RefinedPublicPrivateKeyPair)[i].CertificateHandle = profileAssociation.ClientCertificate.(publickey.RefinedPublicKeyCertificateResponse).InstanceID
				// save this public key handle since we know it pairs with the profileAssociation's certificate
				publicKeyHandle = securitySettings.Keys.([]publicprivate.RefinedPublicPrivateKeyPair)[i].InstanceID

				break
			}
		}
	}

	// Loop thru certificates looking for the one that matches the current profileAssociation's certificate and append profile name
	for i := range securitySettings.Certificates.([]publickey.RefinedPublicKeyCertificateResponse) {
		if (profileAssociation.ClientCertificate != nil && securitySettings.Certificates.([]publickey.RefinedPublicKeyCertificateResponse)[i].InstanceID == profileAssociation.ClientCertificate.(publickey.RefinedPublicKeyCertificateResponse).InstanceID) ||
			(profileAssociation.RootCertificate != nil && securitySettings.Certificates.([]publickey.RefinedPublicKeyCertificateResponse)[i].InstanceID == profileAssociation.RootCertificate.(publickey.RefinedPublicKeyCertificateResponse).InstanceID) {
			// if client cert found, associate the previously found key handle with it
			if !securitySettings.Certificates.([]publickey.RefinedPublicKeyCertificateResponse)[i].TrustedRootCertificate {
				securitySettings.Certificates.([]publickey.RefinedPublicKeyCertificateResponse)[i].PublicKeyHandle = publicKeyHandle
			}

			securitySettings.Certificates.([]publickey.RefinedPublicKeyCertificateResponse)[i].AssociatedProfiles = append(securitySettings.Certificates.([]publickey.RefinedPublicKeyCertificateResponse)[i].AssociatedProfiles, profileAssociation.ProfileID)

			break
		}
	}
}

func buildProfileAssociations(certificateHandle string, profileAssociation *ProfileAssociation, response Certificates, securitySettings *SecuritySettings) {
	isNewProfileAssociation := true

	for idx := range response.PublicKeyCertificateResponse {
		if response.PublicKeyCertificateResponse[idx].InstanceID != certificateHandle {
			continue
		}

		if response.PublicKeyCertificateResponse[idx].TrustedRootCertificate {
			profileAssociation.RootCertificate = response.PublicKeyCertificateResponse[idx]

			continue
		}

		profileAssociation.ClientCertificate = response.PublicKeyCertificateResponse[idx]

		processConcreteDependencies(certificateHandle, profileAssociation, response.ConcreteDependencyResponse, response.PublicPrivateKeyPairResponse)
	}

	// Check if the certificate is already in the list
	for idx := range securitySettings.ProfileAssociation {
		if !(securitySettings.ProfileAssociation[idx].ProfileID == profileAssociation.ProfileID) {
			continue
		}

		if profileAssociation.RootCertificate != nil {
			securitySettings.ProfileAssociation[idx].RootCertificate = profileAssociation.RootCertificate
		}

		if profileAssociation.ClientCertificate != nil {
			securitySettings.ProfileAssociation[idx].ClientCertificate = profileAssociation.ClientCertificate
		}

		if profileAssociation.Key != nil {
			securitySettings.ProfileAssociation[idx].Key = profileAssociation.Key
		}

		isNewProfileAssociation = false

		break
	}

	// If the profile is not in the list, add it
	if isNewProfileAssociation {
		securitySettings.ProfileAssociation = append(securitySettings.ProfileAssociation, *profileAssociation)
	}
}

func processCertificates(contextItems []credential.CredentialContext, response Certificates, profileType string, securitySettings *SecuritySettings) {
	for idx := range contextItems {
		var profileAssociation ProfileAssociation

		profileAssociation.Type = profileType
		profileAssociation.ProfileID = strings.TrimPrefix(contextItems[idx].ElementProvidingContext.ReferenceParameters.SelectorSet.Selectors[0].Text, "Intel(r) AMT:IEEE 802.1x Settings ")
		certificateHandle := contextItems[idx].ElementInContext.ReferenceParameters.SelectorSet.Selectors[0].Text

		buildProfileAssociations(certificateHandle, &profileAssociation, response, securitySettings)
		buildCertificateAssociations(profileAssociation, securitySettings)
	}
}

func (service *ProvisioningService) GetPrivateKeyHandle(securitySettings SecuritySettings, privateKey string) (privateKeyHandle string, err error) {
	privateKeyHandle, err = service.interfacedWsmanMessage.AddPrivateKey(privateKey)
	if err != nil && strings.Contains(err.Error(), "already exists") {
		for i := range securitySettings.Keys.([]publicprivate.RefinedPublicPrivateKeyPair) {
			key := securitySettings.Keys.([]publicprivate.RefinedPublicPrivateKeyPair)[i]
			if key.DERKey == privateKey {
				privateKeyHandle = key.InstanceID
				service.handlesWithCerts[privateKeyHandle] = privateKey //TODO: remove if not necessary
				return privateKeyHandle, nil
			}
		}
		if privateKeyHandle == "" {
			return "", utils.GenericFailure
		}
	} else if err != nil {
		return "", err
	}
	service.handlesWithCerts[privateKeyHandle] = privateKey //TODO: remove if not necessary
	return privateKeyHandle, nil
}

func (service *ProvisioningService) GetClientCertHandle(securitySettings SecuritySettings, clientCert string) (clientCertHandle string, err error) {
	clientCertHandle, err = service.interfacedWsmanMessage.AddClientCert(clientCert)
	if err != nil && strings.Contains(err.Error(), "already exists") {
		for i := range securitySettings.Certificates.([]publickey.RefinedPublicKeyCertificateResponse) {
			cert := securitySettings.Certificates.([]publickey.RefinedPublicKeyCertificateResponse)[i]
			if !cert.TrustedRootCertificate && cert.X509Certificate == clientCert {
				clientCertHandle = cert.InstanceID
				service.handlesWithCerts[clientCertHandle] = clientCert //TODO: remove if not necessary
				return clientCertHandle, nil
			}
		}
		if clientCertHandle == "" {
			return "", utils.GenericFailure
		}
	} else if err != nil {
		return "", err
	}
	service.handlesWithCerts[clientCertHandle] = clientCert //TODO: remove if not necessary
	return clientCertHandle, err
}

func (service *ProvisioningService) GetTrustedRootCertHandle(securitySettings SecuritySettings, caCert string) (rootCertHandle string, err error) {
	rootCertHandle, err = service.interfacedWsmanMessage.AddTrustedRootCert(caCert)
	if err != nil && strings.Contains(err.Error(), "already exists") {
		for i := range securitySettings.Certificates.([]publickey.RefinedPublicKeyCertificateResponse) {
			cert := securitySettings.Certificates.([]publickey.RefinedPublicKeyCertificateResponse)[i]
			if cert.TrustedRootCertificate && cert.X509Certificate == caCert {
				rootCertHandle = cert.InstanceID
				service.handlesWithCerts[rootCertHandle] = caCert //TODO: remove if not necessary
				return rootCertHandle, nil
			}
		}
		if rootCertHandle == "" {
			return "", utils.GenericFailure
		}
	} else if err != nil {
		return "", err
	}
	service.handlesWithCerts[rootCertHandle] = caCert //TODO: remove if not necessary
	return rootCertHandle, nil
}
