package certs

import (
	"reflect"
	"strings"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/publickey"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/publicprivate"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/concrete"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/credential"
	"github.com/device-management-toolkit/rpc-go/v2/internal/interfaces"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
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

func PruneCerts(wsman interfaces.WSMANer) error {
	getCertificateResponse, err := GetCertificates(wsman)
	if err != nil {
		return err // Return the actual error instead of nil
	}

	// Prune unused certificates
	pruneUnusedCertificates(wsman, getCertificateResponse.Certificates.([]publickey.RefinedPublicKeyCertificateResponse))

	// Prune unused keys
	pruneUnusedKeys(wsman, getCertificateResponse.Keys.([]publicprivate.RefinedPublicPrivateKeyPair))

	return nil
}

// pruneUnusedCertificates removes certificates that aren't associated with any profile
func pruneUnusedCertificates(wsman interfaces.WSMANer, certificates []publickey.RefinedPublicKeyCertificateResponse) {
	for i := range certificates {
		cert := certificates[i]
		if cert.AssociatedProfiles == nil {
			if err := wsman.DeletePublicCert(cert.InstanceID); err != nil {
				log.Debugf("unable to delete certificate %s: %v", cert.InstanceID, err)
			}
		}
	}
}

// pruneUnusedKeys removes keys that aren't associated with any certificate
func pruneUnusedKeys(wsman interfaces.WSMANer, keys []publicprivate.RefinedPublicPrivateKeyPair) {
	for i := range keys {
		key := keys[i]
		if key.CertificateHandle == "" {
			if err := wsman.DeletePublicPrivateKeyPair(key.InstanceID); err != nil {
				log.Debugf("unable to delete key %s: %v", key.InstanceID, err)
			}
		}
	}
}

func GetCertificates(wsman interfaces.WSMANer) (SecuritySettings, error) {
	concreteDepResponse, err := wsman.GetConcreteDependencies()
	if err != nil {
		return SecuritySettings{}, err
	}

	pubKeyCertResponse, err := wsman.GetPublicKeyCerts()
	if err != nil {
		return SecuritySettings{}, err
	}

	pubPrivKeyPairResponse, err := wsman.GetPublicPrivateKeyPairs()
	if err != nil {
		return SecuritySettings{}, err
	}

	credentialResponse, err := wsman.GetCredentialRelationships()
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
		if securitySettings.ProfileAssociation[idx].ProfileID != profileAssociation.ProfileID {
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

// findExistingPrivateKeyHandle searches for an existing private key handle by DER key data
func findExistingPrivateKeyHandle(securitySettings SecuritySettings, privateKey string) (string, bool) {
	for i := range securitySettings.Keys.([]publicprivate.RefinedPublicPrivateKeyPair) {
		key := securitySettings.Keys.([]publicprivate.RefinedPublicPrivateKeyPair)[i]
		if key.DERKey == privateKey {
			return key.InstanceID, true
		}
	}

	return "", false
}

// addPrivateKeyToCache adds a private key handle to the service cache
func addPrivateKeyToCache(cache map[string]string, handle, privateKey string) {
	cache[handle] = privateKey // TODO: remove if not necessary
}

func GetPrivateKeyHandle(wsman interfaces.WSMANer, securitySettings SecuritySettings, privateKey string, cache map[string]string) (privateKeyHandle string, err error) {
	// Check if key already exists
	if handle, found := findExistingPrivateKeyHandle(securitySettings, privateKey); found {
		addPrivateKeyToCache(cache, handle, privateKey)

		return handle, nil
	}

	// Add new private key
	privateKeyHandle, err = wsman.AddPrivateKey(privateKey)
	if err != nil && strings.Contains(err.Error(), "already exists") {
		// If it already exists but we couldn't find it, try searching again
		if handle, found := findExistingPrivateKeyHandle(securitySettings, privateKey); found {
			addPrivateKeyToCache(cache, handle, privateKey)

			return handle, nil
		}

		return "", utils.GenericFailure
	} else if err != nil {
		return "", err
	}

	addPrivateKeyToCache(cache, privateKeyHandle, privateKey)

	return privateKeyHandle, nil
}

// findExistingClientCertHandle searches for an existing client certificate handle by certificate data
func findExistingClientCertHandle(securitySettings SecuritySettings, clientCert string) (string, bool) {
	for i := range securitySettings.Certificates.([]publickey.RefinedPublicKeyCertificateResponse) {
		cert := securitySettings.Certificates.([]publickey.RefinedPublicKeyCertificateResponse)[i]
		if !cert.TrustedRootCertificate && cert.X509Certificate == clientCert {
			return cert.InstanceID, true
		}
	}

	return "", false
}

func GetClientCertHandle(wsman interfaces.WSMANer, securitySettings SecuritySettings, clientCert string, cache map[string]string) (clientCertHandle string, err error) {
	// Check if certificate already exists
	if handle, found := findExistingClientCertHandle(securitySettings, clientCert); found {
		addPrivateKeyToCache(cache, handle, clientCert)

		return handle, nil
	}

	// Add new client certificate
	clientCertHandle, err = wsman.AddClientCert(clientCert)
	if err != nil && strings.Contains(err.Error(), "already exists") {
		// If it already exists but we couldn't find it, try searching again
		if handle, found := findExistingClientCertHandle(securitySettings, clientCert); found {
			addPrivateKeyToCache(cache, handle, clientCert)

			return handle, nil
		}

		return "", utils.GenericFailure
	} else if err != nil {
		return "", err
	}

	addPrivateKeyToCache(cache, clientCertHandle, clientCert)

	return clientCertHandle, nil
}

// findExistingTrustedRootCertHandle searches for an existing trusted root certificate handle by certificate data
func findExistingTrustedRootCertHandle(securitySettings SecuritySettings, caCert string) (string, bool) {
	for i := range securitySettings.Certificates.([]publickey.RefinedPublicKeyCertificateResponse) {
		cert := securitySettings.Certificates.([]publickey.RefinedPublicKeyCertificateResponse)[i]
		if cert.TrustedRootCertificate && cert.X509Certificate == caCert {
			return cert.InstanceID, true
		}
	}

	return "", false
}

func GetTrustedRootCertHandle(wsman interfaces.WSMANer, securitySettings SecuritySettings, caCert string, cache map[string]string) (rootCertHandle string, err error) {
	// Check if certificate already exists
	if handle, found := findExistingTrustedRootCertHandle(securitySettings, caCert); found {
		addPrivateKeyToCache(cache, handle, caCert)

		return handle, nil
	}

	// Add new trusted root certificate
	rootCertHandle, err = wsman.AddTrustedRootCert(caCert)
	if err != nil && strings.Contains(err.Error(), "already exists") {
		// If it already exists but we couldn't find it, try searching again
		if handle, found := findExistingTrustedRootCertHandle(securitySettings, caCert); found {
			addPrivateKeyToCache(cache, handle, caCert)

			return handle, nil
		}

		return "", utils.GenericFailure
	} else if err != nil {
		return "", err
	}

	addPrivateKeyToCache(cache, rootCertHandle, caCert)

	return rootCertHandle, nil
}
