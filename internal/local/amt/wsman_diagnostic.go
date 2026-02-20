/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package amt

import (
	"encoding/xml"
	"fmt"
	"strings"
	"time"
)

const (
	wsmanAddressAnonymous = "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"
	wsmanActionGet        = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get"
	wsmanActionEnumerate  = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate"
	wsmanActionPull       = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull"
	wsmanAMTSchema        = "http://intel.com/wbem/wscim/1/amt-schema/1/"
	wsmanCIMSchema        = "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/"
	wsmanIPSSchema        = "http://intel.com/wbem/wscim/1/ips-schema/1/"
)

var supportedWSMANClasses = []string{
	"AMT_8021XProfile",
	"AMT_AssetTable",
	"AMT_AssetTableService",
	"AMT_MessageLog",
	"AMT_Hdr8021Filter",
	"AMT_AuditLog",
	"AMT_BootCapabilities",
	"AMT_BootSettingData",
	"AMT_CryptographicCapabilities",
	"AMT_EventLogEntry",
	"AMT_EnvironmentDetectionSettingData",
	"AMT_EthernetPortSettings",
	"AMT_GeneralSettings",
	"AMT_ManagementPresenceRemoteSAP",
	"AMT_RedirectionService",
	"AMT_RemoteAccessCapabilities",
	"AMT_RemoteAccessPolicyRule",
	"AMT_SetupAndConfigurationService",
	"AMT_SystemPowerScheme",
	"AMT_WiFiPortConfigurationService",
	"AMT_UserInitiatedConnectionService",
	"AMT_RemoteAccessPolicyAppliesToMPS",
	"CIM_BIOSFeature",
	"CIM_EthernetPort",
	"CIM_KVMRedirectionSAP",
	"CIM_PowerManagementCapabilities",
	"CIM_RedirectionService",
	"CIM_SoftwareIdentity",
	"CIM_WiFiEndpoint",
	"CIM_WiFiEndpointCapabilities",
	"CIM_WiFiEndpointSettings",
	"CIM_WiFiPort",
	"CIM_WiFiPortCapabilities",
	"IPS_HostBasedSetupService",
	"IPS_HostBootReason",
	"IPS_HostIPSettings",
	"IPS_IEEE8021xSettings",
	"IPS_IPv6PortSettings",
	"IPS_KVMRedirectionSettingData",
	"IPS_LANEndpoint",
	"IPS_OptInService",
	"IPS_ProvisioningRecordLog",
	"IPS_ScreenSettingData",
	"IPS_SecIOService",
	"IPS_HTTPProxyAccessPoint",
	"AMT_TimeSynchronizationService",
}

var wsmanClassNameLookup = func() map[string]string {
	out := make(map[string]string, len(supportedWSMANClasses))
	for _, className := range supportedWSMANClasses {
		out[strings.ToUpper(className)] = className
	}

	return out
}()

func SupportedWSMANClasses() []string {
	out := make([]string, len(supportedWSMANClasses))
	copy(out, supportedWSMANClasses)

	return out
}

func ResolveWSMANClassName(name string) (string, bool) {
	resolved, ok := wsmanClassNameLookup[strings.ToUpper(strings.TrimSpace(name))]

	return resolved, ok
}

func (g *GoWSMANMessages) ListSupportedWSMANClasses() []string {
	return SupportedWSMANClasses()
}

func (g *GoWSMANMessages) FetchWSMANClass(className string) (responseXML string, err error) {
	resolvedClassName, ok := ResolveWSMANClassName(className)
	if !ok {
		return "", fmt.Errorf("unsupported WSMAN class: %s", className)
	}

	resourceURI, err := resourceURIForClass(resolvedClassName)
	if err != nil {
		return "", err
	}

	enumerateRequest := buildWSMANEnvelope(wsmanActionEnumerate, resourceURI, `<Body><Enumerate xmlns="http://schemas.xmlsoap.org/ws/2004/09/enumeration" /></Body>`)
	enumerateResponse, enumerateErr := g.wsmanMessages.Client.Post(enumerateRequest)
	if enumerateErr == nil {
		enumerationContext := extractEnumerationContext(enumerateResponse)
		if enumerationContext != "" {
			pullBody := fmt.Sprintf(`<Body><Pull xmlns="http://schemas.xmlsoap.org/ws/2004/09/enumeration"><EnumerationContext>%s</EnumerationContext><MaxElements>999</MaxElements><MaxCharacters>99999</MaxCharacters></Pull></Body>`, xmlEscapeText(enumerationContext))
			pullRequest := buildWSMANEnvelope(wsmanActionPull, resourceURI, pullBody)
			pullResponse, pullErr := g.wsmanMessages.Client.Post(pullRequest)
			if pullErr == nil {
				return extractSOAPBodyPayload(pullResponse), nil
			}

			return "", pullErr
		}

		return extractSOAPBodyPayload(enumerateResponse), nil
	}

	getRequest := buildWSMANEnvelope(wsmanActionGet, resourceURI, `<Body></Body>`)
	getResponse, getErr := g.wsmanMessages.Client.Post(getRequest)
	if getErr != nil {
		return "", fmt.Errorf("enumerate failed: %w; get failed: %w", enumerateErr, getErr)
	}

	return extractSOAPBodyPayload(getResponse), nil
}

func resourceURIForClass(className string) (string, error) {
	switch {
	case strings.HasPrefix(className, "AMT_"):
		return wsmanAMTSchema + className, nil
	case strings.HasPrefix(className, "CIM_"):
		return wsmanCIMSchema + className, nil
	case strings.HasPrefix(className, "IPS_"):
		return wsmanIPSSchema + className, nil
	default:
		return "", fmt.Errorf("unsupported WSMAN class namespace for %s", className)
	}
}

func buildWSMANEnvelope(action, resourceURI, body string) string {
	messageID := fmt.Sprintf("uuid:%d", time.Now().UnixNano())

	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?><Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns="http://www.w3.org/2003/05/soap-envelope"><Header><a:Action>%s</a:Action><a:To>/wsman</a:To><w:ResourceURI>%s</w:ResourceURI><a:MessageID>%s</a:MessageID><a:ReplyTo><a:Address>%s</a:Address></a:ReplyTo><w:OperationTimeout>PT60S</w:OperationTimeout></Header>%s</Envelope>`, action, resourceURI, messageID, wsmanAddressAnonymous, body)
}

func extractEnumerationContext(response []byte) string {
	decoder := xml.NewDecoder(strings.NewReader(string(response)))
	for {
		tok, err := decoder.Token()
		if err != nil {
			return ""
		}

		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}

		if start.Name.Local != "EnumerationContext" {
			continue
		}

		var value string
		if err := decoder.DecodeElement(&value, &start); err != nil {
			return ""
		}

		return strings.TrimSpace(value)
	}
}

func xmlEscapeText(in string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;", "'", "&apos;").Replace(in)
}

func extractSOAPBodyPayload(response []byte) string {
	type soapBody struct {
		Inner string `xml:",innerxml"`
	}

	type soapEnvelope struct {
		Body soapBody `xml:"Body"`
	}

	var envelope soapEnvelope
	if err := xml.Unmarshal(response, &envelope); err == nil {
		inner := strings.TrimSpace(envelope.Body.Inner)
		if inner != "" {
			return inner
		}
	}

	return strings.TrimSpace(string(response))
}
