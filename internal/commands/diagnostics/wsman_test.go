/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 *********************************************************************/

package diagnostics

import (
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

type testXMLPayload struct {
	XMLName xml.Name `xml:"Payload"`
	Value   string   `xml:"Value"`
}

type tableTestClass struct {
	XMLName xml.Name `xml:"AMT_GeneralSettings"`
	Value   string   `xml:"Value"`
	Enabled bool     `xml:"Enabled"`
}

type tableTestEnvelope struct {
	XMLName   xml.Name `xml:"Envelope"`
	XMLOutput string
	Body      struct {
		Class tableTestClass `xml:"AMT_GeneralSettings"`
	} `xml:"Body"`
}

func TestWSManGetCmd_ResolveClasses(t *testing.T) {
	tests := []struct {
		name        string
		cmd         WSManGetCmd
		wantErr     bool
		expectedLen int
	}{
		{
			name: "all classes",
			cmd: WSManGetCmd{
				All: true,
			},
			wantErr:     false,
			expectedLen: len(wsmanClassFetchers),
		},
		{
			name: "single class",
			cmd: WSManGetCmd{
				Class: []string{"AMT_GeneralSettings"},
			},
			wantErr:     false,
			expectedLen: 1,
		},
		{
			name: "multiple classes with duplicate",
			cmd: WSManGetCmd{
				Class: []string{"AMT_GeneralSettings", "AMT_AuditLog", "AMT_GeneralSettings"},
			},
			wantErr:     false,
			expectedLen: 2,
		},
		{
			name:    "missing selectors",
			cmd:     WSManGetCmd{},
			wantErr: true,
		},
		{
			name: "all and class together",
			cmd: WSManGetCmd{
				All:   true,
				Class: []string{"AMT_GeneralSettings"},
			},
			wantErr: true,
		},
		{
			name: "unsupported class",
			cmd: WSManGetCmd{
				Class: []string{"INVALID_CLASS"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			classes, err := tt.cmd.resolveClasses()
			if tt.wantErr {
				assert.Error(t, err)

				return
			}

			assert.NoError(t, err)
			assert.Len(t, classes, tt.expectedLen)
		})
	}
}

func TestRenderResults_JSON(t *testing.T) {
	results := []classResult{
		{
			Class: "AMT_GeneralSettings",
			Data:  map[string]string{"value": "one"},
		},
	}

	rendered, err := renderResults(results, "json")
	assert.NoError(t, err)

	var decoded []map[string]any
	assert.NoError(t, json.Unmarshal(rendered, &decoded))
	assert.Len(t, decoded, 1)
	assert.Equal(t, "AMT_GeneralSettings", decoded[0]["class"])
}

func TestRenderResults_XMLSingle(t *testing.T) {
	results := []classResult{
		{
			Class: "AMT_GeneralSettings",
			Data:  testXMLPayload{Value: "single"},
		},
	}

	rendered, err := renderResults(results, "xml")
	assert.NoError(t, err)

	var payload testXMLPayload
	assert.NoError(t, xml.Unmarshal(rendered, &payload))
	assert.Equal(t, "single", payload.Value)
}

func TestRenderResults_XMLMultiple(t *testing.T) {
	results := []classResult{
		{
			Class: "AMT_GeneralSettings",
			Data:  testXMLPayload{Value: "first"},
		},
		{
			Class: "AMT_AuditLog",
			Data:  testXMLPayload{Value: "second"},
		},
	}

	rendered, err := renderResults(results, "xml")
	assert.NoError(t, err)

	var payload xmlResults
	assert.NoError(t, xml.Unmarshal(rendered, &payload))
	assert.Len(t, payload.Items, 2)
	assert.Equal(t, "AMT_GeneralSettings", payload.Items[0].Class)
	assert.Contains(t, payload.Items[0].XML, "<Value>first</Value>")
}

func TestRenderResults_Table(t *testing.T) {
	results := []classResult{
		{
			Class: "AMT_GeneralSettings",
			Data: tableTestEnvelope{
				XMLOutput: `<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope" xmlns:g="http://intel.com/wbem/wscim/1/amt-schema/1/AMT_GeneralSettings">
	<Body>
		<g:AMT_GeneralSettings>
			<g:ElementName>Intel(r) AMT: General Settings</g:ElementName>
			<g:HostName></g:HostName>
			<g:DDNSUpdateEnabled>false</g:DDNSUpdateEnabled>
			<g:PresenceNotificationInterval>0</g:PresenceNotificationInterval>
		</g:AMT_GeneralSettings>
	</Body>
</Envelope>`,
				Body: struct {
					Class tableTestClass `xml:"AMT_GeneralSettings"`
				}{
					Class: tableTestClass{
						Value:   "one",
						Enabled: true,
					},
				},
			},
		},
	}

	rendered, err := renderResults(results, "table")
	assert.NoError(t, err)

	output := string(rendered)
	assert.True(t, strings.Contains(output, "Class: AMT_GeneralSettings"))
	assert.True(t, strings.Contains(output, "Name"))
	assert.True(t, strings.Contains(output, "DDNSUpdateEnabled"))
	assert.True(t, strings.Contains(output, "PresenceNotificationInterval"))
	assert.True(t, strings.Contains(output, "HostName"))
	assert.True(t, strings.Contains(output, "false"))
	assert.True(t, strings.Contains(output, "0"))
}

func TestRenderResults_TableNoInstancesForUnsupported(t *testing.T) {
	results := []classResult{
		{
			Class: "AMT_AssetTable",
			Data: unsupportedClassData{
				Class:   "AMT_AssetTable",
				Status:  "not_supported",
				Message: "not exposed",
			},
		},
	}

	rendered, err := renderResults(results, "table")
	assert.NoError(t, err)

	output := string(rendered)
	assert.True(t, strings.Contains(output, "No instances found for class: AMT_AssetTable"))
	assert.False(t, strings.Contains(output, "not_supported"))
}

func TestRenderResults_UnsupportedFormat(t *testing.T) {
	_, err := renderResults([]classResult{}, "yaml")
	assert.Error(t, err)
}
