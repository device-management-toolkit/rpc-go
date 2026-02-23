/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 *********************************************************************/

package diagnostics

import (
	"encoding/json"
	"encoding/xml"
	"testing"

	"github.com/stretchr/testify/assert"
)

type testXMLPayload struct {
	XMLName xml.Name `xml:"Payload"`
	Value   string   `xml:"Value"`
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

func TestRenderResults_UnsupportedFormat(t *testing.T) {
	_, err := renderResults([]classResult{}, "yaml")
	assert.Error(t, err)
}
