/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 *********************************************************************/

package diagnostics

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	localamt "github.com/device-management-toolkit/rpc-go/v2/internal/local/amt"
)

type WSMANListCmd struct{}

func (cmd *WSMANListCmd) Run(ctx *commands.Context) error {
	_ = ctx

	for _, className := range localamt.SupportedWSMANClasses() {
		fmt.Println(className)
	}

	return nil
}

type WSMANGetCmd struct {
	commands.AMTBaseCmd

	All    bool     `help:"Fetch all supported WSMAN classes" name:"all"`
	Class  []string `help:"WSMAN class name to fetch (repeatable)" name:"class" short:"c"`
	Format string   `help:"Output format" enum:"json,xml" default:"json" name:"format"`
	Output string   `help:"Output file path" name:"output"`
	Raw    bool     `help:"Output raw firmware XML payload(s) without wrapper" name:"raw"`
}

type wsmanDiagnosticProvider interface {
	ListSupportedWSMANClasses() []string
	FetchWSMANClass(className string) (responseXML string, err error)
}

type wsmanFetchResult struct {
	Class    string `json:"class" xml:"class,attr"`
	Success  bool   `json:"success" xml:"success,attr"`
	Error    string `json:"error,omitempty" xml:"Error,omitempty"`
	Response string `json:"response,omitempty" xml:"Response,omitempty"`
}

type wsmanFetchEnvelope struct {
	XMLName     xml.Name           `xml:"WSMANResults"`
	GeneratedAt string             `xml:"generatedAt,attr" json:"generatedAt"`
	Count       int                `xml:"count,attr" json:"count"`
	Results     []wsmanFetchResult `xml:"Result" json:"results"`
}

type WSManCmd struct {
	List WSMANListCmd `cmd:"" name:"list" help:"List all supported WSMAN classes (does not fetch data)"`
	Get  WSMANGetCmd  `cmd:"" name:"get" help:"Fetch WSMAN class data"`
}

func (cmd *WSMANGetCmd) Validate() error {
	if cmd.All && len(cmd.Class) > 0 {
		return fmt.Errorf("use either --all or --class, not both")
	}

	if !cmd.All && len(cmd.Class) == 0 {
		return fmt.Errorf("specify --all or at least one --class")
	}

	return nil
}

func (cmd *WSMANGetCmd) Run(ctx *commands.Context) error {
	if err := cmd.EnsureAMTPassword(ctx, cmd); err != nil {
		return err
	}

	if err := cmd.EnsureWSMAN(ctx); err != nil {
		return err
	}

	provider, ok := cmd.GetWSManClient().(wsmanDiagnosticProvider)
	if !ok {
		return fmt.Errorf("configured WSMAN client does not support diagnostic class retrieval")
	}

	targetClasses, err := cmd.resolveTargetClasses(provider)
	if err != nil {
		return err
	}

	results := make([]wsmanFetchResult, 0, len(targetClasses))
	for _, className := range targetClasses {
		responseXML, fetchErr := provider.FetchWSMANClass(className)
		if fetchErr != nil {
			results = append(results, wsmanFetchResult{
				Class:   className,
				Success: false,
				Error:   fetchErr.Error(),
			})

			continue
		}

		results = append(results, wsmanFetchResult{
			Class:    className,
			Success:  true,
			Response: responseXML,
		})
	}

	envelope := wsmanFetchEnvelope{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Count:       len(results),
		Results:     results,
	}

	if cmd.Raw {
		return cmd.outputRaw(results)
	}

	out, err := cmd.serializeOutput(envelope)
	if err != nil {
		return err
	}

	if strings.TrimSpace(cmd.Output) != "" {
		if err := os.WriteFile(cmd.Output, out, 0o600); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}

		return nil
	}

	fmt.Println(string(out))

	return nil
}

func (cmd *WSMANGetCmd) outputRaw(results []wsmanFetchResult) error {
	var builder strings.Builder

	successCount := 0
	for _, result := range results {
		if !result.Success {
			fmt.Fprintf(os.Stderr, "%s: %s\n", result.Class, result.Error)

			continue
		}

		successCount++
		if len(results) > 1 {
			builder.WriteString("----- ")
			builder.WriteString(result.Class)
			builder.WriteString(" -----\n")
		}

		builder.WriteString(result.Response)
		if !strings.HasSuffix(result.Response, "\n") {
			builder.WriteString("\n")
		}
	}

	if successCount == 0 {
		return fmt.Errorf("failed to fetch WSMAN payload for all requested classes")
	}

	rawOutput := []byte(builder.String())
	if strings.TrimSpace(cmd.Output) != "" {
		if err := os.WriteFile(cmd.Output, rawOutput, 0o600); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}

		return nil
	}

	fmt.Print(string(rawOutput))

	return nil
}

func (cmd *WSMANGetCmd) RequiresAMTPassword() bool { return true }

func (cmd *WSMANGetCmd) resolveTargetClasses(provider wsmanDiagnosticProvider) ([]string, error) {
	if cmd.All {
		return provider.ListSupportedWSMANClasses(), nil
	}

	seen := map[string]struct{}{}
	out := make([]string, 0, len(cmd.Class))

	for _, className := range cmd.Class {
		resolvedClassName, ok := localamt.ResolveWSMANClassName(className)
		if !ok {
			return nil, fmt.Errorf("unsupported WSMAN class: %s", className)
		}

		if _, exists := seen[resolvedClassName]; exists {
			continue
		}

		seen[resolvedClassName] = struct{}{}
		out = append(out, resolvedClassName)
	}

	return out, nil
}

func (cmd *WSMANGetCmd) serializeOutput(envelope wsmanFetchEnvelope) ([]byte, error) {
	if cmd.Format == "xml" {
		xmlBody, err := xml.MarshalIndent(envelope, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("failed to serialize XML output: %w", err)
		}

		return append([]byte(xml.Header), xmlBody...), nil
	}

	jsonBody, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to serialize JSON output: %w", err)
	}

	return jsonBody, nil
}
