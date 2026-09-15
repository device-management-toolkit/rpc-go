/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 *********************************************************************/

package diagnostics

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	log "github.com/sirupsen/logrus"
)

// BundleCmd collects a full diagnostics bundle.
type BundleCmd struct {
	DiagnosticsBaseCmd

	Output string `help:"Output file path for the diagnostics bundle" short:"o"`

	collectors []bundleCollector                           `kong:"-"`
	runWSMan   func(*WSManGetCmd, *commands.Context) error `kong:"-"`
	now        func() time.Time                            `kong:"-"`
}

type bundleCollector struct {
	name     string
	fileName string
	collect  func(string) error
}

type bundleManifest struct {
	CreatedAt  time.Time               `json:"createdAt"`
	Collectors []bundleCollectorResult `json:"collectors"`
}

type bundleCollectorResult struct {
	Name   string `json:"name"`
	File   string `json:"file,omitempty"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

type partialCollectionError struct {
	err error
}

func (err partialCollectionError) Error() string {
	return err.err.Error()
}

func (err partialCollectionError) Unwrap() error {
	return err.err
}

// Run executes the diagnostics bundle collection command.
func (cmd *BundleCmd) Run(ctx *commands.Context) error {
	now := time.Now
	if cmd.now != nil {
		now = cmd.now
	}

	createdAt := now()
	if cmd.Output == "" {
		cmd.Output = fmt.Sprintf("%s_diagnostics_bundle.zip", createdAt.Format("20060102_150405"))
	}

	outputDir := filepath.Dir(cmd.Output)
	if outputDir != "." && outputDir != "" {
		if err := os.MkdirAll(outputDir, 0o755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	tempDir, err := os.MkdirTemp("", "rpc-diagnostics-")
	if err != nil {
		return fmt.Errorf("failed to create temporary diagnostics directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	collectors := cmd.collectors
	if collectors == nil {
		collectors = cmd.defaultCollectors(ctx)
	}

	manifest := bundleManifest{
		CreatedAt:  createdAt,
		Collectors: make([]bundleCollectorResult, 0, len(collectors)),
	}
	archiveFiles := []string{"manifest.json"}

	for _, collector := range collectors {
		result := bundleCollectorResult{Name: collector.name, File: collector.fileName, Status: "success"}
		collectorOutput := filepath.Join(tempDir, collector.fileName)

		collectErr := collector.collect(collectorOutput)
		if collectErr == nil {
			if _, statErr := os.Stat(collectorOutput); statErr != nil {
				collectErr = fmt.Errorf("collector did not create %s: %w", collector.fileName, statErr)
			}
		}

		if collectErr != nil {
			result.File = ""
			result.Status = "failed"
			result.Error = collectErr.Error()
			log.Warnf("failed to collect %s diagnostics: %v", collector.name, collectErr)

			if _, partial := collectErr.(partialCollectionError); partial {
				result.File = collector.fileName
				result.Status = "partial"

				archiveFiles = append(archiveFiles, collector.fileName)
			}
		} else {
			archiveFiles = append(archiveFiles, collector.fileName)
		}

		manifest.Collectors = append(manifest.Collectors, result)
	}

	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to create diagnostics manifest: %w", err)
	}

	if err := os.WriteFile(filepath.Join(tempDir, "manifest.json"), manifestData, 0o644); err != nil {
		return fmt.Errorf("failed to write diagnostics manifest: %w", err)
	}

	if err := zipDirectory(cmd.Output, tempDir, archiveFiles); err != nil {
		return err
	}

	failures := 0

	for _, result := range manifest.Collectors {
		if result.Status == "failed" {
			failures++
		}
	}

	fmt.Printf("Diagnostics bundle successfully created\nOutput file: %s\n", cmd.Output)

	if failures > 0 {
		fmt.Printf("Warning: %d diagnostic collector(s) failed; see manifest.json for details\n", failures)
	}

	return nil
}

func (cmd *BundleCmd) defaultCollectors(ctx *commands.Context) []bundleCollector {
	return []bundleCollector{
		{
			name:     "cira",
			fileName: "cira.txt",
			collect: func(output string) error {
				return (&CIRACmd{DiagnosticsBaseCmd: cmd.DiagnosticsBaseCmd, Output: output}).Run(ctx)
			},
		},
		{
			name:     "csme",
			fileName: "csme_flash_log.bin",
			collect: func(output string) error {
				return (&CSMECmd{DiagnosticsBaseCmd: cmd.DiagnosticsBaseCmd, Output: output}).Run(ctx)
			},
		},
		{
			name:     "wsman",
			fileName: "wsman.json",
			collect: func(output string) error {
				wsmanCmd := &WSManGetCmd{DiagnosticsBaseCmd: cmd.DiagnosticsBaseCmd, Output: output, Format: "json", All: true}
				if cmd.runWSMan != nil {
					wsmanCmd.runOverride = func(ctx *commands.Context) error {
						return cmd.runWSMan(wsmanCmd, ctx)
					}
				}

				if err := wsmanCmd.Run(ctx); err != nil {
					return err
				}

				if wsmanCmd.fetchFailures > 0 {
					return partialCollectionError{err: fmt.Errorf("%d WSMAN class(es) failed to retrieve", wsmanCmd.fetchFailures)}
				}

				return nil
			},
		},
	}
}

func zipDirectory(outputPath, sourceDir string, fileNames []string) (err error) {
	output, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create diagnostics bundle: %w", err)
	}

	defer func() {
		if closeErr := output.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("failed to close diagnostics bundle: %w", closeErr)
		}
	}()

	archive := zip.NewWriter(output)
	defer func() {
		if closeErr := archive.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("failed to finalize diagnostics bundle: %w", closeErr)
		}
	}()

	for _, fileName := range fileNames {
		input, openErr := os.Open(filepath.Join(sourceDir, fileName))
		if openErr != nil {
			return fmt.Errorf("failed to open diagnostic file %s: %w", fileName, openErr)
		}

		writer, createErr := archive.Create(fileName)
		if createErr == nil {
			_, createErr = io.Copy(writer, input)
		}

		closeErr := input.Close()

		if createErr != nil {
			return fmt.Errorf("failed to add diagnostic file %s to bundle: %w", fileName, createErr)
		}

		if closeErr != nil {
			return fmt.Errorf("failed to close diagnostic file %s: %w", fileName, closeErr)
		}
	}

	return nil
}
