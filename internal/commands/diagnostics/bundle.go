/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 *********************************************************************/

package diagnostics

import (
	"archive/zip"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
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

// BundleManifest is the manifest.json a diagnostics bundle carries: when it
// was created and how each collector fared.
type BundleManifest struct {
	CreatedAt  time.Time               `json:"createdAt"`
	Collectors []BundleCollectorResult `json:"collectors"`
}

// Incomplete counts the collectors whose status is not "success".
func (manifest BundleManifest) Incomplete() int {
	failures := 0

	for _, result := range manifest.Collectors {
		if result.Status != "success" {
			failures++
		}
	}

	return failures
}

// BundleCollectorResult is one collector's entry in a BundleManifest. Status
// is "success", "partial" (File is in the bundle but incomplete, Error says
// why) or "failed" (no File, Error says why).
type BundleCollectorResult struct {
	Name   string `json:"name"`
	File   string `json:"file,omitempty"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// BundleResult is what BundleCmd.Collect wrote: the bundle's path and its manifest.
type BundleResult struct {
	// Path is the zip file the bundle was written to.
	Path string
	// Manifest is the manifest.json stored in the bundle.
	Manifest BundleManifest
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
	result, err := cmd.Collect(ctx)
	if err != nil {
		return err
	}

	fmt.Printf("Diagnostics bundle successfully created\nOutput file: %s\n", result.Path)

	if failures := result.Manifest.Incomplete(); failures > 0 {
		fmt.Printf("Warning: %d diagnostic collector(s) were incomplete; see manifest.json for details\n", failures)
	}

	return nil
}

// Collect runs every collector and writes the bundle, the work Run reports
// on. When no collector produced a file, it still writes the bundle with its
// manifest and returns the result together with an error naming each failure.
func (cmd *BundleCmd) Collect(ctx *commands.Context) (*BundleResult, error) {
	now := time.Now
	if cmd.now != nil {
		now = cmd.now
	}

	createdAt := now()
	if cmd.Output == "" {
		cmd.Output = fmt.Sprintf("%s_diagnostics_bundle.zip", createdAt.Format("20060102_150405"))
	} else if filepath.Ext(cmd.Output) == "" {
		cmd.Output += ".zip"
	}

	if err := ensureParentDir(cmd.Output); err != nil {
		return nil, err
	}

	tempDir, err := os.MkdirTemp("", "rpc-diagnostics-")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary diagnostics directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	collectors := cmd.collectors
	if collectors == nil {
		collectors = cmd.defaultCollectors(ctx)
	}

	manifest := BundleManifest{
		CreatedAt:  createdAt,
		Collectors: make([]BundleCollectorResult, 0, len(collectors)),
	}
	archiveFiles := []string{"manifest.json"}

	for _, collector := range collectors {
		result := BundleCollectorResult{Name: collector.name, File: collector.fileName, Status: "success"}
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

			if _, partial := collectErr.(partialCollectionError); partial {
				result.File = collector.fileName
				result.Status = "partial"

				archiveFiles = append(archiveFiles, collector.fileName)

				log.Warnf("%s diagnostics incomplete: %v", collector.name, collectErr)
			} else {
				log.Warnf("failed to collect %s diagnostics: %v", collector.name, collectErr)
			}
		} else {
			archiveFiles = append(archiveFiles, collector.fileName)
		}

		manifest.Collectors = append(manifest.Collectors, result)
	}

	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to create diagnostics manifest: %w", err)
	}

	if err := os.WriteFile(filepath.Join(tempDir, "manifest.json"), manifestData, 0o644); err != nil {
		return nil, fmt.Errorf("failed to write diagnostics manifest: %w", err)
	}

	if err := zipDirectory(cmd.Output, tempDir, archiveFiles); err != nil {
		return nil, err
	}

	result := &BundleResult{Path: cmd.Output, Manifest: manifest}

	if len(archiveFiles) == 1 {
		collectorErrors := make([]string, 0, len(manifest.Collectors))
		for _, collectorResult := range manifest.Collectors {
			collectorErrors = append(collectorErrors, fmt.Sprintf("%s: %s", collectorResult.Name, collectorResult.Error))
		}

		return result, fmt.Errorf("no diagnostics were collected (manifest written to %s): %s", cmd.Output, strings.Join(collectorErrors, "; "))
	}

	return result, nil
}

func (cmd *BundleCmd) defaultCollectors(ctx *commands.Context) []bundleCollector {
	base := cmd.DiagnosticsBaseCmd
	base.quiet = true

	return []bundleCollector{
		{
			name:     "cira",
			fileName: "cira.txt",
			collect: func(output string) error {
				return (&CIRACmd{DiagnosticsBaseCmd: base, Output: output}).Run(ctx)
			},
		},
		{
			name:     "csme",
			fileName: "csme_flash_log.bin",
			collect: func(output string) error {
				return (&CSMECmd{DiagnosticsBaseCmd: base, Output: output}).Run(ctx)
			},
		},
		{
			name:     "wsman",
			fileName: "wsman.json",
			collect: func(output string) error {
				wsmanCmd := &WSManGetCmd{DiagnosticsBaseCmd: base, Output: output, Format: "json", All: true}

				runWSMan := (*WSManGetCmd).collect
				if cmd.runWSMan != nil {
					runWSMan = cmd.runWSMan
				}

				err := runWSMan(wsmanCmd, ctx)

				var fetchErr *wsmanFetchError
				if !errors.As(err, &fetchErr) {
					return err
				}

				if fetchErr.failed == fetchErr.total {
					allErr := fmt.Errorf("all %d WSMAN classes failed to retrieve: %w", fetchErr.total, fetchErr.last)

					var certErr *tls.CertificateVerificationError
					if errors.As(fetchErr.last, &certErr) {
						return fmt.Errorf("%w (retry with --skip-amt-cert-check)", allErr)
					}

					return allErr
				}

				return partialCollectionError{err: fmt.Errorf("%d of %d WSMAN classes failed to retrieve", fetchErr.failed, fetchErr.total)}
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
