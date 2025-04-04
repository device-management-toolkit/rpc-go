/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package certs

import (
	"crypto/x509"
	"embed"
	"errors"
	"io/fs"

	log "github.com/sirupsen/logrus"
)

//go:embed trustedstore/*.cer
var EmbeddedCerts embed.FS

// FileSystem abstracts file operations for testability
type FileSystem interface {
	ReadDir(name string) ([]fs.DirEntry, error)
	ReadFile(name string) ([]byte, error)
}

// embeddedFS is a wrapper around embed.FS to implement FileSystem interface
type embeddedFS struct{}

func (embeddedFS) ReadDir(name string) ([]fs.DirEntry, error) {
	return fs.ReadDir(EmbeddedCerts, name)
}

func (embeddedFS) ReadFile(name string) ([]byte, error) {
	return EmbeddedCerts.ReadFile(name)
}

// LoadRootCAPool loads root CAs using the embedded file system
var LoadRootCAPool = func() (*x509.CertPool, error) {
	return LoadRootCAPoolwithFS(embeddedFS{})
}

// Internal function to load root CA pool from any file system (for testing)
func LoadRootCAPoolwithFS(fs FileSystem) (*x509.CertPool, error) {
	certPool := x509.NewCertPool()
	loadedCerts := 0

	certFiles, err := fs.ReadDir("trustedstore")
	if err != nil {
		return nil, errors.New("failed to read embedded certificates directory")
	}

	for _, certFile := range certFiles {
		if !certFile.IsDir() {
			certPath := "trustedstore/" + certFile.Name()
			certData, err := fs.ReadFile(certPath)

			if err != nil {
				log.Error("Failed to read file: ", certPath, " Error: ", err)

				continue
			}

			derCert, err := x509.ParseCertificate(certData)
			if err != nil {
				continue
			}

			certPool.AddCert(derCert)

			loadedCerts++
		}
	}

	if loadedCerts == 0 {
		return nil, errors.New("no certificates found in the trusted store")
	}

	return certPool, nil
}
