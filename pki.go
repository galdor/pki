// Copyright (c) 2020 Nicolas Martyanoff <khaelin@gmail.com>
//
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"time"
)

const (
	RootCAName = "root-ca"
)

type PKICfg struct {
	Certificates CertificateData `json:"certificates"`
}

func DefaultPKICfg() *PKICfg {
	cfg := PKICfg{
		Certificates: CertificateData{
			Validity: 365,
			Subject:  Subject{CommonName: "localhost"},
		},
	}

	return &cfg
}

type PKI struct {
	Path string
	Cfg  *PKICfg
}

func NewPKI(path string) *PKI {
	pki := PKI{
		Path: path,
	}

	return &pki
}

func (pki *PKI) LoadConfiguration() error {
	cfgPath := pki.CfgPath()

	info("loading configuration file at %q", cfgPath)

	data, err := ioutil.ReadFile(cfgPath)
	if err != nil {
		return fmt.Errorf("cannot read %q: %w", cfgPath, err)
	}

	var cfg PKICfg
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("cannot decode configuration: %w", err)
	}

	pki.Cfg = &cfg

	return nil
}

func (pki *PKI) CfgPath() string {
	return path.Join(pki.Path, "cfg.json")
}

func (pki *PKI) Initialize(certData *CertificateData) error {
	info("initializing pki in %q", pki.Path)

	// Create the top directory if it does not exists
	if err := os.MkdirAll(pki.Path, 0755); err != nil {

		return fmt.Errorf("cannot create %q: %w", pki.Path, err)
	}

	// Make sure it is empty
	if fileInfo, err := ioutil.ReadDir(pki.Path); err != nil {
		return fmt.Errorf("cannot list files in %q: %w",
			pki.Path, err)
	} else if len(fileInfo) > 0 {
		return fmt.Errorf("%q is not empty", pki.Path)
	}

	// Create the default configuration file
	cfg := DefaultPKICfg()

	cfgData, err := encodeJSON(cfg)
	if err != nil {
		return fmt.Errorf("cannot encode configuration: %w", err)
	}

	cfgPath := pki.CfgPath()

	info("creating default configuration file at %q", cfgPath)

	if err := ioutil.WriteFile(cfgPath, cfgData, 0644); err != nil {
		return fmt.Errorf("cannot write %q: %w", cfgPath, err)
	}

	pki.Cfg = cfg

	// Create the root CA private key
	key, err := pki.CreatePrivateKey(RootCAName)
	if err != nil {
		return fmt.Errorf("cannot create root ca private key: %w", err)
	}

	// Create the root CA certificate
	cert, err := pki.CreateCertificate(RootCAName, certData, nil, key)
	if err != nil {
		return fmt.Errorf("cannot create root ca certificate: %w", err)
	}

	// Create the root CA CRL
	currentDate := time.Now().UTC()
	crlValidity := time.Duration(certData.Validity)
	crlExpirationDate := currentDate.Add(crlValidity * 24 * time.Hour)

	crlData := CRLData{
		CurrentDate:    currentDate,
		ExpirationDate: crlExpirationDate,
	}

	_, err = pki.CreateCRL(RootCAName, cert, key, &crlData)
	if err != nil {
		return fmt.Errorf("cannot create root ca crl: %w", err)
	}

	return nil
}
