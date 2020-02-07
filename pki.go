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
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
)

type SANType string

const (
	SANTypeURI          = "uri"
	SANTypeEmailAddress = "emailAddress"
	SANTypeDNSName      = "dnsName"
	SANTypeIPAddress    = "ipAddress"
)

type SAN struct {
	Type  SANType `json:"type"`
	Value string  `json:"value"`
}

type Subject struct {
	Country            string `json:"country,omitempty"`
	Organization       string `json:"organization,omitempty"`
	OrganizationalUnit string `json:"organizationalUnit,omitempty"`
	Locality           string `json:"locality,omitempty"`
	Province           string `json:"province,omitempty"`
	StreetAddress      string `json:"streetAddress,omitempty"`
	PostalCode         string `json:"postalCode,omitempty"`
	CommonName         string `json:"commonName"`
}

type CertificatesCfg struct {
	Validity int     `json:"validity"` // days
	Subject  Subject `json:"subject"`
	SANs     []SAN   `json:"san"`
}

type PKICfg struct {
	Certificates CertificatesCfg `json:"certificates"`
}

func DefaultPKICfg() *PKICfg {
	san := []SAN{
		{Type: SANTypeDNSName, Value: "localhost"},
		{Type: SANTypeIPAddress, Value: "127.0.0.1"},
		{Type: SANTypeIPAddress, Value: "::1"},
	}

	cfg := PKICfg{
		Certificates: CertificatesCfg{
			Validity: 365,
			Subject:  Subject{CommonName: "localhost"},
			SANs:     san,
		},
	}

	return &cfg
}

type PKI struct {
	Path string
}

func NewPKI(path string) *PKI {
	pki := PKI{
		Path: path,
	}

	return &pki
}

func (pki *PKI) Initialize() error {
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

	cfgPath := path.Join(pki.Path, "cfg.json")

	info("creating default configuration file at %q", cfgPath)

	if err := ioutil.WriteFile(cfgPath, cfgData, 0644); err != nil {
		return fmt.Errorf("cannot write %q: %w", cfgPath, err)
	}

	// Create the root private key
	// TODO

	// Create the root CA
	// TODO

	return nil
}

func encodeJSON(value interface{}) ([]byte, error) {
	var buf bytes.Buffer

	e := json.NewEncoder(&buf)
	e.SetIndent("", "  ")

	if err := e.Encode(value); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
