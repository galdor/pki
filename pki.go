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
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
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
			SAN: SAN{
				DNSNames: []string{"localhost"},
				IPAddresses: []net.IP{
					net.ParseIP("127.0.0.1"),
					net.ParseIP("::1"),
				},
			},
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

	pki.Cfg = cfg

	// Create the root CA private key
	key, err := pki.CreatePrivateKey(RootCAName)
	if err != nil {
		return fmt.Errorf("cannot create root ca private key: %w", err)
	}

	// Create the root CA certificate
	certData := pki.Cfg.Certificates
	certData.IsCA = true

	_, err = pki.CreateCertificate(RootCAName, &certData, nil, key)
	if err != nil {
		return fmt.Errorf("cannot create root ca certificate: %w", err)
	}

	return nil
}
