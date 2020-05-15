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
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"path"
)

func (pki *PKI) CreateCRL(name string, cert *x509.Certificate, key crypto.PrivateKey, crlData *CRLData) ([]byte, error) {
	info("creating crl %q", name)

	crl, err := pki.GenerateCRL(cert, key, crlData)
	if err != nil {
		return nil, fmt.Errorf("cannot generate crl: %w", err)
	}

	if err := pki.WriteCRL(crl, name); err != nil {
		return nil, fmt.Errorf("cannot write crl: %w", err)
	}

	return crl, nil
}

func (pki *PKI) GenerateCRL(cert *x509.Certificate, key crypto.PrivateKey, crlData *CRLData) ([]byte, error) {
	revokedCerts := crlData.PKIXRevokedCerts()

	crl, err := cert.CreateCRL(rand.Reader, key, revokedCerts,
		crlData.CurrentDate, crlData.ExpirationDate)
	if err != nil {
		return nil, err
	}

	return crl, nil
}

func (pki *PKI) WriteCRL(crl []byte, name string) error {
	crlPath := pki.CRLPath(name)

	return writeFile(crlPath, crl, 0644)
}

func (pki *PKI) CRLPath(name string) string {
	return path.Join(pki.CertificatesPath(), name+".crl")
}
