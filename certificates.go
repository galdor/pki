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
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"path"
)

func (pki *PKI) LoadCertificate(name string) (*x509.Certificate, error) {
	info("loading certificate %q", name)

	certPath := pki.CertificatePath(name)

	data, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read %q: %w", certPath, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no pem block found")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cannot parse certificate: %w", err)
	}

	return cert, nil
}

func (pki *PKI) CreateCertificate(name string, data *CertificateData, issuerCert *x509.Certificate, issuerKey crypto.PrivateKey) (*x509.Certificate, error) {
	info("creating certificate %q", name)

	cert, err := pki.GenerateCertificate(data, issuerCert, issuerKey)
	if err != nil {
		return nil, fmt.Errorf("cannot generate certificate: %w", err)
	}

	if err := pki.WriteCertificate(cert, name); err != nil {
		return nil, fmt.Errorf("cannot write certificate: %w", err)
	}

	return cert, nil
}

func (pki *PKI) GenerateCertificate(data *CertificateData, issuerCert *x509.Certificate, issuerKey crypto.PrivateKey) (*x509.Certificate, error) {
	template, err := data.CertificateTemplate()
	if err != nil {
		return nil, err
	}

	if issuerCert == nil {
		issuerCert = template
	}

	publicKey := PublicKey(issuerKey)

	derData, err := x509.CreateCertificate(rand.Reader, template,
		issuerCert, publicKey, issuerKey)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(derData)
	if err != nil {
		return nil, fmt.Errorf("cannot parse certificate: %w", err)
	}

	return cert, nil
}

func (pki *PKI) WriteCertificate(cert *x509.Certificate, name string) error {
	block := pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
	pemData := pem.EncodeToMemory(&block)

	certPath := pki.CertificatePath(name)

	return writeFile(certPath, pemData, 0644)
}

func (pki *PKI) CertificatesPath() string {
	return path.Join(pki.Path, "certificates")
}

func (pki *PKI) CertificatePath(name string) string {
	return path.Join(pki.CertificatesPath(), name+".cert")
}

func generateRandomSerialNumber() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, max)
}
