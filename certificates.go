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
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"path"
	"time"
)

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

func (s *Subject) PKIXName() pkix.Name {
	var name pkix.Name

	if s.Country != "" {
		name.Country = []string{s.Country}
	}

	if s.Organization != "" {
		name.Organization = []string{s.Organization}
	}

	if s.OrganizationalUnit != "" {
		name.OrganizationalUnit = []string{s.OrganizationalUnit}
	}

	if s.Locality != "" {
		name.Locality = []string{s.Locality}
	}

	if s.Province != "" {
		name.Province = []string{s.Province}
	}

	if s.StreetAddress != "" {
		name.StreetAddress = []string{s.StreetAddress}
	}

	if s.PostalCode != "" {
		name.PostalCode = []string{s.PostalCode}
	}

	name.CommonName = s.CommonName

	return name
}

type SAN struct {
	URIs           []*url.URL `json:"uris,omitempty"`
	DNSNames       []string   `json:"dnsNames,omitempty"`
	IPAddresses    []net.IP   `json:"ipAddresses,omitempty"`
	EmailAddresses []string   `json:"emailAddresses,omitempty"`
}

type CertificateData struct {
	Validity int     `json:"validity"` // days
	Subject  Subject `json:"subject"`
	SAN      SAN     `json:"san"`
	IsCA     bool    `json:"isCA,omitempty"`
}

func (data *CertificateData) CertificateTemplate() (*x509.Certificate, error) {
	serialNumber, err := generateRandomSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("cannot generate random serial "+
			"number: %w", err)
	}

	now := time.Now().UTC()
	notBefore := now
	notAfter := now.Add(time.Duration(data.Validity) * 24 * time.Hour)

	keyUsage := x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	if data.IsCA {
		keyUsage |= x509.KeyUsageCertSign
	}
	extKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}

	template := x509.Certificate{
		SerialNumber: serialNumber,

		Subject: data.Subject.PKIXName(),

		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:    keyUsage,
		ExtKeyUsage: extKeyUsage,

		BasicConstraintsValid: true,
		IsCA:                  data.IsCA,

		URIs:           data.SAN.URIs,
		DNSNames:       data.SAN.DNSNames,
		IPAddresses:    data.SAN.IPAddresses,
		EmailAddresses: data.SAN.EmailAddresses,
	}

	return &template, nil
}

func (pki *PKI) CreateCertificate(name string, data *CertificateData, parentCert *x509.Certificate, privateKey crypto.PrivateKey) (*x509.Certificate, error) {
	cert, err := pki.GenerateCertificate(data, parentCert, privateKey)
	if err != nil {
		return nil, fmt.Errorf("cannot generate certificate: %w", err)
	}

	if err := pki.WriteCertificate(cert, name); err != nil {
		return nil, fmt.Errorf("cannot write certificate: %w", err)
	}

	return cert, nil
}

func (pki *PKI) GenerateCertificate(data *CertificateData, parentCert *x509.Certificate, privateKey crypto.PrivateKey) (*x509.Certificate, error) {
	template, err := data.CertificateTemplate()
	if err != nil {
		return nil, err
	}

	if parentCert == nil {
		parentCert = template
	}

	publicKey := PublicKey(privateKey)

	derData, err := x509.CreateCertificate(rand.Reader, template,
		parentCert, publicKey, privateKey)
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
