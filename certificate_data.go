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
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"net/url"
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

type CertificateData struct {
	Validity            int     `json:"validity"` // days
	Subject             Subject `json:"subject"`
	SAN                 SAN     `json:"san"`
	IsCA                bool    `json:"isCA,omitempty"`
	IsClientCertificate bool    `json:"isClientCertificate,omitempty"`
}

func (data *CertificateData) UpdateFromDefaults(defaultData *CertificateData) {
	if data.Validity == 0 {
		data.Validity = defaultData.Validity
	}

	// Subject
	if data.Subject.Country == "" {
		data.Subject.Country = defaultData.Subject.Country
	}

	if data.Subject.Organization == "" {
		data.Subject.Organization = defaultData.Subject.Organization
	}

	if data.Subject.OrganizationalUnit == "" {
		data.Subject.OrganizationalUnit =
			defaultData.Subject.OrganizationalUnit
	}

	if data.Subject.Locality == "" {
		data.Subject.Locality = defaultData.Subject.Locality
	}

	if data.Subject.Province == "" {
		data.Subject.Province = defaultData.Subject.Province
	}

	if data.Subject.StreetAddress == "" {
		data.Subject.StreetAddress = defaultData.Subject.StreetAddress
	}

	if data.Subject.PostalCode == "" {
		data.Subject.PostalCode = defaultData.Subject.PostalCode
	}

	if data.Subject.CommonName == "" {
		data.Subject.CommonName = defaultData.Subject.CommonName
	}

	// SAN
	if data.SAN.URIs == nil {
		data.SAN.URIs = append([]*url.URL{},
			defaultData.SAN.URIs...)
	}

	if data.SAN.DNSNames == nil {
		data.SAN.DNSNames = append([]string{},
			defaultData.SAN.DNSNames...)
	}

	if data.SAN.IPAddresses == nil {
		data.SAN.IPAddresses = append([]net.IP{},
			defaultData.SAN.IPAddresses...)
	}

	if data.SAN.EmailAddresses == nil {
		data.SAN.EmailAddresses = append([]string{},
			defaultData.SAN.EmailAddresses...)
	}
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

	var keyUsage x509.KeyUsage
	keyUsage |= x509.KeyUsageKeyEncipherment
	keyUsage |= x509.KeyUsageDigitalSignature
	if data.IsCA {
		keyUsage |= x509.KeyUsageCertSign
		keyUsage |= x509.KeyUsageCRLSign
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,

		Subject: data.Subject.PKIXName(),

		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage: keyUsage,

		BasicConstraintsValid: true,
		IsCA:                  data.IsCA,

		URIs:           data.SAN.URIs,
		DNSNames:       data.SAN.DNSNames,
		IPAddresses:    data.SAN.IPAddresses,
		EmailAddresses: data.SAN.EmailAddresses,
	}

	return &template, nil
}
