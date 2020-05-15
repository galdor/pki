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
	"math/big"
	"time"
)

type CRLRevokedCert struct {
	SerialNumber   big.Int
	RevocationDate time.Time
}

type CRLData struct {
	RevokedCerts   []CRLRevokedCert
	CreationDate   time.Time
	ExpirationDate time.Time
}

func (crl *CRLData) AddRevokedCertificate(rc CRLRevokedCert) {
	crl.RevokedCerts = append(crl.RevokedCerts, rc)
}

func (crl *CRLData) Read(data []byte) error {
	cl, err := x509.ParseCRL(data)
	if err != nil {
		return fmt.Errorf("cannot parse crl: %w", err)
	}

	crl.CreationDate = cl.TBSCertList.ThisUpdate
	crl.ExpirationDate = cl.TBSCertList.NextUpdate

	crl.RevokedCerts = make([]CRLRevokedCert,
		len(cl.TBSCertList.RevokedCertificates))

	for i, pkixRc := range cl.TBSCertList.RevokedCertificates {
		rc := CRLRevokedCert{
			RevocationDate: pkixRc.RevocationTime,
			SerialNumber:   *pkixRc.SerialNumber,
		}

		crl.RevokedCerts[i] = rc
	}

	return nil
}

func (crl *CRLData) PKIXRevokedCerts() []pkix.RevokedCertificate {
	rcs := make([]pkix.RevokedCertificate, len(crl.RevokedCerts))

	for i, c := range crl.RevokedCerts {
		rc := pkix.RevokedCertificate{
			SerialNumber:   &c.SerialNumber,
			RevocationTime: c.RevocationDate,
		}

		rcs[i] = rc
	}

	return rcs
}
