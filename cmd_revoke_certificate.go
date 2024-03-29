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
	"time"

	"github.com/galdor/go-program"
)

func addCmdRevokeCertificate(p *program.Program) {
	c := p.AddCommand("revoke-certificate", "revoke a certificate",
		cmdRevokeCertificate)

	c.AddOption("i", "issuer-certificate", "name", RootCAName,
		"the name of the issuer certificate")

	c.AddArgument("name", "the name of the certificate")
}

func cmdRevokeCertificate(p *program.Program) {
	issuerCertName := p.OptionValue("issuer-certificate")
	issuerKeyName := issuerCertName

	certName := p.ArgumentValue("name")

	issuerCert, err := pki.LoadCertificate(issuerCertName)
	if err != nil {
		p.Fatal("cannot load issuer certificate: %v", err)
	}

	issuerKey, err := pki.LoadPrivateKey(issuerKeyName,
		func() ([]byte, error) {
			return ReadPrivateKeyPassword(issuerKeyName)
		})
	if err != nil {
		p.Fatal("cannot load issuer private key: %v", err)
	}

	cert, err := pki.LoadCertificate(certName)
	if err != nil {
		p.Fatal("cannot load certificate: %v", err)
	}

	data, err := pki.LoadCRL(issuerCertName)
	if err != nil {
		p.Fatal("cannot load crl: %v", err)
	}

	var crlData CRLData
	if err := crlData.Read(data); err != nil {
		p.Fatal("cannot read crl data: %v", err)
	}

	// Since we always create CRLs with an expiration date equal to the
	// expiration date of the CA certificate, there is no point in
	// updating it.
	crlData.CreationDate = time.Now().UTC()

	crlData.AddRevokedCertificate(CRLRevokedCert{
		SerialNumber:   *cert.SerialNumber,
		RevocationDate: time.Now().UTC(),
	})

	_, err = pki.UpdateCRL(issuerCertName, issuerCert, issuerKey, &crlData)
	if err != nil {
		p.Fatal("cannot create crl: %v", err)
	}
}
