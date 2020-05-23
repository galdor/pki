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

	"github.com/galdor/go-cmdline"
)

func cmdRevokeCertificate(args []string, pki *PKI) {
	// Command line
	cl := cmdline.New()

	cl.AddOption("i", "issuer-certificate", "name",
		"the name of the issuer certificate")
	cl.SetOptionDefault("issuer-certificate", RootCAName)

	cl.AddArgument("name", "the name of the certificate to revoke")

	cl.Parse(args)

	issuerCertName := cl.OptionValue("issuer-certificate")
	issuerKeyName := issuerCertName

	certName := cl.ArgumentValue("name")

	// Main
	issuerCert, err := pki.LoadCertificate(issuerCertName)
	if err != nil {
		die("cannot load issuer certificate: %v", err)
	}

	issuerKey, err := pki.LoadPrivateKey(issuerKeyName,
		func() ([]byte, error) {
			return ReadPrivateKeyPassword(issuerKeyName)
		})
	if err != nil {
		die("cannot load issuer private key: %v", err)
	}

	cert, err := pki.LoadCertificate(certName)
	if err != nil {
		die("cannot load certificate: %v", err)
	}

	data, err := pki.LoadCRL(issuerCertName)
	if err != nil {
		die("cannot load crl: %v", err)
	}

	var crlData CRLData
	if err := crlData.Read(data); err != nil {
		die("cannot read crl data: %v", err)
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
		die("cannot create crl: %v", err)
	}
}
