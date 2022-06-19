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
	"math"
	"net"
	"net/url"
	"strconv"

	"github.com/galdor/go-program"
)

func addCmdCreateCertificate(p *program.Program) {
	c := p.AddCommand("create-certificate", "create a new certificate",
		cmdCreateCertificate)

	c.AddArgument("name", "the name of the certificate")

	c.AddOption("i", "issuer-certificate", "name", RootCAName,
		"the name of the issuer certificate")

	c.AddFlag("", "ca", "create a ca certificate")
	c.AddFlag("", "client", "create a client certificate")
	c.AddFlag("e", "encrypt-private-key", "encrypt the private key")

	c.AddOption("", "validity", "days", "",
		"the duration during which the certificate will remain valid")

	c.AddOption("", "country", "name", "", "the subject country")
	c.AddOption("", "organization", "name", "", "the subject organization")
	c.AddOption("", "organizational-unit", "name", "",
		"the subject organizational unit")
	c.AddOption("", "locality", "name", "", "the subject locality")
	c.AddOption("", "province", "name", "", "the subject province")
	c.AddOption("", "street-address", "address", "",
		"the subject street-address")
	c.AddOption("", "postal-code", "code", "", "the subject postal code")
	c.AddOption("", "common-name", "domain", "", "the subject common name")

	c.AddOption("", "san-uris", "uris", "",
		"a list of uris used for the san extension")
	c.AddOption("", "san-dns-names", "names", "",
		"a list of dns names used for the san extension")
	c.AddOption("", "san-ip-addresses", "addresses", "",
		"a list of ip addresses used for the san extension")
	c.AddOption("", "san-email-addresses", "addresses", "",
		"a list of email addresses used for the san extension")
}

func cmdCreateCertificate(p *program.Program) {
	name := p.ArgumentValue("name")

	issuerCertName := p.OptionValue("issuer-certificate")
	issuerKeyName := issuerCertName

	validity := 0
	if p.IsOptionSet("validity") {
		validityString := p.OptionValue("validity")
		i64, err := strconv.ParseInt(validityString, 10, 64)
		if err != nil || i64 < 1 || i64 > math.MaxInt32 {
			p.Fatal("invalid validity")
		}

		validity = int(i64)
	}

	var sanURIs []*url.URL
	if s := p.OptionValue("san-uris"); s != "" {
		uris, err := parseSANUris(s)
		if err != nil {
			p.Fatal("invalid san uris: %v", err)
		}

		sanURIs = uris
	}

	var sanDNSNames []string
	if s := p.OptionValue("san-dns-names"); s != "" {
		names, err := parseSANDNSNames(s)
		if err != nil {
			p.Fatal("invalid san dns names: %v", err)
		}

		sanDNSNames = names
	}

	var sanIPAddresses []net.IP
	if s := p.OptionValue("san-ip-addresses"); s != "" {
		addresses, err := parseSANIPAddresses(s)
		if err != nil {
			p.Fatal("invalid san ip addresses: %v", err)
		}

		sanIPAddresses = addresses
	}

	var sanEmailAddresses []string
	if s := p.OptionValue("san-email-addresses"); s != "" {
		addresses, err := parseSANEmailAddresses(s)
		if err != nil {
			p.Fatal("invalid san email addresses: %v", err)
		}

		sanEmailAddresses = addresses
	}

	issuerKey, err := pki.LoadPrivateKey(issuerKeyName,
		func() ([]byte, error) {
			return ReadPrivateKeyPassword(issuerKeyName)
		})
	if err != nil {
		p.Fatal("cannot load issuer private key: %v", err)
	}

	issuerCert, err := pki.LoadCertificate(issuerCertName)
	if err != nil {
		p.Fatal("cannot load issuer certificate: %v", err)
	}

	certData := CertificateData{
		Validity: validity,

		Subject: Subject{
			Country:            p.OptionValue("country"),
			Organization:       p.OptionValue("organization"),
			OrganizationalUnit: p.OptionValue("organizational-unit"),
			Locality:           p.OptionValue("locality"),
			Province:           p.OptionValue("province"),
			StreetAddress:      p.OptionValue("street-address"),
			PostalCode:         p.OptionValue("postal-code"),
			CommonName:         p.OptionValue("common-name"),
		},

		SAN: SAN{
			URIs:           sanURIs,
			DNSNames:       sanDNSNames,
			IPAddresses:    sanIPAddresses,
			EmailAddresses: sanEmailAddresses,
		},

		IsCA:                p.IsOptionSet("ca"),
		IsClientCertificate: p.IsOptionSet("client"),
	}

	certData.UpdateFromDefaults(&pki.Cfg.Certificates)

	var privateKeyPassword []byte
	if p.IsOptionSet("encrypt-private-key") {
		password, err := ReadPrivateKeyPasswordForCreation(name)
		if err != nil {
			p.Fatal("cannot read private key password: %v", err)
		}

		privateKeyPassword = password
	}

	key, err := pki.CreatePrivateKey(name, privateKeyPassword)
	if err != nil {
		p.Fatal("cannot private key: %v", err)
	}

	_, err = pki.CreateCertificate(name, &certData, issuerCert, issuerKey,
		PublicKey(key))
	if err != nil {
		p.Fatal("cannot initialize pki: %v", err)
	}
}
