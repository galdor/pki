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

	"github.com/galdor/go-cmdline"
)

func cmdCreateCertificate(args []string, pki *PKI) {
	// Command line
	cl := cmdline.New()

	cl.AddArgument("name", "the name of the certificate")

	cl.AddOption("i", "issuer-certificate", "name",
		"the name of the issuer certificate")
	cl.SetOptionDefault("issuer-certificate", RootCAName)

	cl.AddFlag("", "ca", "create a ca certificate")
	cl.AddFlag("", "client", "create a client certificate")

	cl.AddOption("v", "validity", "days",
		"the duration during which the certificate will remain valid")

	cl.AddOption("", "country", "name",
		"the subject country")
	cl.AddOption("", "organization", "name",
		"the subject organization")
	cl.AddOption("", "organizational-unit", "name",
		"the subject organizational unit")
	cl.AddOption("", "locality", "name",
		"the subject locality")
	cl.AddOption("", "province", "name",
		"the subject province")
	cl.AddOption("", "street-address", "name",
		"the subject street-address")
	cl.AddOption("", "postal-code", "name",
		"the subject postal code")
	cl.AddOption("", "common-name", "name",
		"the subject common name")

	cl.AddOption("", "san-uris", "uris",
		"a list of uris used for the san extension")
	cl.AddOption("", "san-dns-names", "names",
		"a list of dns names used for the san extension")
	cl.AddOption("", "san-ip-addresses", "addresses",
		"a list of ip addresses used for the san extension")
	cl.AddOption("", "san-email-addresses", "addresses",
		"a list of email addresses used for the san extension")

	cl.Parse(args)

	name := cl.ArgumentValue("name")

	issuerCertName := cl.OptionValue("issuer-certificate")
	issuerKeyName := issuerCertName

	validity := 0
	if cl.IsOptionSet("validity") {
		validityString := cl.OptionValue("validity")
		i64, err := strconv.ParseInt(validityString, 10, 64)
		if err != nil || i64 < 1 || i64 > math.MaxInt32 {
			die("invalid validity")
		}

		validity = int(i64)
	}

	var sanURIs []*url.URL
	if s := cl.OptionValue("san-uris"); s != "" {
		uris, err := parseSANUris(s)
		if err != nil {
			die("invalid san uris: %v", err)
		}

		sanURIs = uris
	}

	var sanDNSNames []string
	if s := cl.OptionValue("san-dns-names"); s != "" {
		names, err := parseSANDNSNames(s)
		if err != nil {
			die("invalid san dns names: %v", err)
		}

		sanDNSNames = names
	}

	var sanIPAddresses []net.IP
	if s := cl.OptionValue("san-ip-addresses"); s != "" {
		addresses, err := parseSANIPAddresses(s)
		if err != nil {
			die("invalid san ip addresses: %v", err)
		}

		sanIPAddresses = addresses
	}

	var sanEmailAddresses []string
	if s := cl.OptionValue("san-email-addresses"); s != "" {
		addresses, err := parseSANEmailAddresses(s)
		if err != nil {
			die("invalid san email addresses: %v", err)
		}

		sanEmailAddresses = addresses
	}

	// Main
	issuerKey, err := pki.LoadPrivateKey(issuerKeyName)
	if err != nil {
		die("cannot load issuer private key: %v", err)
	}

	issuerCert, err := pki.LoadCertificate(issuerCertName)
	if err != nil {
		die("cannot load issuer certificate: %v", err)
	}

	certData := CertificateData{
		Validity: validity,

		Subject: Subject{
			Country:            cl.OptionValue("country"),
			Organization:       cl.OptionValue("organization"),
			OrganizationalUnit: cl.OptionValue("organizational-unit"),
			Locality:           cl.OptionValue("locality"),
			Province:           cl.OptionValue("province"),
			StreetAddress:      cl.OptionValue("street-address"),
			PostalCode:         cl.OptionValue("postal-code"),
			CommonName:         cl.OptionValue("common-name"),
		},

		SAN: SAN{
			URIs:           sanURIs,
			DNSNames:       sanDNSNames,
			IPAddresses:    sanIPAddresses,
			EmailAddresses: sanEmailAddresses,
		},

		IsCA:                cl.IsOptionSet("ca"),
		IsClientCertificate: cl.IsOptionSet("client"),
	}

	certData.UpdateFromDefaults(&pki.Cfg.Certificates)

	_, err = pki.CreatePrivateKey(name)
	if err != nil {
		die("cannot private key: %v", err)
	}

	_, err = pki.CreateCertificate(name, &certData, issuerCert, issuerKey)
	if err != nil {
		die("cannot initialize pki: %v", err)
	}
}
