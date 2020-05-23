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
	"strconv"

	"github.com/galdor/go-cmdline"
)

func cmdInitializePKI(args []string, pki *PKI) {
	// Command line
	cl := cmdline.New()

	cl.AddOption("v", "validity", "days",
		"the duration during which the root certificate will "+
			"remain valid")
	cl.SetOptionDefault("validity", "365")

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

	cl.Parse(args)

	validityString := cl.OptionValue("validity")
	i64, err := strconv.ParseInt(validityString, 10, 64)
	if err != nil || i64 < 1 || i64 > math.MaxInt32 {
		die("invalid validity")
	}
	validity := int(i64)

	// Private key password prompt
	privateKeyPassword, err := ReadPrivateKeyPasswordForCreation(RootCAName)
	if err != nil {
		die("cannot read private key password: %v", err)
	}

	// Main
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

		IsCA: true,
	}

	if err := pki.Initialize(&certData, privateKeyPassword); err != nil {
		die("cannot initialize pki: %v", err)
	}
}
