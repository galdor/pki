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

	cl.AddOption("", "subject-country", "name",
		"the subject country")
	cl.AddOption("", "subject-organization", "name",
		"the subject organization")
	cl.AddOption("", "subject-organizational-unit", "name",
		"the subject organizational unit")
	cl.AddOption("", "subject-locality", "name",
		"the subject locality")
	cl.AddOption("", "subject-province", "name",
		"the subject province")
	cl.AddOption("", "subject-street-address", "name",
		"the subject street-address")
	cl.AddOption("", "subject-postal-code", "name",
		"the subject postal code")
	cl.AddOption("", "subject-common-name", "name",
		"the subject common name")

	cl.Parse(args)

	validityString := cl.OptionValue("validity")
	i64, err := strconv.ParseInt(validityString, 10, 64)
	if err != nil || i64 < 1 || i64 > math.MaxInt32 {
		die("invalid validity")
	}
	validity := int(i64)

	// Main
	certData := CertificateData{
		Validity: validity,

		Subject: Subject{
			Country:            cl.OptionValue("subject-country"),
			Organization:       cl.OptionValue("subject-organization"),
			OrganizationalUnit: cl.OptionValue("subject-organizational-unit"),
			Locality:           cl.OptionValue("subject-locality"),
			Province:           cl.OptionValue("subject-province"),
			StreetAddress:      cl.OptionValue("subject-street-address"),
			PostalCode:         cl.OptionValue("subject-postal-code"),
			CommonName:         cl.OptionValue("subject-common-name"),
		},

		IsCA: true,
	}

	if err := pki.Initialize(&certData); err != nil {
		die("cannot initialize pki: %v", err)
	}
}
