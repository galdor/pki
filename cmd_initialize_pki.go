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

	"github.com/galdor/go-program"
)

func addCmdInitializePKI(p *program.Program) {
	c := p.AddCommand("initialize-pki",
		"initialize a new public key infrastructure", cmdInitializePKI)

	c.AddOption("", "validity", "days", "365",
		"the duration during which the root certificate will remain valid")
	c.AddFlag("e", "encrypt-private-key", "encrypt the private key")

	c.AddOption("", "country", "name", "", "the subject country")
	c.AddOption("", "organization", "name", "", "the subject organization")
	c.AddOption("", "organizational-unit", "name", "",
		"the subject organizational unit")
	c.AddOption("", "locality", "name", "", "the subject locality")
	c.AddOption("", "province", "name", "", "the subject province")
	c.AddOption("", "street-address", "name", "", "the subject street-address")
	c.AddOption("", "postal-code", "name", "", "the subject postal code")
	c.AddOption("", "common-name", "name", "", "the subject common name")
}

func cmdInitializePKI(p *program.Program) {
	validityString := p.OptionValue("validity")
	i64, err := strconv.ParseInt(validityString, 10, 64)
	if err != nil || i64 < 1 || i64 > math.MaxInt32 {
		p.Fatal("invalid validity")
	}
	validity := int(i64)

	var privateKeyPassword []byte
	if p.IsOptionSet("encrypt-private-key") {
		password, err := ReadPrivateKeyPasswordForCreation(RootCAName)
		if err != nil {
			p.Fatal("cannot read private key password: %v", err)
		}

		privateKeyPassword = password
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

		IsCA: true,
	}

	if err := pki.Initialize(&certData, privateKeyPassword); err != nil {
		p.Fatal("cannot initialize pki: %v", err)
	}
}
