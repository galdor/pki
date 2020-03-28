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
	"encoding/asn1"
	"errors"
)

// See RFC 5280 4.2.1.3.

type ExtKeyUsage struct {
	DigitalSignature bool
	NonRepudiation   bool
	KeyEncipherment  bool
	DataEncipherment bool
	KeyAgreement     bool
	KeyCertSign      bool
	CRLSign          bool
	EncipherOnly     bool
	DecipherOnly     bool
}

func (e *ExtKeyUsage) Values() []string {
	var values []string

	if e.DigitalSignature {
		values = append(values, "digitalSignature")
	}

	if e.NonRepudiation {
		values = append(values, "nonRepudiation")
	}

	if e.KeyEncipherment {
		values = append(values, "keyEncipherment")
	}

	if e.DataEncipherment {
		values = append(values, "dataEncipherment")
	}

	if e.KeyAgreement {
		values = append(values, "keyAgreement")
	}

	if e.KeyCertSign {
		values = append(values, "keyCertSign")
	}

	if e.CRLSign {
		values = append(values, "cRLSign")
	}

	if e.EncipherOnly {
		values = append(values, "encipherOnly")
	}

	if e.DecipherOnly {
		values = append(values, "decipherOnly")
	}

	return values
}

func (e *ExtKeyUsage) Decode(data []byte) error {
	var bits asn1.BitString

	if rest, err := asn1.Unmarshal(data, &bits); err != nil {
		return err
	} else if len(rest) != 0 {
		return errors.New("invalid trailing data")
	}

	if bits.At(0) != 0 {
		e.DigitalSignature = true
	}

	if bits.At(1) != 0 {
		e.NonRepudiation = true
	}

	if bits.At(2) != 0 {
		e.KeyEncipherment = true
	}

	if bits.At(3) != 0 {
		e.DataEncipherment = true
	}

	if bits.At(4) != 0 {
		e.KeyAgreement = true
	}

	if bits.At(5) != 0 {
		e.KeyCertSign = true
	}

	if bits.At(6) != 0 {
		e.CRLSign = true
	}

	if bits.At(7) != 0 {
		e.EncipherOnly = true
	}

	if bits.At(8) != 0 {
		e.DecipherOnly = true
	}

	return nil
}
