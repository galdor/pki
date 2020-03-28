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

// See RFC 5280 4.2.1.12.

type ExtExtendedKeyUsage struct {
	KeyPurposeIds []string
}

func (usage *ExtExtendedKeyUsage) Decode(data []byte) error {
	var purposeIds []asn1.ObjectIdentifier

	if rest, err := asn1.Unmarshal(data, &purposeIds); err != nil {
		return err
	} else if len(rest) != 0 {
		return errors.New("invalid trailing data")
	}

	for _, id := range purposeIds {
		var purpose string

		switch id.String() {
		case "1.3.6.1.5.5.7.3.1":
			purpose = "serverAuth"

		case "1.3.6.1.5.5.7.3.2":
			purpose = "clientAuth"

		case "1.3.6.1.5.5.7.3.3":
			purpose = "codeSigning"

		case "1.3.6.1.5.5.7.3.4":
			purpose = "emailProtection"

		case "1.3.6.1.5.5.7.3.5":
			purpose = "IPSECEndSystem"

		case "1.3.6.1.5.5.7.3.6":
			purpose = "IPSECTunnel"

		case "1.3.6.1.5.5.7.3.7":
			purpose = "IPSECUser"

		case "1.3.6.1.5.5.7.3.8":
			purpose = "timeStamping"

		case "1.3.6.1.5.5.7.3.9":
			purpose = "OCSPSigning"

		default:
			purpose = id.String()
		}

		usage.KeyPurposeIds = append(usage.KeyPurposeIds, purpose)
	}

	return nil
}
