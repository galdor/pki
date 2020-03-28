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
	"fmt"
	"net"
	"net/url"
)

type ExtSubjectAltName struct {
	URIs           []*url.URL `json:"uris,omitempty"`
	DNSNames       []string   `json:"dnsNames,omitempty"`
	IPAddresses    []net.IP   `json:"ipAddresses,omitempty"`
	EmailAddresses []string   `json:"emailAddresses,omitempty"`
}

func (e *ExtSubjectAltName) Decode(data []byte) error {
	var seqValue asn1.RawValue

	rest, err := asn1.Unmarshal(data, &seqValue)
	if err != nil {
		return err
	} else if len(rest) > 0 {
		return errors.New("invalid trailing data")
	}

	if !seqValue.IsCompound {
		return fmt.Errorf("asn.1 data are not a compound type")
	}

	if seqValue.Tag != asn1.TagSequence {
		return fmt.Errorf("asn.1 data are not a sequence")
	}

	if seqValue.Class != asn1.ClassUniversal {
		return fmt.Errorf("asn.1 data class is not universal")
	}

	seqData := seqValue.Bytes
	for len(seqData) > 0 {
		var value asn1.RawValue
		rest, err := asn1.Unmarshal(seqData, &value)
		if err != nil {
			return err
		}

		switch value.Tag {
		case 1:
			// Email address
			address := string(value.Bytes)

			e.EmailAddresses = append(e.EmailAddresses, address)

		case 2:
			// DNS name
			name := string(value.Bytes)

			e.DNSNames = append(e.DNSNames, name)

		case 6:
			// URI
			uriString := string(value.Bytes)

			uri, err := url.Parse(uriString)
			if err != nil {
				return fmt.Errorf("invalid uri %q: %w",
					uriString, err)
			}

			e.URIs = append(e.URIs, uri)

		case 7:
			// IP address
			var address net.IP

			switch len(value.Bytes) {
			case net.IPv4len, net.IPv6len:
				address = value.Bytes[:]
			default:
				return fmt.Errorf("invalid ip address data: "+
					"%+v", value.Bytes)
			}

			e.IPAddresses = append(e.IPAddresses, address)

		default:
			return fmt.Errorf("unknown tag %d", value.Tag)
		}

		seqData = rest
	}

	return nil
}
