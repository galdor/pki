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
	"fmt"
	"net"
	"net/url"
	"strings"
)

type SAN struct {
	URIs           []*url.URL `json:"uris,omitempty"`
	DNSNames       []string   `json:"dnsNames,omitempty"`
	IPAddresses    []net.IP   `json:"ipAddresses,omitempty"`
	EmailAddresses []string   `json:"emailAddresses,omitempty"`
}

func parseSANUris(s string) ([]*url.URL, error) {
	var uris []*url.URL

	parts := strings.Split(s, ",")

	for _, part := range parts {
		uriString := strings.Trim(part, " ")
		if uriString == "" {
			return nil, fmt.Errorf("empty uri")
		}

		uri, err := url.Parse(uriString)
		if err != nil {
			return nil, fmt.Errorf("invalid uri %q: %w",
				uriString, err)
		}

		uris = append(uris, uri)
	}

	return uris, nil
}

func parseSANDNSNames(s string) ([]string, error) {
	var names []string

	parts := strings.Split(s, ",")

	for _, part := range parts {
		name := strings.Trim(part, " ")
		if len(part) == 0 {
			return nil, fmt.Errorf("empty name")
		}

		names = append(names, name)
	}

	return names, nil
}

func parseSANIPAddresses(s string) ([]net.IP, error) {
	var addresses []net.IP

	parts := strings.Split(s, ",")

	for _, part := range parts {
		addressString := strings.Trim(part, " ")
		if addressString == "" {
			return nil, fmt.Errorf("empty ip address")
		}

		address := net.ParseIP(addressString)
		if address == nil {
			return nil, fmt.Errorf("invalid ip address %q",
				addressString)
		}

		addresses = append(addresses, address)
	}

	return addresses, nil
}

func parseSANEmailAddresses(s string) ([]string, error) {
	var addresses []string

	parts := strings.Split(s, ",")

	for _, part := range parts {
		address := strings.Trim(part, " ")
		if len(part) == 0 {
			return nil, fmt.Errorf("empty address")
		}

		addresses = append(addresses, address)
	}

	return addresses, nil
}
