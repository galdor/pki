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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"path"
)

func (pki *PKI) CreatePrivateKey(name string) (crypto.PrivateKey, error) {
	key, err := pki.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("cannot generate private key: %w", err)
	}

	if err := pki.WritePrivateKey(key, name); err != nil {
		return nil, fmt.Errorf("cannot write private key: %w", err)
	}

	return key, nil
}

func (pki *PKI) GeneratePrivateKey() (crypto.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func (pki *PKI) WritePrivateKey(key crypto.PrivateKey, name string) error {
	derData, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("cannot encode private key: %w", err)
	}

	block := pem.Block{Type: "PRIVATE KEY", Bytes: derData}
	pemData := pem.EncodeToMemory(&block)

	keyPath := pki.PrivateKeyPath(name)

	return writeFile(keyPath, pemData, 0600)
}

func (pki *PKI) PrivateKeysPath() string {
	return path.Join(pki.Path, "private-keys")
}

func (pki *PKI) PrivateKeyPath(name string) string {
	return path.Join(pki.PrivateKeysPath(), name+".key")
}
