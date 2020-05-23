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
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"path"
)

type PrivateKeyPasswordReader func() ([]byte, error)

func (pki *PKI) LoadPrivateKey(name string, passwordReader PrivateKeyPasswordReader) (crypto.PrivateKey, error) {
	info("loading private key %q", name)

	keyPath := pki.PrivateKeyPath(name)

	data, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read %q: %w", keyPath, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no pem block found")
	}

	var blockData []byte

	if x509.IsEncryptedPEMBlock(block) {
		info("decrypting private key")

		password, err := passwordReader()
		if err != nil {
			return nil, fmt.Errorf("cannot read password: %w", err)
		}

		decryptedBlock, err := x509.DecryptPEMBlock(block, password)
		if err != nil {
			return nil, fmt.Errorf(
				"cannot decrypt pem block: %w", err)
		}

		blockData = decryptedBlock
	} else {
		blockData = block.Bytes
	}

	keyData, err := x509.ParsePKCS8PrivateKey(blockData)
	if err != nil {
		return nil, fmt.Errorf("cannot parse key: %w", err)
	}

	ecdsaKey, ok := keyData.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("key is not an ecdsa key")
	}

	return ecdsaKey, nil
}

func (pki *PKI) CreatePrivateKey(name string, password []byte) (crypto.PrivateKey, error) {
	info("creating private key %q", name)

	key, err := pki.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("cannot generate private key: %w", err)
	}

	if err := pki.WritePrivateKey(key, name, password); err != nil {
		return nil, fmt.Errorf("cannot write private key: %w", err)
	}

	return key, nil
}

func (pki *PKI) GeneratePrivateKey() (crypto.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func (pki *PKI) WritePrivateKey(key crypto.PrivateKey, name string, password []byte) error {
	derData, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("cannot encode private key: %w", err)
	}

	var block *pem.Block

	blockType := "PRIVATE KEY"

	if password == nil {
		block = &pem.Block{Type: blockType, Bytes: derData}
	} else {
		block, err = x509.EncryptPEMBlock(rand.Reader, blockType,
			derData, password, x509.PEMCipherAES256)
		if err != nil {
			return fmt.Errorf("cannot encrypt pem block: %w", err)
		}
	}

	pemData := pem.EncodeToMemory(block)

	keyPath := pki.PrivateKeyPath(name)

	return createFile(keyPath, pemData, 0600)
}

func (pki *PKI) PrivateKeysPath() string {
	return path.Join(pki.Path, "private-keys")
}

func (pki *PKI) PrivateKeyPath(name string) string {
	return path.Join(pki.PrivateKeysPath(), name+".key")
}

func PublicKey(privateKey crypto.PrivateKey) crypto.PublicKey {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		return &key.PublicKey

	case *ecdsa.PrivateKey:
		return &key.PublicKey

	case ed25519.PrivateKey:
		return key.Public().(ed25519.PublicKey)

	default:
		panic(fmt.Sprintf("unhandled private key %#v", privateKey))
	}
}
