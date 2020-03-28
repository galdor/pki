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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"path"
	"time"
)

func (pki *PKI) LoadCertificate(name string) (*x509.Certificate, error) {
	info("loading certificate %q", name)

	certPath := pki.CertificatePath(name)

	data, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read %q: %w", certPath, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no pem block found")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cannot parse certificate: %w", err)
	}

	return cert, nil
}

func (pki *PKI) CreateCertificate(name string, data *CertificateData, issuerCert *x509.Certificate, issuerKey crypto.PrivateKey) (*x509.Certificate, error) {
	info("creating certificate %q", name)

	cert, err := pki.GenerateCertificate(data, issuerCert, issuerKey)
	if err != nil {
		return nil, fmt.Errorf("cannot generate certificate: %w", err)
	}

	if err := pki.WriteCertificate(cert, name); err != nil {
		return nil, fmt.Errorf("cannot write certificate: %w", err)
	}

	return cert, nil
}

func (pki *PKI) GenerateCertificate(data *CertificateData, issuerCert *x509.Certificate, issuerKey crypto.PrivateKey) (*x509.Certificate, error) {
	template, err := data.CertificateTemplate()
	if err != nil {
		return nil, err
	}

	if issuerCert == nil {
		issuerCert = template
	}

	publicKey := PublicKey(issuerKey)

	derData, err := x509.CreateCertificate(rand.Reader, template,
		issuerCert, publicKey, issuerKey)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(derData)
	if err != nil {
		return nil, fmt.Errorf("cannot parse certificate: %w", err)
	}

	return cert, nil
}

func (pki *PKI) WriteCertificate(cert *x509.Certificate, name string) error {
	block := pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
	pemData := pem.EncodeToMemory(&block)

	certPath := pki.CertificatePath(name)

	return writeFile(certPath, pemData, 0644)
}

func (pki *PKI) CertificatesPath() string {
	return path.Join(pki.Path, "certificates")
}

func (pki *PKI) CertificatePath(name string) string {
	return path.Join(pki.CertificatesPath(), name+".cert")
}

func PrintCertificate(cert *x509.Certificate, w io.Writer) error {
	return printCertificate(NewPrinter(w), cert)
}

func printCertificate(p *Printer, cert *x509.Certificate) error {
	p.Line("Data:")
	p.WithIndent(func() {
		printCertificateData(p, cert)
	})

	p.Line("Signature:")
	p.WithIndent(func() {
		printCertificateSignature(p, cert)
	})

	return p.Error()
}

func printCertificateData(p *Printer, cert *x509.Certificate) {
	p.Line("Version: %d", cert.Version)
	p.Line("Serial number: %s", p.Hex(cert.SerialNumber.Bytes()))
	p.Line("Issuer: %s", cert.Issuer.String())

	p.Line("Validity:")
	p.WithIndent(func() {
		p.Line("Not before: %v", cert.NotBefore.Format(time.RFC3339))
		p.Line("Not after:  %v", cert.NotAfter.Format(time.RFC3339))
	})

	p.Line("Subject: %s", cert.Subject.String())

	p.Line("Public key:")
	p.WithIndent(func() {
		p.Line("Algorithm: %v", cert.PublicKeyAlgorithm)
		switch key := cert.PublicKey.(type) {
		case *ecdsa.PublicKey:
			p.Line("ECDSA curve: %s", key.Curve.Params().Name)
		case *rsa.PublicKey:
			p.Line("Size: %d", key.Size())
		case ed25519.PublicKey:
		default:
			p.Line("Unknown public key type %#v", key)
			return
		}
		publicKeyData, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err != nil {
			err = fmt.Errorf("cannot marshal public key: %w", err)
			return
		}
		p.Line("Data: %s", p.Hex(publicKeyData))
	})

	p.Line("Extensions:")
	p.WithIndent(func() {
		printCertificateExtensions(p, cert)
	})
}

func printCertificateExtensions(p *Printer, cert *x509.Certificate) {
	for _, ext := range cert.Extensions {
		idString := ext.Id.String()

		switch idString {
		case "2.5.29.15":
			printCertificateExtensionKeyUsage(p, ext)

		case "2.5.29.17":
			printCertificateExtensionSubjectAltName(p, ext)

		case "2.5.29.19":
			printCertificateExtensionBasicConstraints(p, ext)

		case "2.5.29.37":
			printCertificateExtensionExtendedKeyUsage(p, ext)

		default:
			printCertificateExtension(p, ext, idString, func() {
				p.Line("Non-decoded data: %s", p.Hex(ext.Value))
			})
		}
	}
}

func printCertificateExtension(p *Printer, ext pkix.Extension, name string, fn func()) {
	criticalString := ""
	if ext.Critical {
		criticalString = " (critical)"
	}

	p.Line("%s%s:", name, criticalString)
	p.WithIndent(fn)
}

func printCertificateExtensionKeyUsage(p *Printer, ext pkix.Extension) {
	var usage ExtKeyUsage
	if err := usage.Decode(ext.Value); err != nil {
		panic(fmt.Sprintf("cannot decode key usage extension: %v",
			err))
	}

	printCertificateExtension(p, ext, "Key usage", func() {
		for _, v := range usage.Values() {
			p.Line("%s", v)
		}
	})
}

func printCertificateExtensionSubjectAltName(p *Printer, ext pkix.Extension) {
	var san ExtSubjectAltName
	if err := san.Decode(ext.Value); err != nil {
		panic(fmt.Sprintf("cannot decode subject alt name extension: "+
			"%v", err))
	}

	printCertificateExtension(p, ext, "Subject alt name", func() {
		p.Line("URIs:")
		p.WithIndent(func() {
			for _, uri := range san.URIs {
				p.Line("%s", uri.String())
			}
		})

		p.Line("DNS names:")
		p.WithIndent(func() {
			for _, name := range san.DNSNames {
				p.Line("%s", name)
			}
		})

		p.Line("IP addresses")
		p.WithIndent(func() {
			for _, address := range san.IPAddresses {
				p.Line("%s", address.String())
			}
		})

		p.Line("Email addresses")
		p.WithIndent(func() {
			for _, address := range san.EmailAddresses {
				p.Line("%s", address)
			}
		})
	})
}

func printCertificateExtensionBasicConstraints(p *Printer, ext pkix.Extension) {
	var cs ExtBasicConstraints
	if err := cs.Decode(ext.Value); err != nil {
		panic(fmt.Sprintf("cannot decode basic contraints extension: "+
			"%v", err))
	}

	printCertificateExtension(p, ext, "Basic constraints", func() {
		p.Line("CA: %v", cs.CA)
		if cs.PathLenConstraint != -1 {
			p.Line("Path length constraint: %d",
				cs.PathLenConstraint)
		}
	})
}

func printCertificateExtensionExtendedKeyUsage(p *Printer, ext pkix.Extension) {
	var usage ExtExtendedKeyUsage
	if err2 := usage.Decode(ext.Value); err2 != nil {
		panic(fmt.Sprintf("cannot decode extended key usage "+
			"extension: %v", err2))
	}

	printCertificateExtension(p, ext, "Extended key usage", func() {
		for _, id := range usage.KeyPurposeIds {
			p.Line("%s", id)
		}
	})
}

func printCertificateSignature(p *Printer, cert *x509.Certificate) {
	p.Line("Algorithm: %v", cert.SignatureAlgorithm)
	p.Line("Data: %v", p.Hex(cert.Signature))
}

func generateRandomSerialNumber() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, max)
}
