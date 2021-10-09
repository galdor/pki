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
	"github.com/galdor/go-program"
)

var p *program.Program
var pki *PKI

func main() {
	p = program.NewProgram("pki", "public key infrastructure management")

	p.AddOption("d", "directory", "path", ".", "the path of the pki directory")

	addCmdInitializePKI(p)
	addCmdCreateCertificate(p)
	addCmdPrintCertificate(p)
	addCmdRevokeCertificate(p)

	p.ParseCommandLine()

	pkiPath := p.OptionValue("directory")
	pki = NewPKI(pkiPath)
	if p.CommandName() != "help" && p.CommandName() != "initialize-pki" {
		if err := pki.LoadConfiguration(); err != nil {
			p.Fatal("cannot load pki configuration: %v", err)
		}
	}

	p.Run()
}
