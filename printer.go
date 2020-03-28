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
	"bytes"
	"fmt"
	"io"
)

type Printer struct {
	w   io.Writer
	err error

	indent int
}

func NewPrinter(w io.Writer) *Printer {
	p := Printer{
		w: w,
	}

	return &p
}

func (p *Printer) Error() error {
	return p.err
}

func (p *Printer) Indent() {
	p.indent++
}

func (p *Printer) Unindent() {
	p.indent--
}

func (p *Printer) WithIndent(fn func()) {
	p.Indent()
	fn()
	p.Unindent()
}

func (p *Printer) Line(format string, args ...interface{}) {
	if p.err != nil {
		return
	}

	p.printIndent(p.w)

	if _, err := fmt.Fprintf(p.w, format+"\n", args...); err != nil {
		p.err = err
	}
}

func (p *Printer) Hex(data []byte) string {
	var buf bytes.Buffer

	p.indent++

	for i, byte := range data {
		if i%16 == 0 {
			buf.WriteByte('\n')
			p.printIndent(&buf)
		} else {
			buf.WriteByte(' ')
		}

		fmt.Fprintf(&buf, "%02x", byte)
	}

	p.indent--

	return buf.String()
}

func (p *Printer) printIndent(w io.Writer) {
	for i := 0; i < p.indent*4; i++ {
		if _, err := io.WriteString(w, " "); err != nil {
			p.err = err
			return
		}
	}
}
