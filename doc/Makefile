### Makefile for generating XRP documentation

# Copyright (c) 2015 - 2018 Cadence Design Systems, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


# Running 'make all' here will generate the HTML and PDF output.
# The PDF will be generated in the latex directory and renamed/copied here.
#
# Requires Doxygen 1.8.9.1 or later, pdfTeX 3.14159265-2.6-1.40.16 (TeX Live 2015) or later.

srcdir = .

all: html pdf

doxygen: xrp.conf
	doxygen xrp.conf

html: doxygen
pdf: doxygen
	cp -f $(srcdir)/xrp.sty latex/
	cp -f $(srcdir)/Cadence_Logo_Red.png latex/
	make -C latex pdf
	cp latex/refman.pdf xrp_rm.pdf

clean:
	rm -rf html latex
	rm -f xrp_rm.pdf

.PHONY : all doxygen html pdf clean
