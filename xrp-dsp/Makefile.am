#
# Copyright (c) 2018 Cadence Design Systems Inc.
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
#

SUBDIRS = $(HW_PORT)
if BUILD_ALL_SIMPLE
SUBDIRS += simple simple-xos
endif

AM_CPPFLAGS = -I$(srcdir)/.. \
	      -I$(srcdir)/../xrp-common \
	      -I$(srcdir)/../xrp-kernel
AM_CFLAGS = -W -Wall

include_HEADERS = ../xrp_api.h xrp_dsp_hw.h xrp_dsp_user.h
lib_LIBRARIES = libxrp-dsp.a

libxrp_dsp_a_SOURCES = xrp_dsp.c
