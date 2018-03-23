#
# Copyright (c) 2017 Cadence Design Systems Inc.
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

AM_CPPFLAGS = -I$(srcdir)/..
AM_CFLAGS = -W -Wall

bin_PROGRAMS =

if BUILD_DSP
AM_CPPFLAGS += -I$(srcdir)/../xrp-dsp
AM_CFLAGS += --xtensa-core=$(DSP_CORE)
AM_LDFLAGS = --xtensa-core=$(DSP_CORE) -mlsp=$(DSP_LSP) \
	     -Wl,--defsym,_memmap_cacheattr_reset=$(DSP_CACHEATTR)

xrp_dsp_standalone_LDFLAGS = $(AM_LDFLAGS) \
			     -Wl,--defsym,xrp_dsp_comm_base_magic=$(DSP_COMM_BASE)

xrp_dsp_hosted_LDFLAGS = $(AM_LDFLAGS) \
			 -Wl,--defsym,xrp_dsp_comm_base_magic=0x20161006
if BUILD_STANDALONE
bin_PROGRAMS += xrp-dsp-standalone
endif
if BUILD_HOSTED
bin_PROGRAMS += xrp-dsp-hosted
endif

else
AM_CFLAGS += $(THREADS_CFLAGS)
AM_LDFLAGS = $(THREADS_LDFLAGS)

if BUILD_STANDALONE
BUILT_SOURCES = xrp.dtb
CLEANFILES = xrp.dtb
bin_PROGRAMS += xrp-host-standalone
endif
if BUILD_HOSTED
bin_PROGRAMS += xrp-host-hosted
endif
if BUILD_SINGLE
bin_PROGRAMS += xrp-host-single
endif
endif

if HOST_OS_LINUX
AM_LDFLAGS = -lrt
endif

xrp_dsp_hosted_SOURCES = dsp_main.c dsp_test.c
xrp_dsp_standalone_SOURCES = dsp_main.c dsp_test.c

xrp_dsp_hosted_LDADD = ../xrp-dsp/libxrp-dsp.a ../xrp-dsp/libxrp-dsp-hw-simple.a
xrp_dsp_standalone_LDADD = ../xrp-dsp/libxrp-dsp.a ../xrp-dsp/libxrp-dsp-hw-simple.a

xrp_host_hosted_SOURCES = host_main.c
xrp_host_standalone_SOURCES = host_main.c xrp_dtb.s
xrp_host_single_SOURCES = host_main.c dsp_test.c

xrp_host_hosted_LDADD = ../xrp-host/libxrp-host-hosted.a $(THREADS_LDFLAGS)
xrp_host_standalone_LDADD = ../xrp-host/libxrp-host-standalone.a $(THREADS_LDFLAGS) $(LIBFDT_LDFLAGS) -lfdt
xrp_host_single_LDADD = ../xrp-host/libxrp-host-single.a $(THREADS_LDFLAGS)

xrp_dtb.$(OBJEXT): xrp.dtb
xrp.dtb: $(srcdir)/xrp.dts
	$(AM_V_GEN)$(DTC) -o $@ -O dtb $<
