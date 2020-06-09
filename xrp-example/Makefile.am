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

if BUILD_EXTERNAL
AM_CPPFLAGS = -I$(srcdir)/../xrp-common
else
AM_CPPFLAGS = -I$(srcdir)/.. -I$(srcdir)/../xrp-common
endif
AM_CFLAGS = -W -Wall

bin_PROGRAMS =

if BUILD_STANDALONE
if BUILD_HOST
bin_PROGRAMS += xrp-host-standalone
BUILT_SOURCES = xrp.dtb
CLEANFILES = xrp.dtb
endif
if BUILD_DSP
bin_PROGRAMS += xrp-dsp-standalone
endif
endif

if BUILD_HOSTED
if BUILD_HOST
bin_PROGRAMS += xrp-host-hosted
endif
if BUILD_DSP
bin_PROGRAMS += xrp-dsp-hosted
endif
endif

if BUILD_SINGLE
if BUILD_HOST
bin_PROGRAMS += xrp-host-single
endif
endif

if BUILD_EXTERNAL
dsp_cppflags = $(AM_CPPFLAGS)
else
dsp_cppflags = $(AM_CPPFLAGS) -I$(srcdir)/../xrp-dsp
endif
dsp_ldflags = $(AM_LDFLAGS) \
	      -mlsp=$(DSP_LSP) \
	      -Wl,--defsym,_memmap_cacheattr_reset=$(DSP_CACHEATTR)

xrp_dsp_standalone_SOURCES = dsp_main.c dsp_test.c
xrp_dsp_standalone_CPPFLAGS = $(dsp_cppflags)
xrp_dsp_standalone_LDFLAGS = $(dsp_ldflags) \
			     -Wl,--defsym,xrp_dsp_comm_base_magic=$(DSP_COMM_BASE)
if BUILD_EXAMPLE_LSP
EXTRA_xrp_dsp_standalone_DEPENDENCIES = $(DSP_LSP)
endif

if BUILD_EXTERNAL
xrp_dsp_standalone_LDADD = -lxrp-dsp \
			   -lxrp-dsp-hw-$(HW_PORT) \
			   -lxrp-common \
			   $(THREADS_LDFLAGS)
else
xrp_dsp_standalone_LDADD = ../xrp-dsp/libxrp-dsp.a \
			   ../xrp-dsp/$(HW_PORT)/libxrp-dsp-hw-$(HW_PORT).a \
			   ../xrp-common/libxrp-common.a \
			   $(THREADS_LDFLAGS)
endif

xrp_dsp_hosted_SOURCES = dsp_main.c dsp_test.c
xrp_dsp_hosted_CPPFLAGS = $(dsp_cppflags)
xrp_dsp_hosted_LDFLAGS = $(dsp_ldflags) \
			 -Wl,--defsym,xrp_dsp_comm_base_magic=0x20161006
if BUILD_EXAMPLE_LSP
EXTRA_xrp_dsp_hosted_DEPENDENCIES = $(DSP_LSP)
endif

if BUILD_EXTERNAL
xrp_dsp_hosted_LDADD = -lxrp-dsp \
		       -lxrp-dsp-hw-$(HW_PORT) \
		       -lxrp-common \
		       $(THREADS_LDFLAGS)
else
xrp_dsp_hosted_LDADD = ../xrp-dsp/libxrp-dsp.a \
		       ../xrp-dsp/$(HW_PORT)/libxrp-dsp-hw-$(HW_PORT).a \
		       ../xrp-common/libxrp-common.a \
		       $(THREADS_LDFLAGS)
endif

xrp_host_standalone_SOURCES = host_main.c xrp_dtb.s
xrp_host_standalone_CFLAGS = $(AM_CFLAGS) $(THREAD_CFLAGS)
if BUILD_EXTERNAL
xrp_host_standalone_LDADD = -lxrp-host-standalone $(THREADS_LDFLAGS) $(LIBFDT_LDFLAGS) -lfdt
else
xrp_host_standalone_LDADD = ../xrp-host/libxrp-host-standalone.a $(THREADS_LDFLAGS) $(LIBFDT_LDFLAGS) -lfdt
endif

if HOST_OS_ELF
xrp_host_standalone_LDFLAGS = $(AM_LDFLAGS) \
			      -mlsp=$(HOST_LSP) \
			      -Wl,--defsym,_memmap_cacheattr_reset=$(HOST_CACHEATTR)
EXTRA_xrp_host_standalone_DEPENDENCIES = $(HOST_LSP)
endif

if HOST_OS_LINUX
xrp_host_standalone_LDADD += -lrt
endif

xrp_host_hosted_SOURCES = host_main.c
xrp_host_hosted_CFLAGS = $(AM_CFLAGS) $(THREAD_CFLAGS)
if BUILD_EXTERNAL
xrp_host_hosted_LDADD = -lxrp-host-hosted $(THREADS_LDFLAGS)
else
xrp_host_hosted_LDADD = ../xrp-host/libxrp-host-hosted.a $(THREADS_LDFLAGS)
endif

xrp_host_single_SOURCES = host_main.c dsp_test.c
if BUILD_EXTERNAL
xrp_host_single_LDADD = -lxrp-host-single $(THREADS_LDFLAGS)
else
xrp_host_single_LDADD = ../xrp-host/libxrp-host-single.a $(THREADS_LDFLAGS)
endif

xrp_dtb.$(OBJEXT): xrp.dtb
xrp.dtb: $(srcdir)/xrp.dts
	$(AM_V_GEN)$(DTC) -o $@ -O dtb $<

vp6-mp/package/%: $(srcdir)/vp6-mp/subsys.xtsys
	$$(dirname $$(which $(CC)))/../libexec/xt-mbuild \
		-socfile $< -root `pwd` -syspkg `pwd`/vp6-mp/package -sysbuild `pwd`/vp6-mp/build \
		-preclean -build sw -lsps sim,sim-stacklocal
