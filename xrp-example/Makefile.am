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
	     -Wl,--defsym,_memmap_cacheattr_reset=0x44441141

xrp_dsp_sim_LDFLAGS = $(AM_LDFLAGS) \
		      -Wl,--defsym,xrp_dsp_comm_base_magic=$(DSP_COMM_BASE)

xrp_dsp_nat_LDFLAGS = $(AM_LDFLAGS) \
		      -Wl,--defsym,xrp_dsp_comm_base_magic=0x20161006
if BUILD_SIM
bin_PROGRAMS += xrp-dsp-sim
endif
if BUILD_NAT
bin_PROGRAMS += xrp-dsp-nat
endif

else
if BUILD_SIM
BUILT_SOURCES = xrp.s
CLEANFILES = xrp.s
bin_PROGRAMS += xrp-linux-sim
endif
if BUILD_NAT
bin_PROGRAMS += xrp-linux-nat
endif
endif

xrp_dsp_nat_SOURCES = dsp_main.c
xrp_dsp_sim_SOURCES = dsp_main.c

xrp_dsp_nat_LDADD = ../xrp-dsp/libxrp-dsp.a ../xrp-dsp/libxrp-dsp-hw-simple.a
xrp_dsp_sim_LDADD = ../xrp-dsp/libxrp-dsp.a ../xrp-dsp/libxrp-dsp-hw-simple.a

xrp_linux_nat_SOURCES = linux_main.c
xrp_linux_sim_SOURCES = linux_main.c xrp.s

xrp_linux_nat_CFLAGS = -pthread
xrp_linux_nat_LDFLAGS = -pthread

xrp_linux_sim_CFLAGS = -pthread
xrp_linux_sim_LDFLAGS = -pthread

xrp_linux_nat_LDADD = ../xrp-linux-native/libxrp-linux-native.a
xrp_linux_sim_LDADD = ../xrp-linux-sim/libxrp-linux-sim.a -lrt -lfdt

xrp.s: $(srcdir)/xrp.dts
	$(AM_V_GEN)$(DTC) -o $@ -O asm $<
