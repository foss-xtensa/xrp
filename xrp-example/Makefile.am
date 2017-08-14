AM_CPPFLAGS = -I$(srcdir)/..
AM_CFLAGS = -W -Wall

bin_PROGRAMS =

if BUILD_DSP
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
