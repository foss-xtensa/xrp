AM_CPPFLAGS = -I$(srcdir)/.. -I$(srcdir)/../xrp-kernel
AM_CFLAGS = -W -Wall --xtensa-core=$(DSP_CORE)

include_HEADERS = ../xrp_api.h xrp_dsp_hw.h
lib_LIBRARIES = libxrp-dsp.a libxrp-dsp-hw-simple.a

libxrp_dsp_a_SOURCES = xrp_dsp.c
libxrp_dsp_hw_simple_a_SOURCES = xrp_dsp_hw_simple.c
