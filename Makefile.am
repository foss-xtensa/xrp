SUBDIRS =

if BUILD_DSP
SUBDIRS += xrp-dsp
else
if BUILD_SIM
SUBDIRS += xrp-linux-sim
endif
if BUILD_NAT
SUBDIRS += xrp-linux-native
endif
endif

if BUILD_EXAMPLE
SUBDIRS += xrp-example
endif
