CC := xt-xcc
override CFLAGS += -W -Wall -I.. -I../xrp-kernel -mlongcalls -g -mlsp=$(LSP) --xtensa-core=$(DSP_CORE)
override LDFLAGS += -g -mlsp=$(LSP) --xtensa-core=$(DSP_CORE) \
		    -Wl,--defsym,_memmap_cacheattr_reset=0x44441141 \
		    -Wl,--defsym,xrp_dsp_comm_base_magic=0x20161006

DSP_CORE ?= IVPEP_SNY_IVP_AL2_P1
LSP ?= ./IVP_D233L_SNY_Subsystem/LSP_IVP0/sim

OBJS := xrp_dsp.o user_main.o

default: xrp-dsp
clean:
	rm -f xrp-dsp $(OBJS)

FORCE:

$(OBJS): ../xrp_api.h
xrp_dsp.o: ../xrp-kernel/xrp_kernel_dsp_interface.h
xrp_dsp.o: FORCE

xrp-dsp: $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)
