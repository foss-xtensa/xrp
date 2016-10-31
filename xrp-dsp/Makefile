CC := xt-xcc
CFLAGS += -W -Wall -I.. -I../xrp-kernel -mlongcalls -g -mlsp=$(LSP_DIR)/sim --xtensa-core=$(DSP_CORE)
LDFLAGS += -g -mlsp=$(LSP_DIR)/sim --xtensa-core=$(DSP_CORE) -Wl,--defsym,_memmap_cacheattr_reset=0x44441141

DSP_CORE ?= IVPEP_SNY_IVP_AL2_P1
LSP_DIR ?= ./IVP_D233L_SNY_Subsystem/LSP_IVP0

OBJS := xrp_dsp.o user_main.o

default: xrp-dsp
clean:
	rm -f xrp-dsp $(OBJS)

$(OBJS): ../xrp_api.h
xrp_dsp.o: ../xrp-kernel/xrp_kernel_dsp_interface.h

xrp-dsp: $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)
