CFLAGS += -W -Wall -I.. -I../xrp-kernel -I../dtc/libfdt -g
LDFLAGS += -L../dtc/libfdt -lfdt -lrt
DTC := ../dtc/dtc

OBJS := main.o xrp_linux_sim.o xrp_alloc.o xrp.o

default: linux-sim-test
clean:
	rm -f linux-sim-test $(OBJS) xrp.s

xrp.s: xrp.dts
	$(DTC) -o $@ -O asm $<

$(OBJS): ../xrp_api.h
xrp_linux_native.o: ../xrp-kernel/xrp_kernel_defs.h

linux-sim-test: $(OBJS)
	$(CC) $(OBJS) -o $@ $(CFLAGS) $(LDFLAGS)
