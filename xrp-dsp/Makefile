CC := xt-xcc
CFLAGS += -W -Wall -I.. -I../xrp-kernel -g

OBJS := xrp_dsp.o user_main.o

default: xrp-dsp
clean:
	rm -f xrp-dsp $(OBJS)

$(OBJS): ../xrp_api.h
xrp_dsp.o: ../xrp-kernel/xrp_kernel_dsp_interface.h

xrp-dsp: $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)
