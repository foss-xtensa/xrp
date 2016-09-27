CFLAGS += -W -Wall -I.. -I../xrp-kernel -g

OBJS := main.o xrp_linux_native.o

default: linux-native-test
clean:
	rm -f linux-native-test $(OBJS)

$(OBJS): ../xrp_api.h
xrp_linux_native.o: ../xrp-kernel/xrp_kernel_defs.h

linux-native-test: $(OBJS)
	$(CC) $(OBJS) -o $@ $(CFLAGS)
